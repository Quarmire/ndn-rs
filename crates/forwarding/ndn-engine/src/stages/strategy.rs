use std::sync::Arc;

use smallvec::SmallVec;
use tracing::trace;

use crate::Fib;
use crate::enricher::ContextEnricher;
use crate::observability::targets as t;
use crate::pipeline::{
    Action, AnyMap, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_discovery_core::scope::is_link_local;
use ndn_packet::Name;

fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

fn is_localhop_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhop")
}
use ndn_store::{Pit, StrategyTable};
use ndn_strategy::{ErasedStrategy, MeasurementsTable, SignalsTable, StrategyContext};
use ndn_transport::face::FaceScope;

/// Outcome of consulting the `NextHopFaceId` LP header (NDNLPv2 0x0330)
/// before strategy dispatch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum NextHopOverride {
    None,
    /// Forward directly to the named face, bypassing FIB / strategy.
    Forward(ndn_transport::FaceId),
    /// Tag set but the named face is unknown; drop.
    DropFaceGone,
}

/// `NextHopFaceId` is a privileged "send to this face, bypass FIB / strategy"
/// directive (NDNLPv2). Decode-stage `/localhost` / `/localhop` checks have
/// already run, so this does not re-apply scope.
pub(crate) fn next_hop_override(
    tags: &AnyMap,
    face_exists: impl Fn(ndn_transport::FaceId) -> bool,
) -> NextHopOverride {
    use crate::stages::decode::NextHopFaceId;
    let Some(NextHopFaceId(face_id_u64)) = tags.get::<NextHopFaceId>().copied() else {
        return NextHopOverride::None;
    };
    let face_id = ndn_transport::FaceId(face_id_u64);
    if face_exists(face_id) {
        NextHopOverride::Forward(face_id)
    } else {
        NextHopOverride::DropFaceGone
    }
}

/// Producer-region prefixes for NDNLPv2 ForwardingHint handling — the
/// NFD `NetworkRegionTable`. Empty = this forwarder hosts no producer region,
/// so a hinted Interest is always forwarded toward its hint.
///
/// Runtime-mutable: a mobile node learns its own producer region (its
/// `/ndn/node/<id>` prefix) at discovery start rather than at build time, so a
/// hinted Interest reaching it can be stripped and forwarded by name to the
/// local producer. The lock is only taken when an Interest actually carries a
/// forwarding hint (rare on the hot path).
#[derive(Default)]
pub struct NetworkRegionTable {
    regions: std::sync::RwLock<Vec<Name>>,
}

impl NetworkRegionTable {
    pub fn new(regions: Vec<Name>) -> Self {
        Self {
            regions: std::sync::RwLock::new(regions),
        }
    }

    /// True if any delegation in the hint reaches (is a prefix of) a producer
    /// region — `NetworkRegionTable::isInProducerRegion`. At that point NFD
    /// strips the hint and forwards by the Interest name.
    pub fn is_in_producer_region(&self, hint: &[Arc<Name>]) -> bool {
        let regions = self.regions.read().unwrap();
        regions
            .iter()
            .any(|region| hint.iter().any(|deleg| region.has_prefix(deleg)))
    }

    /// Add a producer region this forwarder hosts (idempotent). Used at runtime
    /// when a node learns its own routable prefix (e.g. discovery start).
    pub fn add_region(&self, region: Name) {
        let mut regions = self.regions.write().unwrap();
        if !regions.contains(&region) {
            regions.push(region);
        }
    }
}

/// Host part of a face's remote URI — the URI with scheme and port removed, so
/// `udp4://192.168.1.11:6363` and `udp4://192.168.1.11:40759` both yield
/// `192.168.1.11`.
///
/// Used to decide "is this nexthop the same NODE the Interest arrived from?".
/// Excluding by FaceId alone is not enough here: a pre-connected outbound UDP
/// face binds an ephemeral local port, so the peer's replies arrive on a
/// SEPARATE on-demand face. The same neighbour then occupies two face objects,
/// `nexthops_excluding(in_face)` misses the other one, and the Interest is
/// forwarded straight back to its origin.
///
/// Measured consequence on the fleet: 12 wire copies per Interest against NFD's
/// 9 — the 3 extra being exactly the returns to the originator — which put 35%
/// more packets on a shared medium and cost ~30% of video throughput.
///
/// `None` for a QUIC link face: a link is one connection to one device,
/// identified by its key, and devices behind one NAT (or on one host) share
/// an address — a relay must forward between them.
fn peer_host(face_table: &ndn_transport::FaceTable, face_id: ndn_transport::FaceId) -> Option<String> {
    let face = face_table.get(face_id)?;
    if face.kind() == ndn_transport::FaceKind::Quic {
        return None;
    }
    let uri = face.remote_uri()?;
    // strip scheme
    Some(host_of_remote_uri(&uri).to_string())
}

pub struct StrategyStage {
    pub strategy_table: Arc<StrategyTable<dyn ErasedStrategy>>,
    pub default_strategy: Arc<dyn ErasedStrategy>,
    pub fib: Arc<Fib>,
    pub measurements: Arc<MeasurementsTable>,
    pub signals: Arc<SignalsTable>,
    pub pit: Arc<Pit>,
    pub face_table: Arc<ndn_transport::FaceTable>,
    pub enrichers: Vec<Arc<dyn ContextEnricher>>,
    pub runtime: Arc<dyn ndn_runtime::Runtime>,
    pub network_region: Arc<NetworkRegionTable>,
}

impl StrategyStage {
    /// NDNLPv2 ForwardingHint: the FIB lookup name. Normally the Interest name,
    /// but when the Interest carries a forwarding hint that has not yet reached
    /// a producer region, forward toward the hint's delegation name instead
    /// (NFD `onIncomingInterest`). The PIT still keys on the Interest name.
    fn fib_lookup_name(&self, ctx: &PacketContext, interest_name: &Name) -> Name {
        let DecodedPacket::Interest(i) = &ctx.packet else {
            return interest_name.clone();
        };
        let Some(hint) = i.forwarding_hint() else {
            return interest_name.clone();
        };
        if hint.is_empty() || self.network_region.is_in_producer_region(hint) {
            return interest_name.clone();
        }
        // Forward toward the first delegation that resolves in the FIB; if none
        // do, use the first delegation (the lookup misses → NoRoute).
        for deleg in hint {
            if self.fib.lpm(deleg).is_some() {
                return deleg.as_ref().clone();
            }
        }
        hint[0].as_ref().clone()
    }
}

impl StrategyStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        match &ctx.packet {
            DecodedPacket::Interest(_) => {}
            _ => return Action::Continue(ctx),
        };

        let name = match &ctx.name {
            Some(n) => n.clone(),
            None => return Action::Drop(DropReason::MalformedPacket),
        };

        match next_hop_override(&ctx.tags, |fid| self.face_table.get(fid).is_some()) {
            NextHopOverride::Forward(face_id) => {
                trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, override_face=%face_id, action="forward", "strategy decision");
                ctx.out_faces.push(face_id);
                let out = ctx.out_faces.clone();
                return Action::Send(ctx, out);
            }
            NextHopOverride::DropFaceGone => {
                trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, action="drop", "strategy decision");
                return Action::Drop(DropReason::UnknownFace);
            }
            NextHopOverride::None => {}
        }

        // ForwardingHint: FIB lookup may target the hint's delegation rather
        // than the Interest name (the PIT still keys on the Interest name).
        let fib_name = self.fib_lookup_name(&ctx, &name);
        let fib_lookup = self.fib.lpm_with_depth(&fib_name);
        let fib_entry_arc = fib_lookup.as_ref().map(|(_, e)| Arc::clone(e));
        let fib_entry_ref = fib_entry_arc.as_deref();

        // The longest-prefix-match diagnostic (skyfall FIELD-REPORT-2 SS2): the event names
        // the MATCHED ENTRY'S prefix, not the queried name — LPM returns exactly one entry,
        // so a coarse route and an exact registration at different lengths never merge, and
        // the loser vanishes silently ("zero packets, no error"). With this event, the
        // shadow is one line: the face you expected is absent from the matched entry's
        // nexthops, and `matched_prefix` tells you which entry actually won.
        if let Some((depth, e)) = &fib_lookup {
            if tracing::enabled!(target: t::FWD_FIB, tracing::Level::TRACE) {
                let matched_prefix = ndn_packet::Name::from_components(
                    fib_name.components().iter().take(*depth).cloned(),
                );
                trace!(target: t::FWD_FIB, face=%ctx.face_id, name=%name, matched=true,
                    matched_prefix=%matched_prefix, matched_depth=*depth,
                    nexthops=?e.nexthops.iter().map(|nh| (nh.face_id, nh.cost)).collect::<Vec<_>>(),
                    "fib lookup: Interest matched THIS entry; an expected face missing from these nexthops sits on a shadowed entry");
            }
        } else {
            trace!(target: t::FWD_FIB, face=%ctx.face_id, name=%name, matched=false, "fib lookup: no entry");
        }

        let strategy_fib: Option<ndn_strategy::FibEntry> =
            fib_entry_ref.map(|e| ndn_strategy::FibEntry {
                nexthops: e
                    .nexthops
                    .iter()
                    .map(|nh| ndn_strategy::FibNexthop {
                        face_id: nh.face_id,
                        cost: nh.cost,
                    })
                    .collect(),
            });

        // Hot path: known cross-layer inputs (RSSI, GPS, …) come from
        // `signals`, so when no open-ended enricher is registered and no A-LAL
        // geo headers were decoded, we skip building a per-packet AnyMap
        // entirely and share one empty map.
        let pl = ctx.tags.get::<ndn_strategy::PrevHopLocation>().copied();
        let dl = ctx.tags.get::<ndn_strategy::DataLocation>().copied();
        let built_extensions;
        let extensions: &AnyMap = if self.enrichers.is_empty() && pl.is_none() && dl.is_none() {
            static EMPTY: std::sync::LazyLock<AnyMap> = std::sync::LazyLock::new(AnyMap::new);
            &EMPTY
        } else {
            let mut e = AnyMap::new();
            for enricher in &self.enrichers {
                enricher.enrich(strategy_fib.as_ref(), &mut e);
            }
            // Forward A-LAL geo headers (CCLF Location Score) per-Interest.
            if let Some(pl) = pl {
                e.insert(pl);
            }
            if let Some(dl) = dl {
                e.insert(dl);
            }
            built_extensions = e;
            &built_extensions
        };

        // The PIT entry as this Interest found it on arrival. NFD runs the
        // Interests of an entry one at a time in arrival order; the parallel
        // pipeline can run two strategy passes for one entry together (the PIT
        // check sends a new downstream's Interest to the strategy while
        // nothing went upstream yet), or a later Interest's first. An
        // out-record sent for an Interest that arrived later (`sent_at` is
        // that Interest's arrival) is not part of this view, and suppression
        // is judged at this arrival: the time base of `sent_at` and of the
        // PIT check's retransmission window. `seen` is also what the
        // out-record commit below checks against.
        let arrival = ctx.arrival;
        let (seen, suppressed_faces, entry_retx_suppressed) = ctx
            .pit_token
            .and_then(|tok| {
                self.pit.with_entry(&tok, |e| {
                    (
                        e.out_records
                            .iter()
                            .filter(|r| r.sent_at <= arrival)
                            .map(|r| (r.face_id, r.last_nonce, r.sent_at))
                            .collect::<SmallVec<[(u64, u32, u64); 4]>>(),
                        // Retransmission suppression (NFD
                        // RetxSuppressionExponential). Read-only here: the
                        // per-entry window grows in `note_forward_decision`,
                        // i.e. when a forward actually happens, so merely
                        // consulting a strategy never advances it.
                        e.suppressed_upstreams(arrival)
                            .into_iter()
                            .map(ndn_transport::FaceId)
                            .collect::<SmallVec<[ndn_transport::FaceId; 4]>>(),
                        e.entry_retx_suppressed(arrival),
                    )
                })
            })
            .unwrap_or_default();
        // Upstreams already forwarded to for this PIT entry (D.09). Empty on the
        // first forward; populated when PitCheck re-forwards a retransmission,
        // so the strategy picks an untried nexthop instead of the same one.
        let tried_faces: SmallVec<[ndn_transport::FaceId; 4]> = seen
            .iter()
            .map(|&(face_id, _, _)| ndn_transport::FaceId(face_id))
            .collect();

        let sctx = StrategyContext {
            name: &name,
            in_face: ctx.face_id,
            fib_entry: strategy_fib.as_ref(),
            pit_token: ctx.pit_token,
            tried_faces: &tried_faces,
            suppressed_faces: &suppressed_faces,
            entry_retx_suppressed,
            measurements: &self.measurements,
            signals: self.signals.as_ref(),
            extensions,
            runtime: &self.runtime,
        };

        // Choose the strategy by the FIB-lookup name, not the raw Interest name:
        // a forwarding-hinted Interest is routed toward its hint delegation, so it
        // must use that namespace's strategy. Otherwise a hinted file Interest
        // (`/ripple/<id>/file/...`, hint `/ndn/node/<peer>`) has no strategy entry
        // for its own name and falls back to the root `MulticastStrategy`, which
        // fans it over *every* nexthop (incl. dead radios) instead of the per-peer
        // best-route that prefers the fast face. For non-hinted Interests
        // `fib_name == name`, so this is a no-op. (NFD picks the strategy for the
        // namespace being forwarded.)
        let strategy = self
            .strategy_table
            .lpm(&fib_name)
            .unwrap_or_else(|| Arc::clone(&self.default_strategy));
        trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, fib_name=%fib_name, strategy=%strategy.name(), "strategy invoked");

        let actions = if let Some(a) = strategy.decide_sync(&sctx) {
            a
        } else {
            strategy.after_receive_interest_erased(&sctx)
        };

        // Self-learning discovery: expand `Broadcast` to every eligible face
        // (the strategy has no face table). The Forward handling below applies
        // scope and split-horizon, so a no-route flood is safe.
        let action = match actions.into_iter().next() {
            Some(ForwardingAction::Broadcast) => {
                let faces: smallvec::SmallVec<[ndn_transport::FaceId; 4]> = self
                    .face_table
                    .face_ids()
                    .into_iter()
                    .filter(|f| *f != ctx.face_id)
                    .collect();
                Some(ForwardingAction::Forward(faces))
            }
            other => other,
        };

        if let Some(action) = action {
            match action {
                ForwardingAction::Broadcast => unreachable!("mapped to Forward above"),
                ForwardingAction::Forward(faces) => {
                    trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, out_faces=?faces, action="forward", "strategy decision");
                    // Egress scope (mirrors NFD `wouldViolateScope`):
                    //   /localhost  → never egress to a non-local face
                    //   /localhop   → only egress to non-local if arrived
                    //                 on a local face
                    //   /ndn/local/* → link-local, local-only
                    let in_face_scope = self
                        .face_table
                        .get(ctx.face_id)
                        .map(|f| f.scope())
                        .unwrap_or(FaceScope::NonLocal);
                    let restrict_to_local = is_link_local(&name)
                        || is_localhost_name(&name)
                        || (is_localhop_name(&name) && in_face_scope == FaceScope::NonLocal);
                    let effective_faces: SmallVec<[ndn_transport::FaceId; 4]> = if restrict_to_local
                    {
                        faces
                            .iter()
                            .copied()
                            .filter(|fid| {
                                let keep = self
                                    .face_table
                                    .get(*fid)
                                    .map(|f| f.scope() == FaceScope::Local)
                                    .unwrap_or(false);
                                if !keep {
                                    trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, out_face=%fid, "strategy: scope violation, dropping out-face");
                                }
                                keep
                            })
                            .collect()
                    } else {
                        faces.iter().copied().collect()
                    };
                    if effective_faces.is_empty() {
                        return Action::Nack(ctx, NackReason::NoRoute);
                    }
                    // Outgoing-Interest loop avoidance: record (face_id,
                    // nonce) in out-records and suppress re-sends matching
                    // an existing pair. An upstream whose out-record is not
                    // the one this pass `seen` is skipped too: another pass
                    // for this entry sent there meanwhile, or for a later
                    // Interest. In NFD's serial order one of the two would
                    // have found the other's out-record and been suppressed;
                    // the Interest pending there brings the Data that
                    // satisfies this downstream as well.
                    let interest_nonce = match &ctx.packet {
                        DecodedPacket::Interest(i) => i.nonce(),
                        _ => None,
                    };
                    let now = ctx.arrival;
                    let pit_token = ctx.pit_token;
                    let surviving_faces: SmallVec<[ndn_transport::FaceId; 4]> =
                        if let (Some(nonce), Some(token)) = (interest_nonce, pit_token) {
                            effective_faces
                                .into_iter()
                                .filter(|fid| {
                                    let skip = self.pit.with_entry_mut(&token, |entry| {
                                        let skip = entry
                                            .out_records
                                            .iter()
                                            .find(|or| or.face_id == fid.0)
                                            .is_some_and(|or| {
                                                or.last_nonce == nonce
                                                    || !seen.contains(&(
                                                        or.face_id,
                                                        or.last_nonce,
                                                        or.sent_at,
                                                    ))
                                            });
                                        if !skip {
                                            entry.add_out_record(fid.0, nonce, now);
                                        }
                                        skip
                                    });
                                    !skip.unwrap_or(false)
                                })
                                .collect()
                        } else {
                            effective_faces.into_iter().collect()
                        };
                    // Never send an Interest back to the NODE it came from.
                    // `nexthops_excluding(in_face)` removes the ingress FACE,
                    // but a neighbour reached over a pre-connected UDP face
                    // (ephemeral local port) delivers its packets on a separate
                    // on-demand face, so the same node appears twice in the
                    // face table and the FIB nexthop survives that exclusion.
                    let surviving_faces: SmallVec<[ndn_transport::FaceId; 4]> =
                        match peer_host(&self.face_table, ctx.face_id) {
                            Some(ingress_host) => surviving_faces
                                .into_iter()
                                .filter(|fid| {
                                    peer_host(&self.face_table, *fid)
                                        .is_none_or(|h| h != ingress_host)
                                })
                                .collect(),
                            None => surviving_faces,
                        };
                    if surviving_faces.is_empty() {
                        trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, action="drop", "strategy decision: no chosen upstream left (each already has this entry's Interest, or is the ingress node)");
                        return Action::Drop(DropReason::Suppressed);
                    }
                    // One forward DECISION -> one growth of the per-entry
                    // suppression window, however many upstreams it fans out to
                    // (NFD's decidePerPitEntry takes the entry, not a face).
                    if let Some(token) = pit_token {
                        self.pit.with_entry_mut(&token, |entry| {
                            entry.note_forward_decision();
                        });
                    }
                    ctx.out_faces.extend_from_slice(&surviving_faces);
                    let out = ctx.out_faces.clone();
                    return Action::Send(ctx, out);
                }
                ForwardingAction::ForwardAfter { faces, delay } => {
                    trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, out_faces=?faces, delay_ms=%delay.as_millis(), action="forward-after", "strategy decision");
                    let pit = Arc::clone(&self.pit);
                    let face_table = Arc::clone(&self.face_table);
                    let raw_bytes = ctx.raw_bytes.clone();
                    let pit_token = ctx.pit_token;
                    let runtime = Arc::clone(&self.runtime);
                    let sleep = runtime.sleep(delay);
                    self.runtime.spawn(Box::pin(async move {
                        sleep.await;
                        // Re-check the PIT on wake. Skip the (re)broadcast if the
                        // entry is gone (satisfied by Data / expired) OR its
                        // overhear-cancel flag was set — a neighbor forwarded the
                        // same Interest first and won the CCLF election.
                        if let Some(token) = pit_token {
                            let proceed = pit
                                .with_entry(&token, |e| !e.forward_cancelled)
                                .unwrap_or(false);
                            if !proceed {
                                return;
                            }
                        }
                        for face_id in &faces {
                            if let Some(face) = face_table.get(*face_id) {
                                let _ = face.send_bytes(raw_bytes.clone()).await;
                            }
                        }
                    }));
                    return Action::Drop(DropReason::Other);
                }
                ForwardingAction::Nack(reason) => {
                    trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, reason=?reason, action="nack", "strategy decision");
                    return Action::Nack(ctx, reason);
                }
                ForwardingAction::Suppress => {
                    trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, action="drop", "strategy decision");
                    return Action::Drop(DropReason::Suppressed);
                }
            }
        }

        trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, action="nack", "strategy decision");
        Action::Nack(ctx, NackReason::NoRoute)
    }
}

/// Host extraction, factored out of `peer_host` so it is testable without a
/// FaceTable.
fn host_of_remote_uri(uri: &str) -> &str {
    let after_scheme = uri.split("://").nth(1).unwrap_or(uri);
    if let Some(end) = after_scheme.find(']') {
        &after_scheme[..=end]
    } else {
        after_scheme.rsplit_once(':').map_or(after_scheme, |(h, _)| h)
    }
}

#[cfg(test)]
mod tests {
    use super::host_of_remote_uri;

    /// The same neighbour reached over a pre-connected face and over the
    /// on-demand face its replies create must resolve to ONE host, so the
    /// strategy can tell they are the same node.
    #[test]
    fn two_faces_to_one_peer_resolve_to_the_same_host() {
        let persistent = host_of_remote_uri("udp4://192.168.1.11:6363");
        let on_demand = host_of_remote_uri("udp4://192.168.1.11:40759");
        assert_eq!(persistent, "192.168.1.11");
        assert_eq!(
            persistent, on_demand,
            "an ephemeral source port must not make a peer look like a different node"
        );
    }

    #[test]
    fn distinct_peers_stay_distinct() {
        assert_ne!(
            host_of_remote_uri("udp4://192.168.1.11:6363"),
            host_of_remote_uri("udp4://192.168.1.12:6363"),
        );
    }

    /// IPv6 literals are bracketed; the port must be stripped without eating
    /// the address's own colons.
    #[test]
    fn ipv6_literal_keeps_its_colons() {
        assert_eq!(host_of_remote_uri("udp6://[fe80::1]:6363"), "[fe80::1]");
        assert_eq!(
            host_of_remote_uri("udp6://[fe80::1]:6363"),
            host_of_remote_uri("udp6://[fe80::1]:40759"),
        );
    }

    /// Non-network faces (unix sockets, internal) have no host:port shape;
    /// they must not collide with each other or suppress forwarding.
    #[test]
    fn non_network_uris_do_not_collapse_together() {
        assert_ne!(
            host_of_remote_uri("unix:///run/nfd/nfd.sock"),
            host_of_remote_uri("internal://management"),
        );
    }

    use super::*;

    #[test]
    fn link_local_scope_check_is_accurate() {
        use std::str::FromStr;
        let link_local = ndn_packet::Name::from_str("/ndn/local/nd/hello/1").unwrap();
        let global = ndn_packet::Name::from_str("/ndn/edu/test").unwrap();
        assert!(is_link_local(&link_local), "/ndn/local/ must be link-local");
        assert!(!is_link_local(&global), "/ndn/edu/ must not be link-local");
    }

    #[test]
    fn d03_next_hop_override_absent_falls_through() {
        let tags = AnyMap::new();
        let outcome = next_hop_override(&tags, |_| false);
        assert_eq!(outcome, NextHopOverride::None);
    }

    #[test]
    fn d03_next_hop_override_forwards_when_face_exists() {
        use crate::stages::decode::NextHopFaceId;
        use ndn_transport::FaceId;
        let mut tags = AnyMap::new();
        tags.insert(NextHopFaceId(7));
        let outcome = next_hop_override(&tags, |fid| fid == FaceId(7));
        assert_eq!(outcome, NextHopOverride::Forward(FaceId(7)));
    }

    #[test]
    fn d03_next_hop_override_drops_when_face_unknown() {
        use crate::stages::decode::NextHopFaceId;
        let mut tags = AnyMap::new();
        tags.insert(NextHopFaceId(99));
        let outcome = next_hop_override(&tags, |_| false);
        assert_eq!(outcome, NextHopOverride::DropFaceGone);
    }

    #[test]
    fn d03_next_hop_override_drops_when_face_id_unknown() {
        use crate::stages::decode::NextHopFaceId;
        let mut tags = AnyMap::new();
        tags.insert(NextHopFaceId(u64::from(u32::MAX) + 1));
        let outcome = next_hop_override(&tags, |_| false);
        assert_eq!(outcome, NextHopOverride::DropFaceGone);
    }

    /// PIT out-record duplicate-detection primitive (used by the
    /// StrategyStage Forward branch's loop-avoidance filter).
    #[test]
    fn d06_pit_out_record_detects_duplicate_face_nonce() {
        use ndn_packet::Name;
        use ndn_store::{Pit, PitEntry, PitToken};
        use std::str::FromStr;
        use std::sync::Arc;

        let pit = Pit::new();
        let name = Arc::new(Name::from_str("/d06/test").unwrap());
        let token = PitToken(0xDEADBEEF);
        pit.insert(token, PitEntry::new(name, 0, 1000));

        let already_first = pit
            .with_entry_mut(&token, |entry| {
                let dup = entry
                    .out_records
                    .iter()
                    .any(|or| or.face_id == 5 && or.last_nonce == 0xCAFEBABE);
                if !dup {
                    entry.add_out_record(5, 0xCAFEBABE, 0);
                }
                dup
            })
            .unwrap();
        assert!(
            !already_first,
            "first send should not be flagged as duplicate"
        );

        let already_second = pit
            .with_entry_mut(&token, |entry| {
                let dup = entry
                    .out_records
                    .iter()
                    .any(|or| or.face_id == 5 && or.last_nonce == 0xCAFEBABE);
                if !dup {
                    entry.add_out_record(5, 0xCAFEBABE, 1);
                }
                dup
            })
            .unwrap();
        assert!(already_second, "duplicate (face, nonce) must be flagged");

        let different_nonce = pit
            .with_entry_mut(&token, |entry| {
                let dup = entry
                    .out_records
                    .iter()
                    .any(|or| or.face_id == 5 && or.last_nonce == 0x11112222);
                if !dup {
                    entry.add_out_record(5, 0x11112222, 2);
                }
                dup
            })
            .unwrap();
        assert!(!different_nonce, "regenerated nonce must be admitted");

        let other_face = pit
            .with_entry_mut(&token, |entry| {
                let dup = entry
                    .out_records
                    .iter()
                    .any(|or| or.face_id == 9 && or.last_nonce == 0xCAFEBABE);
                if !dup {
                    entry.add_out_record(9, 0xCAFEBABE, 3);
                }
                dup
            })
            .unwrap();
        assert!(!other_face, "same nonce on a fresh face is allowed");
    }
}

/// Two Interests for one PIT entry whose strategy passes run in an order the
/// parallel pipeline allows: both pass the PIT check (the second arrives from
/// a new downstream before anything went upstream), then the passes run one
/// after the other in the order under test, through the real stages.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod concurrent_pass_tests {
    use super::*;
    use crate::stages::pit::{PitCheckStage, PitMatchStage};
    use ndn_packet::encode::{InterestBuilder, encode_data_unsigned};
    use ndn_packet::{Data, Interest};
    use ndn_strategy::BestRouteStrategy;
    use ndn_transport::FaceId;

    const A: FaceId = FaceId(1);
    const B: FaceId = FaceId(2);
    const UPSTREAM: FaceId = FaceId(3);

    struct Rig {
        name: Name,
        check: PitCheckStage,
        strategy: StrategyStage,
        matcher: PitMatchStage,
        /// Arrival of the first Interest, read from the runtime clock that
        /// stamps arrivals in the engine; the second arrives 0.1 ms later.
        t0: u64,
        t1: u64,
    }

    /// Best-route, with `route` the only nexthop for `name`.
    fn rig(name: &str, route: FaceId) -> Rig {
        let name: Name = name.parse().unwrap();
        let pit = Arc::new(Pit::new());
        let face_table = Arc::new(ndn_transport::FaceTable::new());
        let fib = Arc::new(Fib::new());
        fib.add_nexthop(&name, route, 0);
        let runtime = ndn_runtime::default_runtime();
        let t0 = runtime.unix_nanos();
        Rig {
            check: PitCheckStage {
                pit: Arc::clone(&pit),
                face_table: Arc::clone(&face_table),
                dead_nonce_list: None,
                validator: None,
                replay_guard: None,
            },
            strategy: StrategyStage {
                strategy_table: Arc::new(StrategyTable::new()),
                default_strategy: Arc::new(BestRouteStrategy::new()),
                fib,
                measurements: Arc::new(MeasurementsTable::new()),
                signals: Arc::new(SignalsTable::new()),
                pit: Arc::clone(&pit),
                face_table,
                enrichers: Vec::new(),
                runtime,
                network_region: Arc::new(NetworkRegionTable::new(Vec::new())),
            },
            matcher: PitMatchStage {
                pit,
                dead_nonce_list: None,
            },
            name,
            t0,
            t1: t0 + 100_000,
        }
    }

    impl Rig {
        /// An Interest for the name from `face`, arrived at `arrival`, past
        /// the PIT check and on its way to the strategy.
        async fn arrive(&self, face: FaceId, arrival: u64) -> PacketContext {
            let wire = InterestBuilder::new(self.name.clone()).build();
            let interest = Interest::decode(wire.clone()).unwrap();
            let mut ctx = PacketContext::new(wire, face, arrival);
            ctx.name = Some(Arc::clone(&interest.name));
            ctx.packet = DecodedPacket::Interest(Box::new(interest));
            match self.check.process(ctx).await {
                Action::Continue(ctx) => ctx,
                other => panic!("PIT check: {}", verdict(&other)),
            }
        }

        /// The downstreams the upstream's Data reaches.
        fn data_reaches(&self) -> Vec<FaceId> {
            let wire = encode_data_unsigned(&self.name, b"x");
            let mut ctx = PacketContext::new(wire.clone(), UPSTREAM, self.t1 + 1_000_000);
            ctx.packet = DecodedPacket::Data(Box::new(Data::decode(wire).unwrap()));
            match self.matcher.process(ctx) {
                Action::Continue(ctx) => {
                    let mut faces = ctx.out_faces.to_vec();
                    faces.sort_by_key(|f| f.0);
                    faces
                }
                _ => Vec::new(),
            }
        }
    }

    fn verdict(action: &Action) -> String {
        match action {
            Action::Send(_, faces) => format!("Send{faces:?}"),
            Action::Nack(_, reason) => format!("Nack({reason:?})"),
            Action::Drop(reason) => format!("Drop({reason:?})"),
            Action::Continue(_) => "Continue".into(),
            _ => "other".into(),
        }
    }

    /// The interleaving traced on the engine: B's pass runs after A's sent
    /// A's Interest upstream. B is suppressed and waits on the entry, so the
    /// upstream's one Data reaches both. It used to be Nacked NoRoute, with
    /// its in-record released: the strategy's "suppressed" read as "no route".
    #[tokio::test]
    async fn a_pass_finding_the_interest_already_sent_upstream_waits_for_its_data() {
        let rig = rig("/race/second-pass-later", UPSTREAM);
        let a = rig.arrive(A, rig.t0).await;
        let b = rig.arrive(B, rig.t1).await;

        let a = rig.strategy.process(a).await;
        assert_eq!(verdict(&a), format!("Send{:?}", [UPSTREAM]));
        let b = rig.strategy.process(b).await;
        assert_eq!(verdict(&b), "Drop(Suppressed)", "B waits on the entry");
        assert_eq!(rig.data_reaches(), [A, B]);
    }

    /// The passes the other way round: B's pass forwards first. A's pass
    /// judges the entry as at A's arrival, before B's Interest went upstream,
    /// so it picks the same upstream, which already has the entry's Interest:
    /// nothing is sent again, and A waits for that Data with B.
    #[tokio::test]
    async fn an_earlier_interest_whose_pass_runs_second_does_not_ask_the_upstream_again() {
        let rig = rig("/race/first-pass-later", UPSTREAM);
        let a = rig.arrive(A, rig.t0).await;
        let b = rig.arrive(B, rig.t1).await;

        let b = rig.strategy.process(b).await;
        assert_eq!(verdict(&b), format!("Send{:?}", [UPSTREAM]));
        let a = rig.strategy.process(a).await;
        assert_eq!(verdict(&a), "Drop(Suppressed)", "A waits on the entry");
        assert_eq!(rig.data_reaches(), [A, B]);
    }

    /// B's Interest has no route but back to B; A's, arrived just after,
    /// goes to B and its pass ran first. Judged as at B's arrival, when
    /// nothing was sent, B's Interest has no route and is Nacked, as NFD's
    /// arrival order gives. Suppressed instead, it would wait on its own
    /// face, while B aggregates A's Interest onto B's own entry: both would
    /// wait out their lifetimes.
    #[tokio::test]
    async fn an_interest_routed_only_back_is_nacked_though_a_later_one_went_there() {
        let rig = rig("/race/route-back", B);
        let b = rig.arrive(B, rig.t0).await;
        let a = rig.arrive(A, rig.t1).await;

        let a = rig.strategy.process(a).await;
        assert_eq!(verdict(&a), format!("Send{:?}", [B]));
        let b = rig.strategy.process(b).await;
        assert_eq!(verdict(&b), "Nack(NoRoute)");
    }
}
