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
        let fib_entry_arc = self.fib.lpm(&fib_name);
        let fib_entry_ref = fib_entry_arc.as_deref();

        if let Some(e) = fib_entry_ref {
            trace!(target: t::FWD_FIB, face=%ctx.face_id, name=%name, matched=true, prefix=%name, nexthops=?e.nexthops.iter().map(|nh| (nh.face_id, nh.cost)).collect::<Vec<_>>(), "fib lookup");
        } else {
            trace!(target: t::FWD_FIB, face=%ctx.face_id, name=%name, matched=false, prefix=%name, "fib lookup");
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

        let sctx = StrategyContext {
            name: &name,
            in_face: ctx.face_id,
            fib_entry: strategy_fib.as_ref(),
            pit_token: ctx.pit_token,
            measurements: &self.measurements,
            signals: self.signals.as_ref(),
            extensions,
            runtime: &self.runtime,
        };

        let strategy = self
            .strategy_table
            .lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.default_strategy));
        trace!(target: t::FWD_STRATEGY, face=%ctx.face_id, name=%name, strategy=%strategy.name(), "strategy invoked");

        let actions = if let Some(a) = strategy.decide_sync(&sctx) {
            a
        } else {
            strategy.after_receive_interest_erased(&sctx).await
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
                    // an existing pair.
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
                                    let dup = self.pit.with_entry_mut(&token, |entry| {
                                        let already = entry.out_records.iter().any(|or| {
                                            or.face_id == fid.0 && or.last_nonce == nonce
                                        });
                                        if !already {
                                            entry.add_out_record(fid.0, nonce, now);
                                        }
                                        already
                                    });
                                    !dup.unwrap_or(false)
                                })
                                .collect()
                        } else {
                            effective_faces.into_iter().collect()
                        };
                    if surviving_faces.is_empty() {
                        return Action::Drop(DropReason::Suppressed);
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

#[cfg(test)]
mod tests {
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
