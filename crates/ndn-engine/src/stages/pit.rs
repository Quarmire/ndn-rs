use std::sync::Arc;
use web_time::SystemTime;
use web_time::UNIX_EPOCH;

use smallvec::SmallVec;
use tracing::trace;

use crate::observability::targets as t;
use crate::pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_store::{
    DeadNonceList, NameHashes, NonceFingerprint, PersistentState, Pit, PitEntry,
    PitKeyDiscriminator, PitToken,
};
use ndn_transport::FaceId;

#[cfg(not(target_arch = "wasm32"))]
use ndn_security::{InterestValidationOutcome, Validator};
use ndn_security::{ReplayCheck, ReplayGuard};

/// Upper bound on `max_lifetime_secs` from a `SubscriptionRequest`. 1 hour
/// matches the typical NDN FreshnessPeriod default and ndn-cxx's PIT reaper.
pub const MAX_PERSISTENT_LIFETIME_SECS: u32 = ndn_packet::MAX_PERSISTENT_LIFETIME_SECS;

/// Checks the PIT for a pending Interest:
/// - duplicate nonce → `Drop(LoopDetected)`
/// - same-name entry → aggregate as new in-record, `Drop(Suppressed)`
/// - valid `SubscriptionRequest` sub-TLV → install `PersistentState`
/// - else → create a new entry, set `ctx.pit_token`, continue
pub struct PitCheckStage {
    pub pit: Arc<Pit>,
    pub dead_nonce_list: Option<Arc<DeadNonceList>>,
    #[cfg(not(target_arch = "wasm32"))]
    pub validator: Option<Arc<Validator>>,
    /// Pre-PIT replay guard. Rejects signed Interests whose `SignatureInfo`
    /// aliases a recently admitted record under the same signer key. This is
    /// the integrity floor for universal strip-at-insert: without it two
    /// replayed signed Interests would silently coalesce into one PIT entry.
    /// Wasm engines forward signed Interests too (NDNCERT, ndn-mgmt) and
    /// need the same floor.
    pub replay_guard: Option<Arc<ReplayGuard>>,
}

impl PitCheckStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let DecodedPacket::Interest(_) = &ctx.packet else {
            return Action::Continue(ctx);
        };

        if let Some(guard) = self.replay_guard.as_ref() {
            let interest = match &ctx.packet {
                DecodedPacket::Interest(i) => i.as_ref(),
                _ => unreachable!(),
            };
            if let Some(si) = interest.sig_info() {
                match guard.check(si) {
                    ReplayCheck::Replay => {
                        trace!(
                            target: t::FWD_PIT,
                            face=%ctx.face_id,
                            name=%interest.name,
                            action="replay-rejected",
                            "pit op"
                        );
                        return Action::Drop(DropReason::LoopDetected);
                    }
                    ReplayCheck::Fresh | ReplayCheck::NoAntiReplayFields => {}
                }
            }
        }

        let persistent = match self.check_persistent(&ctx).await {
            Ok(ps) => ps,
            Err(action) => return action,
        };

        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i,
            _ => unreachable!(),
        };

        let now_ns = now_ns();
        let lifetime_ms = interest
            .lifetime()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(4_000);

        let nonce = interest.nonce().unwrap_or(0);

        // Universal strip-at-insert: a trailing PSDC (0x02) or implicit
        // digest (0x01) is removed from the PIT key so wire-level digest
        // components do not multiplex. Concurrent signed-Interest RPC at the
        // same logical name must disambiguate via a request-id component.
        // The replay guard above is the integrity floor that makes this safe.
        let key_name: ndn_packet::Name = strip_digest_components(&interest.name);
        let name_hash = NameHashes::full_name_hash(&key_name);
        // Persistent (SubscriptionRequest) Interests occupy a distinct PIT
        // entry from classical Interests at the same logical name.
        let discriminator = if persistent.is_some() {
            PitKeyDiscriminator::PersistentAttach
        } else {
            PitKeyDiscriminator::Classical
        };
        let token =
            PitToken::from_name_hash_keyed(name_hash, interest.forwarding_hint(), discriminator);
        ctx.pit_token = Some(token);
        let in_selector = interest.selectors().clone();

        if let Some(dnl) = self.dead_nonce_list.as_ref() {
            let fp = NonceFingerprint::new(name_hash, nonce);
            if dnl.contains(fp, now_ns) {
                trace!(
                    target: t::FWD_PIT,
                    face=%ctx.face_id,
                    name=%interest.name,
                    nonce,
                    action="dead-nonce-loop",
                    "pit op"
                );
                return Action::Drop(DropReason::LoopDetected);
            }
        }

        enum CheckResult {
            Loop,
            Aggregated,
            Inserted,
        }
        // Atomic check-and-insert: holding the per-shard write lock across
        // lookup and insert prevents two concurrent same-name Interests on
        // the parallel pipeline path from both falling through to insert.
        let result = self.pit.with_entry_or_insert(
            token,
            |entry| {
                if entry.nonces_seen.contains(&nonce) {
                    // Overhear-cancel (CCLF): a duplicate nonce means a neighbor
                    // is forwarding this very Interest instance. If we have a
                    // scheduled forward pending (timer election), cancel it —
                    // a peer already won. Inert for immediate-forward strategies.
                    entry.forward_cancelled = true;
                    return CheckResult::Loop;
                }
                let expires_at = now_ns + lifetime_ms * 1_000_000;
                // Each aggregated persistent subscriber owns its own
                // `PersistentState` (own credit, own deadline). Mixing
                // regimes inside one entry is prevented by the discriminator.
                entry.add_in_record_with_persistent(
                    ctx.face_id.0,
                    nonce,
                    expires_at,
                    ctx.lp_pit_token.clone(),
                    in_selector.clone(),
                    persistent.clone(),
                );
                // Extend entry deadline to cover the longest live in-record.
                if let Some(ref ps) = persistent
                    && ps.reap_at > entry.expires_at
                {
                    entry.expires_at = ps.reap_at;
                }
                CheckResult::Aggregated
            },
            || {
                let mut entry = PitEntry::new(interest.name.clone(), now_ns, lifetime_ms);
                if let Some(ref ps) = persistent {
                    entry.expires_at = ps.reap_at;
                    // Entry-level state preserved for back-compat with callers
                    // reading `PitEntry::persistent`; per-InRecord state is
                    // authoritative.
                    entry.persistent = Some(ps.clone());
                }
                entry.add_in_record_with_persistent(
                    ctx.face_id.0,
                    nonce,
                    now_ns + lifetime_ms * 1_000_000,
                    ctx.lp_pit_token.clone(),
                    in_selector.clone(),
                    persistent.clone(),
                );
                (entry, CheckResult::Inserted)
            },
        );

        match result {
            CheckResult::Loop => {
                trace!(target: t::FWD_PIT, face=%ctx.face_id, name=%interest.name, nonce, action="loop", "pit op");
                Action::Drop(DropReason::LoopDetected)
            }
            CheckResult::Aggregated => {
                trace!(target: t::FWD_PIT, face=%ctx.face_id, name=%interest.name, nonce, action="aggregate", "pit op");
                Action::Drop(DropReason::Suppressed)
            }
            CheckResult::Inserted => {
                trace!(target: t::FWD_PIT, face=%ctx.face_id, name=%interest.name, nonce, lifetime_ms, action="insert", "pit op");
                Action::Continue(ctx)
            }
        }
    }

    /// Detect and validate a `SubscriptionRequest` sub-TLV.
    /// `Ok(None)`: non-persistent fast path. `Ok(Some(ps))`: state to install.
    /// `Err(Action)`: bounds violation; caller drops with this action.
    #[cfg(not(target_arch = "wasm32"))]
    async fn check_persistent(
        &self,
        ctx: &PacketContext,
    ) -> Result<Option<PersistentState>, Action> {
        use ndn_packet::SubscriptionRequest;

        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i.as_ref(),
            _ => return Ok(None),
        };

        let ap = match interest.app_parameters() {
            Some(ap) => ap,
            None => return Ok(None),
        };

        let sub_req = match SubscriptionRequest::find_in(ap) {
            Some(r) => r,
            None => return Ok(None),
        };

        if sub_req.version != 1
            || sub_req.max_data_count == 0
            || sub_req.max_lifetime_secs == 0
            || sub_req.max_lifetime_secs > MAX_PERSISTENT_LIFETIME_SECS
        {
            return Err(Action::Drop(DropReason::InvalidPersistentRequest));
        }

        let state = if let Some(v) = &self.validator {
            match v.validate_interest(interest).await {
                InterestValidationOutcome::Valid => {
                    let reap_at = now_ns() + (sub_req.max_lifetime_secs as u64) * 1_000_000_000;
                    Some(PersistentState {
                        data_count_remaining: sub_req.max_data_count,
                        reap_at,
                    })
                }
                // Invalid or Pending → degrade to classical (one-shot).
                InterestValidationOutcome::Invalid(_) | InterestValidationOutcome::Pending => None,
            }
        } else {
            None
        };

        Ok(state)
    }

    #[cfg(target_arch = "wasm32")]
    async fn check_persistent(
        &self,
        _ctx: &PacketContext,
    ) -> Result<Option<PersistentState>, Action> {
        Ok(None)
    }
}

/// A CanBePrefix in-record drained during the prefix-walk: (face id, LP PIT
/// token to echo, trace ids for fan-out instrumentation).
type DrainedInRecord = (u64, Option<bytes::Bytes>, Vec<ndn_packet::lp::TraceId>);

enum PersistentMatchResult {
    /// Persistent entry: faces collected, per-subscriber counter decremented.
    Matched {
        faces: SmallVec<[FaceId; 4]>,
        lp_tokens: SmallVec<[Option<bytes::Bytes>; 4]>,
        should_reap: bool,
    },
    /// Entry exists but is not persistent — use classical remove-on-match.
    Classical,
}

/// Matches a Data packet against the PIT. Persistent entries decrement
/// `data_count_remaining` and survive until exhausted; classical entries
/// are removed on first match. Unsolicited Data is dropped.
pub struct PitMatchStage {
    pub pit: Arc<Pit>,
    pub dead_nonce_list: Option<Arc<DeadNonceList>>,
}

impl PitMatchStage {
    pub fn process(&self, mut ctx: PacketContext) -> Action {
        if !matches!(&ctx.packet, DecodedPacket::Data(_)) {
            return Action::Continue(ctx);
        }
        // Owned name handle so we don't hold an immutable borrow of
        // `ctx.packet` across the later mutation of `ctx.out_faces`.
        let data_name = match &ctx.packet {
            DecodedPacket::Data(d) => d.name.clone(),
            _ => unreachable!(),
        };

        // Materialize every name hash we need up front, then release the
        // borrow of `ctx.name_hashes` so the tail is free to mutate `ctx`.
        // `prefix_hashes` is the longest-first list of proper-prefix hashes
        // for the CanBePrefix walk.
        let (full_hash, prefix_hashes) = {
            let hashes = ctx
                .name_hashes
                .get_or_insert_with(|| NameHashes::compute(&data_name));
            let n = hashes.len();
            let prefixes: SmallVec<[u64; 8]> =
                (1..n).rev().map(|pl| hashes.prefix_hash(pl)).collect();
            (hashes.full_hash(), prefixes)
        };

        // PIT key is Name(+ForwardingHint); selectors live on each in-record.
        let token =
            PitToken::from_name_hash_keyed(full_hash, None, PitKeyDiscriminator::PersistentAttach);
        let token_classical =
            PitToken::from_name_hash_keyed(full_hash, None, PitKeyDiscriminator::Classical);

        // PitCheckStage strips a trailing PSDC/implicit-digest from the PIT
        // key. Data named WITH a trailing digest (NFD ControlResponse,
        // full-name Data) must still match; compute the stripped fallback.
        let stripped_token = {
            use ndn_packet::tlv_type::{IMPLICIT_SHA256, PARAMETERS_SHA256};
            let comps = data_name.components();
            let last_typ = comps.last().map(|c| c.typ);
            if (last_typ == Some(PARAMETERS_SHA256) || last_typ == Some(IMPLICIT_SHA256))
                && comps.len() > 1
            {
                let stripped =
                    ndn_packet::Name::from_components(comps[..comps.len() - 1].iter().cloned());
                let h = NameHashes::full_name_hash(&stripped);
                Some(PitToken::from_name_hash(h, None))
            } else {
                None
            }
        };

        // findAllDataMatches (NFD forwarder.cpp:315): one Data can satisfy
        // *several* PIT entries at once — the exact-name entry under either
        // discriminator, the PSDC/digest-stripped fallback, and any CanBePrefix
        // entry at a shorter prefix. Accumulate the union of their downstream
        // faces, deduped by face id, rather than returning on the first hit.
        let mut faces: SmallVec<[FaceId; 4]> = SmallVec::new();
        let mut tokens: SmallVec<[Option<bytes::Bytes>; 4]> = SmallVec::new();
        let mut seen: SmallVec<[u64; 8]> = SmallVec::new();
        let mut fan_out: Vec<(u64, Vec<ndn_packet::lp::TraceId>)> = Vec::new();

        // Exact-name entries: every in-record matches regardless of CanBePrefix.
        self.consume_entry(
            &token,
            false,
            &mut faces,
            &mut tokens,
            &mut seen,
            &mut fan_out,
        );
        self.consume_entry(
            &token_classical,
            false,
            &mut faces,
            &mut tokens,
            &mut seen,
            &mut fan_out,
        );
        if let Some(alt) = stripped_token.as_ref() {
            self.consume_entry(alt, false, &mut faces, &mut tokens, &mut seen, &mut fan_out);
        }

        // CanBePrefix walk: at each shorter prefix only CanBePrefix in-records
        // participate.
        for prefix_hash in prefix_hashes {
            for disc in [
                PitKeyDiscriminator::PersistentAttach,
                PitKeyDiscriminator::Classical,
            ] {
                let tok = PitToken::from_name_hash_keyed(prefix_hash, None, disc);
                self.consume_entry(&tok, true, &mut faces, &mut tokens, &mut seen, &mut fan_out);
            }
        }

        if !faces.is_empty() {
            if !fan_out.is_empty() {
                crate::observability::fan_out::emit_data_fan_out(fan_out, &data_name.to_string());
            }
            trace!(target: t::FWD_PIT, face=%ctx.face_id, name=%data_name, out_faces=?faces, action="satisfy", "pit op");
            ctx.out_faces = faces;
            ctx.out_pit_tokens = tokens;
            return Action::Continue(ctx);
        }

        // No PIT entry matched. The Data is unsolicited: it is never forwarded
        // (`out_faces` stays empty). Carry it through with the `unsolicited`
        // flag set so the dispatcher can apply its `UnsolicitedDataPolicy`
        // (drop by default, or opportunistically cache on a broadcast bearer).
        trace!(target: t::FWD_PIT, face=%ctx.face_id, name=%data_name, "pit-match: unsolicited Data");
        ctx.unsolicited = true;
        Action::Continue(ctx)
    }

    /// Consume a single PIT entry identified by `token`, appending its
    /// downstream faces + LP tokens to `faces`/`tokens` (deduped via `seen` by
    /// face id). `cbp_only` restricts participation to CanBePrefix in-records —
    /// the prefix-walk case — so exact-match subscribers at a shorter prefix
    /// are left untouched. Handles per-subscriber persistent-credit decrement
    /// and entry reaping. A no-op when no entry exists at `token`.
    #[allow(clippy::too_many_arguments)]
    fn consume_entry(
        &self,
        token: &PitToken,
        cbp_only: bool,
        faces: &mut SmallVec<[FaceId; 4]>,
        tokens: &mut SmallVec<[Option<bytes::Bytes>; 4]>,
        seen: &mut SmallVec<[u64; 8]>,
        fan_out: &mut Vec<(u64, Vec<ndn_packet::lp::TraceId>)>,
    ) {
        // Persistent-aware path: per-subscriber credit pools, survives until
        // exhausted (mirrors the classic persistent-Interest semantics).
        let probe = self.pit.with_entry_mut(token, |entry| {
            let any_per_record = entry
                .in_records
                .iter()
                .any(|r| r.persistent.is_some() && (!cbp_only || r.selector.can_be_prefix));
            if !any_per_record && entry.persistent.is_none() {
                return PersistentMatchResult::Classical;
            }

            let mut f: SmallVec<[FaceId; 4]> = SmallVec::new();
            let mut t: SmallVec<[Option<bytes::Bytes>; 4]> = SmallVec::new();
            let mut exhausted: SmallVec<[usize; 4]> = SmallVec::new();

            for (i, r) in entry.in_records.iter_mut().enumerate() {
                if cbp_only && !r.selector.can_be_prefix {
                    continue;
                }
                if let Some(ps) = r.persistent.as_mut() {
                    if ps.data_count_remaining > 0 {
                        ps.data_count_remaining -= 1;
                        f.push(FaceId(r.face_id));
                        t.push(r.lp_pit_token.clone());
                        if ps.data_count_remaining == 0 {
                            exhausted.push(i);
                        }
                    }
                } else if entry.persistent.is_some() {
                    f.push(FaceId(r.face_id));
                    t.push(r.lp_pit_token.clone());
                }
            }

            if let Some(p) = entry.persistent.as_mut() {
                p.data_count_remaining = p.data_count_remaining.saturating_sub(1);
            }

            for &idx in exhausted.iter().rev() {
                entry.in_records.swap_remove(idx);
            }

            let no_persistent_left = !entry.in_records.iter().any(|r| r.persistent.is_some());
            let entry_level_exhausted = entry
                .persistent
                .as_ref()
                .is_some_and(|p| p.data_count_remaining == 0);
            let should_reap = if any_per_record {
                no_persistent_left
            } else {
                entry_level_exhausted
            };
            PersistentMatchResult::Matched {
                faces: f,
                lp_tokens: t,
                should_reap,
            }
        });

        match probe {
            Some(PersistentMatchResult::Matched {
                faces: f,
                lp_tokens: t,
                should_reap,
            }) => {
                if should_reap && let Some((_, entry)) = self.pit.remove(token) {
                    insert_dead_nonces(&self.dead_nonce_list, &entry);
                }
                for (fid, tok) in f.into_iter().zip(t) {
                    if seen.contains(&fid.0) {
                        continue;
                    }
                    seen.push(fid.0);
                    faces.push(fid);
                    tokens.push(tok);
                }
                return;
            }
            Some(PersistentMatchResult::Classical) | None => {}
        }

        // Classical remove-on-match.
        if cbp_only {
            // Prefix-walk: a Data at a longer name satisfies only the
            // CanBePrefix in-records at this prefix. Drain *those* and leave any
            // exact-match subscribers (who want Data named exactly at the
            // prefix) pending — removing the whole entry would silently starve
            // them. Reap the entry only once it is empty.
            let drained = self.pit.with_entry_mut(token, |entry| {
                let mut taken: SmallVec<[DrainedInRecord; 4]> = SmallVec::new();
                let mut i = 0;
                while i < entry.in_records.len() {
                    if entry.in_records[i].selector.can_be_prefix {
                        let r = entry.in_records.swap_remove(i);
                        taken.push((
                            r.face_id,
                            r.lp_pit_token,
                            r.trace_ids.iter().copied().collect(),
                        ));
                    } else {
                        i += 1;
                    }
                }
                (taken, entry.in_records.is_empty())
            });
            if let Some((taken, now_empty)) = drained {
                for (face_id, lp_token, trace_ids) in taken {
                    if seen.contains(&face_id) {
                        continue;
                    }
                    seen.push(face_id);
                    faces.push(FaceId(face_id));
                    tokens.push(lp_token);
                    fan_out.push((face_id, trace_ids));
                }
                if now_empty && let Some((_, entry)) = self.pit.remove(token) {
                    insert_dead_nonces(&self.dead_nonce_list, &entry);
                }
            }
            return;
        }
        // Exact match: every in-record is satisfied; remove the entry.
        if let Some((_, entry)) = self.pit.remove(token) {
            insert_dead_nonces(&self.dead_nonce_list, &entry);
            for r in entry.in_records.iter() {
                if seen.contains(&r.face_id) {
                    continue;
                }
                seen.push(r.face_id);
                faces.push(FaceId(r.face_id));
                tokens.push(r.lp_pit_token.clone());
                fan_out.push((r.face_id, r.trace_ids.iter().copied().collect()));
            }
        }
    }
}

pub(crate) fn insert_dead_nonces(dnl: &Option<Arc<DeadNonceList>>, entry: &PitEntry) {
    let Some(dnl) = dnl.as_ref() else {
        return;
    };
    let key_name = strip_digest_components(&entry.name);
    let name_hash = NameHashes::full_name_hash(&key_name);
    let now = now_ns();
    for &nonce in &entry.nonces_seen {
        dnl.insert(NonceFingerprint::new(name_hash, nonce), now);
    }
}

/// Return `name` with a trailing PSDC (0x02) or implicit digest (0x01)
/// component removed. Stripping is symmetric on insert and match; ndn-rs
/// deliberately does not multiplex PIT entries by wire-level digest
/// components.
fn strip_digest_components(name: &ndn_packet::Name) -> ndn_packet::Name {
    use ndn_packet::tlv_type::{IMPLICIT_SHA256, PARAMETERS_SHA256};
    let comps = name.components();
    let last_typ = comps.last().map(|c| c.typ);
    if last_typ == Some(PARAMETERS_SHA256) || last_typ == Some(IMPLICIT_SHA256) {
        ndn_packet::Name::from_components(comps[..comps.len() - 1].iter().cloned())
    } else {
        name.clone()
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod d07_tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::Selector;
    use ndn_packet::encode::encode_data_unsigned;
    use ndn_packet::{Data, Name};
    use ndn_store::PitEntry;
    use std::str::FromStr;

    #[test]
    fn d07_pit_match_propagates_lp_token_to_out_tokens() {
        let pit = Arc::new(Pit::new());
        let name: Name = "/audit/d07".parse().unwrap();
        let name_arc = Arc::new(name.clone());

        let token = PitToken::from_interest(&name);
        let mut entry = PitEntry::new(Arc::clone(&name_arc), 0, 4000);
        let lp_token = Bytes::from_static(&[0x11, 0x22, 0x33, 0x44]);
        entry.add_in_record(7, 1, u64::MAX, Some(lp_token.clone()), Selector::default());
        pit.insert(token, entry);

        let stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };
        let data_wire = encode_data_unsigned(&name, b"payload");
        let data = Data::decode(data_wire.clone()).unwrap();
        let mut ctx = PacketContext::new(data_wire, FaceId(99), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));

        let action = stage.process(ctx);
        let new_ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("PitMatchStage must return Continue when an entry exists"),
        };
        assert_eq!(new_ctx.out_faces.as_slice(), &[FaceId(7)]);
        assert_eq!(new_ctx.out_pit_tokens.len(), 1);
        assert_eq!(
            new_ctx.out_pit_tokens[0].as_deref(),
            Some(lp_token.as_ref()),
        );
        let _ = Name::from_str("/").map(|_| ());
    }
}

#[cfg(test)]
mod multi_match_tests {
    use super::*;
    use ndn_packet::encode::encode_data_unsigned;
    use ndn_packet::{Data, Name, Selector};
    use ndn_store::PitEntry;

    fn run_match(stage: &PitMatchStage, data_wire: bytes::Bytes) -> Action {
        let data = Data::decode(data_wire.clone()).unwrap();
        let mut ctx = PacketContext::new(data_wire, FaceId(99), 0);
        ctx.packet = DecodedPacket::Data(Box::new(data));
        stage.process(ctx)
    }

    /// One Data satisfies BOTH an exact-name pending Interest and a CanBePrefix
    /// pending Interest at a shorter prefix (NFD findAllDataMatches). Both
    /// downstream faces must appear in `out_faces` — the pre-rewrite code
    /// returned on the first (exact) match and starved the CanBePrefix one.
    #[test]
    fn data_satisfies_exact_and_canbeprefix_entries() {
        let pit = Arc::new(Pit::new());

        let exact: Name = "/a/b/c".parse().unwrap();
        let mut e1 = PitEntry::new(Arc::new(exact.clone()), 0, 4000);
        e1.add_in_record(1, 11, u64::MAX, None, Selector::default());
        pit.insert(PitToken::from_interest(&exact), e1);

        let prefix: Name = "/a".parse().unwrap();
        let sel = Selector {
            can_be_prefix: true,
            ..Selector::default()
        };
        let mut e2 = PitEntry::new(Arc::new(prefix.clone()), 0, 4000);
        e2.add_in_record(2, 22, u64::MAX, None, sel);
        pit.insert(PitToken::from_interest(&prefix), e2);

        let stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };
        let action = run_match(&stage, encode_data_unsigned(&exact, b"x"));
        let ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("Data must satisfy at least one entry"),
        };

        let mut got: Vec<u64> = ctx.out_faces.iter().map(|f| f.0).collect();
        got.sort_unstable();
        assert_eq!(
            got,
            vec![1, 2],
            "both exact and CanBePrefix downstreams must be satisfied by one Data"
        );
        assert!(!ctx.unsolicited);
        assert!(!pit.contains(&PitToken::from_interest(&exact)));
        assert!(!pit.contains(&PitToken::from_interest(&prefix)));
    }

    /// A single face that expressed both an exact and a prefix Interest gets
    /// exactly one Data copy (dedup by face id, like NFD's `pendingDownstreams`
    /// set).
    #[test]
    fn duplicate_downstream_face_deduped() {
        let pit = Arc::new(Pit::new());

        let exact: Name = "/x/y".parse().unwrap();
        let mut e1 = PitEntry::new(Arc::new(exact.clone()), 0, 4000);
        e1.add_in_record(5, 1, u64::MAX, None, Selector::default());
        pit.insert(PitToken::from_interest(&exact), e1);

        let prefix: Name = "/x".parse().unwrap();
        let sel = Selector {
            can_be_prefix: true,
            ..Selector::default()
        };
        let mut e2 = PitEntry::new(Arc::new(prefix.clone()), 0, 4000);
        e2.add_in_record(5, 2, u64::MAX, None, sel);
        pit.insert(PitToken::from_interest(&prefix), e2);

        let stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };
        let action = run_match(&stage, encode_data_unsigned(&exact, b"x"));
        let ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("must satisfy"),
        };
        assert_eq!(
            ctx.out_faces.as_slice(),
            &[FaceId(5)],
            "a face that appears in two matched entries must receive one copy"
        );
    }

    /// A prefix entry holding ONLY an exact-match (non-CanBePrefix) subscriber
    /// must NOT be consumed by Data at a longer name — the prefix-walk only
    /// touches CanBePrefix in-records.
    #[test]
    fn prefix_entry_without_canbeprefix_untouched() {
        let pit = Arc::new(Pit::new());

        let prefix: Name = "/p".parse().unwrap();
        let mut e = PitEntry::new(Arc::new(prefix.clone()), 0, 4000);
        // can_be_prefix = false → wants Data named exactly /p.
        e.add_in_record(3, 1, u64::MAX, None, Selector::default());
        pit.insert(PitToken::from_interest(&prefix), e);

        let stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };
        let longer: Name = "/p/q".parse().unwrap();
        let action = run_match(&stage, encode_data_unsigned(&longer, b"x"));
        let ctx = match action {
            Action::Continue(c) => c,
            _ => panic!(),
        };
        assert!(
            ctx.unsolicited,
            "Data /p/q must not satisfy an exact-only /p subscriber"
        );
        assert!(
            pit.contains(&PitToken::from_interest(&prefix)),
            "the exact-only prefix entry must remain pending"
        );
    }

    /// A prefix entry holding BOTH a CanBePrefix subscriber and an exact-match
    /// subscriber: Data at a longer name satisfies only the CanBePrefix one;
    /// the exact-match in-record stays pending and the entry survives. Guards
    /// the latent "remove-whole-entry starves exact subscribers" bug.
    #[test]
    fn mixed_prefix_entry_drains_only_canbeprefix_records() {
        let pit = Arc::new(Pit::new());

        let prefix: Name = "/m".parse().unwrap();
        let mut e = PitEntry::new(Arc::new(prefix.clone()), 0, 4000);
        // Face 1: CanBePrefix (wants Data under /m). Face 2: exact (wants /m).
        let cbp = Selector {
            can_be_prefix: true,
            ..Selector::default()
        };
        e.add_in_record(1, 1, u64::MAX, None, cbp);
        e.add_in_record(2, 2, u64::MAX, None, Selector::default());
        pit.insert(PitToken::from_interest(&prefix), e);

        let stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };
        let longer: Name = "/m/seq=0".parse().unwrap();
        let action = run_match(&stage, encode_data_unsigned(&longer, b"x"));
        let ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("CanBePrefix subscriber must be satisfied"),
        };

        assert_eq!(
            ctx.out_faces.as_slice(),
            &[FaceId(1)],
            "only the CanBePrefix in-record is satisfied by the longer-named Data"
        );
        // The entry survives, now holding just the exact-match subscriber.
        let remaining = pit
            .with_entry(&PitToken::from_interest(&prefix), |e| {
                e.in_records
                    .iter()
                    .map(|r| (r.face_id, r.selector.can_be_prefix))
                    .collect::<Vec<_>>()
            })
            .expect("entry must still exist for the exact-match subscriber");
        assert_eq!(
            remaining,
            vec![(2, false)],
            "the exact-match (non-CanBePrefix) subscriber must remain pending"
        );
    }
}

#[cfg(test)]
mod n06_dead_nonce_engine_tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::encode::{InterestBuilder, encode_data_unsigned};
    use ndn_packet::{Data, Interest, Name};

    fn interest_ctx(wire: Bytes, face: FaceId) -> PacketContext {
        let interest = Interest::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, face, 0);
        ctx.packet = DecodedPacket::Interest(Box::new(interest));
        ctx
    }

    fn data_ctx(name: &Name) -> PacketContext {
        let wire = encode_data_unsigned(name, b"payload");
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(99), 0);
        ctx.packet = DecodedPacket::Data(Box::new(data));
        ctx
    }

    #[tokio::test]
    async fn n06_dnl_rejects_nonce_after_satisfied_pit_entry_is_erased() {
        let pit = Arc::new(Pit::new());
        let dnl = Arc::new(DeadNonceList::new());
        let check = PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: Some(Arc::clone(&dnl)),
            validator: None,
            replay_guard: None,
        };
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: Some(Arc::clone(&dnl)),
        };
        let name: Name = "/audit/n06/dead-nonce".parse().unwrap();
        let interest_wire = InterestBuilder::new(name.clone()).build();

        let first = check
            .process(interest_ctx(interest_wire.clone(), FaceId(1)))
            .await;
        assert!(matches!(first, Action::Continue(_)));

        let satisfied = match_stage.process(data_ctx(&name));
        assert!(matches!(satisfied, Action::Continue(_)));
        assert!(pit.is_empty(), "Data satisfaction must erase the PIT entry");
        assert_eq!(dnl.len(), 1, "erased PIT nonce must enter the DNL");

        let replay = check.process(interest_ctx(interest_wire, FaceId(2))).await;
        assert!(
            matches!(replay, Action::Drop(DropReason::LoopDetected)),
            "same name+nonce after PIT erasure must hit the DeadNonceList"
        );
    }
}

#[cfg(test)]
mod d19_tests {
    use super::*;
    use ndn_packet::Name;
    use ndn_packet::encode::encode_interest;
    use std::sync::Barrier;

    fn run_concurrent_first_arrival(n: usize) {
        let pit = Arc::new(Pit::new());
        let stage = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            #[cfg(not(target_arch = "wasm32"))]
            validator: None,
            replay_guard: None,
        });
        let barrier = Arc::new(Barrier::new(n));
        let name: Name = "/audit/d19/seq=0".parse().unwrap();

        let mut handles = Vec::with_capacity(n);
        for face_id in 0..n {
            let stage = Arc::clone(&stage);
            let barrier = Arc::clone(&barrier);
            let name = name.clone();
            handles.push(std::thread::spawn(move || {
                let wire = encode_interest(&name, None);
                let interest = ndn_packet::Interest::decode(wire.clone()).expect("interest decode");
                let mut ctx = PacketContext::new(wire, FaceId(face_id as u64), 0);
                ctx.packet = DecodedPacket::Interest(Box::new(interest));
                barrier.wait();
                // Drive the async future to completion using a single-threaded
                // runtime.  Since no await points are taken for non-persistent
                // Interests, this completes immediately.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let _ = rt.block_on(stage.process(ctx));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            pit.len(),
            1,
            "expected one PIT entry for the shared name; race produced {}",
            pit.len()
        );

        let token = {
            let h = NameHashes::full_name_hash(&name);
            PitToken::from_name_hash(h, None)
        };
        let in_record_count = pit
            .with_entry(&token, |e| e.in_records.len())
            .expect("PIT entry must exist");
        assert_eq!(
            in_record_count,
            n,
            "expected {n} in-records; got {in_record_count} (race lost {} in-records)",
            n - in_record_count
        );
    }

    #[test]
    fn d19_concurrent_same_name_n2() {
        run_concurrent_first_arrival(2);
    }

    #[test]
    fn d19_concurrent_same_name_n10() {
        run_concurrent_first_arrival(10);
    }

    #[test]
    fn d19_concurrent_same_name_n100_multi_iter() {
        for _ in 0..5 {
            run_concurrent_first_arrival(100);
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod persistent_tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::encode::{InterestBuilder, encode_data_unsigned};
    use ndn_packet::{Data, Name, Selector, SubscriptionRequest};
    use ndn_security::{TrustSchema, Validator};
    use ndn_store::{PitEntry, PitKeyDiscriminator};

    fn persistent_token(name: &Name) -> PitToken {
        let h = NameHashes::full_name_hash(name);
        PitToken::from_name_hash_keyed(h, None, PitKeyDiscriminator::PersistentAttach)
    }

    fn make_validator() -> Arc<Validator> {
        Arc::new(Validator::new(TrustSchema::accept_all()))
    }

    fn build_persistent_interest(name: &str, max_data: u32, max_lifetime: u32) -> Bytes {
        let sr = SubscriptionRequest {
            version: 1,
            max_data_count: max_data,
            max_lifetime_secs: max_lifetime,
        };
        let ap_bytes = sr.encode();
        InterestBuilder::new(name)
            .app_parameters(ap_bytes.to_vec())
            .sign_digest_sha256()
    }

    fn run_check(stage: &Arc<PitCheckStage>, interest_wire: Bytes) -> Action {
        let interest = ndn_packet::Interest::decode(interest_wire.clone()).unwrap();
        let mut ctx = PacketContext::new(interest_wire, FaceId(1), 0);
        ctx.packet = DecodedPacket::Interest(Box::new(interest));
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(stage.process(ctx))
    }

    fn run_match(stage: &PitMatchStage, data_wire: Bytes) -> Action {
        let data = Data::decode(data_wire.clone()).unwrap();
        let mut ctx = PacketContext::new(data_wire, FaceId(99), 0);
        ctx.packet = DecodedPacket::Data(Box::new(data));
        stage.process(ctx)
    }

    #[test]
    fn persistent_interest_survives_multiple_data_until_credit_exhausted() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };

        let name: Name = "/persistent/test".parse().unwrap();
        let wire = build_persistent_interest("/persistent/test", 3, 60);
        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Continue(_)),
            "valid persistent Interest must be inserted"
        );

        // Verify the PIT entry has persistent state with credit 3.
        let token = persistent_token(&name);
        pit.with_entry(&token, |e| {
            let ps = e
                .persistent
                .as_ref()
                .expect("persistent state must be present");
            assert_eq!(ps.data_count_remaining, 3);
        })
        .expect("entry must exist");

        // First Data: entry must survive, credit becomes 2.
        let data1 = encode_data_unsigned(&name, b"data1");
        let a1 = run_match(&match_stage, data1);
        assert!(matches!(a1, Action::Continue(_)), "first Data must satisfy");
        assert!(
            pit.contains(&token),
            "entry must still exist after 1st Data"
        );
        pit.with_entry(&token, |e| {
            assert_eq!(e.persistent.as_ref().unwrap().data_count_remaining, 2);
        })
        .unwrap();

        // Second Data: credit becomes 1.
        let data2 = encode_data_unsigned(&name, b"data2");
        let a2 = run_match(&match_stage, data2);
        assert!(matches!(a2, Action::Continue(_)));
        assert!(pit.contains(&token));
        pit.with_entry(&token, |e| {
            assert_eq!(e.persistent.as_ref().unwrap().data_count_remaining, 1);
        })
        .unwrap();

        // Third Data: credit hits 0 → entry reaped.
        let data3 = encode_data_unsigned(&name, b"data3");
        let a3 = run_match(&match_stage, data3);
        assert!(matches!(a3, Action::Continue(_)));
        assert!(
            !pit.contains(&token),
            "entry must be reaped after credit exhausted"
        );
    }

    /// Invalid signature → entry installed non-persistently (classical
    /// match-and-remove on first Data).
    #[test]
    fn persistent_interest_invalid_sig_degrades_to_classical() {
        // Validator will reject because of a bad signature.
        // Build an Interest signed with DigestSha256 but then corrupt the
        // sig value.  Our Validator computes SHA256 of the signed region;
        // the forged sig won't match.
        let pit = Arc::new(Pit::new());
        // Use a validator that verifies the sig; a corrupted sig returns Invalid.
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };

        // Build a correctly signed Interest and then corrupt the last byte.
        let name: Name = "/persistent/degrade".parse().unwrap();
        let mut wire = build_persistent_interest("/persistent/degrade", 5, 30).to_vec();
        if let Some(last) = wire.last_mut() {
            *last ^= 0xff;
        }
        let wire = Bytes::from(wire);

        let action = run_check(&check, wire);
        // Should still be inserted (classical); bad sig causes degradation not drop.
        assert!(
            matches!(action, Action::Continue(_)),
            "invalid-sig persistent Interest must degrade to classical insert"
        );

        let token = PitToken::from_interest(&name);
        pit.with_entry(&token, |e| {
            assert!(
                e.persistent.is_none(),
                "degraded entry must have no persistent state"
            );
        })
        .expect("entry must exist");

        // One Data removes the entry (classical semantics).
        let data = encode_data_unsigned(&name, b"payload");
        run_match(&match_stage, data);
        assert!(
            !pit.contains(&token),
            "classical entry reaped on first Data"
        );
    }

    /// Persistent Interest with `max_data_count = 0` → `InvalidPersistentRequest`.
    #[test]
    fn persistent_interest_zero_count_is_dropped() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        let wire = build_persistent_interest("/persistent/bad", 0, 60);
        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Drop(DropReason::InvalidPersistentRequest)),
            "max_data_count=0 must be rejected"
        );
    }

    /// Persistent Interest with `max_lifetime_secs = 0` → `InvalidPersistentRequest`.
    #[test]
    fn persistent_interest_zero_lifetime_is_dropped() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        let wire = build_persistent_interest("/persistent/bad", 10, 0);
        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Drop(DropReason::InvalidPersistentRequest)),
            "max_lifetime_secs=0 must be rejected"
        );
    }

    /// Persistent Interest exceeding `MAX_PERSISTENT_LIFETIME_SECS` → drop.
    #[test]
    fn persistent_interest_over_max_lifetime_is_dropped() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        let wire =
            build_persistent_interest("/persistent/bad", 10, MAX_PERSISTENT_LIFETIME_SECS + 1);
        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Drop(DropReason::InvalidPersistentRequest)),
            "max_lifetime_secs > MAX must be rejected"
        );
    }

    /// Persistent Interest with `version != 1` → drop.
    #[test]
    fn persistent_interest_wrong_version_is_dropped() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        let sr = SubscriptionRequest {
            version: 2, // wrong
            max_data_count: 10,
            max_lifetime_secs: 60,
        };
        let ap_bytes = sr.encode();
        let wire = InterestBuilder::new("/persistent/v2")
            .app_parameters(ap_bytes.to_vec())
            .sign_digest_sha256();

        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Drop(DropReason::InvalidPersistentRequest)),
            "version != 1 must be rejected"
        );
    }

    /// Same-name marker-bearing re-issue → aggregated into one PersistentAttach
    /// entry; each in-record carries its own per-subscriber credit pool.
    /// Marker-bearing and non-marker Interests at the same logical name
    /// occupy *distinct* entries by the PIT-key discriminator — see
    /// `persistent_and_classical_same_name_isolated`.
    #[test]
    fn persistent_reissue_aggregates_without_revalidation() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        // First marker-bearing Interest installs the persistent entry.
        let wire1 = build_persistent_interest("/persistent/agg", 10, 60);
        let a1 = run_check(&check, wire1);
        assert!(matches!(a1, Action::Continue(_)));

        // Second marker-bearing Interest at the same logical name, different
        // face → aggregated.  Per-InRecord credit means each subscriber owns
        // its own credit (5 here vs 10 above).
        let wire2 = build_persistent_interest("/persistent/agg", 5, 60);
        let interest2b = ndn_packet::Interest::decode(wire2.clone()).unwrap();
        let mut ctx2 = PacketContext::new(wire2, FaceId(2), 0);
        ctx2.packet = DecodedPacket::Interest(Box::new(interest2b));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let a2 = rt.block_on(check.process(ctx2));
        assert!(
            matches!(a2, Action::Drop(DropReason::Suppressed)),
            "same-name marker re-issue must be aggregated (Suppressed)"
        );

        let agg_name: Name = "/persistent/agg".parse().unwrap();
        let token = persistent_token(&agg_name);
        pit.with_entry(&token, |e| {
            assert_eq!(e.in_records.len(), 2, "both in-records must be present");
            let credits: Vec<u32> = e
                .in_records
                .iter()
                .map(|r| r.persistent.as_ref().unwrap().data_count_remaining)
                .collect();
            assert!(
                credits.contains(&10) && credits.contains(&5),
                "each subscriber must retain its own credit pool: {credits:?}"
            );
        })
        .expect("entry must exist");
    }

    /// Marker-bearing and non-marker Interests at the same logical name
    /// occupy distinct PIT entries — no semantic collision between regimes.
    /// Doctrine: the PIT-key discriminator keeps them keyed apart.
    #[test]
    fn persistent_and_classical_same_name_isolated() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });

        // Marker-bearing Interest installs the PersistentAttach entry.
        let wire1 = build_persistent_interest("/iso/agg", 10, 60);
        let a1 = run_check(&check, wire1);
        assert!(matches!(a1, Action::Continue(_)));

        // Classical (non-marker) Interest at the same logical name on a
        // different face → inserts a *new* Classical entry, not aggregated.
        let agg_name: Name = "/iso/agg".parse().unwrap();
        let wire2 = ndn_packet::encode::encode_interest(&agg_name, None);
        let interest2 = ndn_packet::Interest::decode(wire2.clone()).unwrap();
        let mut ctx2 = PacketContext::new(wire2, FaceId(2), 0);
        ctx2.packet = DecodedPacket::Interest(Box::new(interest2));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let a2 = rt.block_on(check.process(ctx2));
        assert!(
            matches!(a2, Action::Continue(_)),
            "classical Interest at same logical name must insert a fresh entry"
        );

        let persistent_t = persistent_token(&agg_name);
        let classical_t = PitToken::from_interest(&agg_name);
        assert!(
            pit.contains(&persistent_t),
            "PersistentAttach entry must exist"
        );
        assert!(pit.contains(&classical_t), "Classical entry must exist");
        assert_eq!(pit.len(), 2, "two distinct entries, no aggregation");
    }

    /// No validator → persistent request degrades to classical (no persistent
    /// state installed).
    #[test]
    fn no_validator_degrades_to_classical() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: None,
            replay_guard: None,
        });
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };

        let wire = build_persistent_interest("/persistent/novalidator", 5, 60);
        let action = run_check(&check, wire);
        assert!(matches!(action, Action::Continue(_)));

        let name: Name = "/persistent/novalidator".parse().unwrap();
        let token = PitToken::from_interest(&name);
        pit.with_entry(&token, |e| {
            assert!(e.persistent.is_none(), "no validator → no persistent state");
        })
        .expect("entry must exist");

        // First Data removes the entry (classical).
        let data = encode_data_unsigned(&name, b"data");
        run_match(&match_stage, data);
        assert!(
            !pit.contains(&token),
            "classical entry reaped after one Data"
        );
    }

    /// Persistent Interest with CanBePrefix satisfies sequenced Data under
    /// the prefix; the entry survives until credit is exhausted.
    #[test]
    fn persistent_can_be_prefix_survives_until_credit_exhausted() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };

        // Build a persistent Interest with CanBePrefix for /stream, credit 3.
        let sr = SubscriptionRequest {
            version: 1,
            max_data_count: 3,
            max_lifetime_secs: 60,
        };
        let ap_bytes = sr.encode();
        let wire = InterestBuilder::new("/stream")
            .can_be_prefix()
            .app_parameters(ap_bytes.to_vec())
            .sign_digest_sha256();

        let action = run_check(&check, wire);
        assert!(
            matches!(action, Action::Continue(_)),
            "persistent CanBePrefix must insert"
        );

        // Marker-bearing entries are keyed under PersistentAttach at the
        // logical prefix /stream (PSDC stripped).
        let prefix_name: Name = "/stream".parse().unwrap();
        let token = persistent_token(&prefix_name);
        pit.with_entry(&token, |e| {
            let ps = e
                .persistent
                .as_ref()
                .expect("persistent state must be present");
            assert_eq!(ps.data_count_remaining, 3);
        })
        .expect("entry must be keyed at /stream, not /stream/<digest>");

        let seq_names: [&str; 3] = ["/stream/seq=0", "/stream/seq=1", "/stream/seq=2"];

        // First two Data: entry must survive.
        for (i, n) in seq_names[..2].iter().enumerate() {
            let seq_name: Name = n.parse().unwrap();
            let data_wire = encode_data_unsigned(&seq_name, b"payload");
            let a = run_match(&match_stage, data_wire);
            assert!(matches!(a, Action::Continue(_)), "Data {} must satisfy", i);
            assert!(pit.contains(&token), "entry must survive after Data {}", i);
        }
        pit.with_entry(&token, |e| {
            assert_eq!(e.persistent.as_ref().unwrap().data_count_remaining, 1);
        })
        .unwrap();

        // Third Data: credit exhausted → entry reaped.
        let seq_name: Name = seq_names[2].parse().unwrap();
        let data_wire = encode_data_unsigned(&seq_name, b"payload");
        let a = run_match(&match_stage, data_wire);
        assert!(matches!(a, Action::Continue(_)), "third Data must satisfy");
        assert!(
            !pit.contains(&token),
            "entry must be reaped after credit exhausted"
        );
    }

    /// Classical CanBePrefix Interest is still removed on first Data match
    /// (regression guard for the persistent-aware prefix-walk path).
    #[test]
    fn classical_can_be_prefix_removed_on_first_match() {
        let pit = Arc::new(Pit::new());
        let check = Arc::new(PitCheckStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
            validator: Some(make_validator()),
            replay_guard: None,
        });
        let match_stage = PitMatchStage {
            pit: Arc::clone(&pit),
            dead_nonce_list: None,
        };

        // Non-persistent Interest with CanBePrefix.
        let prefix_name: Name = "/classical/prefix".parse().unwrap();
        let wire = InterestBuilder::new("/classical/prefix")
            .can_be_prefix()
            .build();
        let action = run_check(&check, wire);
        assert!(matches!(action, Action::Continue(_)));

        let token = PitToken::from_interest(&prefix_name);
        assert!(
            pit.contains(&token),
            "entry must be present before any Data"
        );

        // Data under the prefix satisfies and removes the entry.
        let child_name: Name = "/classical/prefix/seq=0".parse().unwrap();
        let data_wire = encode_data_unsigned(&child_name, b"payload");
        let a = run_match(&match_stage, data_wire);
        assert!(
            matches!(a, Action::Continue(_)),
            "classical CanBePrefix must satisfy"
        );
        assert!(
            !pit.contains(&token),
            "classical entry must be removed on first match"
        );

        // Second Data under the same prefix is unsolicited: PitMatchStage now
        // carries it through as Continue with `unsolicited` set (the dispatcher
        // applies the UnsolicitedDataPolicy), rather than dropping in-stage.
        let data2_wire = encode_data_unsigned(&child_name, b"payload2");
        let a2 = run_match(&match_stage, data2_wire);
        match a2 {
            Action::Continue(c) => {
                assert!(c.unsolicited, "unmatched Data must be flagged unsolicited");
                assert!(c.out_faces.is_empty(), "unsolicited Data forwards nowhere");
            }
            _ => panic!("unsolicited Data must Continue with the unsolicited flag"),
        }
    }

    /// Past-deadline persistent entry is reaped by `drain_expired`.
    #[test]
    fn persistent_entry_expired_by_drain() {
        let pit = Arc::new(Pit::new());

        let name: Name = "/persistent/expiry".parse().unwrap();
        let token = PitToken::from_interest(&name);

        // Manually insert a persistent entry with a deadline already in the past.
        let mut entry = PitEntry::new(Arc::new(name.clone()), 0, 4000);
        entry.persistent = Some(PersistentState {
            data_count_remaining: 99,
            reap_at: 1, // 1 ns since epoch — already expired
        });
        entry.expires_at = 1; // same value — drain_expired checks this field
        entry.add_in_record(1, 42, 1, None, Selector::default());
        pit.insert(token, entry);

        assert!(pit.contains(&token), "entry should exist before drain");
        let expired = pit.drain_expired(now_ns());
        assert!(!expired.is_empty(), "drain_expired must return the token");
        assert!(!pit.contains(&token), "entry must be gone after drain");
    }
}
