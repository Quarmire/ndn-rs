use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use smallvec::SmallVec;
use tracing::trace;

use crate::pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_packet::Selector;
use ndn_store::{NameHashes, Pit, PitEntry, PitToken};
use ndn_transport::FaceId;

/// Checks the PIT for a pending Interest.
///
/// **Duplicate suppression:** if the nonce has already been seen in the PIT
/// entry, the Interest is a loop — drop it.
///
/// **Aggregation:** if a PIT entry already exists for the same (name, selector),
/// add an in-record and return `Action::Drop` (the original forwarder already
/// has an outstanding Interest; no need to forward again).
///
/// **New entry:** create a PIT entry, write `ctx.pit_token`, continue to
/// `StrategyStage`.
pub struct PitCheckStage {
    pub pit: Arc<Pit>,
}

impl PitCheckStage {
    pub fn process(&self, mut ctx: PacketContext) -> Action {
        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i,
            _ => return Action::Continue(ctx),
        };

        let now_ns = now_ns();
        let lifetime_ms = interest
            .lifetime()
            .map(|d| d.as_millis() as u64)
            .unwrap_or(4_000); // NDN default 4 s

        let nonce = interest.nonce().unwrap_or(0);
        let name_hash = ctx
            .name_hashes
            .as_ref()
            .map(|h| h.full_hash())
            .unwrap_or_else(|| NameHashes::full_name_hash(&interest.name));
        let token = PitToken::from_name_hash(
            name_hash,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );
        ctx.pit_token = Some(token);

        enum ExistingResult {
            Loop,
            Aggregated,
        }
        if let Some(result) = self.pit.with_entry_mut(&token, |entry| {
            // Loop detection.
            if entry.nonces_seen.contains(&nonce) {
                return ExistingResult::Loop;
            }
            // Aggregate: add in-record, suppress forwarding.
            let expires_at = now_ns + lifetime_ms * 1_000_000;
            entry.add_in_record(ctx.face_id.0, nonce, expires_at, ctx.lp_pit_token.clone());
            ExistingResult::Aggregated
        }) {
            match result {
                ExistingResult::Loop => {
                    trace!(face=%ctx.face_id, name=%interest.name, nonce, "pit-check: loop detected");
                    return Action::Drop(DropReason::LoopDetected);
                }
                ExistingResult::Aggregated => {
                    trace!(face=%ctx.face_id, name=%interest.name, nonce, "pit-check: aggregated (suppressed)");
                    return Action::Drop(DropReason::Suppressed);
                }
            }
        }

        // New PIT entry.
        let name = interest.name.clone();
        let selector = Some(interest.selectors().clone());
        let mut entry = PitEntry::new(name, selector, now_ns, lifetime_ms);
        entry.add_in_record(
            ctx.face_id.0,
            nonce,
            now_ns + lifetime_ms * 1_000_000,
            ctx.lp_pit_token.clone(),
        );
        self.pit.insert(token, entry);
        trace!(face=%ctx.face_id, name=%interest.name, nonce, lifetime_ms, "pit-check: new entry");

        Action::Continue(ctx)
    }
}

/// Matches a Data packet against the PIT.
///
/// Collects in-record faces into `ctx.out_faces`, removes the PIT entry,
/// and returns `Action::Continue(ctx)` so `CsInsertStage` can cache the Data.
///
/// If no matching PIT entry is found, the Data is unsolicited — drop it.
pub struct PitMatchStage {
    pub pit: Arc<Pit>,
}

impl PitMatchStage {
    pub fn process(&self, mut ctx: PacketContext) -> Action {
        let data = match &ctx.packet {
            DecodedPacket::Data(d) => d,
            _ => return Action::Continue(ctx),
        };

        // Pre-computed name hashes eliminate per-probe re-hashing.  For the
        // full name we use the memoized hash; for CanBePrefix prefix probes
        // we index into the prefix_hashes array instead of allocating a
        // temporary Name and hashing it from scratch.
        let hashes = ctx
            .name_hashes
            .get_or_insert_with(|| NameHashes::compute(&data.name));

        // Try all selector combinations to find the PIT entry.
        //
        // PitCheck inserts with `from_name_hash(full, Some(selectors()), hint)`.
        // Since Data packets don't carry selector information, we must probe
        // all possible (can_be_prefix, must_be_fresh) combinations used at
        // insertion time.  The default (false, false) is tried first as the
        // common-case fast path.
        let selector_probes: &[Option<Selector>] = &[
            Some(Selector {
                can_be_prefix: false,
                must_be_fresh: false,
            }),
            Some(Selector {
                can_be_prefix: true,
                must_be_fresh: false,
            }),
            Some(Selector {
                can_be_prefix: false,
                must_be_fresh: true,
            }),
            Some(Selector {
                can_be_prefix: true,
                must_be_fresh: true,
            }),
            None,
        ];

        let full_hash = hashes.full_hash();
        for sel in selector_probes {
            let token = PitToken::from_name_hash(full_hash, sel.as_ref(), None);
            if let Some((_, entry)) = self.pit.remove(&token) {
                let faces: SmallVec<[FaceId; 4]> = entry.in_record_faces().map(FaceId).collect();
                trace!(face=%ctx.face_id, name=%data.name, out_faces=?faces, "pit-match: satisfied");
                ctx.out_faces = faces;
                return Action::Continue(ctx);
            }
        }

        // CanBePrefix: the Data name may be longer than the Interest name.
        // Walk progressively shorter prefixes using pre-computed prefix hashes
        // instead of allocating temporary Name objects and re-hashing.
        let can_be_prefix_probes: &[Option<Selector>] = &[
            Some(Selector {
                can_be_prefix: true,
                must_be_fresh: false,
            }),
            Some(Selector {
                can_be_prefix: true,
                must_be_fresh: true,
            }),
            None,
        ];
        let n_comps = hashes.len();
        for prefix_len in (1..n_comps).rev() {
            let prefix_hash = hashes.prefix_hash(prefix_len);
            for sel in can_be_prefix_probes {
                let token = PitToken::from_name_hash(prefix_hash, sel.as_ref(), None);
                if let Some((_, entry)) = self.pit.remove(&token) {
                    let faces: SmallVec<[FaceId; 4]> =
                        entry.in_record_faces().map(FaceId).collect();
                    trace!(face=%ctx.face_id, name=%data.name, prefix_len,
                           out_faces=?faces, "pit-match: satisfied (can-be-prefix)");
                    ctx.out_faces = faces;
                    return Action::Continue(ctx);
                }
            }
        }

        trace!(face=%ctx.face_id, name=%data.name, "pit-match: unsolicited Data");
        Action::Drop(DropReason::Other)
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
