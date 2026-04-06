use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use smallvec::SmallVec;
use tracing::trace;

use ndn_packet::Selector;
use ndn_pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_store::{Pit, PitEntry, PitToken};
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
        let token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );
        ctx.pit_token = Some(token);

        if let Some(mut entry) = self.pit.get_mut(&token) {
            // Loop detection.
            if entry.nonces_seen.contains(&nonce) {
                trace!(face=%ctx.face_id, name=%interest.name, nonce, "pit-check: loop detected");
                return Action::Drop(DropReason::LoopDetected);
            }
            // Aggregate: add in-record, suppress forwarding.
            let expires_at = now_ns + lifetime_ms * 1_000_000;
            entry.add_in_record(ctx.face_id.0, nonce, expires_at, ctx.lp_pit_token.clone());
            trace!(face=%ctx.face_id, name=%interest.name, nonce, "pit-check: aggregated (suppressed)");
            return Action::Drop(DropReason::Suppressed);
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

        // Try all selector combinations to find the PIT entry.
        //
        // PitCheck inserts with `from_interest_full(name, Some(selectors()), hint)`.
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

        for sel in selector_probes {
            let token = PitToken::from_interest(&data.name, sel.as_ref());
            if let Some((_, entry)) = self.pit.remove(&token) {
                let faces: SmallVec<[FaceId; 4]> = entry.in_record_faces().map(FaceId).collect();
                trace!(face=%ctx.face_id, name=%data.name, out_faces=?faces, "pit-match: satisfied");
                ctx.out_faces = faces;
                return Action::Continue(ctx);
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
