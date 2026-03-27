use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use smallvec::SmallVec;

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
        let token = PitToken::from_interest(&interest.name, Some(interest.selectors()));
        ctx.pit_token = Some(token);

        if let Some(mut entry) = self.pit.get_mut(&token) {
            // Loop detection.
            if entry.nonces_seen.contains(&nonce) {
                return Action::Drop(DropReason::LoopDetected);
            }
            // Aggregate: add in-record, suppress forwarding.
            let expires_at = now_ns + lifetime_ms * 1_000_000;
            entry.add_in_record(ctx.face_id.0, nonce, expires_at);
            // Return Drop(Suppressed) — we already have an outstanding Interest.
            return Action::Drop(DropReason::Suppressed);
        }

        // New PIT entry.
        let name = interest.name.clone();
        let selector = Some(interest.selectors().clone());
        let mut entry = PitEntry::new(name, selector, now_ns, lifetime_ms);
        entry.add_in_record(ctx.face_id.0, nonce, now_ns + lifetime_ms * 1_000_000);
        self.pit.insert(token, entry);

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

        // Compute token to find the PIT entry.
        // For Data matching we use `from_interest` on the Data name with
        // no selector, then also check with a default selector — simple approach:
        // try the name with None selector first, then default.
        let token = PitToken::from_interest(&data.name, None);

        if let Some((_, entry)) = self.pit.remove(&token) {
            let faces: SmallVec<[FaceId; 4]> = entry
                .in_record_faces()
                .map(FaceId)
                .collect();
            ctx.out_faces = faces;
            Action::Continue(ctx)
        } else {
            // Also try with default (empty) selector.
            let default_sel = ndn_packet::Selector::default();
            let token2 = PitToken::from_interest(&data.name, Some(&default_sel));
            if let Some((_, entry)) = self.pit.remove(&token2) {
                let faces: SmallVec<[FaceId; 4]> = entry
                    .in_record_faces()
                    .map(FaceId)
                    .collect();
                ctx.out_faces = faces;
                Action::Continue(ctx)
            } else {
                // Unsolicited Data — drop.
                Action::Drop(DropReason::Other)
            }
        }
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
