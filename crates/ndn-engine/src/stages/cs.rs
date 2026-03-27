use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ndn_pipeline::{Action, DecodedPacket, PacketContext};
use ndn_store::{CsEntry, CsMeta, ContentStore, LruCs};

/// Look up the CS before hitting the PIT/FIB.
///
/// On a cache hit: stores `CsEntry` in `ctx.tags`, sets `ctx.cs_hit = true`,
/// sets `ctx.out_faces = [ctx.face_id]`, and returns `Action::Satisfy(ctx)`
/// so the dispatcher fans the cached Data back to the requesting face without
/// touching the PIT.
///
/// On a miss: `Action::Continue(ctx)` to proceed to `PitCheckStage`.
pub struct CsLookupStage {
    pub cs: Arc<LruCs>,
}

impl CsLookupStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i,
            // CS lookup only applies to Interests.
            _ => return Action::Continue(ctx),
        };

        if let Some(entry) = self.cs.get(interest).await {
            ctx.cs_hit = true;
            ctx.out_faces.push(ctx.face_id);
            ctx.tags.insert(entry);
            Action::Satisfy(ctx)
        } else {
            Action::Continue(ctx)
        }
    }
}

/// Insert Data into the CS after a successful PIT match.
///
/// Reads `ctx.raw_bytes` (the wire-format Data) and the decoded name.
/// Freshness defaults to 0 (immediately stale) if `FreshnessPeriod` is absent.
pub struct CsInsertStage {
    pub cs: Arc<LruCs>,
}

impl CsInsertStage {
    pub async fn process(&self, ctx: PacketContext) -> Action {
        if let DecodedPacket::Data(ref data) = ctx.packet {
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            let freshness_ms = data
                .meta_info()
                .and_then(|m| m.freshness_period)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let stale_at = now_ns + freshness_ms * 1_000_000;

            let meta = CsMeta { stale_at };
            self.cs.insert(ctx.raw_bytes.clone(), data.name.clone(), meta).await;
        }
        Action::Satisfy(ctx)
    }
}
