use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::trace;

use crate::pipeline::{Action, DecodedPacket, PacketContext};
use ndn_packet::CachePolicyType;
use ndn_store::{CsAdmissionPolicy, CsMeta, ErasedContentStore};

use crate::stages::decode::LpCachePolicy;

pub struct CsLookupStage {
    pub cs: Arc<dyn ErasedContentStore>,
}

impl CsLookupStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i,
            _ => return Action::Continue(ctx),
        };

        if let Some(entry) = self.cs.get_erased(interest).await {
            trace!(face=%ctx.face_id, name=?ctx.name, "cs-lookup: HIT");
            ctx.cs_hit = true;
            ctx.out_faces.push(ctx.face_id);
            ctx.tags.insert(entry);
            Action::Satisfy(ctx)
        } else {
            trace!(face=%ctx.face_id, name=?ctx.name, "cs-lookup: MISS");
            Action::Continue(ctx)
        }
    }
}

pub struct CsInsertStage {
    pub cs: Arc<dyn ErasedContentStore>,
    pub admission: Arc<dyn CsAdmissionPolicy>,
}

impl CsInsertStage {
    pub async fn process(&self, ctx: PacketContext) -> Action {
        if let DecodedPacket::Data(ref data) = ctx.packet {
            if ctx
                .tags
                .get::<LpCachePolicy>()
                .is_some_and(|p| matches!(p.0, CachePolicyType::NoCache))
            {
                trace!(name=%data.name, "cs-insert: NoCache LP policy, skipping");
                return Action::Satisfy(ctx);
            }

            if !self.admission.should_admit(data) {
                trace!(name=%data.name, "cs-insert: rejected by admission policy");
                return Action::Satisfy(ctx);
            }

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
            self.cs
                .insert_erased(ctx.raw_bytes.clone(), data.name.clone(), meta)
                .await;
            trace!(name=%data.name, freshness_ms, "cs-insert: cached");
        }
        Action::Satisfy(ctx)
    }
}
