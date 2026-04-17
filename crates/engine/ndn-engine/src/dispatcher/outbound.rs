use std::sync::atomic::Ordering;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::pipeline::{Action, NackReason, PacketContext};
use ndn_packet::Name;
use ndn_packet::encode::encode_nack;
use ndn_store::CsEntry;
use ndn_transport::{FaceId, FaceScope};

use super::PacketDispatcher;

impl PacketDispatcher {
    pub(super) fn enqueue_send(&self, face_id: FaceId, data: Bytes) {
        if let Some(state) = self.face_states.get(&face_id) {
            match state.send_tx.try_send(data) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    debug!(face=%face_id, "send queue full, dropping packet");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    trace!(face=%face_id, "send queue closed");
                }
            }
        }
    }

    pub(super) fn dispatch_action(&self, action: Action) {
        match action {
            Action::Send(ctx, faces) => {
                trace!(face=%ctx.face_id, name=?ctx.name, out_faces=?faces, raw_len=ctx.raw_bytes.len(), "dispatch: Send");
                let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
                let raw_len = ctx.raw_bytes.len() as u64;
                for face_id in &faces {
                    if is_localhost
                        && let Some(face) = self.face_table.get(*face_id)
                        && face.kind().scope() == FaceScope::NonLocal
                    {
                        trace!(face=%face_id, "dispatch: /localhost blocked on non-local face");
                        continue;
                    }
                    if let Some(state) = self.face_states.get(face_id) {
                        state.counters.out_interests.fetch_add(1, Ordering::Relaxed);
                        state
                            .counters
                            .out_bytes
                            .fetch_add(raw_len, Ordering::Relaxed);
                    }
                    self.enqueue_send(*face_id, ctx.raw_bytes.clone());
                }
            }
            Action::Satisfy(ctx) => {
                trace!(face=%ctx.face_id, name=?ctx.name, out_faces=?ctx.out_faces, cs_hit=ctx.cs_hit, "dispatch: Satisfy");
                self.satisfy(ctx);
            }
            Action::Drop(r) => debug!(reason=?r, "packet dropped"),
            Action::Nack(ctx, reason) => {
                trace!(face=%ctx.face_id, name=?ctx.name, reason=?reason, "dispatch: Nack");
                let packet_reason = match reason {
                    NackReason::NoRoute => ndn_packet::NackReason::NoRoute,
                    NackReason::Duplicate => ndn_packet::NackReason::Duplicate,
                    NackReason::Congestion => ndn_packet::NackReason::Congestion,
                    NackReason::NotYet => ndn_packet::NackReason::NotYet,
                };
                let nack_bytes = encode_nack(packet_reason, &ctx.raw_bytes);
                self.enqueue_send(ctx.face_id, nack_bytes);
            }
            Action::Continue(_) => {} // fell off end of pipeline
        }
    }

    pub(super) fn satisfy(&self, ctx: PacketContext) {
        let data_bytes = if ctx.cs_hit {
            ctx.tags
                .get::<CsEntry>()
                .map(|e| e.data.clone())
                .unwrap_or_else(|| ctx.raw_bytes.clone())
        } else {
            ctx.raw_bytes.clone()
        };

        let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
        let data_len = data_bytes.len() as u64;
        for face_id in &ctx.out_faces {
            if is_localhost
                && let Some(face) = self.face_table.get(*face_id)
                && face.kind().scope() == FaceScope::NonLocal
            {
                trace!(face=%face_id, "satisfy: /localhost blocked on non-local face");
                continue;
            }
            if let Some(state) = self.face_states.get(face_id) {
                state.counters.out_data.fetch_add(1, Ordering::Relaxed);
                state
                    .counters
                    .out_bytes
                    .fetch_add(data_len, Ordering::Relaxed);
            }
            self.enqueue_send(*face_id, data_bytes.clone());
        }
    }
}

fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}
