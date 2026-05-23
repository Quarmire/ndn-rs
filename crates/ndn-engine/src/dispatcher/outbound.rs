use std::sync::atomic::Ordering;
use web_time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::observability::targets as t;
use crate::pipeline::{Action, NackReason, PacketContext};
use ndn_packet::Name;
use ndn_packet::lp::{LpHeaders, encode_lp_nack_with_pit_token, encode_lp_with_headers};
use ndn_packet::wire::encode_nack;
use ndn_store::CsEntry;
use ndn_transport::{CongestionPolicy, FaceId, FaceScope};

use super::PacketDispatcher;

impl PacketDispatcher {
    pub(super) async fn enqueue_send(&self, face_id: FaceId, data: Bytes) {
        self.enqueue_send_with_source(face_id, data, FaceId::INVALID)
            .await;
    }

    /// Push `data` onto `face_id`'s outbound queue, tagging it with the
    /// originating face id `source`. `FaceId::INVALID` means no source.
    /// In-process consumers read the tag via `InProcHandle::recv_tagged`.
    pub(super) async fn enqueue_send_with_source(
        &self,
        face_id: FaceId,
        data: Bytes,
        source: FaceId,
    ) {
        let Some(state) = self.face_states.get(&face_id) else {
            return;
        };
        let item = (data, source);
        match state.congestion_policy {
            CongestionPolicy::Drop => match state.send_tx.try_send(item) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    state.counters.out_drops.fetch_add(1, Ordering::Relaxed);
                    debug!(target: t::FACE_SYSTEM, face=%face_id,
                               "send queue full, dropping packet (policy=Drop)");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    trace!(target: t::FACE_SYSTEM, face=%face_id, "send queue closed");
                }
            },
            CongestionPolicy::Backpressure { deadline } => {
                let start = Instant::now();
                let send_fut = state.send_tx.send(item);
                let sleep = self.runtime.sleep(deadline);
                let outcome = tokio::select! {
                    biased;
                    res = send_fut => Some(res),
                    _ = sleep => None,
                };
                match outcome {
                    Some(Ok(())) => {
                        let blocked = start.elapsed().as_nanos() as u64;
                        if blocked > 0 {
                            state
                                .counters
                                .out_blocked_ns
                                .fetch_add(blocked, Ordering::Relaxed);
                        }
                    }
                    Some(Err(_closed)) => {
                        trace!(target: t::FACE_SYSTEM, face=%face_id, "send queue closed");
                    }
                    None => {
                        state.counters.out_drops.fetch_add(1, Ordering::Relaxed);
                        debug!(target: t::FACE_SYSTEM, face=%face_id,
                               deadline_ms = deadline.as_millis(),
                               "send blocked past deadline, dropping packet \
                                (policy=Backpressure)");
                    }
                }
            }
        }
    }

    pub(super) async fn dispatch_action(&self, action: Action) {
        match action {
            Action::Send(ctx, faces) => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, out_faces=?faces, raw_len=ctx.raw_bytes.len(), "dispatch: Send");
                let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
                let name_for_rl = ctx.name.as_deref();
                for face_id in &faces {
                    let face = self.face_table.get(*face_id);
                    if is_localhost
                        && let Some(ref f) = face
                        && f.scope() == FaceScope::NonLocal
                    {
                        trace!(target: t::FWD_PIPELINE, face=%face_id, "dispatch: /localhost blocked on non-local face");
                        continue;
                    }
                    if !self.check_rate_limit_outbound(
                        *face_id,
                        name_for_rl,
                        true, // Interest
                        ctx.raw_bytes.len(),
                    ) {
                        debug!(target: t::FWD_PIPELINE, face=%face_id, name=?ctx.name, "rate-limit: outbound Interest dropped");
                        continue;
                    }
                    // Wrap egress in LpPacket on LP-framed (wire) faces so
                    // per-hop headers (CongestionMark, NextHopFaceId, …) have a
                    // frame. IPC faces keep bare TLV; source-face provenance
                    // rides the tag-bag instead.
                    let uses_lp = face
                        .as_ref()
                        .map(|f| f.kind().uses_lp_framing())
                        .unwrap_or(false);
                    let egress_bytes = if uses_lp {
                        ndn_packet::lp::encode_lp_packet(&ctx.raw_bytes)
                    } else {
                        ctx.raw_bytes.clone()
                    };
                    let egress_len = egress_bytes.len() as u64;
                    if let Some(state) = self.face_states.get(face_id) {
                        state.counters.out_interests.fetch_add(1, Ordering::Relaxed);
                        state
                            .counters
                            .out_bytes
                            .fetch_add(egress_len, Ordering::Relaxed);
                    }
                    self.enqueue_send_with_source(*face_id, egress_bytes, ctx.face_id)
                        .await;
                }
            }
            Action::Satisfy(ctx) => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, out_faces=?ctx.out_faces, cs_hit=ctx.cs_hit, "dispatch: Satisfy");
                self.satisfy(ctx).await;
            }
            Action::Drop(r) => debug!(target: t::FWD_PIPELINE, reason=?r, "packet dropped"),
            Action::Nack(ctx, reason) => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, reason=?reason, "dispatch: Nack");
                let packet_reason = match reason {
                    NackReason::NoRoute => ndn_packet::NackReason::NoRoute,
                    NackReason::Duplicate => ndn_packet::NackReason::Duplicate,
                    NackReason::Congestion => ndn_packet::NackReason::Congestion,
                    NackReason::NotYet => ndn_packet::NackReason::NotYet,
                };
                // Echo the consumer's PitToken on the Nack return path so
                // it can correlate the response with its outstanding request.
                let nack_bytes = match ctx.lp_pit_token.as_deref() {
                    Some(token) => {
                        encode_lp_nack_with_pit_token(packet_reason, &ctx.raw_bytes, Some(token))
                    }
                    None => encode_nack(packet_reason, &ctx.raw_bytes),
                };
                self.enqueue_send(ctx.face_id, nack_bytes).await;
            }
            Action::Continue(_) => {}
        }
    }

    pub(super) async fn satisfy(&self, ctx: PacketContext) {
        let data_bytes = if ctx.cs_hit {
            ctx.tags
                .get::<CsEntry>()
                .map(|e| e.data.clone())
                .unwrap_or_else(|| ctx.raw_bytes.clone())
        } else {
            ctx.raw_bytes.clone()
        };

        let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
        let name_for_rl = ctx.name.as_deref();
        for (i, face_id) in ctx.out_faces.iter().enumerate() {
            if is_localhost
                && let Some(face) = self.face_table.get(*face_id)
                && face.scope() == FaceScope::NonLocal
            {
                trace!(target: t::FWD_PIPELINE, face=%face_id, "satisfy: /localhost blocked on non-local face");
                continue;
            }
            if !self.check_rate_limit_outbound(
                *face_id,
                name_for_rl,
                false, // Data
                data_bytes.len(),
            ) {
                debug!(target: t::FWD_PIPELINE, face=%face_id, name=?ctx.name, "rate-limit: outbound Data dropped");
                continue;
            }
            // Wrap Data in LpPacket on LP-framed (wire) egress so the PitToken
            // attached on ingress is echoed back to the consumer. IPC faces keep
            // bare TLV (in-proc apps don't speak LP).
            let uses_lp = self
                .face_table
                .get(*face_id)
                .map(|f| f.kind().uses_lp_framing())
                .unwrap_or(false);
            let egress_bytes = match ctx.out_pit_tokens.get(i).and_then(|t| t.clone()) {
                Some(token) => encode_lp_with_headers(
                    &data_bytes,
                    &LpHeaders {
                        pit_token: Some(token),
                        congestion_mark: None,
                        incoming_face_id: None,
                        next_hop_face_id: None,
                        cache_policy: None,
                    },
                ),
                None if uses_lp => ndn_packet::lp::encode_lp_packet(&data_bytes),
                None => data_bytes.clone(),
            };
            let egress_len = egress_bytes.len() as u64;
            if let Some(state) = self.face_states.get(face_id) {
                state.counters.out_data.fetch_add(1, Ordering::Relaxed);
                state
                    .counters
                    .out_bytes
                    .fetch_add(egress_len, Ordering::Relaxed);
                // `NSatisfiedInterests` credits the in-face of the original
                // Interest, which here is the egress face for returning Data
                // (PIT match populated `out_faces` from `in_record_faces`).
                state
                    .counters
                    .in_satisfied_interests
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.enqueue_send(*face_id, egress_bytes).await;
        }
    }
}

fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

#[cfg(test)]
mod tests {
    use crate::engine::FaceState;
    use bytes::Bytes;
    use ndn_transport::{CongestionPolicy, FaceId, FacePersistency};
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    fn make_state(
        policy: CongestionPolicy,
        cap: usize,
    ) -> (FaceState, mpsc::Receiver<crate::engine::EgressItem>) {
        let (tx, rx) = mpsc::channel(cap);
        let state = FaceState::new(
            CancellationToken::new(),
            FacePersistency::OnDemand,
            tx,
            policy,
        );
        (state, rx)
    }

    async fn enqueue_with_state(state: &FaceState, data: Bytes) {
        use web_time::Instant;
        let item = (data, FaceId::INVALID);
        match state.congestion_policy {
            CongestionPolicy::Drop => match state.send_tx.try_send(item) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    state.counters.out_drops.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            },
            CongestionPolicy::Backpressure { deadline } => {
                let start = Instant::now();
                match tokio::time::timeout(deadline, state.send_tx.send(item)).await {
                    Ok(Ok(())) => {
                        let blocked = start.elapsed().as_nanos() as u64;
                        if blocked > 0 {
                            state
                                .counters
                                .out_blocked_ns
                                .fetch_add(blocked, Ordering::Relaxed);
                        }
                    }
                    Ok(Err(_)) => {}
                    Err(_timeout) => {
                        state.counters.out_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn app_face_backpressure_no_drops_with_fast_consumer() {
        let policy = CongestionPolicy::Backpressure {
            deadline: Duration::from_millis(100),
        };
        let (state, mut rx) = make_state(policy, 4);

        tokio::spawn(async move { while rx.recv().await.is_some() {} });

        for i in 0..50u64 {
            enqueue_with_state(&state, Bytes::from(format!("pkt{i}"))).await;
        }

        assert_eq!(state.counters.out_drops.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn app_face_backpressure_drops_after_deadline_stuck_consumer() {
        let policy = CongestionPolicy::Backpressure {
            deadline: Duration::from_millis(10),
        };
        let (state, _rx) = make_state(policy, 1);

        enqueue_with_state(&state, Bytes::from("fill")).await;
        enqueue_with_state(&state, Bytes::from("overflow")).await;

        assert_eq!(state.counters.out_drops.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn network_face_drop_policy_increments_out_drops() {
        let policy = CongestionPolicy::Drop;
        let (state, _rx) = make_state(policy, 1);

        enqueue_with_state(&state, Bytes::from("fill")).await;
        enqueue_with_state(&state, Bytes::from("overflow")).await;

        assert_eq!(state.counters.out_drops.load(Ordering::Relaxed), 1);
    }
}
