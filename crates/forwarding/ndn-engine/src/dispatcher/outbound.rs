use std::sync::atomic::Ordering;
use web_time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, trace};

use crate::engine::EgressIntent;
use crate::observability::targets as t;
use crate::pipeline::{Action, NackReason, PacketContext};
use ndn_packet::Name;
use ndn_packet::lp::LpHeaders;
use ndn_store::CsEntry;
use ndn_transport::{CongestionPolicy, FaceId, FaceScope, LinkType};

use super::PacketDispatcher;

impl PacketDispatcher {
    /// Whether `face_id` has the per-face NDNLPv2 `LocalFields` option enabled
    /// (NFD `BIT_LOCAL_FIELDS`, toggled via `faces/update`). Gates attaching
    /// `IncomingFaceId` to that face's egress.
    fn local_fields_enabled(&self, face_id: FaceId) -> bool {
        self.face_states
            .get(&face_id)
            .is_some_and(|s| s.local_fields_enabled())
    }

    pub(super) fn face_link_type(&self, face_id: FaceId) -> LinkType {
        self.face_table
            .get(face_id)
            .map(|f| f.link_type())
            .unwrap_or(LinkType::PointToPoint)
    }

    /// NDNLPv2 Nacks are point-to-point feedback. Do not emit or accept them
    /// on shared media where one peer's failure must not suppress another
    /// peer's chance to satisfy the Interest.
    pub(super) fn nacks_allowed_on_face(&self, face_id: FaceId) -> bool {
        self.face_link_type(face_id) == LinkType::PointToPoint
    }

    /// Classify an outbound packet into a [`TrafficClass`](crate::egress::TrafficClass).
    /// `TrafficClass::DEFAULT` when no classifier is configured (the FIFO default path
    /// ignores the class anyway).
    pub(super) fn classify(
        &self,
        name: Option<&Name>,
        is_interest: bool,
    ) -> crate::egress::TrafficClass {
        self.name_classifier
            .as_ref()
            .map(|c| c.classify(name, is_interest))
            .unwrap_or_default()
    }

    pub(super) async fn enqueue_send(&self, face_id: FaceId, payload: Bytes, intent: EgressIntent) {
        self.enqueue_send_with_source(
            face_id,
            payload,
            FaceId::INVALID,
            intent,
            crate::egress::TrafficClass::DEFAULT,
        )
        .await;
    }

    /// Push a **bare** `payload` + framing `intent` onto `face_id`'s outbound
    /// queue, tagging it with the originating face id `source`
    /// (`FaceId::INVALID` = none). Framing happens once, in the send loop
    /// ([`crate::engine::frame_with_intent`]); in-process consumers read the
    /// `source` tag via `InProcHandle::recv_tagged`.
    pub(super) async fn enqueue_send_with_source(
        &self,
        face_id: FaceId,
        payload: Bytes,
        source: FaceId,
        intent: EgressIntent,
        class: crate::egress::TrafficClass,
    ) {
        let Some(state) = self.face_states.get(&face_id) else {
            return;
        };
        let item = (payload, source, intent);
        // G4: with a scheduler installed, admit into it (priority order); the congestion
        // policy's queue-full handling is the scheduler's tail-drop. Otherwise the FIFO
        // default below (the raw mpsc + Drop/Backpressure).
        if let Some(scheduler) = &state.scheduler {
            if !scheduler.enqueue(item, class) {
                state.counters.out_drops.fetch_add(1, Ordering::Relaxed);
                debug!(target: t::FACE_SYSTEM, face=%face_id,
                       "egress scheduler queue full, dropping packet");
            }
            return;
        }
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
                    // NDNLPv2 IncomingFaceId (0x032C) is attached only when the
                    // egress face has the per-face LocalFields option enabled
                    // (faces/update, BIT_LOCAL_FIELDS), mirroring NFD's
                    // GenericLinkService::encodeLpFields gate on
                    // `allowLocalFields`. The value is the ingress face the
                    // Interest arrived on (NFD onIncomingInterest tag). The
                    // actual LP wrap happens once, downstream, in the send loop.
                    let uses_lp = face
                        .as_ref()
                        .map(|f| f.kind().uses_lp_framing())
                        .unwrap_or(false);
                    let incoming_face_id =
                        (uses_lp && self.local_fields_enabled(*face_id)).then_some(ctx.face_id.0);
                    let intent = EgressIntent {
                        headers: LpHeaders {
                            incoming_face_id,
                            ..Default::default()
                        },
                        nack: None,
                    };
                    if let Some(state) = self.face_states.get(face_id) {
                        state.counters.out_interests.fetch_add(1, Ordering::Relaxed);
                    }
                    self.enqueue_send_with_source(
                        *face_id,
                        ctx.raw_bytes.clone(),
                        ctx.face_id,
                        intent,
                        self.classify(name_for_rl, true),
                    )
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
                if !self.nacks_allowed_on_face(ctx.face_id) {
                    debug!(target: t::FWD_PIPELINE, face=%ctx.face_id, "nack suppressed on multi-access/ad-hoc face");
                    return;
                }
                let packet_reason = match reason {
                    NackReason::NoRoute => ndn_packet::NackReason::NoRoute,
                    NackReason::Duplicate => ndn_packet::NackReason::Duplicate,
                    NackReason::Congestion => ndn_packet::NackReason::Congestion,
                    NackReason::NotYet => ndn_packet::NackReason::NotYet,
                };
                // Echo the consumer's PitToken on the Nack return path so it
                // can correlate the response with its outstanding request. The
                // Nack LP frame (with the Interest as payload) is built in the
                // send loop from this intent.
                let intent = EgressIntent {
                    headers: LpHeaders {
                        pit_token: ctx.lp_pit_token.clone(),
                        ..Default::default()
                    },
                    nack: Some(packet_reason),
                };
                // NFD NOutNacks (LinkService::sendNack, link-service.cpp:73).
                if let Some(state) = self.face_states.get(&ctx.face_id) {
                    state.counters.out_nacks.fetch_add(1, Ordering::Relaxed);
                }
                self.enqueue_send(ctx.face_id, ctx.raw_bytes.clone(), intent)
                    .await;
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
            // Don't echo forwarded Data back out the face it arrived on —
            // EXCEPT on ad-hoc links, where re-radiating onto the shared
            // medium is how other listeners (including the node we relay for)
            // hear it (NFD onIncomingData, forwarder.cpp:383 guards the
            // skip with `!= LINK_TYPE_AD_HOC`). Cache hits are exempt: there
            // `ctx.face_id` is the consumer's own Interest face and is exactly
            // where the answer must go.
            if !ctx.cs_hit && *face_id == ctx.face_id {
                let ad_hoc = self
                    .face_table
                    .get(*face_id)
                    .is_some_and(|f| f.link_type() == LinkType::AdHoc);
                if !ad_hoc {
                    trace!(target: t::FWD_PIPELINE, face=%face_id, "satisfy: not echoing Data back out non-ad-hoc ingress face");
                    continue;
                }
            }
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
            // Returned Data echoes the consumer's PitToken (so it can correlate
            // the response) and, on a LocalFields face, the IncomingFaceId — the
            // face the Data arrived on (producer face, or the reserved
            // Content-Store id on a cache hit, NFD onContentStoreHit). The LP
            // wrap (or bare TLV, for IPC) is applied once, in the send loop.
            let uses_lp = self
                .face_table
                .get(*face_id)
                .map(|f| f.kind().uses_lp_framing())
                .unwrap_or(false);
            let incoming_face_id =
                (uses_lp && self.local_fields_enabled(*face_id)).then_some(if ctx.cs_hit {
                    FaceId::CONTENT_STORE.0
                } else {
                    ctx.face_id.0
                });
            let intent = EgressIntent {
                headers: LpHeaders {
                    pit_token: ctx.out_pit_tokens.get(i).and_then(|t| t.clone()),
                    incoming_face_id,
                    ..Default::default()
                },
                nack: None,
            };
            if let Some(state) = self.face_states.get(face_id) {
                state.counters.out_data.fetch_add(1, Ordering::Relaxed);
                // `NSatisfiedInterests` credits the in-face of the original
                // Interest, which here is the egress face for returning Data
                // (PIT match populated `out_faces` from `in_record_faces`).
                state
                    .counters
                    .in_satisfied_interests
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.enqueue_send_with_source(
                *face_id,
                data_bytes.clone(),
                FaceId::INVALID,
                intent,
                self.classify(name_for_rl, false),
            )
            .await;
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
            0, // test helper: activity stamp is irrelevant here
        );
        (state, rx)
    }

    async fn enqueue_with_state(state: &FaceState, data: Bytes) {
        use web_time::Instant;
        let item = (
            data,
            FaceId::INVALID,
            crate::engine::EgressIntent::default(),
        );
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
