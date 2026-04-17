use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::pipeline::{
    Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_packet::encode::encode_nack;
use ndn_store::PitToken;
use ndn_transport::{FaceId, FaceScope};

use super::{InboundPacket, PacketDispatcher};

impl PacketDispatcher {
    pub(super) const BATCH_SIZE: usize = 64;

    pub(super) async fn run_pipeline(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
    ) {
        let mut batch = Vec::with_capacity(Self::BATCH_SIZE);
        loop {
            let first = tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = rx.recv() => match pkt {
                    Some(p) => p,
                    None    => break,
                },
            };
            batch.push(first);

            while batch.len() < Self::BATCH_SIZE {
                match rx.try_recv() {
                    Ok(p) => batch.push(p),
                    Err(_) => break,
                }
            }

            let parallel = self.pipeline_threads > 1;
            for pkt in batch.drain(..) {
                let InboundPacket {
                    raw,
                    face_id,
                    arrival,
                    meta,
                } = pkt;
                match self.decode.try_collect_fragment(face_id, raw) {
                    Ok(None) => {
                        trace!(face=%face_id, "fragment collected, awaiting reassembly");
                    }
                    Ok(Some(reassembled)) => {
                        let pkt = InboundPacket {
                            raw: reassembled,
                            face_id,
                            arrival,
                            meta,
                        };
                        if parallel {
                            let d = Arc::clone(self);
                            tokio::spawn(async move { d.process_packet(pkt).await });
                        } else {
                            self.process_packet(pkt).await;
                        }
                    }
                    Err(raw) => {
                        let pkt = InboundPacket {
                            raw,
                            face_id,
                            arrival,
                            meta,
                        };
                        if parallel {
                            let d = Arc::clone(self);
                            tokio::spawn(async move { d.process_packet(pkt).await });
                        } else {
                            self.process_packet(pkt).await;
                        }
                    }
                }
            }
        }
    }

    async fn process_packet(&self, pkt: InboundPacket) {
        trace!(face=%pkt.face_id, len=pkt.raw.len(), "pipeline: packet arrived");
        let meta = pkt.meta;
        let ctx = PacketContext::new(pkt.raw, pkt.face_id, pkt.arrival);

        let ctx = match self.decode.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(DropReason::FragmentCollect) => {
                trace!(face=%pkt.face_id, "fragment collected, awaiting reassembly");
                return;
            }
            Action::Drop(r) => {
                debug!(face=%pkt.face_id, reason=?r, "drop at decode");
                return;
            }
            other => {
                self.dispatch_action(other);
                return;
            }
        };

        // Discovery hook (single call site for on_inbound).
        if self
            .discovery
            .on_inbound(&ctx.raw_bytes, ctx.face_id, &meta, &*self.discovery_ctx)
        {
            return;
        }

        match &ctx.packet {
            DecodedPacket::Interest(_) => {
                if let Some(state) = self.face_states.get(&ctx.face_id) {
                    state.counters.in_interests.fetch_add(1, Ordering::Relaxed);
                    state
                        .counters
                        .in_bytes
                        .fetch_add(ctx.raw_bytes.len() as u64, Ordering::Relaxed);
                }
                trace!(face=%ctx.face_id, name=?ctx.name, "pipeline: Interest → interest_pipeline");
                self.interest_pipeline(ctx).await;
            }
            DecodedPacket::Data(_) => {
                if let Some(state) = self.face_states.get(&ctx.face_id) {
                    state.counters.in_data.fetch_add(1, Ordering::Relaxed);
                    state
                        .counters
                        .in_bytes
                        .fetch_add(ctx.raw_bytes.len() as u64, Ordering::Relaxed);
                }
                trace!(face=%ctx.face_id, name=?ctx.name, "pipeline: Data → data_pipeline");
                self.data_pipeline(ctx).await;
            }
            DecodedPacket::Nack(_) => {
                trace!(face=%ctx.face_id, name=?ctx.name, "pipeline: Nack → nack_pipeline");
                self.nack_pipeline(ctx).await;
            }
            DecodedPacket::Raw => {}
        }
    }

    async fn interest_pipeline(&self, ctx: PacketContext) {
        let ctx = match self.cs_lookup.process(ctx).await {
            Action::Continue(ctx) => ctx,
            Action::Satisfy(ctx) => {
                self.satisfy(ctx);
                return;
            }
            Action::Drop(r) => {
                debug!(reason=?r, "drop at cs lookup");
                return;
            }
            other => {
                self.dispatch_action(other);
                return;
            }
        };

        let ctx = match self.pit_check.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(r) => {
                debug!(reason=?r, "drop at pit check");
                return;
            }
            other => {
                self.dispatch_action(other);
                return;
            }
        };

        let action = self.strategy.process(ctx).await;
        self.dispatch_action(action);
    }

    async fn nack_pipeline(&self, ctx: PacketContext) {
        let nack = match &ctx.packet {
            DecodedPacket::Nack(n) => n,
            _ => return,
        };

        let name = match &ctx.name {
            Some(n) => n.clone(),
            None => return,
        };

        // Look up PIT entry by the nacked Interest's name.
        let token = PitToken::from_interest(&nack.interest.name, Some(nack.interest.selectors()));

        let has_pit_entry = self.strategy.pit.contains(&token);
        if !has_pit_entry {
            debug!(face=?ctx.face_id, "nack for unknown PIT entry, dropping");
            return;
        }

        let fib_entry_arc = self.strategy.fib.lpm(&name);
        let fib_entry_ref = fib_entry_arc.as_deref();
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

        let mut extensions = ndn_transport::AnyMap::new();
        for enricher in &self.strategy.enrichers {
            enricher.enrich(strategy_fib.as_ref(), &mut extensions);
        }

        let sctx = ndn_strategy::StrategyContext {
            name: &name,
            in_face: ctx.face_id,
            fib_entry: strategy_fib.as_ref(),
            pit_token: Some(token),
            measurements: &self.strategy.measurements,
            extensions: &extensions,
        };

        let nack_reason = match nack.reason {
            ndn_packet::NackReason::NoRoute => NackReason::NoRoute,
            ndn_packet::NackReason::Duplicate => NackReason::Duplicate,
            ndn_packet::NackReason::Congestion => NackReason::Congestion,
            ndn_packet::NackReason::NotYet => NackReason::NotYet,
            ndn_packet::NackReason::Other(_) => NackReason::NoRoute,
        };

        let strategy = self
            .strategy
            .strategy_table
            .lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.strategy.default_strategy));
        let action = strategy.on_nack_erased(&sctx, nack_reason).await;
        match action {
            ForwardingAction::Forward(faces) => {
                let interest_wire = nack.interest.raw().clone();
                let wire_len = interest_wire.len() as u64;
                for face_id in &faces {
                    if let Some(state) = self.face_states.get(face_id) {
                        state.counters.out_interests.fetch_add(1, Ordering::Relaxed);
                        state
                            .counters
                            .out_bytes
                            .fetch_add(wire_len, Ordering::Relaxed);
                    }
                    self.enqueue_send(*face_id, interest_wire.clone());
                }
            }
            ForwardingAction::Nack(_reason) => {
                if let Some((_, entry)) = self.strategy.pit.remove(&token) {
                    let interest_wire = nack.interest.raw().clone();
                    let packet_reason = nack.reason;
                    for face_id_raw in entry.in_record_faces() {
                        let face_id = FaceId(face_id_raw);
                        let nack_bytes = encode_nack(packet_reason, &interest_wire);
                        self.enqueue_send(face_id, nack_bytes);
                    }
                }
            }
            ForwardingAction::Suppress | ForwardingAction::ForwardAfter { .. } => {
                debug!("nack suppressed by strategy");
            }
        }
    }

    async fn data_pipeline(&self, ctx: PacketContext) {
        let ctx = match self.pit_match.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(r) => {
                debug!(reason=?r, "unsolicited data");
                return;
            }
            other => {
                self.dispatch_action(other);
                return;
            }
        };

        // Local faces are trusted by OS-level IPC; only network data needs
        // cryptographic validation.
        let is_local = self
            .face_table
            .get(ctx.face_id)
            .map(|f| f.kind().scope() == FaceScope::Local)
            .unwrap_or(false);

        let ctx = if is_local {
            ctx
        } else {
            match self.validation.process(ctx).await {
                Action::Satisfy(ctx) => ctx,
                Action::Drop(r) => {
                    debug!(reason=?r, "data validation failed");
                    return;
                }
                other => {
                    self.dispatch_action(other);
                    return;
                }
            }
        };

        let action = self.cs_insert.process(ctx).await;
        self.dispatch_action(action);
    }

    pub(super) async fn run_validation_drain(&self, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    let actions = self.validation.drain_pending().await;
                    for action in actions {
                        match action {
                            Action::Satisfy(ctx) => {
                                let action = self.cs_insert.process(ctx).await;
                                self.dispatch_action(action);
                            }
                            other => self.dispatch_action(other),
                        }
                    }
                }
            }
        }
    }
}
