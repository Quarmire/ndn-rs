use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use ndn_packet::encode::encode_nack;
use ndn_pipeline::{
    Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_store::PitToken;
use ndn_transport::FaceId;

use super::{InboundPacket, PacketDispatcher};

impl PacketDispatcher {
    /// Maximum packets to drain from the channel per batch.
    ///
    /// After the first blocking `recv()`, we drain up to this many more with
    /// non-blocking `try_recv()`.  This amortises the `tokio::select!`
    /// overhead across a burst of packets (especially fragments).
    pub(super) const BATCH_SIZE: usize = 64;

    pub(super) async fn run_pipeline(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
    ) {
        let mut batch = Vec::with_capacity(Self::BATCH_SIZE);
        loop {
            // Block for the first packet.
            let first = tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = rx.recv() => match pkt {
                    Some(p) => p,
                    None    => break,
                },
            };
            batch.push(first);

            // Drain more without blocking.
            while batch.len() < Self::BATCH_SIZE {
                match rx.try_recv() {
                    Ok(p) => batch.push(p),
                    Err(_) => break,
                }
            }

            // Fast-path fragment sieve: collect fragments without creating
            // a full PacketContext.  Only reassembled packets and non-fragment
            // packets proceed to the full pipeline.
            //
            // The sieve always runs inline (cheap, ~2 µs per fragment).
            // Complete packets are either processed inline (single-threaded
            // mode) or spawned as tokio tasks (parallel mode).
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
                        // Fragment buffered, waiting for more.
                        trace!(face=%face_id, "fragment collected, awaiting reassembly");
                    }
                    Ok(Some(reassembled)) => {
                        // Reassembled bytes are LP-unwrapped; meta is from the
                        // first fragment (good enough for discovery — hellos are
                        // never fragmented in practice).
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

        // 1. Decode (LP-unwrap + TLV parse).
        //    After this, `ctx.raw_bytes` holds the bare NDN Interest/Data bytes
        //    (LP header stripped, fragment reassembly already done).
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

        // 2. Discovery hook — called after decode so protocols receive
        //    LP-unwrapped, reassembled bytes.  This is the single call site
        //    for on_inbound; neither run_face_reader nor inject_packet call it.
        //    Returns true if the packet was consumed (e.g. hello Interest/Data
        //    or service-record browse).
        if self
            .discovery
            .on_inbound(&ctx.raw_bytes, ctx.face_id, &meta, &*self.discovery_ctx)
        {
            return;
        }

        match &ctx.packet {
            DecodedPacket::Interest(_) => {
                trace!(face=%ctx.face_id, name=?ctx.name, "pipeline: Interest → interest_pipeline");
                self.interest_pipeline(ctx).await;
            }
            DecodedPacket::Data(_) => {
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
        // 2. CS lookup.
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

        // 3. PIT check.
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

        // 4. Strategy.
        let action = self.strategy.process(ctx).await;
        self.dispatch_action(action);
    }

    /// Nack pipeline: look up PIT out-record, consult strategy, act on result.
    ///
    /// When a Nack arrives for an Interest we forwarded, the strategy gets to
    /// decide: try an alternate nexthop (`Forward`), give up (`Nack` back to
    /// all in-record consumers), or suppress.
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

        // Build strategy context and ask the strategy what to do.
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
                // Strategy chose alternate nexthops — forward the original Interest.
                let interest_wire = nack.interest.raw().clone();
                for face_id in &faces {
                    self.enqueue_send(*face_id, interest_wire.clone());
                }
            }
            ForwardingAction::Nack(_reason) => {
                // Strategy gave up — propagate Nack back to all in-record consumers.
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
        // 2. PIT match.
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

        // 3. Signature / chain validation (optional).
        let ctx = match self.validation.process(ctx).await {
            Action::Satisfy(ctx) => ctx,
            Action::Drop(r) => {
                debug!(reason=?r, "data validation failed");
                return;
            }
            other => {
                self.dispatch_action(other);
                return;
            }
        };

        // 4. CS insert.
        let action = self.cs_insert.process(ctx).await;
        self.dispatch_action(action);
    }

    /// Periodically drain the validation pending queue and dispatch
    /// re-validated packets through the remainder of the data pipeline.
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
                                // Resume from CsInsert stage.
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
