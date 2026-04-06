use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use ndn_packet::Name;
use ndn_packet::encode::encode_nack;
use ndn_pipeline::{
    Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_store::{CsEntry, PitToken};
use ndn_transport::{FaceError, FaceId, FaceKind, FacePersistency, FaceScope, FaceTable};

use ndn_discovery::{DiscoveryProtocol, InboundMeta};

use crate::discovery_context::EngineDiscoveryContext;
use crate::engine::{self, DEFAULT_SEND_QUEUE_CAP, FaceState};

use crate::stages::{
    CsInsertStage, CsLookupStage, PitCheckStage, PitMatchStage, StrategyStage, TlvDecodeStage,
    ValidationStage,
};

/// A raw packet arriving from a face, bundled with the face it came from.
pub(crate) struct InboundPacket {
    pub(crate) raw: Bytes,
    pub(crate) face_id: FaceId,
    pub(crate) arrival: u64,
    /// Link-layer source metadata (source IP:port for UDP, source MAC for Ethernet).
    /// Used by discovery protocols to create unicast reply faces.
    /// `None` when the injection path does not have source information.
    pub(crate) meta: InboundMeta,
}

/// The packet dispatcher.
///
/// Spawns one Tokio task per face that reads packets from that face and sends
/// them to a shared `mpsc` channel.  A single pipeline runner drains the
/// channel, performs the fast-path fragment sieve, and spawns per-packet tasks
/// for full pipeline processing across multiple cores.
///
/// The fragment sieve stays single-threaded (cheap DashMap entry, ~2 µs) while
/// the expensive pipeline stages (decode, CS, PIT, strategy) run in parallel.
/// All shared tables (PIT, FIB, CS, face table) are concurrent-safe, so
/// parallel pipeline tasks are correct without additional synchronisation.
pub struct PacketDispatcher {
    pub face_table: Arc<FaceTable>,
    pub face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
    pub decode: TlvDecodeStage,
    pub cs_lookup: CsLookupStage,
    pub pit_check: PitCheckStage,
    pub strategy: StrategyStage,
    pub pit_match: PitMatchStage,
    pub validation: ValidationStage,
    pub cs_insert: CsInsertStage,
    pub channel_cap: usize,
    /// Resolved pipeline thread count (always ≥ 1).
    pub pipeline_threads: usize,
    /// Active discovery protocol — receives `on_inbound` calls before packets
    /// enter the NDN forwarding pipeline.
    pub discovery: Arc<dyn DiscoveryProtocol>,
    /// Engine discovery context — passed to protocol hooks.
    pub discovery_ctx: Arc<EngineDiscoveryContext>,
}

impl PacketDispatcher {
    /// Spawn face-reader tasks for all currently registered faces, plus the
    /// pipeline runner.
    ///
    /// Returns the pipeline channel sender so the engine can spawn reader tasks
    /// for faces added dynamically after `build()`.
    pub fn spawn(
        self,
        cancel: CancellationToken,
        tasks: &mut JoinSet<()>,
    ) -> mpsc::Sender<InboundPacket> {
        let (tx, rx) = mpsc::channel::<InboundPacket>(self.channel_cap);
        let dispatcher = Arc::new(self);

        // Spawn reader + sender tasks for each pre-registered face.
        for face_id in dispatcher.face_table.face_ids() {
            if let Some(face) = dispatcher.face_table.get(face_id) {
                // Create FaceState with a send queue if not already present.
                if !dispatcher.face_states.contains_key(&face_id) {
                    let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
                    let persistency = FacePersistency::Permanent;
                    let state = if face.kind() == FaceKind::Udp {
                        FaceState::new_reliable(
                            cancel.child_token(),
                            persistency,
                            send_tx,
                            ndn_face_net::DEFAULT_UDP_MTU,
                        )
                    } else {
                        FaceState::new(cancel.child_token(), persistency, send_tx)
                    };
                    dispatcher.face_states.insert(face_id, state);
                    // Spawn per-face send task.
                    let send_face = Arc::clone(&face);
                    let send_cancel = cancel.clone();
                    let fs = Arc::clone(&dispatcher.face_states);
                    let ft = Arc::clone(&dispatcher.face_table);
                    let fib = Arc::clone(&dispatcher.strategy.fib);
                    tasks.spawn(engine::run_face_sender(
                        face_id,
                        send_face,
                        send_rx,
                        send_cancel,
                        persistency,
                        fs,
                        ft,
                        fib,
                        Arc::clone(&dispatcher.discovery),
                        Arc::clone(&dispatcher.discovery_ctx),
                    ));
                }

                let tx2 = tx.clone();
                let cancel = cancel.clone();
                let face_table = Arc::clone(&dispatcher.face_table);
                let fib = Arc::clone(&dispatcher.strategy.fib);
                let pit = Arc::clone(&dispatcher.pit_check.pit);
                let face_states = Arc::clone(&dispatcher.face_states);
                let d = Arc::clone(&dispatcher.discovery);
                let ctx = Arc::clone(&dispatcher.discovery_ctx);
                tasks.spawn(async move {
                    run_face_reader(
                        face_id,
                        face,
                        tx2,
                        cancel,
                        face_table,
                        fib,
                        pit,
                        face_states,
                        d,
                        ctx,
                    )
                    .await;
                });
            }
        }

        // Pipeline runner.
        let d = Arc::clone(&dispatcher);
        let cancel2 = cancel.clone();
        tasks.spawn(async move {
            d.run_pipeline(rx, cancel2).await;
        });

        // Validation pending queue drain task.
        if dispatcher.validation.validator.is_some() {
            let d = Arc::clone(&dispatcher);
            let cancel3 = cancel.clone();
            tasks.spawn(async move {
                d.run_validation_drain(cancel3).await;
            });
        }

        tx
    }

    /// Maximum packets to drain from the channel per batch.
    ///
    /// After the first blocking `recv()`, we drain up to this many more with
    /// non-blocking `try_recv()`.  This amortises the `tokio::select!`
    /// overhead across a burst of packets (especially fragments).
    const BATCH_SIZE: usize = 64;

    async fn run_pipeline(
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
        if self.discovery.on_inbound(&ctx.raw_bytes, ctx.face_id, &meta, &*self.discovery_ctx) {
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

        let has_pit_entry = self.strategy.pit.get(&token).is_some();
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

    /// Push a packet to a face's outbound send queue.
    ///
    /// Uses `try_send` so the pipeline is never blocked by a slow face.
    /// If the queue is full, the packet is dropped — this is equivalent to an
    /// output-queue congestion drop and is the correct NDN behaviour (the
    /// consumer will re-express the Interest).
    fn enqueue_send(&self, face_id: FaceId, data: Bytes) {
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

    fn dispatch_action(&self, action: Action) {
        match action {
            Action::Send(ctx, faces) => {
                trace!(face=%ctx.face_id, name=?ctx.name, out_faces=?faces, raw_len=ctx.raw_bytes.len(), "dispatch: Send");
                let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
                for face_id in &faces {
                    if is_localhost {
                        if let Some(face) = self.face_table.get(*face_id) {
                            if face.kind().scope() == FaceScope::NonLocal {
                                trace!(face=%face_id, "dispatch: /localhost blocked on non-local face");
                                continue;
                            }
                        }
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

    /// Periodically drain the validation pending queue and dispatch
    /// re-validated packets through the remainder of the data pipeline.
    async fn run_validation_drain(&self, cancel: CancellationToken) {
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

    /// Fan Data (or a cached CS entry) back to all in-record faces.
    fn satisfy(&self, ctx: PacketContext) {
        let data_bytes = if ctx.cs_hit {
            ctx.tags
                .get::<CsEntry>()
                .map(|e| e.data.clone())
                .unwrap_or_else(|| ctx.raw_bytes.clone())
        } else {
            ctx.raw_bytes.clone()
        };

        let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
        for face_id in &ctx.out_faces {
            if is_localhost {
                if let Some(face) = self.face_table.get(*face_id) {
                    if face.kind().scope() == FaceScope::NonLocal {
                        trace!(face=%face_id, "satisfy: /localhost blocked on non-local face");
                        continue;
                    }
                }
            }
            self.enqueue_send(*face_id, data_bytes.clone());
        }
    }
}

/// Reader loop for a single face.
///
/// Exposed as `pub(crate)` so `ForwarderEngine::add_face` can spawn readers for
/// faces registered after the initial `build()`.
///
/// Cleanup behaviour depends on the face's persistence level:
///
/// - **Permanent**: recv errors are logged but the loop retries indefinitely
///   (only cancellation or pipeline closure breaks the loop).
/// - **Persistent**: the recv loop exits on error/close, but the face is NOT
///   removed from the table or FIB — it can be re-used later.
/// - **OnDemand** (and any face without a FaceState): the face is fully removed
///   from the table and all FIB routes are cleaned up.
///
/// Internal faces (`FaceKind::App` / `FaceKind::Internal`) are long-lived
/// engine objects and are never removed on reader exit regardless of
/// persistency.
pub(crate) async fn run_face_reader(
    face_id: FaceId,
    face: Arc<dyn ndn_transport::ErasedFace>,
    tx: mpsc::Sender<InboundPacket>,
    cancel: CancellationToken,
    face_table: Arc<FaceTable>,
    fib: Arc<crate::Fib>,
    pit: Arc<ndn_store::Pit>,
    face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
    discovery: Arc<dyn DiscoveryProtocol>,
    discovery_ctx: Arc<EngineDiscoveryContext>,
) {
    let kind = face.kind();
    let persistency = face_states
        .get(&face_id)
        .map(|s| s.persistency)
        .unwrap_or(FacePersistency::OnDemand);

    // Cache whether this face needs idle-timeout tracking.  Local faces
    // (App, Shm, Internal) don't idle-timeout, so skip the per-packet
    // DashMap lookup + clock read for them.
    let track_activity = matches!(persistency, FacePersistency::OnDemand)
        && !matches!(kind, FaceKind::App | FaceKind::Shm | FaceKind::Internal);

    // Cache whether this face has reliability enabled.
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);

    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            r = face.recv_bytes_with_addr()  => r,
        };
        match result {
            Ok((raw, src_addr)) => {
                trace!(face=%face_id, len=raw.len(), "face-reader: recv");

                // Feed inbound packet to reliability layer (extracts TxSeq for
                // Ack, processes piggybacked Acks from remote).
                if has_reliability {
                    if let Some(state) = face_states.get(&face_id) {
                        if let Some(ref rel) = state.reliability {
                            rel.lock().unwrap().on_receive(&raw);
                        }
                    }
                }

                let arrival = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                // Reuse the arrival timestamp for idle tracking (avoids
                // a second clock read and DashMap lookup per packet).
                if track_activity {
                    if let Some(state) = face_states.get(&face_id) {
                        state.last_activity.store(arrival, Ordering::Relaxed);
                    }
                }
                // Build InboundMeta from the link-layer source address when
                // the face exposed it (e.g. MulticastUdpFace).  Flows through
                // InboundPacket into process_packet where discovery.on_inbound
                // is called after LP-unwrap and decode.
                let meta = match src_addr {
                    Some(addr) => ndn_discovery::InboundMeta::udp(addr),
                    None => ndn_discovery::InboundMeta::none(),
                };

                // Use try_send to avoid blocking the face reader when the
                // pipeline channel is full.  Blocking here cascades back
                // through the SHM ring — the face can't recv, its peer's
                // send() spins and eventually times out, killing the peer
                // application.  Dropping the packet is the correct NDN
                // behaviour: consumers re-express, and the pipeline is
                // protected from overload.
                match tx.try_send(InboundPacket {
                    raw,
                    face_id,
                    arrival,
                    meta,
                }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        debug!(face=%face_id, "pipeline full, dropping inbound packet");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        break; // Runner dropped.
                    }
                }
            }
            Err(FaceError::Closed) => {
                debug!(face=%face_id, "face closed");
                break;
            }
            Err(e) => {
                match persistency {
                    FacePersistency::Permanent => {
                        // Permanent faces retry on transient errors.
                        warn!(face=%face_id, error=%e, "recv error on permanent face, retrying");
                        continue;
                    }
                    _ => {
                        warn!(face=%face_id, error=%e, "recv error, stopping");
                        break;
                    }
                }
            }
        }
    }

    // Drain PIT entries whose sole consumer was this face.
    let pit_removed = pit.remove_face(face_id.0);
    if pit_removed > 0 {
        debug!(face=%face_id, count=pit_removed, "PIT entries drained for closed face");
    }

    // Cleanup depends on face kind and persistency.
    match kind {
        FaceKind::App | FaceKind::Internal => {}
        _ => match persistency {
            FacePersistency::Persistent | FacePersistency::Permanent => {
                // Keep the face in the table and FIB — it may reconnect or be
                // re-used.  Only cancel child tokens.
                debug!(face=%face_id, ?persistency, "face reader stopped (face retained)");
            }
            FacePersistency::OnDemand => {
                // Notify discovery before removing from tables.
                discovery.on_face_down(face_id, &*discovery_ctx);
                // Fully remove the face.
                if let Some((_, state)) = face_states.remove(&face_id) {
                    state.cancel.cancel();
                }
                fib.remove_face(face_id);
                face_table.remove(face_id);
                debug!(face=%face_id, "on-demand face removed from table (FIB routes cleaned)");
            }
        },
    }
}

/// Check if a name starts with `/localhost`.
fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}
