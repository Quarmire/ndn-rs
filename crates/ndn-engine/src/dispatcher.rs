use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use ndn_packet::encode::encode_nack;
use ndn_pipeline::{Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext};
use ndn_store::{CsEntry, PitToken};
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId, FacePersistency, FaceScope, FaceTable, FaceKind};

use crate::engine::FaceState;

use crate::stages::{
    CsInsertStage, CsLookupStage, PitCheckStage, PitMatchStage, StrategyStage, TlvDecodeStage,
};

/// A raw packet arriving from a face, bundled with the face it came from.
pub(crate) struct InboundPacket {
    pub(crate) raw:     Bytes,
    pub(crate) face_id: FaceId,
    pub(crate) arrival: u64,
}

/// The packet dispatcher.
///
/// Spawns one Tokio task per face that reads packets from that face and sends
/// them to a shared `mpsc` channel. A single pipeline runner drains the channel
/// and processes each packet through the stage sequence.
pub struct PacketDispatcher {
    pub face_table:   Arc<FaceTable>,
    pub face_states:  Arc<dashmap::DashMap<FaceId, FaceState>>,
    pub decode:       TlvDecodeStage,
    pub cs_lookup:    CsLookupStage,
    pub pit_check:    PitCheckStage,
    pub strategy:     StrategyStage,
    pub pit_match:    PitMatchStage,
    pub cs_insert:    CsInsertStage,
    pub channel_cap:  usize,
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
        tasks:  &mut JoinSet<()>,
    ) -> mpsc::Sender<InboundPacket> {
        let (tx, rx) = mpsc::channel::<InboundPacket>(self.channel_cap);

        // Spawn a reader task for each registered face.
        for face_id in self.face_table.face_ids() {
            if let Some(face) = self.face_table.get(face_id) {
                let tx2          = tx.clone();
                let cancel       = cancel.clone();
                let face_table   = Arc::clone(&self.face_table);
                let fib          = Arc::clone(&self.strategy.fib);
                let face_states  = Arc::clone(&self.face_states);
                tasks.spawn(async move {
                    run_face_reader(face_id, face, tx2, cancel, face_table, fib, face_states).await;
                });
            }
        }

        // Pipeline runner.
        let cancel2 = cancel.clone();
        tasks.spawn(async move {
            self.run_pipeline(rx, cancel2).await;
        });

        tx
    }

    /// Maximum packets to drain from the channel per batch.
    ///
    /// After the first blocking `recv()`, we drain up to this many more with
    /// non-blocking `try_recv()`.  This amortises the `tokio::select!`
    /// overhead across a burst of packets (especially fragments).
    const BATCH_SIZE: usize = 64;

    async fn run_pipeline(
        &self,
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
                    Ok(p)  => batch.push(p),
                    Err(_) => break,
                }
            }

            // Fast-path fragment sieve: collect fragments without creating
            // a full PacketContext.  Only reassembled packets and non-fragment
            // packets proceed to the full pipeline.
            for pkt in batch.drain(..) {
                let InboundPacket { raw, face_id, arrival } = pkt;
                match self.decode.try_collect_fragment(face_id, raw) {
                    Ok(None) => {
                        // Fragment buffered, waiting for more.
                        trace!(face=%face_id, "fragment collected, awaiting reassembly");
                    }
                    Ok(Some(reassembled)) => {
                        // Reassembly complete — process the full packet.
                        self.process_packet(InboundPacket { raw: reassembled, face_id, arrival }).await;
                    }
                    Err(raw) => {
                        // Not a fragment — run through the full pipeline.
                        self.process_packet(InboundPacket { raw, face_id, arrival }).await;
                    }
                }
            }
        }
    }

    async fn process_packet(&self, pkt: InboundPacket) {
        trace!(face=%pkt.face_id, len=pkt.raw.len(), "pipeline: packet arrived");
        let ctx = PacketContext::new(pkt.raw, pkt.face_id, pkt.arrival);

        // 1. Decode.
        let ctx = match self.decode.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(DropReason::FragmentCollect) => { trace!(face=%pkt.face_id, "fragment collected, awaiting reassembly"); return; }
            Action::Drop(r)       => { debug!(face=%pkt.face_id, reason=?r, "drop at decode"); return; }
            other                 => { self.dispatch_action(other).await; return; }
        };

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
            Action::Satisfy(ctx)  => { self.satisfy(ctx).await; return; }
            Action::Drop(r)       => { debug!(reason=?r, "drop at cs lookup"); return; }
            other                 => { self.dispatch_action(other).await; return; }
        };

        // 3. PIT check.
        let ctx = match self.pit_check.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(r)       => { debug!(reason=?r, "drop at pit check"); return; }
            other                 => { self.dispatch_action(other).await; return; }
        };

        // 4. Strategy.
        let action = self.strategy.process(ctx).await;
        self.dispatch_action(action).await;
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
        let strategy_fib: Option<ndn_strategy::FibEntry> = fib_entry_ref.map(|e| {
            ndn_strategy::FibEntry {
                nexthops: e.nexthops.iter().map(|nh| ndn_strategy::FibNexthop {
                    face_id: nh.face_id,
                    cost:    nh.cost,
                }).collect(),
            }
        });

        let sctx = ndn_strategy::StrategyContext {
            name:         &name,
            in_face:      ctx.face_id,
            fib_entry:    strategy_fib.as_ref(),
            pit_token:    Some(token),
            measurements: &self.strategy.measurements,
        };

        let nack_reason = match nack.reason {
            ndn_packet::NackReason::NoRoute    => NackReason::NoRoute,
            ndn_packet::NackReason::Duplicate  => NackReason::Duplicate,
            ndn_packet::NackReason::Congestion => NackReason::Congestion,
            ndn_packet::NackReason::NotYet     => NackReason::NotYet,
            ndn_packet::NackReason::Other(_)   => NackReason::NoRoute,
        };

        let strategy = self.strategy.strategy_table.lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.strategy.default_strategy));
        let action = strategy.on_nack_erased(&sctx, nack_reason).await;
        match action {
            ForwardingAction::Forward(faces) => {
                // Strategy chose alternate nexthops — forward the original Interest.
                for face_id in &faces {
                    if let Some(face) = self.face_table.get(*face_id) {
                        // Re-send the original Interest (the one inside the Nack).
                        if let Err(e) = face.send_bytes(nack.interest.raw().clone()).await {
                            warn!(face=%face_id, error=%e, "nack retry forward failed");
                            self.close_on_demand_face(*face_id);
                        }
                    }
                }
            }
            ForwardingAction::Nack(_reason) => {
                // Strategy gave up — propagate Nack back to all in-record consumers.
                if let Some((_, entry)) = self.strategy.pit.remove(&token) {
                    let interest_wire = nack.interest.raw().clone();
                    let packet_reason = nack.reason;
                    for face_id_raw in entry.in_record_faces() {
                        let face_id = FaceId(face_id_raw);
                        if let Some(face) = self.face_table.get(face_id) {
                            let nack_bytes = encode_nack(packet_reason, &interest_wire);
                            if let Err(e) = face.send_bytes(nack_bytes).await {
                                warn!(face=%face_id, error=%e, "nack propagation failed");
                                self.close_on_demand_face(face_id);
                            }
                        }
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
            Action::Drop(r)       => { debug!(reason=?r, "unsolicited data"); return; }
            other                 => { self.dispatch_action(other).await; return; }
        };

        // 3. CS insert.
        let action = self.cs_insert.process(ctx).await;
        self.dispatch_action(action).await;
    }

    async fn dispatch_action(&self, action: Action) {
        match action {
            Action::Send(ctx, faces) => {
                trace!(face=%ctx.face_id, name=?ctx.name, out_faces=?faces, raw_len=ctx.raw_bytes.len(), "dispatch: Send");
                let is_localhost = ctx.name.as_ref().is_some_and(|n| is_localhost_name(n));
                for face_id in &faces {
                    if let Some(face) = self.face_table.get(*face_id) {
                        if is_localhost && face.kind().scope() == FaceScope::NonLocal {
                            trace!(face=%face_id, "dispatch: /localhost blocked on non-local face");
                            continue;
                        }
                        if let Err(e) = face.send_bytes(ctx.raw_bytes.clone()).await {
                            warn!(face=%face_id, error=%e, "forward send failed");
                            self.close_on_demand_face(*face_id);
                        } else {
                            trace!(face=%face_id, len=ctx.raw_bytes.len(), "dispatch: sent ok");
                        }
                    } else {
                        warn!(face=%face_id, "dispatch: face not found in table");
                    }
                }
            }
            Action::Satisfy(ctx) => {
                trace!(face=%ctx.face_id, name=?ctx.name, out_faces=?ctx.out_faces, cs_hit=ctx.cs_hit, "dispatch: Satisfy");
                self.satisfy(ctx).await;
            }
            Action::Drop(r)      => debug!(reason=?r, "packet dropped"),
            Action::Nack(ctx, reason) => {
                trace!(face=%ctx.face_id, name=?ctx.name, reason=?reason, "dispatch: Nack");
                // Encode a Nack wrapping the original Interest and send it
                // back to the face that originated the Interest.
                let packet_reason = match reason {
                    NackReason::NoRoute    => ndn_packet::NackReason::NoRoute,
                    NackReason::Duplicate  => ndn_packet::NackReason::Duplicate,
                    NackReason::Congestion => ndn_packet::NackReason::Congestion,
                    NackReason::NotYet     => ndn_packet::NackReason::NotYet,
                };
                let nack_bytes = encode_nack(packet_reason, &ctx.raw_bytes);
                if let Some(face) = self.face_table.get(ctx.face_id) {
                    if let Err(e) = face.send_bytes(nack_bytes).await {
                        warn!(face=%ctx.face_id, error=%e, "nack send failed");
                        self.close_on_demand_face(ctx.face_id);
                    }
                }
            }
            Action::Continue(_)  => {} // fell off end of pipeline
        }
    }

    /// Cancel an on-demand face after a send error.
    ///
    /// Persistent and permanent faces are kept alive (NFD semantics).
    /// Cancelling the face's token triggers `run_face_reader` cleanup which
    /// removes FIB routes and the face table entry.
    fn close_on_demand_face(&self, face_id: FaceId) {
        if let Some(state) = self.face_states.get(&face_id) {
            if state.persistency == FacePersistency::OnDemand {
                debug!(face=%face_id, "closing on-demand face after send error");
                state.cancel.cancel();
            }
        }
    }

    /// Fan Data (or a cached CS entry) back to all in-record faces.
    async fn satisfy(&self, ctx: PacketContext) {
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
            if let Some(face) = self.face_table.get(*face_id) {
                if is_localhost && face.kind().scope() == FaceScope::NonLocal {
                    trace!(face=%face_id, "satisfy: /localhost blocked on non-local face");
                    continue;
                }
                if let Err(e) = face.send_bytes(data_bytes.clone()).await {
                    warn!(face=%face_id, error=%e, "satisfy send failed");
                    self.close_on_demand_face(*face_id);
                }
            }
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
    face_id:     FaceId,
    face:        Arc<dyn ndn_transport::ErasedFace>,
    tx:          mpsc::Sender<InboundPacket>,
    cancel:      CancellationToken,
    face_table:  Arc<FaceTable>,
    fib:         Arc<crate::Fib>,
    face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
) {
    let kind = face.kind();
    let persistency = face_states.get(&face_id)
        .map(|s| s.persistency)
        .unwrap_or(FacePersistency::OnDemand);

    // Cache whether this face needs idle-timeout tracking.  Local faces
    // (App, Shm, Internal) don't idle-timeout, so skip the per-packet
    // DashMap lookup + clock read for them.
    let track_activity = matches!(persistency, FacePersistency::OnDemand)
        && !matches!(kind, FaceKind::App | FaceKind::Shm | FaceKind::Internal);

    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            r = face.recv_bytes()  => r,
        };
        match result {
            Ok(raw) => {
                trace!(face=%face_id, len=raw.len(), "face-reader: recv");
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
                if tx.send(InboundPacket { raw, face_id, arrival }).await.is_err() {
                    break; // Runner dropped.
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
