use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use ndn_packet::encode::encode_nack;
use ndn_pipeline::{Action, DecodedPacket, ForwardingAction, NackReason, PacketContext};
use ndn_store::{CsEntry, PitToken};
use ndn_transport::{FaceError, FaceId, FaceTable, FaceKind};

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
    pub face_tokens:  Arc<dashmap::DashMap<FaceId, CancellationToken>>,
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
                let face_tokens  = Arc::clone(&self.face_tokens);
                tasks.spawn(async move {
                    run_face_reader(face_id, face, tx2, cancel, face_table, fib, face_tokens).await;
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

    async fn run_pipeline(
        &self,
        mut rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
    ) {
        loop {
            let pkt = tokio::select! {
                _ = cancel.cancelled() => break,
                pkt = rx.recv() => match pkt {
                    Some(p) => p,
                    None    => break,
                },
            };

            self.process_packet(pkt).await;
        }
    }

    async fn process_packet(&self, pkt: InboundPacket) {
        let ctx = PacketContext::new(pkt.raw, pkt.face_id, pkt.arrival);

        // 1. Decode.
        let ctx = match self.decode.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(r)       => { debug!(reason=?r, "drop at decode"); return; }
            other                 => { self.dispatch_action(other).await; return; }
        };

        match &ctx.packet {
            DecodedPacket::Interest(_) => self.interest_pipeline(ctx).await,
            DecodedPacket::Data(_)     => self.data_pipeline(ctx).await,
            DecodedPacket::Nack(_)     => self.nack_pipeline(ctx).await,
            DecodedPacket::Raw         => {}
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
                for face_id in &faces {
                    if let Some(face) = self.face_table.get(*face_id) {
                        if let Err(e) = face.send_bytes(ctx.raw_bytes.clone()).await {
                            warn!(face=%face_id, error=%e, "forward send failed");
                        }
                    }
                }
            }
            Action::Satisfy(ctx) => self.satisfy(ctx).await,
            Action::Drop(r)      => debug!(reason=?r, "packet dropped"),
            Action::Nack(ctx, reason) => {
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
                    }
                }
            }
            Action::Continue(_)  => {} // fell off end of pipeline
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

        for face_id in &ctx.out_faces {
            if let Some(face) = self.face_table.get(*face_id) {
                if let Err(e) = face.send_bytes(data_bytes.clone()).await {
                    warn!(face=%face_id, error=%e, "satisfy send failed");
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
/// When the loop exits (face closed or cancelled) the face is removed from
/// `face_table` so it no longer appears in management listings and its ID is
/// recycled.  Internal faces (`FaceKind::App` / `FaceKind::Internal`) are
/// long-lived engine objects and are not removed on reader exit.
pub(crate) async fn run_face_reader(
    face_id:    FaceId,
    face:       Arc<dyn ndn_transport::ErasedFace>,
    tx:         mpsc::Sender<InboundPacket>,
    cancel:     CancellationToken,
    face_table: Arc<FaceTable>,
    fib:        Arc<crate::Fib>,
    face_tokens: Arc<dashmap::DashMap<FaceId, CancellationToken>>,
) {
    let kind = face.kind();
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            r = face.recv_bytes()  => r,
        };
        match result {
            Ok(raw) => {
                let arrival = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                if tx.send(InboundPacket { raw, face_id, arrival }).await.is_err() {
                    break; // Runner dropped.
                }
            }
            Err(FaceError::Closed) => {
                debug!(face=%face_id, "face closed");
                break;
            }
            Err(e) => {
                warn!(face=%face_id, error=%e, "recv error, continuing");
            }
        }
    }

    // Remove transient faces (those accepted dynamically from a listener) so
    // they don't linger in the table after disconnection.
    match kind {
        FaceKind::App | FaceKind::Internal => {}
        _ => {
            // Cancel the face's token — this propagates to any child faces
            // (e.g. SHM faces created via this control face's `faces/create`).
            if let Some((_, token)) = face_tokens.remove(&face_id) {
                token.cancel();
            }
            fib.remove_face(face_id);
            face_table.remove(face_id);
            debug!(face=%face_id, "face removed from table (FIB routes cleaned)");
        }
    }
}
