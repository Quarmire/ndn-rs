use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use ndn_pipeline::{Action, DecodedPacket, PacketContext};
use ndn_store::CsEntry;
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
    pub face_table:  Arc<FaceTable>,
    pub decode:      TlvDecodeStage,
    pub cs_lookup:   CsLookupStage,
    pub pit_check:   PitCheckStage,
    pub strategy:    StrategyStage,
    pub pit_match:   PitMatchStage,
    pub cs_insert:   CsInsertStage,
    pub channel_cap: usize,
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
                let tx2         = tx.clone();
                let cancel      = cancel.clone();
                let face_table  = Arc::clone(&self.face_table);
                tasks.spawn(async move {
                    run_face_reader(face_id, face, tx2, cancel, face_table).await;
                });
            }
        }

        // Pipeline runner.
        let dispatcher = Arc::new(self);
        let cancel2    = cancel.clone();
        tasks.spawn(async move {
            dispatcher.run_pipeline(rx, cancel2).await;
        });

        tx
    }

    async fn run_pipeline(
        self: Arc<Self>,
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

            let d = Arc::clone(&self);
            tokio::spawn(async move { d.process_packet(pkt).await });
        }
    }

    async fn process_packet(self: Arc<Self>, pkt: InboundPacket) {
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
            DecodedPacket::Nack(_)     => {
                debug!(face=?ctx.face_id, "nack handling not yet implemented");
            }
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
            Action::Nack(_)      => debug!("nack response not yet implemented"),
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
            face_table.remove(face_id);
            debug!(face=%face_id, "face removed from table");
        }
    }
}
