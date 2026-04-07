mod inbound;
mod outbound;
mod pipeline;

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_discovery::{DiscoveryProtocol, InboundMeta};
use ndn_transport::{FaceId, FaceKind, FacePersistency, FaceTable};

use crate::discovery_context::EngineDiscoveryContext;
use crate::engine::{self, DEFAULT_SEND_QUEUE_CAP, FaceState};

use crate::stages::{
    CsInsertStage, CsLookupStage, PitCheckStage, PitMatchStage, StrategyStage, TlvDecodeStage,
    ValidationStage,
};

pub(crate) use inbound::run_face_reader;

/// Shared context passed to face reader/sender tasks to avoid exceeding the
/// function argument limit while keeping all fields explicit.
pub(crate) struct FaceRunnerCtx {
    pub(crate) face_id: FaceId,
    pub(crate) cancel: CancellationToken,
    pub(crate) face_table: Arc<FaceTable>,
    pub(crate) fib: Arc<crate::Fib>,
    pub(crate) face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
    pub(crate) discovery: Arc<dyn DiscoveryProtocol>,
    pub(crate) discovery_ctx: Arc<EngineDiscoveryContext>,
}

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
    pub(crate) fn spawn(
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
                    #[cfg(feature = "face-net")]
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
                    #[cfg(not(feature = "face-net"))]
                    let state = FaceState::new(cancel.child_token(), persistency, send_tx);
                    dispatcher.face_states.insert(face_id, state);
                    // Spawn per-face send task.
                    let send_face = Arc::clone(&face);
                    let send_cancel = cancel.clone();
                    let fs = Arc::clone(&dispatcher.face_states);
                    let ft = Arc::clone(&dispatcher.face_table);
                    let fib = Arc::clone(&dispatcher.strategy.fib);
                    tasks.spawn(engine::run_face_sender(
                        send_face,
                        send_rx,
                        persistency,
                        FaceRunnerCtx {
                            face_id,
                            cancel: send_cancel,
                            face_table: ft,
                            fib,
                            face_states: fs,
                            discovery: Arc::clone(&dispatcher.discovery),
                            discovery_ctx: Arc::clone(&dispatcher.discovery_ctx),
                        },
                    ));
                }

                let tx2 = tx.clone();
                let pit = Arc::clone(&dispatcher.pit_check.pit);
                let reader_ctx = FaceRunnerCtx {
                    face_id,
                    cancel: cancel.clone(),
                    face_table: Arc::clone(&dispatcher.face_table),
                    fib: Arc::clone(&dispatcher.strategy.fib),
                    face_states: Arc::clone(&dispatcher.face_states),
                    discovery: Arc::clone(&dispatcher.discovery),
                    discovery_ctx: Arc::clone(&dispatcher.discovery_ctx),
                };
                tasks.spawn(async move {
                    run_face_reader(face, tx2, pit, reader_ctx).await;
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
}
