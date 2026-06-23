mod inbound;
mod outbound;
#[cfg(feature = "partitioned-fwd")]
mod partitioned;
mod pipeline;

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ndn_discovery_core::{DiscoveryProtocol, InboundMeta};
use ndn_transport::{CongestionPolicy, FaceId, FacePersistency, FaceTable};
use tracing::Instrument as _;

use crate::discovery_context::EngineDiscoveryContext;
use crate::engine::{self, DEFAULT_SEND_QUEUE_CAP, FaceState, TaskTracker};
use crate::rib::Rib;

use crate::stages::{
    CsInsertStage, CsLookupStage, PitCheckStage, PitMatchStage, StrategyStage, TlvDecodeStage,
    ValidationStage,
};

pub(crate) use inbound::run_face_reader;

pub(crate) struct FaceRunnerCtx {
    pub(crate) face_id: FaceId,
    pub(crate) cancel: CancellationToken,
    pub(crate) face_table: Arc<FaceTable>,
    pub(crate) fib: Arc<crate::Fib>,
    pub(crate) rib: Arc<Rib>,
    pub(crate) face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
    pub(crate) discovery: Arc<dyn DiscoveryProtocol>,
    pub(crate) discovery_ctx: Arc<EngineDiscoveryContext>,
    pub(crate) runtime: Arc<dyn ndn_runtime::Runtime>,
    /// Optional sink observing `Up` / `Down` transitions; face tasks
    /// short-circuit the publish path when `None`.
    pub(crate) face_lifecycle_sink: Option<Arc<dyn ndn_transport::FaceLifecycleSink>>,
}

pub(crate) struct InboundPacket {
    pub(crate) raw: Bytes,
    pub(crate) face_id: FaceId,
    pub(crate) arrival: u64,
    pub(crate) meta: InboundMeta,
}

/// Which data-plane runtime the engine runs. `Shared` is the default: one
/// pipeline task over a single (`DashMap`) PIT. `Partitioned` selects the
/// decode-in-RX + per-worker forwarding model (`partitioned-fwd` feature; the
/// variant is always present so config round-trips even in a build without the
/// feature, where it falls back to `Shared`). See
/// `.claude/notes/partitioned-fwd-design-2026-05-24.md`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DataPlane {
    #[default]
    Shared,
    Partitioned {
        workers: usize,
    },
}

pub struct PacketDispatcher {
    pub face_table: Arc<FaceTable>,
    pub face_states: Arc<dashmap::DashMap<FaceId, FaceState>>,
    pub rib: Arc<Rib>,
    pub decode: TlvDecodeStage,
    pub cs_lookup: CsLookupStage,
    pub pit_check: PitCheckStage,
    pub strategy: StrategyStage,
    pub pit_match: PitMatchStage,
    pub validation: ValidationStage,
    pub cs_insert: CsInsertStage,
    /// Whether (and on which face scope) to opportunistically cache Data that
    /// arrives without a matching PIT entry. Default `DropAll` (NFD parity).
    pub unsolicited_policy: crate::unsolicited::UnsolicitedDataPolicy,
    pub channel_cap: usize,
    pub pipeline_threads: usize,
    pub discovery: Arc<dyn DiscoveryProtocol>,
    pub discovery_ctx: Arc<EngineDiscoveryContext>,
    pub reflexive: Arc<crate::reflexive::ReflexiveTable>,
    pub runtime: Arc<dyn ndn_runtime::Runtime>,
    /// `None` is the zero-cost path: every probe site short-circuits on
    /// `Option::is_none`, so the per-packet cost is one untaken branch.
    pub rate_limit: Option<crate::rate_limit_hook::SharedRateLimitHook>,
    /// G1 congestion-feedback bridge (opt-in). `None` = zero cost on the data path;
    /// when `Some`, a returning Data carrying an NDNLP congestion mark bumps the
    /// face's mark count, which a background source decays into `LinkSignals.congestion`.
    pub congestion_feedback: Option<Arc<ndn_strategy::CongestionFeedback>>,
    /// Which data-plane runtime to spawn. Default `Shared`.
    pub data_plane: DataPlane,
}

impl PacketDispatcher {
    pub(crate) fn spawn(
        self,
        cancel: CancellationToken,
        tasks: &mut TaskTracker,
    ) -> mpsc::Sender<InboundPacket> {
        let (tx, rx) = mpsc::channel::<InboundPacket>(self.channel_cap);
        let dispatcher = Arc::new(self);

        for face_id in dispatcher.face_table.face_ids() {
            if let Some(face) = dispatcher.face_table.get(face_id) {
                if !dispatcher.face_states.contains_key(&face_id) {
                    let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
                    let persistency = FacePersistency::Permanent;
                    let congestion_policy = CongestionPolicy::default_for_scope(face.scope());
                    // NDN-LP reliability (TxSequence / Ack, types 0x0344 /
                    // 0x0348) is an optional NDNLPv2 extension that ndnd
                    // rejects outright. Default OFF on all faces to preserve
                    // cross-impl interop; opt in explicitly to enable.
                    let state = FaceState::new(
                        cancel.child_token(),
                        persistency,
                        send_tx,
                        congestion_policy,
                    );
                    dispatcher.face_states.insert(face_id, state);
                    let send_face = Arc::clone(&face);
                    let send_cancel = cancel.clone();
                    let fs = Arc::clone(&dispatcher.face_states);
                    let ft = Arc::clone(&dispatcher.face_table);
                    let fib = Arc::clone(&dispatcher.strategy.fib);
                    let rib = Arc::clone(&dispatcher.rib);
                    tasks.spawn(
                        engine::run_face_sender(
                            send_face,
                            send_rx,
                            persistency,
                            FaceRunnerCtx {
                                face_id,
                                cancel: send_cancel,
                                face_table: ft,
                                fib,
                                rib,
                                face_states: fs,
                                discovery: Arc::clone(&dispatcher.discovery),
                                discovery_ctx: Arc::clone(&dispatcher.discovery_ctx),
                                runtime: Arc::clone(&dispatcher.runtime),
                                // Boot-time faces fire no `Up` events: the
                                // sink is installed by `mount_management`
                                // after build, so no subscriber exists yet.
                                face_lifecycle_sink: None,
                            },
                        )
                        .instrument(tracing::info_span!(
                            target: crate::observability::targets::FACE_SYSTEM,
                            "face_write",
                            face_id = face_id.0,
                        )),
                    );
                }

                let tx2 = tx.clone();
                let pit = Arc::clone(&dispatcher.pit_check.pit);
                let reader_ctx = FaceRunnerCtx {
                    face_id,
                    cancel: cancel.clone(),
                    face_table: Arc::clone(&dispatcher.face_table),
                    fib: Arc::clone(&dispatcher.strategy.fib),
                    rib: Arc::clone(&dispatcher.rib),
                    face_states: Arc::clone(&dispatcher.face_states),
                    discovery: Arc::clone(&dispatcher.discovery),
                    discovery_ctx: Arc::clone(&dispatcher.discovery_ctx),
                    runtime: Arc::clone(&dispatcher.runtime),
                    face_lifecycle_sink: None,
                };
                tasks.spawn(
                    async move {
                        run_face_reader(face, tx2, pit, reader_ctx).await;
                    }
                    .instrument(tracing::info_span!(
                        target: crate::observability::targets::FACE_SYSTEM,
                        "face_read",
                        face_id = face_id.0,
                    )),
                );
            }
        }

        let cancel2 = cancel.clone();
        #[cfg(feature = "partitioned-fwd")]
        match dispatcher.data_plane {
            DataPlane::Partitioned { workers } => {
                dispatcher.spawn_partitioned(rx, cancel2, tasks, workers.max(1));
            }
            DataPlane::Shared => dispatcher.spawn_shared_pipeline(rx, cancel2, tasks),
        }
        #[cfg(not(feature = "partitioned-fwd"))]
        {
            if matches!(dispatcher.data_plane, DataPlane::Partitioned { .. }) {
                tracing::warn!(
                    target: crate::observability::targets::FWD_PIPELINE,
                    "data_plane=partitioned requested but the `partitioned-fwd` feature is not built; using the shared runtime"
                );
            }
            dispatcher.spawn_shared_pipeline(rx, cancel2, tasks);
        }

        if dispatcher.validation.validator.is_some() {
            let d = Arc::clone(&dispatcher);
            let cancel3 = cancel.clone();
            tasks.spawn(
                async move {
                    d.run_validation_drain(cancel3).await;
                }
                .instrument(tracing::info_span!(
                    target: crate::observability::targets::FWD_PIPELINE,
                    "validation_drain",
                )),
            );
        }

        tx
    }

    /// Spawn the shared (default) data-plane: one pipeline task draining the
    /// inbound channel over the single PIT.
    fn spawn_shared_pipeline(
        self: &Arc<Self>,
        rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
        tasks: &mut TaskTracker,
    ) {
        let d = Arc::clone(self);
        tasks.spawn(
            async move {
                d.run_pipeline(rx, cancel).await;
            }
            .instrument(tracing::info_span!(
                target: crate::observability::targets::FWD_PIPELINE,
                "pipeline_dispatch",
            )),
        );
    }
}
