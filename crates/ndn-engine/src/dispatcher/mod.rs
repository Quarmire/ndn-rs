mod inbound;
mod outbound;
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
    pub channel_cap: usize,
    pub pipeline_threads: usize,
    pub discovery: Arc<dyn DiscoveryProtocol>,
    pub discovery_ctx: Arc<EngineDiscoveryContext>,
    pub reflexive: Arc<crate::reflexive::ReflexiveTable>,
    pub runtime: Arc<dyn ndn_runtime::Runtime>,
    /// `None` is the zero-cost path: every probe site short-circuits on
    /// `Option::is_none`, so the per-packet cost is one untaken branch.
    pub rate_limit: Option<crate::rate_limit_hook::SharedRateLimitHook>,
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
                    let congestion_policy =
                        CongestionPolicy::default_for_scope(face.scope());
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

        let d = Arc::clone(&dispatcher);
        let cancel2 = cancel.clone();
        tasks.spawn(
            async move {
                d.run_pipeline(rx, cancel2).await;
            }
            .instrument(tracing::info_span!(
                target: crate::observability::targets::FWD_PIPELINE,
                "pipeline_dispatch",
            )),
        );

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
}
