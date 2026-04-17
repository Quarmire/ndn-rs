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
}

impl PacketDispatcher {
    pub(crate) fn spawn(
        self,
        cancel: CancellationToken,
        tasks: &mut JoinSet<()>,
    ) -> mpsc::Sender<InboundPacket> {
        let (tx, rx) = mpsc::channel::<InboundPacket>(self.channel_cap);
        let dispatcher = Arc::new(self);

        for face_id in dispatcher.face_table.face_ids() {
            if let Some(face) = dispatcher.face_table.get(face_id) {
                if !dispatcher.face_states.contains_key(&face_id) {
                    let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
                    let persistency = FacePersistency::Permanent;
                    #[cfg(feature = "face-net")]
                    let state = if face.kind() == FaceKind::Udp {
                        FaceState::new_reliable(
                            cancel.child_token(),
                            persistency,
                            send_tx,
                            ndn_faces::net::DEFAULT_UDP_MTU,
                        )
                    } else {
                        FaceState::new(cancel.child_token(), persistency, send_tx)
                    };
                    #[cfg(not(feature = "face-net"))]
                    let state = FaceState::new(cancel.child_token(), persistency, send_tx);
                    dispatcher.face_states.insert(face_id, state);
                    let send_face = Arc::clone(&face);
                    let send_cancel = cancel.clone();
                    let fs = Arc::clone(&dispatcher.face_states);
                    let ft = Arc::clone(&dispatcher.face_table);
                    let fib = Arc::clone(&dispatcher.strategy.fib);
                    let rib = Arc::clone(&dispatcher.rib);
                    tasks.spawn(engine::run_face_sender(
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
                    rib: Arc::clone(&dispatcher.rib),
                    face_states: Arc::clone(&dispatcher.face_states),
                    discovery: Arc::clone(&dispatcher.discovery),
                    discovery_ctx: Arc::clone(&dispatcher.discovery_ctx),
                };
                tasks.spawn(async move {
                    run_face_reader(face, tx2, pit, reader_ctx).await;
                });
            }
        }

        let d = Arc::clone(&dispatcher);
        let cancel2 = cancel.clone();
        tasks.spawn(async move {
            d.run_pipeline(rx, cancel2).await;
        });

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
