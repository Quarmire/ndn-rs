use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ndn_discovery::{DiscoveryProtocol, NeighborTable};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Interest;
use ndn_packet::lp::encode_lp_packet;
use ndn_security::{SecurityManager, Validator};
use ndn_store::{ErasedContentStore, Pit, PitToken, StrategyTable};
use ndn_strategy::MeasurementsTable;
use ndn_transport::{Face, FaceId, FacePersistency, FaceTable};

use crate::discovery_context::EngineDiscoveryContext;

use crate::stages::ErasedStrategy;

use crate::Fib;
use crate::dispatcher::InboundPacket;
use crate::rib::Rib;
use crate::routing::RoutingManager;

/// Default outbound send queue capacity per face.
///
/// Must be large enough to absorb bursts from parallel pipeline tasks that
/// all dispatch to the same face near-simultaneously.  When full, outbound
/// packets are dropped (equivalent to a congestion drop at the output queue —
/// consistent with NFD's `GenericLinkService` model).
///
/// With NDNLPv2 fragmentation, a single Data packet may expand to ~6
/// fragments, each occupying one queue slot.  2048 slots ≈ ~340 Data
/// packets — enough headroom for sustained bursts over high-throughput
/// links without silent drops.
pub const DEFAULT_SEND_QUEUE_CAP: usize = 2048;

#[derive(Default)]
pub struct FaceCounters {
    pub in_interests: AtomicU64,
    pub in_data: AtomicU64,
    pub out_interests: AtomicU64,
    pub out_data: AtomicU64,
    pub in_bytes: AtomicU64,
    pub out_bytes: AtomicU64,
}

pub struct FaceState {
    pub cancel: CancellationToken,
    pub persistency: FacePersistency,
    /// Last packet activity (nanoseconds since Unix epoch).
    /// Updated on recv and send; used for idle-timeout of on-demand faces.
    pub last_activity: AtomicU64,
    pub counters: FaceCounters,
    /// Outbound send queue. Decouples pipeline processing from I/O, preserves
    /// per-face ordering (critical for TCP framing), and provides bounded
    /// backpressure.
    pub send_tx: mpsc::Sender<bytes::Bytes>,
    #[cfg(feature = "face-net")]
    pub reliability: Option<std::sync::Mutex<ndn_faces::net::reliability::LpReliability>>,
    /// Auto-detected when the remote peer sends LP-wrapped packets (type 0x64).
    /// Mirrors NFD's `GenericLinkService` behavior: LP encoding is a per-link
    /// property determined by what the peer sends, not by face kind.
    pub uses_lp: AtomicBool,
}

impl FaceState {
    pub fn new(
        cancel: CancellationToken,
        persistency: FacePersistency,
        send_tx: mpsc::Sender<bytes::Bytes>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            cancel,
            persistency,
            last_activity: AtomicU64::new(now),
            counters: FaceCounters::default(),
            send_tx,
            #[cfg(feature = "face-net")]
            reliability: None,
            uses_lp: AtomicBool::new(false),
        }
    }

    #[cfg(feature = "face-net")]
    pub fn new_reliable(
        cancel: CancellationToken,
        persistency: FacePersistency,
        send_tx: mpsc::Sender<bytes::Bytes>,
        mtu: usize,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            cancel,
            persistency,
            last_activity: AtomicU64::new(now),
            counters: FaceCounters::default(),
            send_tx,
            reliability: Some(std::sync::Mutex::new(
                ndn_faces::net::reliability::LpReliability::new(mtu),
            )),
            uses_lp: AtomicBool::new(false),
        }
    }

    pub fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.last_activity.store(now, Ordering::Relaxed);
    }
}

pub struct EngineInner {
    pub fib: Arc<Fib>,
    pub rib: Arc<Rib>,
    pub routing: Arc<RoutingManager>,
    pub pit: Arc<Pit>,
    pub cs: Arc<dyn ErasedContentStore>,
    pub face_table: Arc<FaceTable>,
    pub measurements: Arc<MeasurementsTable>,
    pub strategy_table: Arc<StrategyTable<dyn ErasedStrategy>>,
    pub security: Option<Arc<SecurityManager>>,
    /// Schema inside the validator is behind a `RwLock`, allowing runtime
    /// modification via `/localhost/nfd/security/schema-*` commands.
    pub validator: Option<Arc<Validator>>,
    /// `OnceLock` because the sender comes from `PacketDispatcher::spawn()`
    /// which runs after `Arc<EngineInner>` is created.
    pub(crate) pipeline_tx: OnceLock<mpsc::Sender<InboundPacket>>,
    pub(crate) face_states: Arc<DashMap<FaceId, FaceState>>,
    pub discovery: Arc<dyn DiscoveryProtocol>,
    pub neighbors: Arc<NeighborTable>,
    /// Set once after `Arc<EngineInner>` is created to break the reference
    /// cycle (EngineInner -> Arc<ctx> -> Weak<EngineInner>).
    pub(crate) discovery_ctx: OnceLock<Arc<EngineDiscoveryContext>>,
}

/// Handle to a running forwarding engine.
///
/// Cloning the handle gives another reference to the same running engine.
#[derive(Clone)]
pub struct ForwarderEngine {
    pub(crate) inner: Arc<EngineInner>,
}

impl ForwarderEngine {
    pub fn fib(&self) -> Arc<Fib> {
        Arc::clone(&self.inner.fib)
    }

    pub fn rib(&self) -> Arc<Rib> {
        Arc::clone(&self.inner.rib)
    }

    pub fn routing(&self) -> Arc<RoutingManager> {
        Arc::clone(&self.inner.routing)
    }

    pub fn faces(&self) -> Arc<FaceTable> {
        Arc::clone(&self.inner.face_table)
    }

    pub fn pit(&self) -> Arc<Pit> {
        Arc::clone(&self.inner.pit)
    }

    pub fn cs(&self) -> Arc<dyn ErasedContentStore> {
        Arc::clone(&self.inner.cs)
    }

    pub fn security(&self) -> Option<Arc<SecurityManager>> {
        self.inner.security.as_ref().map(Arc::clone)
    }

    pub fn validator(&self) -> Option<Arc<Validator>> {
        self.inner.validator.as_ref().map(Arc::clone)
    }

    pub fn strategy_table(&self) -> Arc<StrategyTable<dyn ErasedStrategy>> {
        Arc::clone(&self.inner.strategy_table)
    }

    pub fn neighbors(&self) -> Arc<NeighborTable> {
        Arc::clone(&self.inner.neighbors)
    }

    pub fn measurements(&self) -> Arc<MeasurementsTable> {
        Arc::clone(&self.inner.measurements)
    }

    pub fn discovery(&self) -> Arc<dyn DiscoveryProtocol> {
        Arc::clone(&self.inner.discovery)
    }

    /// Panics if called before `build()` completes (OnceLock not yet set).
    pub fn discovery_ctx(&self) -> Arc<EngineDiscoveryContext> {
        self.inner
            .discovery_ctx
            .get()
            .expect("discovery_ctx not initialized")
            .clone()
    }

    pub fn source_face_id(&self, interest: &Interest) -> Option<FaceId> {
        let token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );
        self.inner
            .pit
            .with_entry(&token, |entry| {
                entry.in_records.first().map(|r| FaceId(r.face_id))
            })
            .flatten()
    }

    pub fn add_face<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        self.add_face_with_persistency(face, cancel, FacePersistency::OnDemand);
    }

    pub fn add_face_with_persistency<F: Face + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = face.id();
        let kind = face.kind();
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        #[cfg(feature = "face-net")]
        let state = if kind == ndn_transport::FaceKind::Udp {
            FaceState::new_reliable(
                cancel.clone(),
                persistency,
                send_tx,
                ndn_faces::net::DEFAULT_UDP_MTU,
            )
        } else {
            FaceState::new(cancel.clone(), persistency, send_tx)
        };
        #[cfg(not(feature = "face-net"))]
        let state = FaceState::new(cancel.clone(), persistency, send_tx);
        self.inner.face_states.insert(face_id, state);
        self.inner.face_table.insert(face);
        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");

        let discovery = Arc::clone(&self.inner.discovery);
        let discovery_ctx = self.discovery_ctx();

        tokio::spawn(run_face_sender(
            Arc::clone(&erased),
            send_rx,
            persistency,
            crate::dispatcher::FaceRunnerCtx {
                face_id,
                cancel: cancel.clone(),
                face_table: Arc::clone(&self.inner.face_table),
                fib: Arc::clone(&self.inner.fib),
                rib: Arc::clone(&self.inner.rib),
                face_states: Arc::clone(&self.inner.face_states),
                discovery: Arc::clone(&discovery),
                discovery_ctx: Arc::clone(&discovery_ctx),
            },
        ));

        tokio::spawn(crate::dispatcher::run_face_reader(
            erased,
            self.inner
                .pipeline_tx
                .get()
                .expect("pipeline_tx initialized")
                .clone(),
            Arc::clone(&self.inner.pit),
            crate::dispatcher::FaceRunnerCtx {
                face_id,
                cancel,
                face_table: Arc::clone(&self.inner.face_table),
                fib: Arc::clone(&self.inner.fib),
                rib: Arc::clone(&self.inner.rib),
                face_states: Arc::clone(&self.inner.face_states),
                discovery: Arc::clone(&discovery),
                discovery_ctx,
            },
        ));

        let ctx = self.discovery_ctx();
        discovery.on_face_up(face_id, &*ctx);
    }

    /// Register a send-only face (no recv loop spawned).
    ///
    /// For faces created by a listener that handles inbound packets itself
    /// via `inject_packet`.
    pub fn add_face_send_only<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        let face_id = face.id();
        let kind = face.kind();
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        #[cfg(feature = "face-net")]
        let state = if kind == ndn_transport::FaceKind::Udp {
            FaceState::new_reliable(
                cancel.clone(),
                FacePersistency::OnDemand,
                send_tx,
                ndn_faces::net::DEFAULT_UDP_MTU,
            )
        } else {
            FaceState::new(cancel.clone(), FacePersistency::OnDemand, send_tx)
        };
        #[cfg(not(feature = "face-net"))]
        let state = FaceState::new(cancel.clone(), FacePersistency::OnDemand, send_tx);
        self.inner.face_states.insert(face_id, state);
        self.inner.face_table.insert(face);

        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");
        let discovery = Arc::clone(&self.inner.discovery);
        let discovery_ctx = self.discovery_ctx();
        tokio::spawn(run_face_sender(
            erased,
            send_rx,
            FacePersistency::OnDemand,
            crate::dispatcher::FaceRunnerCtx {
                face_id,
                cancel,
                face_table: Arc::clone(&self.inner.face_table),
                fib: Arc::clone(&self.inner.fib),
                rib: Arc::clone(&self.inner.rib),
                face_states: Arc::clone(&self.inner.face_states),
                discovery: Arc::clone(&discovery),
                discovery_ctx: Arc::clone(&discovery_ctx),
            },
        ));

        discovery.on_face_up(face_id, &*discovery_ctx);
    }

    /// Inject a raw packet into the pipeline as if it arrived from `face_id`.
    ///
    /// Returns `Err(())` if the pipeline channel is closed.
    pub async fn inject_packet(
        &self,
        raw: bytes::Bytes,
        face_id: FaceId,
        arrival: u64,
        meta: ndn_discovery::InboundMeta,
    ) -> Result<(), ()> {
        if let Some(states) = self.inner.face_states.get(&face_id)
            && let Some(rel) = states.reliability.as_ref()
        {
            rel.lock().unwrap().on_receive(&raw);
        }

        let tx = match self.inner.pipeline_tx.get() {
            Some(tx) => tx,
            None => return Err(()),
        };
        tx.send(InboundPacket {
            raw,
            face_id,
            arrival,
            meta,
        })
        .await
        .map_err(|_| ())
    }

    pub fn face_token(&self, face_id: FaceId) -> Option<CancellationToken> {
        self.inner
            .face_states
            .get(&face_id)
            .map(|r| r.cancel.clone())
    }

    pub fn face_states(&self) -> Arc<DashMap<FaceId, FaceState>> {
        Arc::clone(&self.inner.face_states)
    }
}

pub struct ShutdownHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) tasks: JoinSet<()>,
}

impl ShutdownHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!("engine task panicked during shutdown: {e}");
            }
        }
    }
}

/// Per-face outbound send task, preserving per-face ordering (critical for
/// TCP TLV framing). For reliability-enabled faces (unicast UDP), a 50ms tick
/// drives retransmit and Ack flushing.
pub(crate) async fn run_face_sender(
    face: Arc<dyn ndn_transport::ErasedFace>,
    mut rx: mpsc::Receiver<bytes::Bytes>,
    persistency: FacePersistency,
    ctx: crate::dispatcher::FaceRunnerCtx,
) {
    let crate::dispatcher::FaceRunnerCtx {
        face_id,
        cancel,
        face_table,
        fib,
        rib,
        face_states,
        discovery,
        discovery_ctx,
    } = ctx;
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);

    let mut retx_tick = tokio::time::interval(std::time::Duration::from_millis(50));
    retx_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let handle_send_error = |e: ndn_transport::FaceError| -> bool {
        match persistency {
            FacePersistency::Permanent => {
                tracing::warn!(face=%face_id, error=%e, "send error on permanent face, continuing");
                false // don't break
            }
            _ => {
                tracing::warn!(face=%face_id, error=%e, "send error, closing face");
                if persistency == FacePersistency::OnDemand {
                    discovery.on_face_down(face_id, &*discovery_ctx);
                    if let Some((_, state)) = face_states.remove(&face_id) {
                        state.cancel.cancel();
                    }
                    rib.handle_face_down(face_id, &fib);
                    fib.remove_face(face_id);
                    face_table.remove(face_id);
                }
                true // break
            }
        }
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            pkt = rx.recv() => {
                let pkt = match pkt {
                    Some(p) => p,
                    None => break,
                };

                if has_reliability {
                    let wires = {
                        let state = face_states.get(&face_id);
                        match state.as_ref().and_then(|s| s.reliability.as_ref()) {
                            Some(rel) => rel.lock().unwrap().on_send(&pkt),
                            None => vec![pkt],
                        }
                    };
                    for wire in wires {
                        if let Err(e) = face.send_bytes(wire).await
                            && handle_send_error(e)
                        {
                            return;
                        }
                    }
                } else {
                    let wire = if face_states
                        .get(&face_id)
                        .map(|s| s.uses_lp.load(Ordering::Relaxed))
                        .unwrap_or(false)
                    {
                        encode_lp_packet(&pkt)
                    } else {
                        pkt
                    };
                    if let Err(e) = face.send_bytes(wire).await
                        && handle_send_error(e)
                    {
                        return;
                    }
                }
            },
            _ = retx_tick.tick(), if has_reliability => {
                let (retx, ack_pkt) = {
                    let state = face_states.get(&face_id);
                    match state.as_ref().and_then(|s| s.reliability.as_ref()) {
                        Some(rel) => {
                            let mut rel = rel.lock().unwrap();
                            let retx = rel.check_retransmit();
                            let ack_pkt = rel.flush_acks();
                            (retx, ack_pkt)
                        }
                        None => (vec![], None),
                    }
                };
                for wire in retx {
                    if let Err(e) = face.send_bytes(wire).await
                        && handle_send_error(e)
                    {
                        return;
                    }
                }
                if let Some(wire) = ack_pkt {
                    let _ = face.send_bytes(wire).await;
                }
            }
        }
    }
}
