use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use ndn_discovery::{DiscoveryProtocol, NeighborTable};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Interest;
use ndn_security::SecurityManager;
use ndn_store::{ErasedContentStore, Pit, PitToken, StrategyTable};
use ndn_strategy::MeasurementsTable;
use ndn_transport::{Face, FaceId, FacePersistency, FaceTable};

use crate::discovery_context::EngineDiscoveryContext;

use crate::stages::ErasedStrategy;

use crate::Fib;
use crate::dispatcher::InboundPacket;

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

/// Per-face lifecycle state stored alongside the cancellation token.
pub struct FaceState {
    pub cancel: CancellationToken,
    pub persistency: FacePersistency,
    /// Last packet activity (nanoseconds since Unix epoch).
    /// Updated on recv and send; used for idle-timeout of on-demand faces.
    pub last_activity: AtomicU64,
    /// Outbound send queue.
    ///
    /// The pipeline pushes packets here via `try_send` (non-blocking) and a
    /// dedicated per-face send task drains the queue, calling `face.send()`
    /// sequentially.  This decouples pipeline processing from I/O, preserves
    /// per-face ordering (critical for TCP framing), and provides bounded
    /// backpressure.
    pub send_tx: mpsc::Sender<bytes::Bytes>,
    /// NDNLPv2 per-hop reliability state (unicast UDP faces only).
    pub reliability: Option<std::sync::Mutex<ndn_face_net::reliability::LpReliability>>,
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
            send_tx,
            reliability: None,
        }
    }

    /// Create a FaceState with NDNLPv2 reliability enabled.
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
            send_tx,
            reliability: Some(std::sync::Mutex::new(
                ndn_face_net::reliability::LpReliability::new(mtu),
            )),
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

/// Shared tables owned by the engine, accessible to all tasks via `Arc`.
pub struct EngineInner {
    pub fib: Arc<Fib>,
    pub pit: Arc<Pit>,
    pub cs: Arc<dyn ErasedContentStore>,
    pub face_table: Arc<FaceTable>,
    pub measurements: Arc<MeasurementsTable>,
    pub strategy_table: Arc<StrategyTable<dyn ErasedStrategy>>,
    /// Security manager for signing/verification (optional — `None` disables
    /// security policy enforcement).
    pub security: Option<Arc<SecurityManager>>,
    /// Pipeline inbound channel — used to spawn readers for dynamically-added
    /// faces (those registered after `build()` completes).
    ///
    /// Stored in `OnceLock` because the sender is obtained from
    /// `PacketDispatcher::spawn()` which runs after `Arc<EngineInner>` is
    /// created (needed for the discovery context back-reference).
    pub(crate) pipeline_tx: OnceLock<mpsc::Sender<InboundPacket>>,
    /// Per-face state: cancellation token, persistency level, and last activity.
    pub(crate) face_states: Arc<DashMap<FaceId, FaceState>>,
    /// Active discovery protocol (default: `NoDiscovery`).
    pub discovery: Arc<dyn DiscoveryProtocol>,
    /// Engine-owned neighbor table shared with discovery protocols.
    pub neighbors: Arc<NeighborTable>,
    /// Discovery context.  Set once after `Arc<EngineInner>` is created to
    /// break the reference cycle (EngineInner → Arc<ctx> → Weak<EngineInner>).
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

    pub fn strategy_table(&self) -> Arc<StrategyTable<dyn ErasedStrategy>> {
        Arc::clone(&self.inner.strategy_table)
    }

    pub fn neighbors(&self) -> Arc<NeighborTable> {
        Arc::clone(&self.inner.neighbors)
    }

    pub fn discovery(&self) -> Arc<dyn DiscoveryProtocol> {
        Arc::clone(&self.inner.discovery)
    }

    /// The discovery context for this engine.
    ///
    /// Panics if called before `build()` completes (OnceLock not yet set).
    pub fn discovery_ctx(&self) -> Arc<EngineDiscoveryContext> {
        self.inner
            .discovery_ctx
            .get()
            .expect("discovery_ctx not initialized")
            .clone()
    }

    /// Look up the source face that originally sent an Interest.
    pub fn source_face_id(&self, interest: &Interest) -> Option<FaceId> {
        let token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );
        self.inner
            .pit
            .get(&token)
            .and_then(|entry| entry.in_records.first().map(|r| FaceId(r.face_id)))
    }

    /// Register a face and immediately start its packet-reader task.
    ///
    /// Persistence defaults to `OnDemand`. Use `add_face_with_persistency` for
    /// management-created or permanent faces.
    pub fn add_face<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        self.add_face_with_persistency(face, cancel, FacePersistency::OnDemand);
    }

    /// Register a face with an explicit persistence level.
    ///
    /// Spawns both a recv-reader task (pushes inbound packets to the pipeline
    /// channel) and a send-writer task (drains the per-face outbound queue
    /// and calls `face.send()`).
    pub fn add_face_with_persistency<F: Face + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = face.id();
        let kind = face.kind();
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let state = if kind == ndn_transport::FaceKind::Udp {
            FaceState::new_reliable(
                cancel.clone(),
                persistency,
                send_tx,
                ndn_face_net::DEFAULT_UDP_MTU,
            )
        } else {
            FaceState::new(cancel.clone(), persistency, send_tx)
        };
        self.inner.face_states.insert(face_id, state);
        self.inner.face_table.insert(face);
        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");

        let discovery = Arc::clone(&self.inner.discovery);
        let discovery_ctx = self.discovery_ctx();

        // Spawn the outbound send task.
        {
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            tokio::spawn(run_face_sender(
                face_id,
                Arc::clone(&erased),
                send_rx,
                cancel.clone(),
                persistency,
                Arc::clone(&self.inner.face_states),
                Arc::clone(&self.inner.face_table),
                Arc::clone(&self.inner.fib),
                d,
                ctx,
            ));
        }

        // Spawn the inbound recv task.
        tokio::spawn(crate::dispatcher::run_face_reader(
            face_id,
            erased,
            self.inner.pipeline_tx.get().expect("pipeline_tx initialized").clone(),
            cancel,
            Arc::clone(&self.inner.face_table),
            Arc::clone(&self.inner.fib),
            Arc::clone(&self.inner.pit),
            Arc::clone(&self.inner.face_states),
            Arc::clone(&discovery),
            discovery_ctx,
        ));

        // Notify discovery that a new face is up.
        let ctx = self.discovery_ctx();
        discovery.on_face_up(face_id, &*ctx);
    }

    /// Register a send-only face (no recv loop spawned).
    ///
    /// Use this for faces created by a listener that handles inbound packets
    /// itself via `inject_packet`.  The face is added to the face table so
    /// the dispatcher can send Data/Nack to it, but no `run_face_reader`
    /// task is spawned.  A send-writer task is spawned to drain the outbound
    /// queue.
    pub fn add_face_send_only<F: Face + 'static>(&self, face: F, cancel: CancellationToken) {
        let face_id = face.id();
        let kind = face.kind();
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let state = if kind == ndn_transport::FaceKind::Udp {
            FaceState::new_reliable(
                cancel.clone(),
                FacePersistency::OnDemand,
                send_tx,
                ndn_face_net::DEFAULT_UDP_MTU,
            )
        } else {
            FaceState::new(cancel.clone(), FacePersistency::OnDemand, send_tx)
        };
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
            face_id,
            erased,
            send_rx,
            cancel,
            FacePersistency::OnDemand,
            Arc::clone(&self.inner.face_states),
            Arc::clone(&self.inner.face_table),
            Arc::clone(&self.inner.fib),
            Arc::clone(&discovery),
            Arc::clone(&discovery_ctx),
        ));

        // Notify discovery (send-only faces are still reachable peers).
        discovery.on_face_up(face_id, &*discovery_ctx);
    }

    /// Inject a raw packet into the pipeline as if it arrived from `face_id`.
    ///
    /// Processes the reliability layer (Ack extraction / piggybacked Ack
    /// processing) before enqueuing, matching the same path as `run_face_reader`.
    /// `meta` carries the link-layer source address when available (use
    /// `InboundMeta::udp(src)` for UDP listeners, `InboundMeta::none()` when
    /// the source is implicit in the face).
    ///
    /// `discovery.on_inbound()` is called later inside `process_packet`, after
    /// LP-unwrap and fragment reassembly, at the single call site in the pipeline.
    ///
    /// Returns `Err(())` if the pipeline channel is closed.
    pub async fn inject_packet(
        &self,
        raw: bytes::Bytes,
        face_id: FaceId,
        arrival: u64,
        meta: ndn_discovery::InboundMeta,
    ) -> Result<(), ()> {
        // Feed inbound packet to the reliability layer (same as run_face_reader).
        // This extracts TxSeq for Ack and processes piggybacked Acks from the
        // remote end.  Only applies when the face has reliability enabled.
        if let Some(states) = self.inner.face_states.get(&face_id) {
            if let Some(ref rel) = states.reliability {
                rel.lock().unwrap().on_receive(&raw);
            }
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

    /// Get the cancellation token for a face, if one exists.
    pub fn face_token(&self, face_id: FaceId) -> Option<CancellationToken> {
        self.inner
            .face_states
            .get(&face_id)
            .map(|r| r.cancel.clone())
    }

    /// Access the face states map (for idle timeout sweeps).
    pub fn face_states(&self) -> Arc<DashMap<FaceId, FaceState>> {
        Arc::clone(&self.inner.face_states)
    }
}

/// Handle to gracefully shut down the engine.
pub struct ShutdownHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) tasks: JoinSet<()>,
}

impl ShutdownHandle {
    /// Cancel all engine tasks and wait for them to finish.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!("engine task panicked during shutdown: {e}");
            }
        }
    }
}

/// Per-face outbound send task.
///
/// Drains the face's outbound channel and calls `face.send_bytes()` for each
/// packet, preserving per-face ordering (critical for TCP TLV framing).
///
/// For reliability-enabled faces (unicast UDP), outgoing packets are processed
/// through `LpReliability::on_send()` which fragments, assigns TxSequences,
/// piggybacks Acks, and buffers for retransmit. A 50ms tick drives the
/// retransmit timer and flushes pending Acks.
///
/// On send error:
/// - **Permanent**: log and continue (the face retries on the next packet).
/// - **Persistent/OnDemand**: stop the send loop.
///
/// On cancellation or channel close: exits cleanly.
pub(crate) async fn run_face_sender(
    face_id: FaceId,
    face: Arc<dyn ndn_transport::ErasedFace>,
    mut rx: mpsc::Receiver<bytes::Bytes>,
    cancel: CancellationToken,
    persistency: FacePersistency,
    face_states: Arc<DashMap<FaceId, FaceState>>,
    face_table: Arc<FaceTable>,
    fib: Arc<crate::Fib>,
    discovery: Arc<dyn ndn_discovery::DiscoveryProtocol>,
    discovery_ctx: Arc<EngineDiscoveryContext>,
) {
    // Check if reliability is enabled by looking at the face state.
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);

    let mut retx_tick = tokio::time::interval(std::time::Duration::from_millis(50));
    retx_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Helper closure for send errors.
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
                    // Reliability-enabled path: fragment + assign TxSeq + piggyback Acks.
                    let wires = {
                        let state = face_states.get(&face_id);
                        match state.as_ref().and_then(|s| s.reliability.as_ref()) {
                            Some(rel) => rel.lock().unwrap().on_send(&pkt),
                            None => vec![pkt],
                        }
                    };
                    for wire in wires {
                        if let Err(e) = face.send_bytes(wire).await {
                            if handle_send_error(e) { return; }
                        }
                    }
                } else {
                    // Non-reliability path: send directly.
                    if let Err(e) = face.send_bytes(pkt).await {
                        if handle_send_error(e) { return; }
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
                    if let Err(e) = face.send_bytes(wire).await {
                        if handle_send_error(e) { return; }
                    }
                }
                if let Some(wire) = ack_pkt {
                    let _ = face.send_bytes(wire).await;
                }
            }
        }
    }
}
