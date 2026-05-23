//! `ForwarderEngine` and its inner state.
//!
//! `ForwarderEngine` is a `Clone`-able handle wrapping `Arc<EngineInner>`.
//! Every long-lived subsystem (FIB, RIB, PIT, ContentStore, FaceTable, …)
//! is independently `Arc`-shared so pipeline stages, mgmt handlers, and
//! embedders can hold references without coordinating.
//!
//! New subsystems that need to call back into the engine must hold
//! `Weak<EngineInner>` and upgrade on each call (see `EngineDiscoveryContext`
//! for the canonical pattern). Storing `Arc<ForwarderEngine>` on a long-lived
//! subsystem creates a reference cycle that leaks at shutdown.
//!
//! `ShutdownHandle::shutdown().await` cancels the root `CancellationToken`
//! and awaits the `TaskTracker`. `Drop for RoutingManager` cancels but
//! cannot await, so embedders should always call `shutdown()` explicitly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use web_time::SystemTime;
use web_time::UNIX_EPOCH;

use dashmap::DashMap;
use ndn_discovery_core::{DiscoveryProtocol, NeighborTable};
use ndn_runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use ndn_packet::Interest;
use ndn_packet::lp::encode_lp_packet;
#[cfg(not(target_arch = "wasm32"))]
use ndn_security::SecurityManager;
use ndn_security::Validator;
use ndn_store::{ErasedContentStore, Pit, PitToken, StrategyTable};
use ndn_strategy::MeasurementsTable;
use ndn_transport::{
    BIT_CONGESTION_MARKING, BIT_LOCAL_FIELDS, BIT_LP_RELIABILITY, CongestionPolicy, FaceId,
    FacePersistency, FaceTable, NFD_FLAG_BITS,
};

use crate::discovery_context::EngineDiscoveryContext;

use crate::observability::targets as t;
use crate::stages::ErasedStrategy;

use crate::Fib;
use crate::dispatcher::InboundPacket;
use crate::rib::Rib;
use crate::routing::RoutingManager;

/// Default outbound send queue capacity per face. Must absorb bursts from
/// parallel pipeline tasks dispatching to the same face simultaneously. When
/// full, outbound packets are dropped. With NDNLPv2 fragmentation a single
/// Data packet may expand to ~6 fragments; 2048 slots ≈ ~340 Data packets.
pub const DEFAULT_SEND_QUEUE_CAP: usize = 2048;

#[derive(Default)]
pub struct FaceCounters {
    pub in_interests: AtomicU64,
    pub in_data: AtomicU64,
    pub out_interests: AtomicU64,
    pub out_data: AtomicU64,
    pub in_bytes: AtomicU64,
    pub out_bytes: AtomicU64,
    /// Packets dropped because the outbound queue was full (Drop policy or
    /// Backpressure deadline exceeded).
    pub out_drops: AtomicU64,
    /// Total nanoseconds the engine spent blocked on `send().await` for this
    /// face (Backpressure policy only). High values indicate slow consumers.
    pub out_blocked_ns: AtomicU64,
    /// NFD `NSatisfiedInterests`: Interests on this face that returned Data.
    pub in_satisfied_interests: AtomicU64,
    /// NFD `NUnsatisfiedInterests`: Interests on this face whose PIT entry
    /// expired without a matching Data.
    pub in_unsatisfied_interests: AtomicU64,
}

/// Per-egress-packet queue item. Pairs wire bytes with the originating
/// face id; [`FaceId::INVALID`] denotes locally produced packets (Nacks,
/// retransmissions, discovery beacons).
pub type EgressItem = (bytes::Bytes, FaceId);

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
    pub send_tx: mpsc::Sender<EgressItem>,
    /// Policy applied when the outbound `send_tx` queue is full —
    /// drop, nack, or block.  Distinct from CoDel egress
    /// congestion-marking (a Tier 3 feature that observes the same
    /// queue's depth to emit LP `CongestionMark` TLVs); this is the
    /// **queue-full** fallback, not the queue-depth signal.
    pub congestion_policy: CongestionPolicy,
    #[cfg(feature = "face-net")]
    pub reliability: Option<std::sync::Mutex<ndn_transport::reliability::LpReliability>>,
    /// Set when the remote peer sends LP-wrapped packets (type 0x64). LP
    /// encoding is a per-link property determined by what the peer sends.
    pub uses_lp: AtomicBool,
    /// NFD `FaceFlags` bitmap (`FaceStatus.Flags`, TLV 0x6C), mutable via
    /// `faces/update` with `Flags`+`Mask`. External callers go through the
    /// named accessors on this struct.
    pub(crate) flags: AtomicU64,
}

impl FaceState {
    pub fn new(
        cancel: CancellationToken,
        persistency: FacePersistency,
        send_tx: mpsc::Sender<EgressItem>,
        congestion_policy: CongestionPolicy,
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
            congestion_policy,
            #[cfg(feature = "face-net")]
            reliability: None,
            uses_lp: AtomicBool::new(false),
            flags: AtomicU64::new(0),
        }
    }

    #[cfg(feature = "face-net")]
    pub fn new_reliable(
        cancel: CancellationToken,
        persistency: FacePersistency,
        send_tx: mpsc::Sender<EgressItem>,
        congestion_policy: CongestionPolicy,
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
            congestion_policy,
            reliability: Some(std::sync::Mutex::new(
                ndn_transport::reliability::LpReliability::new(mtu),
            )),
            uses_lp: AtomicBool::new(false),
            flags: AtomicU64::new(BIT_LP_RELIABILITY),
        }
    }

    /// Raw NFD face-flags bitmap. Prefer the named accessors below.
    pub fn face_flags_raw(&self) -> u64 {
        self.flags.load(Ordering::Relaxed)
    }

    /// Read-modify-write with the NFD `Flags`+`Mask` shape: bits set in
    /// `mask` take their value from `flags`, others are preserved. Bits
    /// outside [`NFD_FLAG_BITS`] are silently masked off. Returns the
    /// post-update bitmap.
    pub fn apply_face_flags_mask(&self, flags: u64, mask: u64) -> u64 {
        let allowed = mask & NFD_FLAG_BITS;
        let current = self.flags.load(Ordering::Relaxed);
        let updated = (current & !allowed) | (flags & allowed);
        self.flags.store(updated, Ordering::Relaxed);
        updated
    }

    pub fn set_local_fields_bit(&self, enabled: bool) {
        if enabled {
            self.flags.fetch_or(BIT_LOCAL_FIELDS, Ordering::Relaxed);
        } else {
            self.flags.fetch_and(!BIT_LOCAL_FIELDS, Ordering::Relaxed);
        }
    }

    pub fn local_fields_enabled(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & BIT_LOCAL_FIELDS != 0
    }

    pub fn lp_reliability_enabled(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & BIT_LP_RELIABILITY != 0
    }

    pub fn congestion_marking_enabled(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & BIT_CONGESTION_MARKING != 0
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
    #[cfg(not(target_arch = "wasm32"))]
    pub security: Option<Arc<SecurityManager>>,
    /// Schema inside the validator is behind a `RwLock`, allowing runtime
    /// modification via `/localhost/nfd/security/schema-*` commands.
    pub validator: Option<Arc<Validator>>,
    /// Pre-PIT replay guard. `Some` for production-shaped engines (default);
    /// `None` only when explicitly disabled via the builder escape hatch.
    /// Active on both native and wasm — wasm engines forward signed Interests
    /// (NDNCERT in-browser, dashboard mgmt) and need the same integrity floor.
    pub replay_guard: Option<Arc<ndn_security::ReplayGuard>>,
    /// `OnceLock` because the sender is created by `PacketDispatcher::spawn`
    /// after `Arc<EngineInner>` exists.
    pub(crate) pipeline_tx: OnceLock<mpsc::Sender<InboundPacket>>,
    pub(crate) face_states: Arc<DashMap<FaceId, FaceState>>,
    pub discovery: Arc<dyn DiscoveryProtocol>,
    pub neighbors: Arc<NeighborTable>,
    /// Reflexive-forwarding reverse routes (temporary, reverse-path routes
    /// installed from `REFLEXIVE_NAME` Interests).
    pub reflexive: Arc<crate::reflexive::ReflexiveTable>,
    /// `OnceLock` breaks the EngineInner → Arc<ctx> → Weak<EngineInner> cycle.
    pub(crate) discovery_ctx: OnceLock<Arc<EngineDiscoveryContext>>,
    pub(crate) runtime: Arc<dyn Runtime>,
    /// Optional sink observing per-face `Up` / `Down` transitions. Installed
    /// by `mount_management` after engine build (mgmt owns the notification
    /// stream lifecycle).
    pub(crate) face_lifecycle_sink: OnceLock<Arc<dyn ndn_transport::FaceLifecycleSink>>,
}

/// Cloning gives another reference to the same running engine.
#[derive(Clone)]
pub struct ForwarderEngine {
    pub(crate) inner: Arc<EngineInner>,
}

impl ForwarderEngine {
    /// Instrument-tier surface — direct table access. Stable for in-tree
    /// consumers; hidden from default docs behind `experimental-instrument`.
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn fib(&self) -> Arc<Fib> {
        Arc::clone(&self.inner.fib)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn rib(&self) -> Arc<Rib> {
        Arc::clone(&self.inner.rib)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn routing(&self) -> Arc<RoutingManager> {
        Arc::clone(&self.inner.routing)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn faces(&self) -> Arc<FaceTable> {
        Arc::clone(&self.inner.face_table)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn pit(&self) -> Arc<Pit> {
        Arc::clone(&self.inner.pit)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn cs(&self) -> Arc<dyn ErasedContentStore> {
        Arc::clone(&self.inner.cs)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn security(&self) -> Option<Arc<SecurityManager>> {
        self.inner.security.as_ref().map(Arc::clone)
    }

    pub fn validator(&self) -> Option<Arc<Validator>> {
        self.inner.validator.as_ref().map(Arc::clone)
    }

    /// Reflexive-forwarding reverse-route table.
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn reflexive(&self) -> Arc<crate::reflexive::ReflexiveTable> {
        Arc::clone(&self.inner.reflexive)
    }

    /// Pre-PIT replay guard. `Some` for production-shaped engines; `None`
    /// only when explicitly disabled via the builder escape hatch.
    pub fn replay_guard(&self) -> Option<Arc<ndn_security::ReplayGuard>> {
        self.inner.replay_guard.as_ref().map(Arc::clone)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn strategy_table(&self) -> Arc<StrategyTable<dyn ErasedStrategy>> {
        Arc::clone(&self.inner.strategy_table)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn neighbors(&self) -> Arc<NeighborTable> {
        Arc::clone(&self.inner.neighbors)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn measurements(&self) -> Arc<MeasurementsTable> {
        Arc::clone(&self.inner.measurements)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn discovery(&self) -> Arc<dyn DiscoveryProtocol> {
        Arc::clone(&self.inner.discovery)
    }

    /// Install a per-face lifecycle sink. May be called at most once;
    /// subsequent calls are silently ignored. Without a sink the engine
    /// fires no `Up` / `Down` events on `/localhost/nfd/faces/notifications`.
    pub fn set_face_lifecycle_sink(&self, sink: Arc<dyn ndn_transport::FaceLifecycleSink>) {
        let _ = self.inner.face_lifecycle_sink.set(sink);
    }

    pub(crate) fn face_lifecycle_sink(&self) -> Option<Arc<dyn ndn_transport::FaceLifecycleSink>> {
        self.inner.face_lifecycle_sink.get().cloned()
    }

    /// Panics if called before `build()` completes.
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn discovery_ctx(&self) -> Arc<EngineDiscoveryContext> {
        self.inner
            .discovery_ctx
            .get()
            .expect("discovery_ctx not initialized")
            .clone()
    }

    pub fn source_face_id(&self, interest: &Interest) -> Option<FaceId> {
        let fh = interest.forwarding_hint();
        let probe = |name: &ndn_packet::Name| {
            let token = PitToken::from_interest_full(name, fh);
            self.inner
                .pit
                .with_entry(&token, |entry| {
                    entry.in_records.first().map(|r| FaceId(r.face_id))
                })
                .flatten()
        };
        if let Some(face) = probe(&interest.name) {
            return Some(face);
        }
        // PitCheckStage keys AppParameters Interests at the PSDC-stripped
        // name. Re-try with the trailing PSDC stripped so mgmt handlers can
        // recover the requesting face for signed / param-carrying commands.
        use ndn_packet::tlv_type::PARAMETERS_SHA256;
        let comps = interest.name.components();
        if comps.last().map(|c| c.typ) == Some(PARAMETERS_SHA256) && comps.len() > 1 {
            let stripped =
                ndn_packet::Name::from_components(comps[..comps.len() - 1].iter().cloned());
            return probe(&stripped);
        }
        None
    }

    pub fn add_face<F: ndn_transport::Transport + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
    ) {
        self.add_face_with_persistency(face, cancel, FacePersistency::OnDemand);
    }

    pub fn add_face_with_persistency<F: ndn_transport::Transport + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = face.id();
        let congestion_policy = CongestionPolicy::default_for_scope(face.scope());
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let state = FaceState::new(
            cancel.clone(),
            persistency,
            send_tx.clone(),
            congestion_policy,
        );
        self.inner.face_states.insert(face_id, state);
        self.inner.face_table.insert(face);
        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");

        // Inject the egress queue-depth closure into the LinkService's
        // CongestionMarkingFeature (no-op for PassthroughLinkService).
        {
            let depth_tx = send_tx.clone();
            let queue_depth_fn: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || {
                let max = depth_tx.max_capacity() as u64;
                let avail = depth_tx.capacity() as u64;
                max.saturating_sub(avail)
            });
            erased.link_service.wire_queue_depth_fn(queue_depth_fn);
        }

        let discovery = Arc::clone(&self.inner.discovery);
        let discovery_ctx = self.discovery_ctx();

        self.inner.runtime.spawn(Box::pin(
            run_face_sender(
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
                    runtime: Arc::clone(&self.inner.runtime),
                    face_lifecycle_sink: self.face_lifecycle_sink(),
                },
            )
            .instrument(tracing::info_span!(
                target: t::FACE_SYSTEM,
                "face_write",
                face_id = face_id.0,
            )),
        ));

        self.inner.runtime.spawn(Box::pin(
            crate::dispatcher::run_face_reader(
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
                    runtime: Arc::clone(&self.inner.runtime),
                    face_lifecycle_sink: self.face_lifecycle_sink(),
                },
            )
            .instrument(tracing::info_span!(
                target: t::FACE_SYSTEM,
                "face_read",
                face_id = face_id.0,
            )),
        ));

        let ctx = self.discovery_ctx();
        discovery.on_face_up(face_id, &*ctx);

        if let Some(sink) = self.face_lifecycle_sink() {
            sink.on_up(face_id);
        }
    }

    /// Register a send-only face (no recv loop spawned).
    ///
    /// For faces created by a listener that handles inbound packets itself
    /// via `inject_packet`.
    pub fn add_face_send_only<F: ndn_transport::Transport + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
    ) {
        let face_id = face.id();
        let congestion_policy = CongestionPolicy::default_for_scope(face.scope());
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let state = FaceState::new(
            cancel.clone(),
            FacePersistency::OnDemand,
            send_tx,
            congestion_policy,
        );
        self.inner.face_states.insert(face_id, state);
        self.inner.face_table.insert(face);

        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");
        let discovery = Arc::clone(&self.inner.discovery);
        let discovery_ctx = self.discovery_ctx();
        self.inner.runtime.spawn(Box::pin(
            run_face_sender(
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
                    runtime: Arc::clone(&self.inner.runtime),
                    face_lifecycle_sink: self.face_lifecycle_sink(),
                },
            )
            .instrument(tracing::info_span!(
                target: t::FACE_SYSTEM,
                "face_write",
                face_id = face_id.0,
            )),
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
        meta: ndn_discovery_core::InboundMeta,
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

    /// Toggle the NFD `LocalFieldsEnabled` flag on `face_id`. Surfaced in
    /// `FaceStatus.Flags` (bit 0) for NFD-mgmt parity; source-face provenance
    /// rides the tag-bag instead, so this is purely a wire-visible flag.
    pub fn set_local_fields(&self, face_id: FaceId, enabled: bool) {
        if let Some(state) = self.inner.face_states.get(&face_id) {
            state.set_local_fields_bit(enabled);
        }
    }
}

/// Tracks fire-and-forget tasks spawned via the runtime abstraction so the
/// same path works on native (Tokio) and wasm32 (wasm-bindgen-futures), where
/// no `JoinHandle` equivalent exists. Each task drops a oneshot sender on
/// exit; `join_all` awaits the corresponding receivers.
pub(crate) struct TaskTracker {
    runtime: Arc<dyn Runtime>,
    drains: Vec<oneshot::Receiver<()>>,
}

impl TaskTracker {
    pub(crate) fn new(runtime: Arc<dyn Runtime>) -> Self {
        Self {
            runtime,
            drains: Vec::new(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn spawn<F>(&mut self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.drains.push(rx);
        self.runtime.spawn(Box::pin(async move {
            fut.await;
            let _ = tx.send(());
        }));
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn spawn<F>(&mut self, fut: F)
    where
        F: std::future::Future<Output = ()> + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.drains.push(rx);
        self.runtime.spawn(Box::pin(async move {
            fut.await;
            let _ = tx.send(());
        }));
    }

    pub(crate) async fn join_all(self) {
        for rx in self.drains {
            let _ = rx.await;
        }
    }
}

pub struct ShutdownHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) tracker: TaskTracker,
}

impl ShutdownHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub async fn shutdown(self) {
        self.cancel.cancel();
        self.tracker.join_all().await;
    }
}

/// Per-face outbound send task, preserving per-face ordering (critical for
/// TCP TLV framing). For reliability-enabled faces (unicast UDP), a 50ms tick
/// drives retransmit and Ack flushing.
pub(crate) async fn run_face_sender(
    face: Arc<ndn_transport::Face>,
    mut rx: mpsc::Receiver<EgressItem>,
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
        runtime,
        face_lifecycle_sink,
    } = ctx;
    let has_reliability = face_states
        .get(&face_id)
        .map(|s| s.reliability.is_some())
        .unwrap_or(false);

    // The LinkService-side reliability feature may also be on this face
    // (runtime-mutable). Pump both on the same retx tick so faces that have
    // reliability flipped on via `faces/update` still see retransmissions.
    let lp_reliability_feature = face.link_service.reliability_feature_handle();
    let has_lp_reliability_feature = lp_reliability_feature.is_some();

    let retx_tick_dur = std::time::Duration::from_millis(50);

    let handle_send_error = |e: ndn_transport::FaceError| -> bool {
        match persistency {
            FacePersistency::Permanent => {
                tracing::warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "send error on permanent face, continuing");
                false
            }
            _ => {
                tracing::warn!(target: t::FACE_SYSTEM, face=%face_id, error=%e, "send error, closing face");
                if persistency == FacePersistency::OnDemand {
                    discovery.on_face_down(face_id, &*discovery_ctx);
                    // Publish Down BEFORE removing the face so subscribers
                    // see the transition with the right face_id even when a
                    // faces/list poller races the cleanup.
                    if let Some(sink) = face_lifecycle_sink.as_ref() {
                        sink.on_down(face_id);
                    }
                    if let Some((_, state)) = face_states.remove(&face_id) {
                        state.cancel.cancel();
                    }
                    rib.handle_face_down(face_id, &fib);
                    fib.remove_face(face_id);
                    face_table.remove(face_id);
                }
                true
            }
        }
    };

    loop {
        let retx_sleep = runtime.sleep(retx_tick_dur);
        tokio::select! {
            biased;            _ = cancel.cancelled() => break,
            item = rx.recv() => {
                let (pkt, source) = match item {
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
                        if let Err(e) = face.send_bytes_with_source(wire, source).await
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
                    if let Err(e) = face.send_bytes_with_source(wire, source).await
                        && handle_send_error(e)
                    {
                        return;
                    }
                }
            },
            _ = retx_sleep, if has_reliability || has_lp_reliability_feature => {
                let (retx, ack_pkt) = if has_reliability {
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
                } else {
                    (vec![], None)
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
                // Pump per-face ReliabilityFeature retransmissions onto the
                // same egress path. `take_retransmissions` is empty when
                // disabled, so this is cheap.
                if let Some(feature) = lp_reliability_feature.as_ref() {
                    for wire in feature.take_retransmissions() {
                        if let Err(e) = face.send_bytes(wire).await
                            && handle_send_error(e)
                        {
                            return;
                        }
                    }
                }
            }
        }
    }
}
