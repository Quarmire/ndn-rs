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
#[cfg(not(target_arch = "wasm32"))]
use ndn_security::SecurityManager;
use ndn_security::Validator;
use ndn_store::{ErasedContentStore, Pit, PitToken, StrategyTable};
use ndn_strategy::{MeasurementsTable, SignalsTable};
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
    /// NFD `NInNacks`: Nacks received on this face.
    pub in_nacks: AtomicU64,
    /// NFD `NOutNacks`: Nacks sent on this face.
    pub out_nacks: AtomicU64,
}

/// NDNLPv2 framing intent for one outbound packet. Produced by the
/// forwarding pipeline (which no longer frames the wire itself) and applied
/// once, downstream, by [`frame_with_intent`] in the per-face send loop —
/// the single egress-framing authority. This is what lets the reliability
/// layer frame *bare* packets canonically (it sees them before LP-wrap).
#[derive(Debug, Clone, Default)]
pub struct EgressIntent {
    /// LP headers to attach (PitToken, IncomingFaceId, …). All-`None` for a
    /// plain wrap.
    pub headers: ndn_packet::lp::LpHeaders,
    /// When set, the payload is the Interest a Nack wraps (not a fragment).
    pub nack: Option<ndn_packet::NackReason>,
}

/// Per-egress-packet queue item: **bare** network payload, the originating
/// face id ([`FaceId::INVALID`] = locally produced — Nacks, beacons), and the
/// LP framing intent. Framing happens once in the send loop, not the pipeline.
pub type EgressItem = (bytes::Bytes, FaceId, EgressIntent);

/// Turn a bare network packet + [`EgressIntent`] into wire bytes — the one
/// place egress LP framing happens. Reproduces, byte-for-byte, what the
/// dispatcher used to encode inline:
/// - a Nack wraps the Interest (`encode_lp_nack_with_pit_token` / `encode_nack`);
/// - an LP-framed face wraps the payload, attaching any headers;
/// - an IPC (bare-TLV) face stays bare unless a PitToken forces an LP frame;
/// - already-LP input (a retransmission) passes through untouched.
pub fn frame_with_intent(payload: &[u8], intent: &EgressIntent, uses_lp: bool) -> bytes::Bytes {
    use ndn_packet::lp::{
        encode_lp_nack_with_pit_token, encode_lp_packet, encode_lp_with_headers, is_lp_packet,
    };
    use ndn_packet::wire::encode_nack;
    if let Some(reason) = intent.nack {
        return match intent.headers.pit_token.as_deref() {
            Some(token) => encode_lp_nack_with_pit_token(reason, payload, Some(token)),
            None => encode_nack(reason, payload),
        };
    }
    if is_lp_packet(payload) {
        // Already framed (e.g. a reliability retransmission) — never re-wrap.
        return encode_lp_packet(payload);
    }
    if uses_lp {
        // All-`None` headers make this identical to `encode_lp_packet`.
        encode_lp_with_headers(payload, &intent.headers)
    } else if intent.headers.pit_token.is_some() {
        encode_lp_with_headers(payload, &intent.headers)
    } else {
        bytes::Bytes::copy_from_slice(payload)
    }
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
    pub send_tx: mpsc::Sender<EgressItem>,
    /// Policy applied when the outbound `send_tx` queue is full —
    /// drop, nack, or block.  Distinct from CoDel egress
    /// congestion-marking (a Tier 3 feature that observes the same
    /// queue's depth to emit LP `CongestionMark` TLVs); this is the
    /// **queue-full** fallback, not the queue-depth signal.
    pub congestion_policy: CongestionPolicy,
    /// G4 egress scheduler (opt-in QoS). `None` ⇒ the FIFO default: enqueue goes straight
    /// to `send_tx` and the send loop drains it, today's behavior. `Some` ⇒ enqueue
    /// classifies into the scheduler and the send loop drains *it* in priority order.
    pub scheduler: Option<Arc<dyn crate::egress::EgressScheduler>>,
    /// Set when the remote peer sends LP-wrapped packets (type 0x64). LP
    /// encoding is a per-link property determined by what the peer sends.
    pub uses_lp: AtomicBool,
    /// Require cryptographic Data validation on this face even when it is
    /// Local-scope. Default `false`: Local faces (IPC/SHM/loopback) are trusted
    /// by OS access control and skip verification (the fast path). Set `true`
    /// for a multi-tenant host where mutually-distrusting local apps share one
    /// forwarder, so forged Data cannot poison the CS or spoof another app's
    /// namespace. Fail-closed: with no validator configured, required-validation
    /// Data is dropped. NonLocal faces always validate regardless of this flag.
    pub require_data_validation: AtomicBool,
    /// NFD `FaceFlags` bitmap (`FaceStatus.Flags`, TLV 0x6C), mutable via
    /// `faces/update` with `Flags`+`Mask`. External callers go through the
    /// named accessors on this struct.
    pub(crate) flags: AtomicU64,
}

impl FaceState {
    /// Create face state stamped with `now_ns`, the current time in Unix
    /// nanoseconds. Callers **must** source this from the engine runtime
    /// (`runtime.unix_nanos()`), not the system clock directly: `last_activity`
    /// is compared against `runtime.unix_nanos()` by the idle-face reaper
    /// (`expiry.rs`), so under a virtual/simulation runtime a wall-clock stamp
    /// here would make face expiry non-deterministic. This is the last
    /// forwarding-path clock read that was routed through the seam (ndn-lab).
    pub fn new(
        cancel: CancellationToken,
        persistency: FacePersistency,
        send_tx: mpsc::Sender<EgressItem>,
        congestion_policy: CongestionPolicy,
        now_ns: u64,
    ) -> Self {
        Self {
            cancel,
            persistency,
            last_activity: AtomicU64::new(now_ns),
            counters: FaceCounters::default(),
            send_tx,
            congestion_policy,
            scheduler: None,
            uses_lp: AtomicBool::new(false),
            require_data_validation: AtomicBool::new(false),
            flags: AtomicU64::new(0),
        }
    }

    /// Whether this face requires Data validation even when Local-scope.
    pub fn require_data_validation(&self) -> bool {
        self.require_data_validation.load(Ordering::Relaxed)
    }

    /// Set the [`require_data_validation`](Self::require_data_validation) policy.
    pub fn set_require_data_validation(&self, enabled: bool) {
        self.require_data_validation
            .store(enabled, Ordering::Relaxed);
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

    /// Record activity on this face at `now_ns` (Unix nanoseconds), refreshing
    /// its idle-expiry deadline. As with [`FaceState::new`], `now_ns` must come
    /// from `runtime.unix_nanos()` so the reaper's comparison stays on one
    /// clock.
    pub fn touch(&self, now_ns: u64) {
        self.last_activity.store(now_ns, Ordering::Relaxed);
    }
}

pub struct EngineInner {
    pub start_timestamp_ms: u64,
    pub fib: Arc<Fib>,
    pub rib: Arc<Rib>,
    pub routing: Arc<RoutingManager>,
    pub pit: Arc<Pit>,
    pub dead_nonce_list: Arc<ndn_store::DeadNonceList>,
    pub cs: Arc<dyn ErasedContentStore>,
    pub face_table: Arc<FaceTable>,
    pub measurements: Arc<MeasurementsTable>,
    pub signals: Arc<SignalsTable>,
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
    /// Force Data validation on Local faces as they are added (see
    /// `EngineConfig::require_local_validation`).
    pub(crate) require_local_validation: bool,
    /// G4 egress QoS (opt-in): the per-face scheduler factory (strict-priority or DRR).
    /// `None` ⇒ the FIFO default on every face. The matching classifier lives on the
    /// dispatcher (`name_classifier`), which is where outbound packets are classified.
    pub(crate) egress_factory: Option<crate::egress::EgressSchedulerFactory>,
    pub(crate) face_states: Arc<DashMap<FaceId, FaceState>>,
    pub discovery: Arc<dyn DiscoveryProtocol>,
    pub neighbors: Arc<NeighborTable>,
    /// Reflexive-forwarding reverse routes (temporary, reverse-path routes
    /// installed from `REFLEXIVE_NAME` Interests).
    pub reflexive: Arc<crate::reflexive::ReflexiveTable>,
    /// `OnceLock` breaks the `EngineInner -> Arc<ctx> -> Weak<EngineInner>` cycle.
    pub(crate) discovery_ctx: OnceLock<Arc<EngineDiscoveryContext>>,
    pub(crate) runtime: Arc<dyn Runtime>,
    /// Optional sink observing per-face `Up` / `Down` transitions. Installed
    /// by `mount_management` after engine build (mgmt owns the notification
    /// stream lifecycle).
    pub(crate) face_lifecycle_sink: OnceLock<Arc<dyn ndn_transport::FaceLifecycleSink>>,
    /// Producer regions for NDNLPv2 ForwardingHint stripping (shared with the
    /// strategy stage). Mutable at runtime via [`ForwarderEngine::network_region`]
    /// so a node can declare its own routable prefix as a producer region after
    /// build (e.g. at discovery start).
    pub(crate) network_region: Arc<crate::stages::strategy::NetworkRegionTable>,
}

/// Handle to a running NDN forwarding plane.
///
/// Owns the FIB, PIT, Content Store, face table, and the Tokio task set that
/// drives packet processing. Built via [`EngineBuilder`](crate::EngineBuilder).
/// Cheap to clone: every
/// clone is another reference-counted handle to the *same* running engine, not
/// a new instance — so all clones observe one shared set of tables and tasks.
#[derive(Clone)]
pub struct ForwarderEngine {
    pub(crate) inner: Arc<EngineInner>,
}

impl ForwarderEngine {
    /// Unix timestamp, in milliseconds, when this engine handle was built.
    pub fn start_timestamp_ms(&self) -> u64 {
        self.inner.start_timestamp_ms
    }

    /// The portable task runtime (Tokio on native, `wasm-bindgen-futures` on
    /// wasm). In-engine components that spawn background tasks must use this —
    /// raw `tokio::spawn` panics in the browser.
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::clone(&self.inner.runtime)
    }

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
    pub fn dead_nonce_list(&self) -> Arc<ndn_store::DeadNonceList> {
        Arc::clone(&self.inner.dead_nonce_list)
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

    /// The validator's [`Keyring`](ndn_security::Keyring) — the set of trust
    /// contexts this engine dispatches validation against. Adopting a context
    /// here makes Data under its namespace verifiable without rebuilding the
    /// engine. `None` when no validator is configured.
    pub fn keyring(&self) -> Option<Arc<ndn_security::Keyring>> {
        self.inner
            .validator
            .as_ref()
            .map(|v| Arc::clone(v.keyring()))
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

    /// The NDNLPv2 ForwardingHint producer-region table (NFD
    /// `NetworkRegionTable`). A node adds its own routable prefix here so a
    /// hinted Interest that reaches it is stripped and forwarded by name to the
    /// local producer. Mutable at runtime via [`NetworkRegionTable::add_region`].
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn network_region(&self) -> Arc<crate::stages::strategy::NetworkRegionTable> {
        Arc::clone(&self.inner.network_region)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn neighbors(&self) -> Arc<NeighborTable> {
        Arc::clone(&self.inner.neighbors)
    }

    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn measurements(&self) -> Arc<MeasurementsTable> {
        Arc::clone(&self.inner.measurements)
    }

    /// The cross-layer signal store. Signal sources push readings here; the
    /// strategy stage reads it via `StrategyContext::signals`.
    pub fn signals(&self) -> Arc<SignalsTable> {
        Arc::clone(&self.inner.signals)
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

    /// Remove a face and all routing that points at it: cancel its I/O task,
    /// tear down RIB/FIB nexthops on it, and drop it from the face table. The
    /// counterpart to [`Self::add_face`] for faces that come and go at runtime
    /// (e.g. a Wi-Fi Aware NDP that the platform tears down). Idempotent.
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn remove_face(&self, face_id: FaceId) {
        if let Some((_, state)) = self.inner.face_states.remove(&face_id) {
            state.cancel.cancel();
        }
        self.inner.rib.handle_face_down(face_id, &self.inner.fib);
        self.inner.fib.remove_face(face_id);
        self.inner.face_table.remove(face_id);
    }

    pub fn add_face_with_persistency<F: ndn_transport::Transport + 'static>(
        &self,
        face: F,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = face.id();
        self.inner.face_table.insert(face);
        let erased = self
            .inner
            .face_table
            .get(face_id)
            .expect("face was just inserted");
        self.wire_face(erased, cancel, persistency);
    }

    /// Wire an already-composed, table-resident face: register its `FaceState`
    /// and spawn its sender + reader tasks on the engine runtime. Shared by
    /// [`Self::add_face_with_persistency`] (after it wraps a transport into a
    /// `Face`) and `WasmEngineBuilder`, which inserts pre-composed `Arc<Face>`s
    /// and must wire them the same way — without this, a builder-added face
    /// (e.g. the dioxus upstream WebTransport face) sits in the table but can
    /// neither send nor receive.
    pub(crate) fn wire_face(
        &self,
        erased: Arc<ndn_transport::Face>,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        let face_id = erased.id();
        let scope = erased.scope();
        let congestion_policy = CongestionPolicy::default_for_scope(scope);
        let (send_tx, send_rx) = mpsc::channel(DEFAULT_SEND_QUEUE_CAP);
        let mut state = FaceState::new(
            cancel.clone(),
            persistency,
            send_tx.clone(),
            congestion_policy,
            self.inner.runtime.unix_nanos(),
        );
        if self.inner.require_local_validation && scope == ndn_transport::FaceScope::Local {
            state.set_require_data_validation(true);
        }
        // G4: install a per-face egress scheduler when QoS is configured (the factory
        // chooses strict-priority or DRR). The send loop (run_face_sender) reads
        // `state.scheduler` and drains it instead of `send_rx`.
        let scheduler: Option<Arc<dyn crate::egress::EgressScheduler>> =
            self.inner.egress_factory.as_ref().map(|f| f());
        state.scheduler = scheduler.clone();
        self.inner.face_states.insert(face_id, state);

        // Inject the egress queue-depth closure into the LinkService's
        // CongestionMarkingFeature (no-op for PassthroughLinkService). With a scheduler
        // installed the backlog lives entirely in it — enqueue admits into the scheduler
        // and the send loop drains it, so `send_tx`/`send_rx` are bypassed on the data
        // path (not a 1-deep handoff) — so read the scheduler's depth; otherwise read the
        // mpsc's fill level.
        {
            let depth_tx = send_tx.clone();
            let sched = scheduler.clone();
            let queue_depth_fn: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(move || {
                if let Some(s) = &sched {
                    return s.depth().0;
                }
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
            self.inner.runtime.unix_nanos(),
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
        // Discovery's recv path bypasses the LinkService feature pipeline, so
        // feed inbound bytes to the reliability feature here (peer Acks clear
        // tracked frames; received reliable frames queue an Ack). Socket faces
        // drive the same state via `LinkServiceFeature::on_ingress`.
        if let Some(face) = self.inner.face_table.get(face_id)
            && let Some(feature) = face.link_service.reliability_feature_handle()
        {
            feature.note_receive(&raw);
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

    /// Toggle the NFD `LocalFieldsEnabled` flag on `face_id` (bit 0 of
    /// `FaceStatus.Flags`). When enabled, the dispatcher attaches the NDNLPv2
    /// `IncomingFaceId` header to that face's LP-framed egress — the ingress
    /// face of the forwarded Interest/Data — matching NFD's
    /// `GenericLinkService::encodeLpFields` gate on `allowLocalFields`.
    /// Off by default. (In-process source-face provenance for mgmt rides the
    /// tag-bag separately; see `InProcHandle::recv_tagged`.)
    pub fn set_local_fields(&self, face_id: FaceId, enabled: bool) {
        if let Some(state) = self.inner.face_states.get(&face_id) {
            state.set_local_fields_bit(enabled);
        }
    }

    /// Require cryptographic Data validation on `face_id` even when it is
    /// Local-scope. Off by default (Local faces are trusted by OS access
    /// control and skip verification). Enable on a multi-tenant host so a
    /// malicious/buggy local app cannot inject forged Data into the shared CS
    /// or satisfy another app's Interests. Fail-closed: with no validator
    /// configured, Data on a required-validation face is dropped. See
    /// `data_pipeline` and `.claude/notes/partitioned-fwd-design-2026-05-24.md`.
    pub fn set_require_data_validation(&self, face_id: FaceId, enabled: bool) {
        if let Some(state) = self.inner.face_states.get(&face_id) {
            state.set_require_data_validation(enabled);
        }
    }
}

pub(crate) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

/// Cooperative shutdown control for a running [`ForwarderEngine`].
///
/// Signals the engine's cancellation token and then waits on its task tracker
/// so every pipeline, face, and background task drains before returning — an
/// ordered teardown rather than an abrupt drop that could leave sockets or
/// store writes half-finished.
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

    /// Run the engine for the rest of the process's life: consume the handle, giving up
    /// cooperative shutdown. The named replacement for the `std::mem::forget(shutdown)` idiom —
    /// same effect, but it reads as intent instead of a leak workaround. Teardown then happens
    /// at process exit (sockets close abruptly), which is exactly what a daemon or demo that
    /// never shuts down early wants.
    pub fn detach(self) {
        // Deliberate: the cancellation token and task-drain receivers must outlive every
        // engine task, i.e. the whole process. (Dropping them is inert today — tokens don't
        // cancel on drop — but `detach()` pins the contract, not the implementation detail.)
        std::mem::forget(self);
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
    // G4: if this face has an egress scheduler installed, the send loop drains *it* (in
    // priority order) instead of the raw `rx`. `None` ⇒ the FIFO default (drain `rx`).
    let scheduler = face_states.get(&face_id).and_then(|s| s.scheduler.clone());
    // NDNLPv2 reliability lives entirely in the per-face `ReliabilityFeature`
    // (runtime-mutable via `faces/update` / discovery enablement). The send arm
    // frames through it when enabled; the retx tick pumps its retransmissions
    // and Acks. `take_*` are empty when disabled, so the tick is cheap.
    let lp_reliability_feature = face.link_service.reliability_feature_handle();
    // A-LAL idle-fallback beacon (CCLF): the tick emits a beacon on a face that
    // has been silent for the configured interval. Disabled unless a beacon is
    // installed, so the tick stays cheap.
    let a_lal_feature = face.link_service.a_lal_feature_handle();

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
            item = async {
                match scheduler.as_ref() {
                    Some(s) => s.dequeue().await,
                    None => rx.recv().await,
                }
            } => {
                let first = match item {
                    Some(p) => p,
                    None => break,
                };

                let bump = |wires: &[bytes::Bytes]| {
                    if let Some(state) = face_states.get(&face_id) {
                        let total: u64 = wires.iter().map(|w| w.len() as u64).sum();
                        state.counters.out_bytes.fetch_add(total, Ordering::Relaxed);
                    }
                };

                // Reliability frames canonically per packet (TxSequence +
                // piggybacked Acks + retx tracking) and is low-volume, so it
                // bypasses cross-item batching. (A reliable face ignores
                // `intent` headers — its only traffic is header-less control.)
                if lp_reliability_feature.as_ref().is_some_and(|f| f.is_enabled()) {
                    let wires = lp_reliability_feature.as_ref().unwrap().frame(&first.0);
                    bump(&wires);
                    if let Err(e) = face.send_batch(&wires, Some(first.1)).await
                        && handle_send_error(e)
                    {
                        return;
                    }
                } else {
                    // Opportunistic egress batching: drain whatever is already
                    // queued (non-blocking — no added latency at low load) and
                    // coalesce same-`source` runs into one `send_batch`, i.e. a
                    // single `sendmmsg` on UDP. Source grouping keeps the egress
                    // feature context (e.g. IncomingFaceId) correct per frame.
                    //
                    // Drain from whichever queue `first` came from: the scheduler when QoS
                    // is installed (the raw `rx` is bypassed in that mode — enqueue feeds
                    // the scheduler, not the channel — so draining `rx` here would always
                    // be empty and silently collapse batching to one packet per syscall),
                    // else the raw channel.
                    const MAX_DRAIN: usize = 64;
                    let lp = face.kind().uses_lp_framing();
                    let mut items = vec![first];
                    while items.len() < MAX_DRAIN {
                        let next = match scheduler.as_ref() {
                            Some(s) => s.try_dequeue(),
                            None => rx.try_recv().ok(),
                        };
                        match next {
                            Some(i) => items.push(i),
                            None => break,
                        }
                    }
                    let mut idx = 0;
                    while idx < items.len() {
                        let src = items[idx].1;
                        let mut wires = Vec::new();
                        while idx < items.len() && items[idx].1 == src {
                            wires.push(frame_with_intent(&items[idx].0, &items[idx].2, lp));
                            idx += 1;
                        }
                        bump(&wires);
                        if let Err(e) = face.send_batch(&wires, Some(src)).await
                            && handle_send_error(e)
                        {
                            return;
                        }
                    }
                }
            },
            _ = retx_sleep, if lp_reliability_feature.is_some()
                || a_lal_feature.as_ref().is_some_and(|a| a.is_beacon_enabled()) => {
                // Pump the reliability feature's retransmissions and standalone
                // Acks onto the egress path. Both are empty when disabled.
                if let Some(feature) = lp_reliability_feature.as_ref() {
                    for wire in feature.take_retransmissions() {
                        if let Err(e) = face.send_bytes(wire).await
                            && handle_send_error(e)
                        {
                            return;
                        }
                    }
                    if let Some(ack) = feature.take_acks() {
                        let _ = face.send_bytes(ack).await;
                    }
                }
                // A-LAL idle beacon: emit when the face has been silent for the
                // configured interval (a no-op otherwise).
                if let Some(a) = a_lal_feature.as_ref()
                    && let Some(beacon) = a.due_beacon()
                    && let Err(e) = face.send_bytes(beacon).await
                    && handle_send_error(e)
                {
                    return;
                }
            }
        }
    }
}

/// Lets an external face provisioner (interface enumeration, auto-multicast,
/// hotplug — see `ndn_transport::FaceSink`) install and tear down faces on the
/// engine. Implemented here so the provisioner stays decoupled from the engine
/// and is reusable by any engine that embeds a `ForwarderEngine`.
impl ndn_transport::FaceSink for ForwarderEngine {
    fn alloc_face_id(&self) -> FaceId {
        self.faces().alloc_id()
    }

    fn install_transport<T: ndn_transport::Transport + 'static>(
        &self,
        face: T,
        cancel: CancellationToken,
        persistency: FacePersistency,
    ) {
        self.add_face_with_persistency(face, cancel, persistency);
    }

    fn installed_face_ids(&self) -> Vec<FaceId> {
        self.faces().face_ids()
    }

    fn face_local_uri(&self, id: FaceId) -> Option<String> {
        self.faces().get(id).and_then(|f| f.local_uri())
    }

    fn cancel_face(&self, id: FaceId) {
        if let Some(tok) = self.face_token(id) {
            tok.cancel();
        }
    }
}
