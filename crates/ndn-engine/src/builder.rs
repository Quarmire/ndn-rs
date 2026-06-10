use std::sync::{Arc, OnceLock};

use anyhow::Result;
use ndn_discovery_core::{DiscoveryProtocol, NeighborTable, NoDiscovery};
use ndn_runtime::{Runtime, default_runtime};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use ndn_packet::Name;
use ndn_security::{
    CertFetcher, ReplayGuard, SchemaRule, SecurityManager, SecurityProfile, TrustSchema, Validator,
};
use ndn_store::{
    CsAdmissionPolicy, CsObserver, DeadNonceList, ErasedContentStore, LruCs, ObservableCs, Pit,
    StrategyTable,
};
use ndn_strategy::{BestRouteStrategy, MeasurementsTable, SignalsTable};
use ndn_transport::{FaceTable, Transport};

use crate::observability::targets as t;
use crate::{
    Fib, ForwarderEngine,
    discovery_context::EngineDiscoveryContext,
    dispatcher::PacketDispatcher,
    engine::{EngineInner, ShutdownHandle, TaskTracker},
    enricher::ContextEnricher,
    rib::Rib,
    routing::{RoutingManager, RoutingProtocol},
    stages::{
        CsInsertStage, CsLookupStage, ErasedStrategy, PitCheckStage, PitMatchStage, StrategyStage,
        TlvDecodeStage, ValidationStage,
    },
};

/// Configuration for the forwarding engine.
pub struct EngineConfig {
    pub pipeline_channel_cap: usize,
    pub cs_capacity_bytes: usize,
    /// Number of parallel pipeline processing threads.
    ///
    /// - `0` (default): auto-detect from available CPU parallelism.
    /// - `1`: single-threaded — all pipeline processing runs inline in the
    ///   pipeline runner task (lowest latency, no task spawn overhead).
    /// - `N > 1`: spawn per-packet tokio tasks so up to N pipeline passes
    ///   run in parallel across cores (highest throughput with fragmented
    ///   UDP traffic).
    pub pipeline_threads: usize,
    /// Pre-PIT replay-guard config. Default is "guard on, non-monotonic" —
    /// the safe choice for general-purpose forwarders where signed-Interest
    /// re-attaches after clock skew, device sleep, or process restart are
    /// legitimate.
    pub replay_guard: ReplayGuardConfig,
    /// Reflexive-forwarding defaults (enabled / per-face cap / lifetime). The
    /// values are runtime-mutable afterwards via the `reflexive` mgmt module.
    pub reflexive: crate::reflexive::ReflexiveConfig,
    /// Producer-region prefixes for NDNLPv2 ForwardingHint handling
    /// (NFD NetworkRegionTable). An Interest whose forwarding hint reaches one
    /// of these regions has its hint stripped; otherwise it is forwarded toward
    /// the hint's delegation name. Empty (default) = no local producer region.
    pub network_region: Vec<ndn_packet::Name>,
    /// Whether to opportunistically cache **unsolicited** Data (Data with no
    /// matching PIT entry, e.g. overheard on a broadcast/ad-hoc medium).
    /// Default `DropAll` (NFD parity); `AdmitNetwork` is the choice for a
    /// broadcast bearer. Admitted Data is cached only, never forwarded, and
    /// still must pass validation before entering the CS.
    pub unsolicited_data: crate::unsolicited::UnsolicitedDataPolicy,
    /// Which data-plane runtime to run. Default `Shared` (one pipeline over a
    /// single PIT). `Partitioned` selects the decode-in-RX + per-worker model
    /// and requires the `partitioned-fwd` feature (otherwise it falls back to
    /// `Shared` with a warning). See `crate::dispatcher::DataPlane`.
    pub data_plane: crate::dispatcher::DataPlane,
    /// Require cryptographic Data validation even on Local-scope faces
    /// (IPC/SHM/loopback), which otherwise skip it. Default `false`. Set `true`
    /// on a multi-tenant host so a local app cannot poison the CS or spoof
    /// another namespace; applied to every Local face as it is added.
    pub require_local_validation: bool,
}

pub use crate::replay_guard_config::ReplayGuardConfig;

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            pipeline_channel_cap: 4096,
            cs_capacity_bytes: 64 * 1024 * 1024,
            pipeline_threads: 0,
            replay_guard: ReplayGuardConfig::default(),
            reflexive: crate::reflexive::ReflexiveConfig::default(),
            require_local_validation: false,
            network_region: Vec::new(),
            unsolicited_data: crate::unsolicited::UnsolicitedDataPolicy::default(),
            data_plane: crate::dispatcher::DataPlane::default(),
        }
    }
}

pub struct EngineBuilder {
    config: EngineConfig,
    face_table: Arc<FaceTable>,
    faces: Vec<Box<dyn FnOnce(Arc<FaceTable>) + Send>>,
    strategy: Option<Arc<dyn ErasedStrategy>>,
    security: Option<Arc<SecurityManager>>,
    enrichers: Vec<Arc<dyn ContextEnricher>>,
    signal_sources: Vec<Box<dyn ndn_signal_sources::SignalSource<ndn_transport::FaceId>>>,
    cs: Option<Arc<dyn ErasedContentStore>>,
    admission: Option<Arc<dyn CsAdmissionPolicy>>,
    cs_observer: Option<Arc<dyn CsObserver>>,
    security_profile: SecurityProfile,
    discovery: Option<Arc<dyn DiscoveryProtocol>>,
    routing_protocols: Vec<Arc<dyn RoutingProtocol>>,
    schema_rules: Vec<SchemaRule>,
    /// When `Some`, overrides `config.replay_guard` at `build()` time.
    /// `Some(None)` explicitly disables the guard; `Some(Some(g))` shares
    /// `g` across engines.
    replay_guard_override: Option<Option<Arc<ReplayGuard>>>,
    runtime: Arc<dyn Runtime>,
    rate_limit_hook: Option<crate::rate_limit_hook::SharedRateLimitHook>,
}

impl EngineBuilder {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            face_table: Arc::new(FaceTable::new()),
            faces: Vec::new(),
            strategy: None,
            security: None,
            enrichers: Vec::new(),
            signal_sources: Vec::new(),
            cs: None,
            admission: None,
            cs_observer: None,
            security_profile: SecurityProfile::Default,
            discovery: None,
            routing_protocols: Vec::new(),
            schema_rules: Vec::new(),
            replay_guard_override: None,
            runtime: default_runtime(),
            rate_limit_hook: None,
        }
    }

    /// Install a rate-limit hook consulted after `TlvDecodeStage` (inbound)
    /// and before face dispatch (outbound).
    pub fn with_rate_limit_hook(
        mut self,
        hook: Option<crate::rate_limit_hook::SharedRateLimitHook>,
    ) -> Self {
        self.rate_limit_hook = hook;
        self
    }

    /// Share a pre-built `ReplayGuard`, overriding `config.replay_guard`.
    /// Passing `None` disables the guard (test-only; the per-PIT integrity
    /// floor depends on it in production).
    pub fn with_replay_guard(mut self, guard: Option<Arc<ReplayGuard>>) -> Self {
        self.replay_guard_override = Some(guard);
        self
    }

    /// Test-only escape hatch that disables the replay guard.
    pub fn replay_guard_disabled(self) -> Self {
        self.with_replay_guard(None)
    }

    pub fn runtime(mut self, rt: Arc<dyn Runtime>) -> Self {
        self.runtime = rt;
        self
    }

    /// Pre-allocate a `FaceId` before `build()` so it can be passed to
    /// discovery protocols or other components at construction time.
    pub fn alloc_face_id(&self) -> ndn_transport::FaceId {
        self.face_table.alloc_id()
    }

    /// Add a face built from a [`Transport`] impl, using the default
    /// [`LinkService`](ndn_transport::LinkService) for the transport's
    /// `FaceKind` (Passthrough for local, LpLinkService for non-local).
    pub fn face<T: Transport>(mut self, transport: T) -> Self {
        self.faces.push(Box::new(move |table| {
            table.insert(transport);
        }));
        self
    }

    /// Add a pre-composed [`ndn_transport::Face`]. Use this when you
    /// want to choose a non-default `LinkService`.
    pub fn face_composed(mut self, face: ndn_transport::Face) -> Self {
        self.faces.push(Box::new(move |table| {
            table.insert_face(face);
        }));
        self
    }

    pub fn strategy<S: ErasedStrategy>(mut self, s: S) -> Self {
        self.strategy = Some(Arc::new(s));
        self
    }

    pub fn security(mut self, mgr: SecurityManager) -> Self {
        self.security = Some(Arc::new(mgr));
        self
    }

    pub fn content_store(mut self, cs: Arc<dyn ErasedContentStore>) -> Self {
        self.cs = Some(cs);
        self
    }

    /// Set the unsolicited-Data caching policy (default `DropAll`). Convenience
    /// over building an [`EngineConfig`] by hand.
    pub fn unsolicited_data_policy(
        mut self,
        policy: crate::unsolicited::UnsolicitedDataPolicy,
    ) -> Self {
        self.config.unsolicited_data = policy;
        self
    }

    pub fn admission_policy(mut self, policy: Arc<dyn CsAdmissionPolicy>) -> Self {
        self.admission = Some(policy);
        self
    }

    pub fn cs_observer(mut self, obs: Arc<dyn CsObserver>) -> Self {
        self.cs_observer = Some(obs);
        self
    }

    pub fn security_profile(mut self, p: SecurityProfile) -> Self {
        self.security_profile = p;
        self
    }

    /// Add a static trust schema rule, applied after the profile's default rules.
    pub fn schema_rule(mut self, rule: SchemaRule) -> Self {
        self.schema_rules.push(rule);
        self
    }

    pub fn validator(mut self, v: Arc<Validator>) -> Self {
        self.security_profile = SecurityProfile::Custom(v);
        self
    }

    /// Register the discovery protocol slot. Called by an
    /// [`crate::InstallableProtocol::install`] implementation; the
    /// host does not call this directly.
    pub fn register_discovery(&mut self, d: Arc<dyn DiscoveryProtocol>) {
        self.discovery = Some(d);
    }

    /// Append a routing protocol to the engine's routing manager.
    /// Called by an [`crate::InstallableProtocol::install`]
    /// implementation; the host does not call this directly.
    pub fn register_routing_protocol(&mut self, proto: Arc<dyn RoutingProtocol>) {
        self.routing_protocols.push(proto);
    }

    /// `&mut self` variant of [`Self::face`] for use inside
    /// [`crate::InstallableProtocol::install`].
    pub fn add_face<T: Transport>(&mut self, transport: T) {
        self.faces.push(Box::new(move |table| {
            table.insert(transport);
        }));
    }

    /// `&mut self` variant of [`Self::face_composed`] for use inside
    /// [`crate::InstallableProtocol::install`].
    pub fn add_face_composed(&mut self, face: ndn_transport::Face) {
        self.faces.push(Box::new(move |table| {
            table.insert_face(face);
        }));
    }

    /// Install an [`crate::InstallableProtocol`]. The protocol allocates
    /// its faces, registers itself on the engine's slots, and queues
    /// post-build work in `post_build`.
    pub fn install<P: crate::InstallableProtocol>(
        mut self,
        protocol: Arc<P>,
        post_build: &mut crate::PostBuildQueue,
    ) -> Self {
        protocol.install(&mut self, post_build);
        self
    }

    pub fn context_enricher(mut self, e: Arc<dyn ContextEnricher>) -> Self {
        self.enrichers.push(e);
        self
    }

    /// Register a cross-layer [`SignalSource`](ndn_signal_sources::SignalSource)
    /// (radio metrics, GPS, …). The engine spawns a background task that polls
    /// every registered source on its cadence and pushes readings into the
    /// shared `SignalsTable`, which strategies read via `StrategyContext::signals`.
    pub fn signal_source(
        mut self,
        source: Box<dyn ndn_signal_sources::SignalSource<ndn_transport::FaceId>>,
    ) -> Self {
        self.signal_sources.push(source);
        self
    }

    pub async fn build(mut self) -> Result<(ForwarderEngine, ShutdownHandle)> {
        let fib = Arc::new(Fib::new());
        let rib = Arc::new(Rib::new());
        let pit = Arc::new(Pit::new());
        let dead_nonce_list = Arc::new(DeadNonceList::new());
        let base_cs: Arc<dyn ErasedContentStore> = self
            .cs
            .unwrap_or_else(|| Arc::new(LruCs::new(self.config.cs_capacity_bytes)));
        let cs: Arc<dyn ErasedContentStore> = if let Some(obs) = self.cs_observer {
            Arc::new(ObservableCs::new(base_cs, Some(obs)))
        } else {
            base_cs
        };
        let face_table = self.face_table;
        let measurements = Arc::new(MeasurementsTable::new());
        let signals = Arc::new(SignalsTable::new());

        for add_face in self.faces {
            add_face(Arc::clone(&face_table));
        }

        let cancel = CancellationToken::new();
        let runtime = self.runtime;
        let mut tasks = TaskTracker::new(Arc::clone(&runtime));

        let reflexive = Arc::new(crate::reflexive::ReflexiveTable::new(self.config.reflexive));

        // Must outlive the expiry task, which credits `NUnsatisfiedInterests`
        // on the in-faces of timed-out PIT entries.
        let face_states: Arc<dashmap::DashMap<ndn_transport::FaceId, crate::engine::FaceState>> =
            Arc::new(dashmap::DashMap::new());

        {
            let pit_clone = Arc::clone(&pit);
            let dead_nonce_list_clone = Some(Arc::clone(&dead_nonce_list));
            let face_states_clone = Arc::clone(&face_states);
            let cancel_clone = cancel.clone();
            let runtime_clone = Arc::clone(&runtime);
            tasks.spawn(async move {
                crate::expiry::run_expiry_task(
                    pit_clone,
                    dead_nonce_list_clone,
                    face_states_clone,
                    cancel_clone,
                    runtime_clone,
                )
                .await;
            });
        }

        {
            let rib_clone = Arc::clone(&rib);
            let fib_clone = Arc::clone(&fib);
            let reflexive_clone = Arc::clone(&reflexive);
            let cancel_clone = cancel.clone();
            let runtime_clone = Arc::clone(&runtime);
            tasks.spawn(async move {
                crate::expiry::run_rib_expiry_task(
                    rib_clone,
                    fib_clone,
                    reflexive_clone,
                    cancel_clone,
                    runtime_clone,
                )
                .await;
            });
        }

        if !self.signal_sources.is_empty() {
            let sources = std::mem::take(&mut self.signal_sources);
            let signals_clone = Arc::clone(&signals);
            let cancel_clone = cancel.clone();
            let runtime_clone = Arc::clone(&runtime);
            tasks.spawn(async move {
                crate::signals_driver::run_signal_sources(
                    sources,
                    signals_clone,
                    cancel_clone,
                    runtime_clone,
                )
                .await;
            });
        }

        let default_strategy: Arc<dyn ErasedStrategy> = self
            .strategy
            .unwrap_or_else(|| Arc::new(BestRouteStrategy::new()));
        let strategy_table = Arc::new(StrategyTable::<dyn ErasedStrategy>::new());
        strategy_table.insert(&Name::root(), Arc::clone(&default_strategy));

        let (validator, cert_fetcher) =
            resolve_security_profile(self.security_profile, &self.security);

        if let Some(v) = &validator {
            for rule in self.schema_rules {
                v.add_schema_rule(rule);
            }
        }

        let engine_validator = validator.clone();

        let replay_guard: Option<Arc<ReplayGuard>> = match self.replay_guard_override {
            Some(explicit) => explicit,
            None => {
                let rg = self.config.replay_guard;
                if rg.enabled {
                    Some(Arc::new(ReplayGuard::new(
                        rg.per_key_capacity,
                        rg.monotonic,
                    )))
                } else {
                    None
                }
            }
        };

        let discovery: Arc<dyn DiscoveryProtocol> =
            self.discovery.unwrap_or_else(|| Arc::new(NoDiscovery));
        let neighbors = NeighborTable::new();

        // Shared between the strategy stage (reads it for ForwardingHint
        // stripping) and `EngineInner` (so a node can add its own producer
        // region at runtime — see `ForwarderEngine::network_region`).
        let network_region = Arc::new(crate::stages::strategy::NetworkRegionTable::new(
            self.config.network_region.clone(),
        ));

        let routing = Arc::new(RoutingManager::new(
            Arc::clone(&rib),
            Arc::clone(&fib),
            Arc::clone(&face_table),
            Arc::clone(&neighbors),
            cancel.clone(),
        ));

        let inner = Arc::new(EngineInner {
            start_timestamp_ms: crate::engine::unix_time_ms(),
            fib: Arc::clone(&fib),
            rib: Arc::clone(&rib),
            routing: Arc::clone(&routing),
            pit: Arc::clone(&pit),
            dead_nonce_list: Arc::clone(&dead_nonce_list),
            cs: Arc::clone(&cs),
            face_table: Arc::clone(&face_table),
            measurements: Arc::clone(&measurements),
            signals: Arc::clone(&signals),
            strategy_table: Arc::clone(&strategy_table),
            security: self.security,
            validator: engine_validator,
            replay_guard: replay_guard.clone(),
            pipeline_tx: OnceLock::new(),
            require_local_validation: self.config.require_local_validation,
            face_states: Arc::clone(&face_states),
            discovery: Arc::clone(&discovery),
            neighbors: Arc::clone(&neighbors),
            reflexive: Arc::clone(&reflexive),
            discovery_ctx: OnceLock::new(),
            runtime: Arc::clone(&runtime),
            face_lifecycle_sink: OnceLock::new(),
            network_region: Arc::clone(&network_region),
        });

        let discovery_ctx = EngineDiscoveryContext::new(
            Arc::downgrade(&inner),
            Arc::clone(&neighbors),
            cancel.child_token(),
        );
        let _ = inner.discovery_ctx.set(Arc::clone(&discovery_ctx));

        let dispatcher = PacketDispatcher {
            face_table: Arc::clone(&face_table),
            face_states: Arc::clone(&face_states),
            rib: Arc::clone(&rib),
            runtime: Arc::clone(&runtime),
            decode: TlvDecodeStage::new(Arc::clone(&face_table), Arc::clone(&face_states)),
            cs_lookup: CsLookupStage {
                cs: Arc::clone(&cs),
            },
            pit_check: PitCheckStage {
                pit: Arc::clone(&pit),
                dead_nonce_list: Some(Arc::clone(&dead_nonce_list)),
                validator: validator.clone(),
                replay_guard: replay_guard.clone(),
            },
            strategy: StrategyStage {
                strategy_table: Arc::clone(&strategy_table),
                default_strategy: Arc::clone(&default_strategy),
                fib: Arc::clone(&fib),
                measurements: Arc::clone(&measurements),
                signals: Arc::clone(&signals),
                pit: Arc::clone(&pit),
                face_table: Arc::clone(&face_table),
                enrichers: self.enrichers,
                runtime: Arc::clone(&runtime),
                network_region: Arc::clone(&network_region),
            },
            pit_match: PitMatchStage {
                pit: Arc::clone(&pit),
                dead_nonce_list: Some(Arc::clone(&dead_nonce_list)),
            },
            validation: ValidationStage::new(
                validator,
                cert_fetcher,
                crate::stages::validation::PendingQueueConfig::default(),
                Arc::clone(&runtime),
            ),
            cs_insert: CsInsertStage {
                cs: Arc::clone(&cs),
                admission: self
                    .admission
                    .unwrap_or_else(|| Arc::new(ndn_store::DefaultAdmissionPolicy)),
            },
            unsolicited_policy: self.config.unsolicited_data,
            channel_cap: self.config.pipeline_channel_cap,
            pipeline_threads: resolve_pipeline_threads(self.config.pipeline_threads),
            discovery: Arc::clone(&discovery),
            discovery_ctx: Arc::clone(&discovery_ctx),
            reflexive: Arc::clone(&reflexive),
            rate_limit: self.rate_limit_hook.clone(),
            data_plane: self.config.data_plane,
        };

        let pipeline_tx = dispatcher.spawn(cancel.clone(), &mut tasks);

        let _ = inner.pipeline_tx.set(pipeline_tx);

        {
            let face_states_clone = Arc::clone(&face_states);
            let face_table_clone = Arc::clone(&face_table);
            let fib_clone = Arc::clone(&fib);
            let rib_clone = Arc::clone(&rib);
            let cancel_clone = cancel.clone();
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            let runtime_clone = Arc::clone(&runtime);
            tasks.spawn(async move {
                crate::expiry::run_idle_face_task(
                    face_states_clone,
                    face_table_clone,
                    fib_clone,
                    rib_clone,
                    cancel_clone,
                    d,
                    ctx,
                    runtime_clone,
                )
                .await;
            });
        }

        {
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            let cancel_clone = cancel.clone();
            let tick_dur = discovery.tick_interval();
            let runtime_for_tick = Arc::clone(&runtime);
            tasks.spawn(
                async move {
                    loop {
                        let sleep = runtime_for_tick.sleep(tick_dur);
                        tokio::select! {
                            _ = cancel_clone.cancelled() => break,
                            _ = sleep => {
                                d.on_tick(std::time::Instant::now(), &*ctx);
                            }
                        }
                    }
                }
                .instrument(tracing::info_span!(target: t::ENGINE, "engine_task")),
            );
        }

        for face_id in face_table.face_ids() {
            discovery.on_face_up(face_id, &*discovery_ctx);
        }

        for proto in self.routing_protocols {
            routing.enable(proto).await;
        }

        let engine = ForwarderEngine { inner };
        let handle = ShutdownHandle {
            cancel,
            tracker: tasks,
        };
        Ok((engine, handle))
    }
}

fn resolve_security_profile(
    profile: SecurityProfile,
    security: &Option<Arc<SecurityManager>>,
) -> (Option<Arc<Validator>>, Option<Arc<CertFetcher>>) {
    use std::time::Duration;

    match profile {
        SecurityProfile::Disabled => (None, None),

        SecurityProfile::Custom(v) => (Some(v), None),

        SecurityProfile::AcceptSigned => {
            let validator = if let Some(mgr) = security {
                // Share the manager's keyring: its ambient context already
                // holds the loaded anchors; just set the operative schema.
                mgr.keyring()
                    .ambient()
                    .set_schema(TrustSchema::accept_all());
                Arc::new(Validator::with_keyring(
                    Arc::clone(mgr.keyring()),
                    mgr.cert_cache_arc(),
                    None,
                    1,
                ))
            } else {
                Arc::new(Validator::new(TrustSchema::accept_all()))
            };
            (Some(validator), None)
        }

        SecurityProfile::Default => {
            let Some(mgr) = security else {
                tracing::info!(target: t::SECURITY,
                    "No SecurityManager configured; using AcceptSigned validation \
                     (DigestSha256 or stronger required, hierarchy not enforced). \
                     Configure a [security] block with trust anchors for full \
                     hierarchical validation."
                );
                let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
                return (Some(validator), None);
            };

            // Share the manager's keyring (its ambient context holds the
            // loaded anchors) and cert cache (holds issued certs), so the
            // validator sees CA-issued material without copying. Set the
            // operative schema on the shared ambient context.
            mgr.keyring()
                .ambient()
                .set_schema(TrustSchema::hierarchical());
            let cert_cache = mgr.cert_cache_arc();

            // No-op FetchFn placeholder; the router wires a real one via
            // AppFace after engine construction.
            let fetcher = Arc::new(CertFetcher::new(
                Arc::clone(&cert_cache),
                Arc::new(|_name| Box::pin(async { None })),
                Duration::from_secs(4),
            ));

            let validator = Arc::new(Validator::with_keyring(
                Arc::clone(mgr.keyring()),
                cert_cache,
                Some(Arc::clone(&fetcher)),
                5,
            ));

            (Some(validator), Some(fetcher))
        }
    }
}

/// Resolve `pipeline_threads` config: 0 → auto-detect, otherwise clamp to ≥ 1.
fn resolve_pipeline_threads(configured: usize) -> usize {
    if configured == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A face that captures every packet the engine sends to it.
    struct CaptureFace {
        id: ndn_transport::FaceId,
        tx: tokio::sync::mpsc::UnboundedSender<bytes::Bytes>,
    }
    impl ndn_transport::Transport for CaptureFace {
        fn id(&self) -> ndn_transport::FaceId {
            self.id
        }
        fn kind(&self) -> ndn_transport::FaceKind {
            ndn_transport::FaceKind::App
        }
        async fn send_bytes(&self, pkt: bytes::Bytes) -> Result<(), ndn_transport::FaceError> {
            let _ = self.tx.send(pkt);
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<bytes::Bytes, ndn_transport::FaceError> {
            std::future::pending::<Result<bytes::Bytes, ndn_transport::FaceError>>().await
        }
    }

    /// Register a capture face; returns its id and a receiver of every packet
    /// the engine sends to it.
    fn add_capture(
        engine: &ForwarderEngine,
    ) -> (
        ndn_transport::FaceId,
        tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>,
    ) {
        let id = engine.faces().alloc_id();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        engine.add_face(
            CaptureFace { id, tx },
            tokio_util::sync::CancellationToken::new(),
        );
        (id, rx)
    }

    /// Inject `wire` as if it arrived on `face`.
    async fn inject(engine: &ForwarderEngine, wire: bytes::Bytes, face: ndn_transport::FaceId) {
        engine
            .inject_packet(wire, face, 0, ndn_discovery_core::InboundMeta::none())
            .await
            .expect("inject");
    }

    /// True iff a bare Interest named `expect` is delivered on `rx` within
    /// `window` (LP-wrapped Nacks and other frames are skipped).
    async fn received_interest(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<bytes::Bytes>,
        expect: &str,
        window: Duration,
    ) -> bool {
        let scan = async {
            while let Some(pkt) = rx.recv().await {
                if let Ok(i) = ndn_packet::Interest::decode(pkt)
                    && i.name.to_string() == expect
                {
                    return true;
                }
            }
            false
        };
        tokio::time::timeout(window, scan).await.unwrap_or(false)
    }

    #[tokio::test]
    async fn build_returns_usable_engine() {
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let _ = engine.fib();
        let _ = engine.pit();
        let _ = engine.faces();
        let _ = engine.cs();
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn default_build_has_replay_guard_active() {
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        assert!(
            engine.replay_guard().is_some(),
            "production-default build must populate PitCheckStage.replay_guard \
             (PIT substrate doctrine); got None"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn replay_guard_disabled_escape_hatch_works() {
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .replay_guard_disabled()
            .build()
            .await
            .unwrap();
        assert!(
            engine.replay_guard().is_none(),
            "replay_guard_disabled() must produce engine with no guard"
        );
        handle.shutdown().await;
    }

    #[test]
    fn replay_guard_config_defaults_documented() {
        let d = ReplayGuardConfig::default();
        assert!(d.enabled, "default must enable the guard");
        assert_eq!(d.per_key_capacity, 64);
        assert!(!d.monotonic, "default monotonic must be false");

        let off = ReplayGuardConfig::disabled();
        assert!(!off.enabled);

        let mono = ReplayGuardConfig::monotonic();
        assert!(mono.enabled && mono.monotonic);
        assert_eq!(mono.per_key_capacity, 64);
    }

    #[tokio::test]
    async fn engine_clone_shares_same_tables() {
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let clone = engine.clone();
        assert!(Arc::ptr_eq(&engine.fib(), &clone.fib()));
        handle.shutdown().await;
    }

    // RF §2b witness: an Interest carrying a REFLEXIVE_NAME installs a reverse
    // route pointing at the ingress face.
    #[tokio::test]
    async fn reflexive_route_installed_on_ingress() {
        use ndn_packet::encode::InterestBuilder;
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();

        let rname: ndn_packet::Name = "/rfx/ingress-test".parse().unwrap();
        let wire = InterestBuilder::new("/some/compute/job")
            .reflexive_name(rname.clone())
            .lifetime(Duration::from_secs(4))
            .build();

        engine
            .inject_packet(
                wire,
                ndn_transport::FaceId(42),
                0,
                ndn_discovery_core::InboundMeta::none(),
            )
            .await
            .expect("inject");

        let mut found = None;
        for _ in 0..100 {
            if let Some(f) = engine.reflexive().lookup(&rname) {
                found = Some(f);
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            found,
            Some(ndn_transport::FaceId(42)),
            "reflexive route must point at the Interest's ingress face",
        );

        handle.shutdown().await;
    }

    // RF §3 witness: a reverse Interest (name under an installed reflexive
    // route) is forwarded to the route's face — the exact face the original
    // Interest arrived on — not via FIB.
    #[tokio::test]
    async fn reflexive_reverse_routing_forwards_to_install_face() {
        use ndn_packet::encode::InterestBuilder;

        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let (consumer_id, mut rx) = add_capture(&engine);

        // I1 from the consumer face installs the reverse route R → consumer_id.
        let rname: ndn_packet::Name = "/rfx/reverse-test".parse().unwrap();
        let i1 = InterestBuilder::new("/svc/compute")
            .reflexive_name(rname.clone())
            .lifetime(Duration::from_secs(4))
            .build();
        inject(&engine, i1, consumer_id).await;
        for _ in 0..100 {
            if engine.reflexive().lookup(&rname).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(engine.reflexive().lookup(&rname), Some(consumer_id));

        // I2 named under R, from a different face, must be reverse-routed to the
        // consumer face.
        let i2 = InterestBuilder::new("/rfx/reverse-test/params")
            .lifetime(Duration::from_secs(2))
            .build();
        inject(&engine, i2, ndn_transport::FaceId(777)).await;

        assert!(
            received_interest(&mut rx, "/rfx/reverse-test/params", Duration::from_secs(2)).await,
            "reverse Interest must be forwarded to the route's install face",
        );

        handle.shutdown().await;
    }

    // RF §4 / W-RF-5 witness: a reverse-style Interest with NO matching reflexive
    // route is not reverse-routed (scope confinement) — reflexive names never
    // appear in the FIB, so it NoRoutes instead of leaking to the install face.
    #[tokio::test]
    async fn reflexive_no_route_is_not_reverse_routed() {
        use ndn_packet::encode::InterestBuilder;

        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let (consumer_id, mut rx) = add_capture(&engine);

        // Install a route for R via an I1 from the consumer face.
        let rname: ndn_packet::Name = "/rfx/installed".parse().unwrap();
        let i1 = InterestBuilder::new("/svc/x")
            .reflexive_name(rname.clone())
            .lifetime(Duration::from_secs(4))
            .build();
        inject(&engine, i1, consumer_id).await;
        for _ in 0..100 {
            if engine.reflexive().lookup(&rname).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // A reverse Interest under a DIFFERENT reflexive name (no route) must not
        // reach the install face.
        let other = InterestBuilder::new("/rfx/not-installed/params")
            .lifetime(Duration::from_secs(2))
            .build();
        inject(&engine, other, ndn_transport::FaceId(778)).await;

        assert!(
            !received_interest(
                &mut rx,
                "/rfx/not-installed/params",
                Duration::from_millis(500)
            )
            .await,
            "an Interest under an unrouted reflexive name must not be reverse-routed",
        );

        handle.shutdown().await;
    }

    // RF §4 / W-RF-7 witness: a reflexive route grants reachability only for its
    // own name — it must not widen FIB reachability, so an unrelated normal name
    // is not delivered to the install face.
    #[tokio::test]
    async fn reflexive_route_does_not_widen_reachability() {
        use ndn_packet::encode::InterestBuilder;

        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let (consumer_id, mut rx) = add_capture(&engine);

        let rname: ndn_packet::Name = "/rfx/priv-test".parse().unwrap();
        let i1 = InterestBuilder::new("/svc/y")
            .reflexive_name(rname.clone())
            .lifetime(Duration::from_secs(4))
            .build();
        inject(&engine, i1, consumer_id).await;
        for _ in 0..100 {
            if engine.reflexive().lookup(&rname).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // An unrelated, non-reflexive name must not be delivered to the install
        // face via the reflexive route (no FIB widening / privilege escalation).
        let unrelated = InterestBuilder::new("/some/unrelated/data")
            .lifetime(Duration::from_secs(2))
            .build();
        inject(&engine, unrelated, ndn_transport::FaceId(779)).await;

        assert!(
            !received_interest(&mut rx, "/some/unrelated/data", Duration::from_millis(500)).await,
            "a reflexive route must not make its face reachable for other names",
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_completes_promptly() {
        let (_engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(500), handle.shutdown())
            .await
            .expect("shutdown did not complete within 500 ms");
    }
}
