//! Wasm-side `EngineBuilder` analog.
//!
//! The native [`EngineBuilder`](crate::builder::EngineBuilder) imports
//! `ndn-security` (`ring`, `libsqlite3-sys`), which does not build for
//! `wasm32-unknown-unknown`. This builder constructs the same task topology
//! and pipeline, with `ValidationStage` defaulting to permissive (callers
//! that need real verification supply one via [`Self::with_validator`]).
//!
//! Differences from the native builder:
//! - no `SecurityManager` or `CertFetcher`,
//! - `pipeline_threads` is fixed to 1 (single-threaded wasm),
//! - no routing-protocol fan-in (call `engine.routing().enable(...)` later).

use std::sync::{Arc, OnceLock};

use anyhow::Result;
use ndn_discovery_core::{DiscoveryProtocol, NeighborTable, NoDiscovery};
use ndn_packet::Name;
use ndn_runtime::{Runtime, default_runtime};
use ndn_security::Validator;
use ndn_store::{DeadNonceList, ErasedContentStore, LruCs, ObservableCs, Pit, StrategyTable};
use ndn_strategy::{BestRouteStrategy, MeasurementsTable, SignalsTable};
use ndn_transport::{Face, FacePersistency, FaceTable};
use tokio_util::sync::CancellationToken;

use crate::{
    Fib, ForwarderEngine,
    discovery_context::EngineDiscoveryContext,
    dispatcher::PacketDispatcher,
    engine::{EngineInner, ShutdownHandle, TaskTracker},
    enricher::ContextEnricher,
    rib::Rib,
    routing::RoutingManager,
    stages::{
        CsInsertStage, CsLookupStage, ErasedStrategy, PitCheckStage, PitMatchStage, StrategyStage,
        TlvDecodeStage, ValidationStage,
    },
};

/// Configuration knobs that survive the wasm constraint set.
pub struct WasmEngineConfig {
    pub pipeline_channel_cap: usize,
    pub cs_capacity_bytes: usize,
    /// Pre-PIT replay-guard config. Same baseline as native.
    pub replay_guard: crate::replay_guard_config::ReplayGuardConfig,
    /// NDNLPv2 ForwardingHint producer regions (NFD `NetworkRegionTable`).
    /// Empty = this forwarder hosts no producer region. Mirrors native
    /// `EngineConfig::network_region`.
    pub network_region: Vec<ndn_packet::Name>,
    /// Unsolicited-Data caching policy. Mirrors native
    /// `EngineConfig::unsolicited_data`; default `DropAll`.
    pub unsolicited_data: crate::unsolicited::UnsolicitedDataPolicy,
}

impl Default for WasmEngineConfig {
    fn default() -> Self {
        Self {
            pipeline_channel_cap: 1024,
            cs_capacity_bytes: 8 * 1024 * 1024,
            replay_guard: crate::replay_guard_config::ReplayGuardConfig::default(),
            network_region: Vec::new(),
            unsolicited_data: crate::unsolicited::UnsolicitedDataPolicy::default(),
        }
    }
}

pub struct WasmEngineBuilder {
    config: WasmEngineConfig,
    face_table: Arc<FaceTable>,
    pending_faces: Vec<Arc<Face>>,
    strategy: Option<Arc<dyn ErasedStrategy>>,
    enrichers: Vec<Arc<dyn ContextEnricher>>,
    cs: Option<Arc<dyn ErasedContentStore>>,
    discovery: Option<Arc<dyn DiscoveryProtocol>>,
    runtime: Arc<dyn Runtime>,
    validator: Option<Arc<Validator>>,
    replay_guard_override: Option<Option<Arc<ndn_security::ReplayGuard>>>,
    rate_limit_hook: Option<crate::rate_limit_hook::SharedRateLimitHook>,
}

impl WasmEngineBuilder {
    pub fn new(config: WasmEngineConfig) -> Self {
        Self {
            config,
            face_table: Arc::new(FaceTable::new()),
            pending_faces: Vec::new(),
            strategy: None,
            enrichers: Vec::new(),
            cs: None,
            discovery: None,
            runtime: default_runtime(),
            validator: None,
            replay_guard_override: None,
            rate_limit_hook: None,
        }
    }

    /// Install a rate-limit hook. Mirrors `EngineBuilder::with_rate_limit_hook`.
    pub fn with_rate_limit_hook(
        mut self,
        hook: Option<crate::rate_limit_hook::SharedRateLimitHook>,
    ) -> Self {
        self.rate_limit_hook = hook;
        self
    }

    /// Share a pre-built `ReplayGuard` (or pass `None` to disable for tests;
    /// production wasm engines need the integrity floor).
    pub fn with_replay_guard(mut self, guard: Option<Arc<ndn_security::ReplayGuard>>) -> Self {
        self.replay_guard_override = Some(guard);
        self
    }

    /// Test-only escape hatch that disables the replay guard.
    pub fn replay_guard_disabled(self) -> Self {
        self.with_replay_guard(None)
    }

    /// Install a [`Validator`]. Without this call the engine runs in
    /// permissive mode (every Data marked verified).
    pub fn with_validator(mut self, validator: Arc<Validator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Attach a pre-built face. Inserted into the face table before the
    /// dispatcher spawns per-face tasks, so the engine starts with it wired.
    pub fn add_face(mut self, face: Arc<Face>) -> Self {
        self.pending_faces.push(face);
        self
    }

    pub fn with_strategy(mut self, strategy: Arc<dyn ErasedStrategy>) -> Self {
        self.strategy = Some(strategy);
        self
    }

    pub fn with_cs(mut self, cs: Arc<dyn ErasedContentStore>) -> Self {
        self.cs = Some(cs);
        self
    }

    pub fn with_enricher(mut self, enricher: Arc<dyn ContextEnricher>) -> Self {
        self.enrichers.push(enricher);
        self
    }

    pub fn with_discovery(mut self, discovery: Arc<dyn DiscoveryProtocol>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    pub fn with_runtime(mut self, runtime: Arc<dyn Runtime>) -> Self {
        self.runtime = runtime;
        self
    }

    /// Build the engine: spawns per-face tasks, pipeline runner, PIT/RIB
    /// expiry, and idle-face tasks. Same task topology as the native
    /// builder minus security.
    pub fn build(self) -> Result<(ForwarderEngine, ShutdownHandle)> {
        let fib = Arc::new(Fib::new());
        let rib = Arc::new(Rib::new());
        let pit = Arc::new(Pit::new());
        let dead_nonce_list = Arc::new(DeadNonceList::new());
        let base_cs: Arc<dyn ErasedContentStore> = self
            .cs
            .unwrap_or_else(|| Arc::new(LruCs::new(self.config.cs_capacity_bytes)));
        let cs: Arc<dyn ErasedContentStore> = Arc::new(ObservableCs::new(base_cs, None));
        let face_table = self.face_table;
        let measurements = Arc::new(MeasurementsTable::new());
        let signals = Arc::new(SignalsTable::new());

        // Insert builder-added faces into the table now (so the decode stage
        // sees them); their per-face I/O tasks are wired after the engine
        // handle exists, below.
        let pending_faces = self.pending_faces;
        for face in &pending_faces {
            face_table.insert_arc(Arc::clone(face));
        }

        let cancel = CancellationToken::new();
        let runtime = self.runtime;
        let mut tasks = TaskTracker::new(Arc::clone(&runtime));
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

        let reflexive = Arc::new(crate::reflexive::ReflexiveTable::new(
            crate::reflexive::ReflexiveConfig::default(),
        ));

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

        let default_strategy: Arc<dyn ErasedStrategy> = self
            .strategy
            .unwrap_or_else(|| Arc::new(BestRouteStrategy::new()));
        let strategy_table = Arc::new(StrategyTable::<dyn ErasedStrategy>::new());
        strategy_table.insert(&Name::root(), Arc::clone(&default_strategy));

        let face_states = Arc::new(dashmap::DashMap::new());

        let discovery: Arc<dyn DiscoveryProtocol> =
            self.discovery.unwrap_or_else(|| Arc::new(NoDiscovery));
        let neighbors = NeighborTable::new();

        let routing = Arc::new(RoutingManager::new(
            Arc::clone(&rib),
            Arc::clone(&fib),
            Arc::clone(&face_table),
            Arc::clone(&neighbors),
            cancel.clone(),
        ));

        let validator = self.validator;

        let replay_guard: Option<Arc<ndn_security::ReplayGuard>> = match self.replay_guard_override
        {
            Some(explicit) => explicit,
            None => {
                let rg = self.config.replay_guard;
                if rg.enabled {
                    Some(Arc::new(ndn_security::ReplayGuard::new(
                        rg.per_key_capacity,
                        rg.monotonic,
                    )))
                } else {
                    None
                }
            }
        };

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
            // The browser engine has no configured network region (mutable at
            // runtime via ForwarderEngine::network_region); start empty.
            network_region: Arc::new(crate::stages::strategy::NetworkRegionTable::new(Vec::new())),
            validator: validator.clone(),
            replay_guard: replay_guard.clone(),
            pipeline_tx: OnceLock::new(),
            require_local_validation: false,
            face_states: Arc::clone(&face_states),
            discovery: Arc::clone(&discovery),
            neighbors: Arc::clone(&neighbors),
            reflexive: Arc::clone(&reflexive),
            discovery_ctx: OnceLock::new(),
            runtime: Arc::clone(&runtime),
            face_lifecycle_sink: OnceLock::new(),
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
                network_region: Arc::new(crate::stages::strategy::NetworkRegionTable::new(
                    self.config.network_region.clone(),
                )),
            },
            pit_match: PitMatchStage {
                pit: Arc::clone(&pit),
                dead_nonce_list: Some(Arc::clone(&dead_nonce_list)),
            },
            validation: ValidationStage::new(
                validator.clone(),
                None,
                Default::default(),
                Arc::clone(&runtime),
            ),
            cs_insert: CsInsertStage {
                cs: Arc::clone(&cs),
                admission: Arc::new(ndn_store::DefaultAdmissionPolicy),
            },
            unsolicited_policy: self.config.unsolicited_data,
            channel_cap: self.config.pipeline_channel_cap,
            pipeline_threads: 1,
            discovery: Arc::clone(&discovery),
            discovery_ctx: Arc::clone(&discovery_ctx),
            reflexive: Arc::clone(&reflexive),
            rate_limit: self.rate_limit_hook.clone(),
            // wasm drives no signal sources, so the congestion-feedback bridge (which
            // decays via a polled source) has nothing to run it — not wired here.
            congestion_feedback: None,
            // PathControl (producer mobility) is a multi-forwarder concern; not wired
            // into the in-browser single-node engine.
            path_control: None,
            // wasm is single-threaded: the partitioned runtime never applies.
            data_plane: crate::dispatcher::DataPlane::Shared,
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

        // Skip the discovery tick task on wasm: `DiscoveryProtocol::on_tick`
        // takes `std::time::Instant`, which panics on wasm32. The default
        // wasm discovery is `NoDiscovery`, so this loses no function.
        let _ = (&discovery, &discovery_ctx, &runtime);

        for face_id in face_table.face_ids() {
            discovery.on_face_up(face_id, &*discovery_ctx);
        }

        let engine = ForwarderEngine { inner };
        // Wire each builder-added face's I/O (FaceState + sender + reader); the
        // insert_arc above only placed them in the table. Without this, a
        // builder-added face (e.g. the dioxus upstream WebTransport face) can
        // neither send nor receive.
        for face in pending_faces {
            engine.wire_face(face, cancel.child_token(), FacePersistency::Permanent);
        }
        let handle = ShutdownHandle {
            cancel,
            tracker: tasks,
        };
        Ok((engine, handle))
    }
}
