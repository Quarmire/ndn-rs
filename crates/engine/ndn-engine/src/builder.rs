use std::sync::{Arc, OnceLock};

use anyhow::Result;
use ndn_discovery::{DiscoveryProtocol, NeighborTable, NoDiscovery};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_security::{
    CertCache, CertFetcher, SchemaRule, SecurityManager, SecurityProfile, TrustSchema, Validator,
};
use ndn_store::{
    CsAdmissionPolicy, CsObserver, ErasedContentStore, LruCs, ObservableCs, Pit, StrategyTable,
};
use ndn_strategy::{BestRouteStrategy, MeasurementsTable};
use ndn_transport::{Face, FaceTable};

use crate::{
    Fib, ForwarderEngine,
    discovery_context::EngineDiscoveryContext,
    dispatcher::PacketDispatcher,
    engine::{EngineInner, ShutdownHandle},
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
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            pipeline_channel_cap: 4096,
            cs_capacity_bytes: 64 * 1024 * 1024, // 64 MB
            pipeline_threads: 0,
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
    cs: Option<Arc<dyn ErasedContentStore>>,
    admission: Option<Arc<dyn CsAdmissionPolicy>>,
    cs_observer: Option<Arc<dyn CsObserver>>,
    security_profile: SecurityProfile,
    discovery: Option<Arc<dyn DiscoveryProtocol>>,
    routing_protocols: Vec<Arc<dyn RoutingProtocol>>,
    schema_rules: Vec<SchemaRule>,
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
            cs: None,
            admission: None,
            cs_observer: None,
            security_profile: SecurityProfile::Default,
            discovery: None,
            routing_protocols: Vec::new(),
            schema_rules: Vec::new(),
        }
    }

    /// Pre-allocate a `FaceId` before `build()` so it can be passed to
    /// discovery protocols or other components at construction time.
    pub fn alloc_face_id(&self) -> ndn_transport::FaceId {
        self.face_table.alloc_id()
    }

    pub fn face<F: Face>(mut self, face: F) -> Self {
        self.faces.push(Box::new(move |table| {
            table.insert(face);
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

    pub fn discovery<D: DiscoveryProtocol>(mut self, d: D) -> Self {
        self.discovery = Some(Arc::new(d));
        self
    }

    pub fn discovery_arc(mut self, d: Arc<dyn DiscoveryProtocol>) -> Self {
        self.discovery = Some(d);
        self
    }

    pub fn routing_protocol<P: RoutingProtocol>(mut self, proto: P) -> Self {
        self.routing_protocols.push(Arc::new(proto));
        self
    }

    pub fn context_enricher(mut self, e: Arc<dyn ContextEnricher>) -> Self {
        self.enrichers.push(e);
        self
    }

    pub async fn build(self) -> Result<(ForwarderEngine, ShutdownHandle)> {
        let fib = Arc::new(Fib::new());
        let rib = Arc::new(Rib::new());
        let pit = Arc::new(Pit::new());
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

        for add_face in self.faces {
            add_face(Arc::clone(&face_table));
        }

        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();

        {
            let pit_clone = Arc::clone(&pit);
            let cancel_clone = cancel.clone();
            tasks.spawn(async move {
                crate::expiry::run_expiry_task(pit_clone, cancel_clone).await;
            });
        }

        {
            let rib_clone = Arc::clone(&rib);
            let fib_clone = Arc::clone(&fib);
            let cancel_clone = cancel.clone();
            tasks.spawn(async move {
                crate::expiry::run_rib_expiry_task(rib_clone, fib_clone, cancel_clone).await;
            });
        }

        let default_strategy: Arc<dyn ErasedStrategy> = self
            .strategy
            .unwrap_or_else(|| Arc::new(BestRouteStrategy::new()));
        let strategy_table = Arc::new(StrategyTable::<dyn ErasedStrategy>::new());
        strategy_table.insert(&Name::root(), Arc::clone(&default_strategy));

        let face_states = Arc::new(dashmap::DashMap::new());

        let (validator, cert_fetcher) =
            resolve_security_profile(self.security_profile, &self.security);

        if let Some(v) = &validator {
            for rule in self.schema_rules {
                v.add_schema_rule(rule);
            }
        }

        let engine_validator = validator.clone();

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

        let inner = Arc::new(EngineInner {
            fib: Arc::clone(&fib),
            rib: Arc::clone(&rib),
            routing: Arc::clone(&routing),
            pit: Arc::clone(&pit),
            cs: Arc::clone(&cs),
            face_table: Arc::clone(&face_table),
            measurements: Arc::clone(&measurements),
            strategy_table: Arc::clone(&strategy_table),
            security: self.security,
            validator: engine_validator,
            pipeline_tx: OnceLock::new(),
            face_states: Arc::clone(&face_states),
            discovery: Arc::clone(&discovery),
            neighbors: Arc::clone(&neighbors),
            discovery_ctx: OnceLock::new(),
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
            decode: TlvDecodeStage {
                face_table: Arc::clone(&face_table),
                reassembly: dashmap::DashMap::new(),
            },
            cs_lookup: CsLookupStage {
                cs: Arc::clone(&cs),
            },
            pit_check: PitCheckStage {
                pit: Arc::clone(&pit),
            },
            strategy: StrategyStage {
                strategy_table: Arc::clone(&strategy_table),
                default_strategy: Arc::clone(&default_strategy),
                fib: Arc::clone(&fib),
                measurements: Arc::clone(&measurements),
                pit: Arc::clone(&pit),
                face_table: Arc::clone(&face_table),
                enrichers: self.enrichers,
            },
            pit_match: PitMatchStage {
                pit: Arc::clone(&pit),
            },
            validation: ValidationStage::new(
                validator,
                cert_fetcher,
                crate::stages::validation::PendingQueueConfig::default(),
            ),
            cs_insert: CsInsertStage {
                cs: Arc::clone(&cs),
                admission: self
                    .admission
                    .unwrap_or_else(|| Arc::new(ndn_store::DefaultAdmissionPolicy)),
            },
            channel_cap: self.config.pipeline_channel_cap,
            pipeline_threads: resolve_pipeline_threads(self.config.pipeline_threads),
            discovery: Arc::clone(&discovery),
            discovery_ctx: Arc::clone(&discovery_ctx),
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
            tasks.spawn(async move {
                crate::expiry::run_idle_face_task(
                    face_states_clone,
                    face_table_clone,
                    fib_clone,
                    rib_clone,
                    cancel_clone,
                    d,
                    ctx,
                )
                .await;
            });
        }

        {
            let d = Arc::clone(&discovery);
            let ctx = Arc::clone(&discovery_ctx);
            let cancel_clone = cancel.clone();
            let tick_dur = discovery.tick_interval();
            tasks.spawn(async move {
                let mut interval = tokio::time::interval(tick_dur);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = cancel_clone.cancelled() => break,
                        _ = interval.tick() => {
                            d.on_tick(std::time::Instant::now(), &*ctx);
                        }
                    }
                }
            });
        }

        for face_id in face_table.face_ids() {
            discovery.on_face_up(face_id, &*discovery_ctx);
        }

        for proto in self.routing_protocols {
            routing.enable(proto);
        }

        let engine = ForwarderEngine { inner };
        let handle = ShutdownHandle { cancel, tasks };
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
            let schema = TrustSchema::accept_all();
            let validator = if let Some(mgr) = security {
                let cert_cache = Arc::new(CertCache::new());
                let anchors = Arc::new(dashmap::DashMap::new());
                for name in mgr.trust_anchor_names() {
                    if let Some(cert) = mgr.trust_anchor(&name) {
                        cert_cache.insert(cert.clone());
                        anchors.insert(name, cert);
                    }
                }
                Arc::new(Validator::with_chain(schema, cert_cache, anchors, None, 1))
            } else {
                Arc::new(Validator::new(schema))
            };
            (Some(validator), None)
        }

        SecurityProfile::Default => {
            let Some(mgr) = security else {
                // No SecurityManager — fall back to AcceptSigned (signature
                // required, hierarchy not enforced).
                tracing::info!(
                    "No SecurityManager configured; using AcceptSigned validation \
                     (DigestSha256 or stronger required, hierarchy not enforced). \
                     Configure a [security] block with trust anchors for full \
                     hierarchical validation."
                );
                let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
                return (Some(validator), None);
            };

            let schema = TrustSchema::hierarchical();
            let cert_cache = Arc::new(CertCache::new());
            let anchors = Arc::new(dashmap::DashMap::new());

            for name in mgr.trust_anchor_names() {
                if let Some(cert) = mgr.trust_anchor(&name) {
                    cert_cache.insert(cert.clone());
                    anchors.insert(name, cert);
                }
            }

            // No-op FetchFn placeholder; the router wires a real one via
            // AppFace after engine construction.
            let fetcher = Arc::new(CertFetcher::new(
                Arc::clone(&cert_cache),
                Arc::new(|_name| Box::pin(async { None })),
                Duration::from_secs(4),
            ));

            let validator = Arc::new(Validator::with_chain(
                schema,
                Arc::clone(&cert_cache),
                anchors,
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
    async fn engine_clone_shares_same_tables() {
        let (engine, handle) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let clone = engine.clone();
        assert!(Arc::ptr_eq(&engine.fib(), &clone.fib()));
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
