use std::sync::Arc;

use anyhow::Result;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_security::SecurityManager;
use ndn_store::{LruCs, Pit, StrategyTable};
use ndn_strategy::{BestRouteStrategy, MeasurementsTable};
use ndn_transport::{Face, FaceTable};

use crate::{
    dispatcher::PacketDispatcher,
    engine::{EngineInner, ShutdownHandle},
    stages::{
        CsInsertStage, CsLookupStage, ErasedStrategy, PitCheckStage, PitMatchStage, StrategyStage,
        TlvDecodeStage,
    },
    Fib, ForwarderEngine,
};

/// Configuration for the forwarding engine.
pub struct EngineConfig {
    /// Capacity of the inter-task channel (backpressure bound).
    pub pipeline_channel_cap: usize,
    /// Content store byte capacity. Zero disables caching.
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
            cs_capacity_bytes:    64 * 1024 * 1024, // 64 MB
            pipeline_threads:     0,
        }
    }
}

/// Constructs and wires a `ForwarderEngine`.
pub struct EngineBuilder {
    config:   EngineConfig,
    faces:    Vec<Box<dyn FnOnce(Arc<FaceTable>) + Send>>,
    strategy: Option<Arc<dyn ErasedStrategy>>,
    security: Option<Arc<SecurityManager>>,
}

impl EngineBuilder {
    pub fn new(config: EngineConfig) -> Self {
        Self { config, faces: Vec::new(), strategy: None, security: None }
    }

    /// Register a face to be added at startup.
    pub fn face<F: Face>(mut self, face: F) -> Self {
        self.faces.push(Box::new(move |table| { table.insert(face); }));
        self
    }

    /// Override the forwarding strategy (default: `BestRouteStrategy`).
    pub fn strategy<S: ErasedStrategy>(mut self, s: S) -> Self {
        self.strategy = Some(Arc::new(s));
        self
    }

    /// Set the security manager for signing and verification.
    ///
    /// When set, the engine exposes the manager via `ForwarderEngine::security()`
    /// so pipeline stages and the management layer can access it.
    pub fn security(mut self, mgr: SecurityManager) -> Self {
        self.security = Some(Arc::new(mgr));
        self
    }

    /// Build the engine, spawn all tasks, and return handles.
    pub async fn build(self) -> Result<(ForwarderEngine, ShutdownHandle)> {
        let fib          = Arc::new(Fib::new());
        let pit          = Arc::new(Pit::new());
        let cs           = Arc::new(LruCs::new(self.config.cs_capacity_bytes));
        let face_table   = Arc::new(FaceTable::new());
        let measurements = Arc::new(MeasurementsTable::new());

        // Register pre-configured faces.
        for add_face in self.faces {
            add_face(Arc::clone(&face_table));
        }

        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();

        // PIT expiry task.
        {
            let pit_clone    = Arc::clone(&pit);
            let cancel_clone = cancel.clone();
            tasks.spawn(async move {
                crate::expiry::run_expiry_task(pit_clone, cancel_clone).await;
            });
        }

        // Build strategy table with the default strategy at root.
        let default_strategy: Arc<dyn ErasedStrategy> = self
            .strategy
            .unwrap_or_else(|| Arc::new(BestRouteStrategy::new()));
        let strategy_table = Arc::new(StrategyTable::<dyn ErasedStrategy>::new());
        strategy_table.insert(&Name::root(), Arc::clone(&default_strategy));

        let face_states = Arc::new(dashmap::DashMap::new());

        let dispatcher = PacketDispatcher {
            face_table:  Arc::clone(&face_table),
            face_states: Arc::clone(&face_states),
            decode:      TlvDecodeStage { face_table: Arc::clone(&face_table), reassembly: dashmap::DashMap::new() },
            cs_lookup:   CsLookupStage { cs: Arc::clone(&cs) },
            pit_check:   PitCheckStage { pit: Arc::clone(&pit) },
            strategy:    StrategyStage {
                strategy_table: Arc::clone(&strategy_table),
                default_strategy: Arc::clone(&default_strategy),
                fib:          Arc::clone(&fib),
                measurements: Arc::clone(&measurements),
                pit:          Arc::clone(&pit),
                face_table:   Arc::clone(&face_table),
            },
            pit_match:   PitMatchStage { pit: Arc::clone(&pit) },
            cs_insert:   CsInsertStage {
                cs: Arc::clone(&cs),
                admission: Arc::new(ndn_store::DefaultAdmissionPolicy),
            },
            channel_cap:      self.config.pipeline_channel_cap,
            pipeline_threads: resolve_pipeline_threads(self.config.pipeline_threads),
        };

        let pipeline_tx = dispatcher.spawn(cancel.clone(), &mut tasks);

        // Idle face sweep task.
        {
            let face_states_clone = Arc::clone(&face_states);
            let face_table_clone  = Arc::clone(&face_table);
            let fib_clone         = Arc::clone(&fib);
            let cancel_clone      = cancel.clone();
            tasks.spawn(async move {
                crate::expiry::run_idle_face_task(
                    face_states_clone,
                    face_table_clone,
                    fib_clone,
                    cancel_clone,
                ).await;
            });
        }

        let inner = Arc::new(EngineInner {
            fib:            Arc::clone(&fib),
            pit:            Arc::clone(&pit),
            cs:             Arc::clone(&cs),
            face_table:     Arc::clone(&face_table),
            measurements:   Arc::clone(&measurements),
            strategy_table: Arc::clone(&strategy_table),
            security:       self.security,
            pipeline_tx,
            face_states,
        });

        let engine = ForwarderEngine { inner };
        let handle = ShutdownHandle { cancel, tasks };
        Ok((engine, handle))
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
