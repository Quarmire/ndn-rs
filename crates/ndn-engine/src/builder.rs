use std::sync::Arc;

use anyhow::Result;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_store::{ContentStore, LruCs, Pit};
use ndn_transport::{Face, FaceTable};

use crate::{
    engine::{EngineInner, ShutdownHandle},
    Fib, ForwarderEngine,
};

/// Configuration for the forwarding engine.
pub struct EngineConfig {
    /// Capacity of the inter-task channel (backpressure bound).
    pub pipeline_channel_cap: usize,
    /// Content store byte capacity. Zero disables caching.
    pub cs_capacity_bytes: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            pipeline_channel_cap: 1024,
            cs_capacity_bytes:    64 * 1024 * 1024, // 64 MB
        }
    }
}

/// Constructs and wires a `ForwarderEngine`.
pub struct EngineBuilder {
    config: EngineConfig,
    faces:  Vec<Box<dyn FnOnce(Arc<FaceTable>) + Send>>,
}

impl EngineBuilder {
    pub fn new(config: EngineConfig) -> Self {
        Self { config, faces: Vec::new() }
    }

    /// Register a face to be added at startup.
    pub fn face<F: Face>(mut self, face: F) -> Self {
        self.faces.push(Box::new(move |table| { table.insert(face); }));
        self
    }

    /// Build the engine, spawn all tasks, and return handles.
    pub async fn build(self) -> Result<(ForwarderEngine, ShutdownHandle)> {
        let fib        = Arc::new(Fib::new());
        let pit        = Arc::new(Pit::new());
        let face_table = Arc::new(FaceTable::new());

        // Register pre-configured faces.
        for add_face in self.faces {
            add_face(Arc::clone(&face_table));
        }

        let inner = Arc::new(EngineInner {
            fib:        Arc::clone(&fib),
            pit:        Arc::clone(&pit),
            face_table: Arc::clone(&face_table),
        });

        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();

        // Spawn the PIT expiry task.
        {
            let pit_clone    = Arc::clone(&pit);
            let cancel_clone = cancel.clone();
            tasks.spawn(async move {
                crate::expiry::run_expiry_task(pit_clone, cancel_clone).await;
            });
        }

        let engine = ForwarderEngine { inner };
        let handle = ShutdownHandle { cancel, tasks };
        Ok((engine, handle))
    }
}
