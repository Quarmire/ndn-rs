use std::sync::Arc;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use ndn_store::Pit;
use ndn_transport::FaceTable;

use crate::Fib;

/// Shared tables owned by the engine, accessible to all tasks via `Arc`.
pub struct EngineInner {
    pub fib:        Arc<Fib>,
    pub pit:        Arc<Pit>,
    pub face_table: Arc<FaceTable>,
}

/// Handle to a running forwarding engine.
///
/// Cloning the handle gives another reference to the same running engine.
#[derive(Clone)]
pub struct ForwarderEngine {
    pub(crate) inner: Arc<EngineInner>,
}

impl ForwarderEngine {
    /// Access the FIB for prefix registration.
    pub fn fib(&self) -> Arc<Fib> {
        Arc::clone(&self.inner.fib)
    }

    /// Access the face table.
    pub fn faces(&self) -> Arc<FaceTable> {
        Arc::clone(&self.inner.face_table)
    }

    /// Access the PIT.
    pub fn pit(&self) -> Arc<Pit> {
        Arc::clone(&self.inner.pit)
    }
}

/// Handle to gracefully shut down the engine.
pub struct ShutdownHandle {
    pub(crate) cancel: CancellationToken,
    pub(crate) tasks:  JoinSet<()>,
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
