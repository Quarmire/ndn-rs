use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use ndn_packet::Interest;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

use crate::ComputeRegistry;

/// A synthetic face that routes Interests to registered compute handlers.
///
/// The FIB routes Interests matching `/compute/*` (or any registered prefix)
/// to this face. On receipt via [`Face::send`], `ComputeFace` dispatches to
/// the appropriate [`ComputeHandler`](crate::ComputeHandler), encodes the
/// resulting Data, and makes it available through [`Face::recv`] so the
/// engine pipeline can satisfy the originating PIT entries.
///
/// # Wiring
///
/// Register the face with the engine, then add a FIB route pointing the
/// desired prefix at this face's [`FaceId`]. The engine will forward matching
/// Interests here automatically and pick up computed Data through `recv()`.
pub struct ComputeFace {
    id: FaceId,
    registry: Arc<ComputeRegistry>,
    /// Sink for computed Data wire bytes injected by `send()`.
    tx: mpsc::Sender<Bytes>,
    /// Source consumed by `recv()`. `Mutex` makes `&self` usable from async.
    rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl ComputeFace {
    /// Create a new `ComputeFace` with an internal channel depth of `capacity`
    /// pending computed responses.
    pub fn new(id: FaceId, registry: Arc<ComputeRegistry>) -> Self {
        Self::with_capacity(id, registry, 64)
    }

    /// Create with an explicit response channel capacity.
    pub fn with_capacity(id: FaceId, registry: Arc<ComputeRegistry>, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            id,
            registry,
            tx,
            rx: Mutex::new(rx),
        }
    }
}

impl Face for ComputeFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Compute
    }

    /// Receive the next computed Data packet.
    ///
    /// Blocks until a `send()` call completes computation and enqueues a
    /// response, or returns `FaceError::Closed` if all senders are dropped.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }

    /// Dispatch an incoming Interest to the matching compute handler.
    ///
    /// Decodes the Interest, looks up the handler in the registry via
    /// longest-prefix match, and spawns a task to run the handler and inject
    /// the resulting Data wire bytes back through `recv()`.
    ///
    /// Returns immediately — computation is async and non-blocking.
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let interest = match Interest::decode(pkt) {
            Ok(i) => i,
            Err(e) => {
                warn!("ComputeFace: failed to decode Interest: {e}");
                return Ok(());
            }
        };

        let registry = Arc::clone(&self.registry);
        let tx = self.tx.clone();

        tokio::spawn(async move {
            match registry.dispatch(&interest).await {
                Some(Ok(data)) => {
                    let wire = data.raw().clone();
                    if tx.send(wire).await.is_err() {
                        warn!("ComputeFace: pipeline receiver dropped before Data could be injected");
                    }
                }
                Some(Err(e)) => {
                    warn!("ComputeFace: handler error for {:?}: {e}", interest.name);
                }
                None => {
                    warn!("ComputeFace: no handler registered for {:?}", interest.name);
                }
            }
        });

        Ok(())
    }
}
