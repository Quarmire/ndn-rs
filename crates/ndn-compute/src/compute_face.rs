use crate::ComputeRegistry;
use bytes::Bytes;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};
use std::sync::Arc;

/// A synthetic face that routes Interests to registered compute handlers.
///
/// The FIB routes Interests matching `/compute/*` to this face.
/// On receipt, `ComputeFace` dispatches to the appropriate `ComputeHandler`,
/// and the resulting Data is injected back into the pipeline as if it
/// arrived from a remote face. The CS caches the result automatically.
pub struct ComputeFace {
    id: FaceId,
    #[expect(dead_code)]
    registry: Arc<ComputeRegistry>,
    // Sender to inject computed Data back into the pipeline.
    // TODO: wire to pipeline mpsc channel
}

impl ComputeFace {
    pub fn new(id: FaceId, registry: Arc<ComputeRegistry>) -> Self {
        Self { id, registry }
    }
}

impl Face for ComputeFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Compute
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        // ComputeFace never receives packets from the network —
        // it only injects computed Data back into the pipeline.
        std::future::pending::<Result<Bytes, FaceError>>().await
    }

    async fn send(&self, _pkt: Bytes) -> Result<(), FaceError> {
        // Interests arrive here from the pipeline dispatcher.
        // TODO: decode Interest, dispatch to registry, inject Data.
        Ok(())
    }
}
