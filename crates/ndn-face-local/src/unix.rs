use bytes::Bytes;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// NDN face over a Unix domain socket.
///
/// Used as the control-plane channel for prefix registration and face management.
/// Data-plane traffic uses `AppFace` (in-process mpsc) or shared memory.
pub struct UnixFace {
    id: FaceId,
    path: std::path::PathBuf,
}

impl UnixFace {
    pub fn new(id: FaceId, path: impl Into<std::path::PathBuf>) -> Self {
        Self { id, path: path.into() }
    }
}

impl Face for UnixFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Unix }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        Err(FaceError::Closed) // placeholder
    }

    async fn send(&self, _pkt: Bytes) -> Result<(), FaceError> {
        Err(FaceError::Closed) // placeholder
    }
}
