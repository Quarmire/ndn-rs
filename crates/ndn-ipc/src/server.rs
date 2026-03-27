use std::sync::Arc;

use ndn_app::AppFace;
use ndn_packet::Name;

/// High-level NDN IPC server.
///
/// Registers a name prefix and dispatches incoming Interests to handlers.
/// Handlers are registered asynchronously via `AppFace::register_prefix`.
pub struct IpcServer {
    face:   Arc<AppFace>,
    prefix: Name,
}

impl IpcServer {
    pub fn new(face: Arc<AppFace>, prefix: Name) -> Self {
        Self { face, prefix }
    }

    pub fn face(&self) -> &AppFace {
        &self.face
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use ndn_transport::FaceId;

    #[test]
    fn new_and_accessors() {
        let (face, _rx) = AppFace::new(FaceId(2), 8);
        let prefix = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"svc"))
        ]);
        let server = IpcServer::new(Arc::new(face), prefix.clone());
        assert_eq!(server.prefix(), &prefix);
        assert_eq!(server.face().face_id(), FaceId(2));
    }
}
