use std::sync::Arc;

use ndn_app::AppFace;
use ndn_packet::Name;

/// High-level NDN IPC client.
///
/// Wraps `AppFace` with ergonomic request-response and subscription APIs.
/// The namespace is the root name under which this client operates; it is
/// prepended to all expressed Interests by convention (not enforced here).
pub struct IpcClient {
    face:      Arc<AppFace>,
    namespace: Name,
}

impl IpcClient {
    pub fn new(face: Arc<AppFace>, namespace: Name) -> Self {
        Self { face, namespace }
    }

    pub fn face(&self) -> &AppFace {
        &self.face
    }

    pub fn namespace(&self) -> &Name {
        &self.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::FaceId;

    #[test]
    fn new_and_accessors() {
        let (face, _rx) = AppFace::new(FaceId(1), 8);
        let ns = Name::root();
        let client = IpcClient::new(Arc::new(face), ns.clone());
        assert_eq!(client.namespace(), &ns);
        assert_eq!(client.face().face_id(), FaceId(1));
    }
}
