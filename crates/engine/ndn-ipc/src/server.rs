use std::sync::Arc;

use ndn_packet::Name;

/// High-level NDN IPC server, generic over face type `F`.
pub struct IpcServer<F> {
    face: Arc<F>,
    prefix: Name,
}

impl<F> IpcServer<F> {
    pub fn new(face: Arc<F>, prefix: Name) -> Self {
        Self { face, prefix }
    }

    pub fn face(&self) -> &F {
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
    use ndn_faces::local::InProcFace;
    use ndn_packet::NameComponent;
    use ndn_transport::{Face, FaceId};

    #[test]
    fn new_and_accessors() {
        let (face, _rx) = InProcFace::new(FaceId(2), 8);
        let prefix = Name::from_components([NameComponent::generic(Bytes::from_static(b"svc"))]);
        let server = IpcServer::new(Arc::new(face), prefix.clone());
        assert_eq!(server.prefix(), &prefix);
        assert_eq!(server.face().id(), FaceId(2));
    }
}
