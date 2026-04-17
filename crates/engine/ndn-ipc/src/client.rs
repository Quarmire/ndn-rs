use std::sync::Arc;

use ndn_packet::Name;

/// High-level NDN IPC client, generic over face type `F`.
pub struct IpcClient<F> {
    face: Arc<F>,
    namespace: Name,
}

impl<F> IpcClient<F> {
    pub fn new(face: Arc<F>, namespace: Name) -> Self {
        Self { face, namespace }
    }

    pub fn face(&self) -> &F {
        &self.face
    }

    pub fn namespace(&self) -> &Name {
        &self.namespace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_faces::local::InProcFace;
    use ndn_transport::{Face, FaceId};

    #[test]
    fn new_and_accessors() {
        let (face, _rx) = InProcFace::new(FaceId(1), 8);
        let ns = Name::root();
        let client = IpcClient::new(Arc::new(face), ns.clone());
        assert_eq!(client.namespace(), &ns);
        assert_eq!(client.face().id(), FaceId(1));
    }
}
