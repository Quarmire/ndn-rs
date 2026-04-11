use std::sync::Arc;

use ndn_packet::Name;

/// High-level NDN IPC client.
///
/// Generic over the face type `F` so it can work with any transport:
/// - `AppFace` for in-process use (library embedding)
/// - `UnixFace` for cross-process use over a Unix domain socket
/// - A future `ShmFace` for zero-copy cross-process IPC
///
/// The namespace is the root name under which this client operates; it is
/// prepended to all expressed Interests by convention (not enforced here).
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
