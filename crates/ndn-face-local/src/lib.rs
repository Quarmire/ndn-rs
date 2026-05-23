//! In-process NDN face ([`InProcFace`] + [`InProcHandle`]) wiring an
//! application to `ndn_engine::ForwarderEngine` over `tokio::sync::mpsc`.
//!
//! Split from `ndn-face-native` so wasm32 consumers get the channel face without
//! OS-socket transports.

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use ndn_transport::{
    FaceError, FaceId, FaceKind, FacePersistency, MtuError, PersistencyError, Transport,
};

/// Bytes plus optional source-face provenance, delivered to an in-process app
/// via [`InProcHandle::recv_tagged`].
///
/// `source_face` is the face the originating packet arrived on, attached by
/// the dispatcher via [`Transport::send_bytes_with_source`]. Mirrors NFD's
/// `IncomingFaceIdTag` (`daemon/face/face-common.hpp`). `None` for packets the
/// dispatcher produced internally (e.g. a Nack it generated).
#[derive(Clone, Debug)]
pub struct TaggedBytes {
    pub wire: Bytes,
    pub source_face: Option<FaceId>,
}

/// In-process NDN face backed by a pair of `tokio::sync::mpsc` channels.
///
/// `InProcFace` is held by the forwarder pipeline; [`InProcHandle`] is given
/// to the application.
///
/// ```text
///   pipeline                 application
///   ────────                 ───────────
///   InProcFace::recv()  ←  InProcHandle::send()   (face_rx ← face_tx)
///   InProcFace::send()  →  InProcHandle::recv()   (app_tx  → app_rx)
/// ```
///
/// `face_rx` is wrapped in a `Mutex` to satisfy the `&self` requirement of
/// the `Face` trait; the pipeline's single-consumer contract means it never
/// actually contends.
pub struct InProcFace {
    id: FaceId,
    kind: FaceKind,
    face_rx: Mutex<mpsc::Receiver<Bytes>>,
    app_tx: mpsc::Sender<TaggedBytes>,
}

/// Application-side handle to an [`InProcFace`].
///
/// Send Interests with [`send`][InProcHandle::send]; receive Data/Nacks with
/// [`recv`][InProcHandle::recv]. The receiver is wrapped in a `Mutex` so
/// `recv()` takes `&self`, enabling concurrent send/recv from different tasks.
pub struct InProcHandle {
    id: FaceId,
    face_tx: mpsc::Sender<Bytes>,
    app_rx: Mutex<mpsc::Receiver<TaggedBytes>>,
}

impl InProcFace {
    /// Create a linked (`InProcFace`, `InProcHandle`) pair with `buffer` slots
    /// each. The face is stamped as [`FaceKind::App`]; use
    /// [`InProcFace::new_kind`] for mgmt/security/compute subsystems.
    pub fn new(id: FaceId, buffer: usize) -> (Self, InProcHandle) {
        Self::new_kind(id, buffer, FaceKind::App)
    }

    /// Like [`InProcFace::new`] but stamps the face with the given
    /// [`FaceKind`]. The variant should reflect the subsystem on the face
    /// (engine) side: [`FaceKind::Internal`] for mgmt-adjacent pairs,
    /// [`FaceKind::Compute`] for in-network-compute responders,
    /// [`FaceKind::App`] for ordinary applications.
    #[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
    pub fn new_kind(id: FaceId, buffer: usize, kind: FaceKind) -> (Self, InProcHandle) {
        let (face_tx, face_rx) = mpsc::channel(buffer);
        let (app_tx, app_rx) = mpsc::channel(buffer);
        let face = InProcFace {
            id,
            kind,
            face_rx: Mutex::new(face_rx),
            app_tx,
        };
        let handle = InProcHandle {
            id,
            face_tx,
            app_rx: Mutex::new(app_rx),
        };
        (face, handle)
    }
}

impl Transport for InProcFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.face_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.app_tx
            .send(TaggedBytes {
                wire: pkt,
                source_face: None,
            })
            .await
            .map_err(|_| FaceError::Closed)
    }

    async fn send_bytes_with_source(&self, pkt: Bytes, source: FaceId) -> Result<(), FaceError> {
        self.app_tx
            .send(TaggedBytes {
                wire: pkt,
                source_face: Some(source),
            })
            .await
            .map_err(|_| FaceError::Closed)
    }

    /// In-process channels have no link MTU (the mpsc carries `Bytes` of
    /// arbitrary size). Always returns [`MtuError::Immutable`].
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::Immutable)
    }

    /// In-process faces live as long as the channel; persistency is intrinsic.
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::Immutable)
    }
}

impl InProcHandle {
    /// `FaceId` of the paired [`InProcFace`] — identifies the *channel*, not
    /// the originating face of any bytes flowing through it. For source-face
    /// provenance (e.g. mgmt authorization) use
    /// [`recv_tagged`](Self::recv_tagged) and read `TaggedBytes::source_face`.
    pub fn face_id(&self) -> FaceId {
        self.id
    }

    /// Send a packet to the forwarder (readable via `InProcFace::recv`).
    pub async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.face_tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }

    /// Receive a packet from the forwarder, discarding any attached
    /// source-face provenance. Use [`recv_tagged`](Self::recv_tagged) when
    /// the receiver needs the originating face id.
    pub async fn recv(&self) -> Option<Bytes> {
        self.app_rx.lock().await.recv().await.map(|t| t.wire)
    }

    /// Receive a packet together with the originating face id, if the
    /// dispatcher attached one via [`Transport::send_bytes_with_source`].
    pub async fn recv_tagged(&self) -> Option<TaggedBytes> {
        self.app_rx.lock().await.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pkt(tag: u8) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[tag]);
        w.finish()
    }

    #[tokio::test]
    async fn face_kind_and_id() {
        let (face, _handle) = InProcFace::new(FaceId(42), 4);
        assert_eq!(face.id(), FaceId(42));
        assert_eq!(face.kind(), FaceKind::App);
    }

    #[tokio::test]
    async fn app_to_pipeline() {
        let (face, handle) = InProcFace::new(FaceId(0), 4);
        handle.send(test_pkt(1)).await.unwrap();
        let received = face.recv_bytes().await.unwrap();
        assert_eq!(received, test_pkt(1));
    }

    #[tokio::test]
    async fn pipeline_to_app() {
        let (face, handle) = InProcFace::new(FaceId(0), 4);
        face.send_bytes(test_pkt(2)).await.unwrap();
        let received = handle.recv().await.unwrap();
        assert_eq!(received, test_pkt(2));
    }

    #[tokio::test]
    async fn bidirectional() {
        let (face, handle) = InProcFace::new(FaceId(0), 4);
        handle.send(test_pkt(10)).await.unwrap();
        face.send_bytes(test_pkt(20)).await.unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), test_pkt(10));
        assert_eq!(handle.recv().await.unwrap(), test_pkt(20));
    }

    #[tokio::test]
    async fn closed_when_handle_dropped() {
        let (face, handle) = InProcFace::new(FaceId(0), 4);
        drop(handle);
        assert!(matches!(face.recv_bytes().await, Err(FaceError::Closed)));
    }

    #[tokio::test]
    async fn closed_when_face_dropped() {
        let (face, handle) = InProcFace::new(FaceId(0), 4);
        drop(face);
        assert!(handle.recv().await.is_none());
    }

    #[tokio::test]
    async fn multiple_sequential_packets() {
        let (face, handle) = InProcFace::new(FaceId(0), 8);
        for i in 0u8..5 {
            handle.send(test_pkt(i)).await.unwrap();
        }
        for i in 0u8..5 {
            assert_eq!(face.recv_bytes().await.unwrap(), test_pkt(i));
        }
    }
}
