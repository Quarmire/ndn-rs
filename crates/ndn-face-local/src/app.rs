use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// In-process NDN face backed by a pair of `tokio::sync::mpsc` channels.
///
/// `AppFace` is held by the forwarder pipeline; `AppHandle` is given to the
/// application (library user). The forwarder sends packets to the app via
/// `AppFace::send` → `app_tx`; the app sends packets to the forwarder via
/// `AppHandle::send` → `face_tx`.
///
/// ```text
///   pipeline            application
///   ────────            ───────────
///   AppFace::recv()  ←  AppHandle::send()   (face_rx ← face_tx)
///   AppFace::send()  →  AppHandle::recv()   (app_tx  → app_rx)
/// ```
///
/// `face_rx` is wrapped in a `Mutex` to satisfy the `&self` requirement of the
/// `Face` trait; the pipeline's single-consumer contract means it never
/// actually contends.
pub struct AppFace {
    id:      FaceId,
    face_rx: Mutex<mpsc::Receiver<Bytes>>,
    app_tx:  mpsc::Sender<Bytes>,
}

/// Application-side handle to an `AppFace`.
///
/// Send Interests with [`send`][AppHandle::send]; receive Data/Nacks with
/// [`recv`][AppHandle::recv].
///
/// The receiver is wrapped in a `Mutex` so that `recv()` takes `&self`,
/// enabling shared ownership (e.g. concurrent send/recv from different tasks).
pub struct AppHandle {
    face_tx: mpsc::Sender<Bytes>,
    app_rx:  Mutex<mpsc::Receiver<Bytes>>,
}

impl AppFace {
    /// Create a linked (`AppFace`, `AppHandle`) pair with `buffer` slots each.
    pub fn new(id: FaceId, buffer: usize) -> (Self, AppHandle) {
        let (face_tx, face_rx) = mpsc::channel(buffer);
        let (app_tx,  app_rx)  = mpsc::channel(buffer);
        let face   = AppFace  { id, face_rx: Mutex::new(face_rx), app_tx };
        let handle = AppHandle { face_tx, app_rx: Mutex::new(app_rx) };
        (face, handle)
    }
}

impl Face for AppFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::App }

    /// Receive a packet sent by the application via `AppHandle::send`.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.face_rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    /// Forward a packet to the application (readable via `AppHandle::recv`).
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.app_tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

impl AppHandle {
    /// Send a packet to the forwarder (readable via `AppFace::recv`).
    pub async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.face_tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }

    /// Receive a packet from the forwarder (sent via `AppFace::send`).
    pub async fn recv(&self) -> Option<Bytes> {
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
        let (face, _handle) = AppFace::new(FaceId(42), 4);
        assert_eq!(face.id(), FaceId(42));
        assert_eq!(face.kind(), FaceKind::App);
    }

    #[tokio::test]
    async fn app_to_pipeline() {
        let (face, handle) = AppFace::new(FaceId(0), 4);
        handle.send(test_pkt(1)).await.unwrap();
        let received = face.recv().await.unwrap();
        assert_eq!(received, test_pkt(1));
    }

    #[tokio::test]
    async fn pipeline_to_app() {
        let (face, handle) = AppFace::new(FaceId(0), 4);
        face.send(test_pkt(2)).await.unwrap();
        let received = handle.recv().await.unwrap();
        assert_eq!(received, test_pkt(2));
    }

    #[tokio::test]
    async fn bidirectional() {
        let (face, handle) = AppFace::new(FaceId(0), 4);
        handle.send(test_pkt(10)).await.unwrap();
        face.send(test_pkt(20)).await.unwrap();
        assert_eq!(face.recv().await.unwrap(), test_pkt(10));
        assert_eq!(handle.recv().await.unwrap(), test_pkt(20));
    }

    #[tokio::test]
    async fn closed_when_handle_dropped() {
        let (face, handle) = AppFace::new(FaceId(0), 4);
        drop(handle);
        assert!(matches!(face.recv().await, Err(FaceError::Closed)));
    }

    #[tokio::test]
    async fn closed_when_face_dropped() {
        let (face, handle) = AppFace::new(FaceId(0), 4);
        drop(face);
        assert!(handle.recv().await.is_none());
    }

    #[tokio::test]
    async fn multiple_sequential_packets() {
        let (face, handle) = AppFace::new(FaceId(0), 8);
        for i in 0u8..5 {
            handle.send(test_pkt(i)).await.unwrap();
        }
        for i in 0u8..5 {
            assert_eq!(face.recv().await.unwrap(), test_pkt(i));
        }
    }
}
