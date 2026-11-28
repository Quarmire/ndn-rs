//! In-process NDN face ([`InProcFace`] + [`InProcHandle`]) wiring an
//! application to `ndn_engine::ForwarderEngine` over `tokio::sync::mpsc`.
//!
//! Split from `ndn-face` so wasm32 consumers get the channel face without
//! OS-socket transports.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};

use ndn_transport::face::ScopePolicy;
use ndn_transport::{
    FaceError, FaceId, FaceKind, FacePersistency, FaceTrust, MtuError, PersistencyError, SideClass,
    SideRefused, Transport,
};

/// How many side frames an app's side inbox holds before the face refuses more
/// ([`SideRefused::Full`], counted by [`InProcHandle::side_dropped`]).
pub const SIDE_INBOX_FRAMES: usize = 256;

/// How many octets of side frames the side inbox holds in all: a stream frame may be a mebibyte,
/// so the frame count alone would let one face pin a gigabyte. A frame that would pass it is
/// refused like one that finds the frame bound reached.
pub const SIDE_INBOX_BYTES: usize = 8 * 1024 * 1024;

/// What the face and its handle share of the side inbox: the octets queued and the frames refused.
#[derive(Default)]
struct SideGauge {
    queued: AtomicUsize,
    dropped: AtomicU64,
}

impl SideGauge {
    /// Whether `len` more octets are under the byte bound now: the test `admit` makes, read
    /// without counting anything.
    fn fits(&self, len: usize) -> bool {
        self.queued.load(Ordering::Acquire).saturating_add(len) <= SIDE_INBOX_BYTES
    }

    /// Count `len` octets as queued if the byte bound allows it; false (nothing counted) if not.
    fn admit(&self, len: usize) -> bool {
        let before = self.queued.fetch_add(len, Ordering::AcqRel);
        if before.saturating_add(len) > SIDE_INBOX_BYTES {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            return false;
        }
        true
    }
}

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
/// **Trust.** The application on the other end of the channel is a program
/// of this process: a face of an in-process kind ([`FaceKind::App`],
/// [`FaceKind::Internal`], [`FaceKind::Compute`], …) is a
/// [`FaceTrust::Program`] face. A face stamped with a network kind
/// ([`InProcFace::new_kind`] with `Tcp`, `Udp`, `Multicast`, …) stands in for
/// that network peer, as a test or a simulation does, and is validated like
/// one.
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
    side_tx: mpsc::Sender<(Bytes, FaceId)>,
    side: Arc<SideGauge>,
}

/// Application-side handle to an [`InProcFace`].
///
/// Send Interests with `send`[InProcHandle::send]; receive Data/Nacks with
/// [`recv`][InProcHandle::recv]. The receiver is wrapped in a `Mutex` so
/// `recv()` takes `&self`, enabling concurrent send/recv from different tasks.
pub struct InProcHandle {
    id: FaceId,
    face_tx: mpsc::Sender<Bytes>,
    app_rx: Mutex<mpsc::Receiver<TaggedBytes>>,
    side_rx: Mutex<mpsc::Receiver<(Bytes, FaceId)>>,
    side: Arc<SideGauge>,
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
        let (side_tx, side_rx) = mpsc::channel(SIDE_INBOX_FRAMES);
        let side = Arc::new(SideGauge::default());
        let face = InProcFace {
            id,
            kind,
            face_rx: Mutex::new(face_rx),
            app_tx,
            side_tx,
            side: Arc::clone(&side),
        };
        let handle = InProcHandle {
            id,
            face_tx,
            app_rx: Mutex::new(app_rx),
            side_rx: Mutex::new(side_rx),
            side,
        };
        (face, handle)
    }
}

impl Transport for InProcFace {
    fn trust(&self) -> FaceTrust {
        match self.kind.scope_policy() {
            ScopePolicy::AlwaysLocal => FaceTrust::Program,
            ScopePolicy::AlwaysNonLocal | ScopePolicy::ByRemoteAddress => FaceTrust::Validated,
        }
    }

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

    /// An in-process face carries side frames: the mpsc takes any `Bytes`, so the limit is the
    /// largest frame the faces grant ([`ndn_transport::side_header::STREAM_FRAME_GRANT`], 1 MiB:
    /// one stream frame, the same bound every other carrier of a channel applies). A channel's
    /// datagram frame (at most 9,000 octets) and the shared-memory slot (8,960) both fit.
    fn side_frame_max(&self) -> usize {
        ndn_transport::side_header::STREAM_FRAME_GRANT
    }

    /// Push a side frame into the app's side inbox, waiting for room in the frame queue. The
    /// frame did not arrive over another face, so its ingress is this face's own id. Refused
    /// `Full` (and counted) if it would pass [`SIDE_INBOX_BYTES`].
    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        let _ = class;
        if frame.first() != Some(&ndn_transport::SIDE_MARKER) {
            return Err(SideRefused::Malformed);
        }
        let max = self.side_frame_max();
        if frame.len() > max {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max,
            });
        }
        let len = frame.len();
        if !self.side.admit(len) {
            return Err(SideRefused::Full);
        }
        match self.side_tx.reserve().await {
            Ok(permit) => {
                permit.send((frame, self.id));
                Ok(())
            }
            Err(_) => {
                self.side.queued.fetch_sub(len, Ordering::AcqRel);
                Err(SideRefused::Closed)
            }
        }
    }

    /// Without the face a frame came over there is nothing to tell the app: the engine calls
    /// [`forward_side_from`](Transport::forward_side_from) for every sink.
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        let _ = (frame, class);
        Err(SideRefused::Unsupported)
    }

    /// The engine's path to an app: push `(frame, ingress)` into the side inbox and wake its
    /// consumer. Never blocks and never waits: a frame that finds the inbox at its frame bound
    /// ([`SIDE_INBOX_FRAMES`]) or its byte bound ([`SIDE_INBOX_BYTES`]) is refused
    /// [`Full`](SideRefused::Full) and counted ([`InProcHandle::side_dropped`]); the sender's
    /// receiver sees the gap, as a congested link's would.
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        let _ = class;
        let len = frame.len();
        if !self.side.admit(len) {
            self.side.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(SideRefused::Full);
        }
        match self.side_tx.try_send((frame, ingress)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.side.queued.fetch_sub(len, Ordering::AcqRel);
                self.side.dropped.fetch_add(1, Ordering::Relaxed);
                Err(SideRefused::Full)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.side.queued.fetch_sub(len, Ordering::AcqRel);
                Err(SideRefused::Closed)
            }
        }
    }

    /// Whether the side inbox has room for a frame now: under its frame bound and its byte
    /// bound, the two reads `forward_side_from` makes first. Room is not reserved.
    fn side_room(&self, _class: SideClass) -> bool {
        self.side_tx.capacity() > 0 && self.side.queued.load(Ordering::Acquire) < SIDE_INBOX_BYTES
    }

    /// [`side_room`](Self::side_room) for this frame: the inbox must hold the frame under its
    /// byte bound too (`SideGauge::fits`, the test `forward_side_from` makes), not merely be
    /// under it. A mebibyte stream frame judged room at 7.9 of 8 MiB was refused `Full` by
    /// `forward_side_from` and lost at the first hop, which a sender's hold-back claims to
    /// prevent.
    fn side_room_for(&self, frame: &[u8], _class: SideClass) -> bool {
        self.side_tx.capacity() > 0 && self.side.fits(frame.len())
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

    /// Send a packet to the forwarder (readable via `InProcFace::recv`). A frame that starts
    /// with the side marker ([`ndn_transport::SIDE_MARKER`]) is a side frame: the face reader
    /// peels it before the NDN pipeline and the engine's side table routes it.
    pub async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.face_tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }

    /// [`send`](Self::send) that never waits: [`FaceError::Full`] when the face's queue has no
    /// room, [`FaceError::Closed`] when the engine dropped the face.
    pub fn try_send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.face_tx.try_send(pkt).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => FaceError::Full,
            mpsc::error::TrySendError::Closed(_) => FaceError::Closed,
        })
    }

    /// Completes when the face's queue has room for one more packet (at once if it has), or
    /// when the face is gone. Room is not reserved: [`try_send`](Self::try_send) may still find
    /// the queue full if another sender took it.
    pub async fn send_ready(&self) {
        let _ = self.face_tx.reserve().await;
    }

    /// The next side frame the engine routed to this app, with the id of the face it arrived
    /// over at the forwarder (the engine's [`FaceId`]); `None` once the face is gone and the
    /// inbox is read. Side frames never appear on [`recv`](Self::recv).
    pub async fn recv_side(&self) -> Option<(Bytes, FaceId)> {
        let item = self.side_rx.lock().await.recv().await?;
        self.side.queued.fetch_sub(item.0.len(), Ordering::AcqRel);
        Some(item)
    }

    /// The next side frame if one is queued, without waiting.
    pub fn try_recv_side(&self) -> Option<(Bytes, FaceId)> {
        let item = self.side_rx.try_lock().ok()?.try_recv().ok()?;
        self.side.queued.fetch_sub(item.0.len(), Ordering::AcqRel);
        Some(item)
    }

    /// How many side frames the face refused because the inbox was full (frame or byte
    /// bound) since it was made.
    pub fn side_dropped(&self) -> u64 {
        self.side.dropped.load(Ordering::Relaxed)
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

    /// An in-process face opts in to side frames: `send_side` pushes the frame into the side
    /// inbox (not the NDN queue), byte-identical, whatever the class, up to the stream frame
    /// grant.
    #[tokio::test]
    async fn a_side_frame_reaches_the_handle_unchanged() {
        use ndn_transport::{SIDE_MARKER, SideClass};

        let (face, handle) = InProcFace::new(FaceId(5), 4);
        assert_eq!(
            face.side_frame_max(),
            ndn_transport::side_header::STREAM_FRAME_GRANT
        );
        // An app's face is no lossy medium: both classes are carried.
        assert!(face.side_carries(SideClass::Datagram) && face.side_carries(SideClass::Stream));
        for (class, fill) in [(SideClass::Datagram, 1u8), (SideClass::Stream, 2u8)] {
            let mut v = vec![fill; 100_000];
            v[0] = SIDE_MARKER;
            let frame = Bytes::from(v);
            face.send_side(frame.clone(), class).await.unwrap();
            // The side inbox, not the NDN queue; no other face carried it, so the ingress is
            // the face itself.
            let (got, ingress) = handle.recv_side().await.unwrap();
            assert_eq!(got, frame);
            assert_eq!(ingress, FaceId(5));
        }
        // The handle's frames reach the face's reader as is.
        let up = Bytes::from_static(&[SIDE_MARKER, 0x20, 7]);
        handle.send(up.clone()).await.unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), up);
        // Without an ingress there is nothing to tell the app: `forward_side` is `Unsupported`.
        assert_eq!(
            face.forward_side(up.clone(), SideClass::Datagram),
            Err(ndn_transport::SideRefused::Unsupported)
        );
        // A frame that is no side frame, or is over the limit, is refused.
        assert_eq!(
            face.send_side(Bytes::from_static(&[1, 2, 3]), SideClass::Datagram)
                .await,
            Err(ndn_transport::SideRefused::Malformed)
        );
    }

    /// `forward_side_from` is the engine's non-blocking path to an app: the frame and the face
    /// it came over reach the handle's side inbox, in order, apart from NDN packets (which stay
    /// on `recv`).
    #[tokio::test]
    async fn the_side_inbox_carries_the_frame_and_its_ingress() {
        use ndn_transport::{SIDE_MARKER, SideClass};

        let (face, handle) = InProcFace::new(FaceId(5), 4);
        let frame = |n: u8| Bytes::from(vec![SIDE_MARKER, 0x20, n]);
        face.forward_side_from(frame(1), SideClass::Datagram, FaceId(11))
            .unwrap();
        face.forward_side_from(frame(2), SideClass::Stream, FaceId(12))
            .unwrap();
        face.send_bytes(test_pkt(9)).await.unwrap();
        assert_eq!(handle.recv_side().await, Some((frame(1), FaceId(11))));
        assert_eq!(handle.recv_side().await, Some((frame(2), FaceId(12))));
        assert_eq!(
            handle.recv().await,
            Some(test_pkt(9)),
            "NDN packets stay apart"
        );
        assert_eq!(handle.side_dropped(), 0);
    }

    /// The inbox never blocks the engine: past its frame bound or its byte bound a frame is
    /// refused `Full` and counted, and room that the app made is used again.
    #[tokio::test]
    async fn the_side_inbox_is_bounded_and_counts_its_drops() {
        use ndn_transport::{SIDE_MARKER, SideClass, SideRefused};

        let (face, handle) = InProcFace::new(FaceId(5), 4);
        let small = Bytes::from(vec![SIDE_MARKER, 1, 2]);
        for _ in 0..SIDE_INBOX_FRAMES {
            face.forward_side_from(small.clone(), SideClass::Datagram, FaceId(1))
                .unwrap();
        }
        assert_eq!(
            face.forward_side_from(small.clone(), SideClass::Datagram, FaceId(1)),
            Err(SideRefused::Full)
        );
        assert_eq!(handle.side_dropped(), 1);
        assert!(
            !face.side_room(SideClass::Datagram),
            "an inbox at its frame bound has no room"
        );
        assert!(handle.recv_side().await.is_some());
        assert!(
            face.side_room(SideClass::Datagram),
            "the app took one: there is room for one"
        );
        face.forward_side_from(small.clone(), SideClass::Datagram, FaceId(1))
            .unwrap();
        while handle.try_recv_side().is_some() {}

        // The byte bound: a few big frames fill it long before the frame bound.
        let big = Bytes::from(vec![SIDE_MARKER; SIDE_INBOX_BYTES / 4 + 1]);
        let mut taken = 0;
        while face
            .forward_side_from(big.clone(), SideClass::Stream, FaceId(2))
            .is_ok()
        {
            taken += 1;
            assert!(taken <= 4, "the byte bound must hold");
        }
        assert_eq!(taken, 3);
        assert_eq!(handle.side_dropped(), 2);
        // Closed handle: the face says so instead of counting a drop.
        drop(handle);
        assert_eq!(
            face.forward_side_from(small, SideClass::Datagram, FaceId(1)),
            Err(SideRefused::Closed)
        );
    }

    /// Room for a frame is room for **that** frame: with 7.5 of the 8 MiB byte bound queued, an
    /// inbox takes a small frame and refuses a mebibyte, and `side_room_for` says so before the
    /// frame is sent. `side_room` alone (is the inbox under its bound) said room for the
    /// mebibyte, and the engine's `forward_side_from` then refused it `Full`: a frame the
    /// first hop held back for its sender, lost there.
    #[tokio::test]
    async fn side_room_for_a_frame_reads_the_bound_forward_side_from_checks() {
        use ndn_transport::{SIDE_MARKER, SideClass, SideRefused};

        let (face, handle) = InProcFace::new(FaceId(5), 4);
        let mebibyte = Bytes::from(vec![SIDE_MARKER; 1024 * 1024]);
        let small = Bytes::from(vec![SIDE_MARKER; 1024]);
        for _ in 0..7 {
            face.forward_side_from(mebibyte.clone(), SideClass::Stream, FaceId(1))
                .unwrap();
        }
        face.forward_side_from(
            Bytes::from(vec![SIDE_MARKER; 512 * 1024]),
            SideClass::Stream,
            FaceId(1),
        )
        .unwrap();
        assert!(
            face.side_room(SideClass::Stream),
            "the inbox is under its bound"
        );
        assert!(face.side_room_for(&small, SideClass::Stream));
        assert!(
            !face.side_room_for(&mebibyte, SideClass::Stream),
            "forward_side_from refuses a mebibyte here, and the read said room"
        );
        assert_eq!(
            face.forward_side_from(mebibyte.clone(), SideClass::Stream, FaceId(1)),
            Err(SideRefused::Full)
        );
        face.forward_side_from(small.clone(), SideClass::Stream, FaceId(1))
            .unwrap();
        // Draining one frame makes room for it again.
        assert!(handle.recv_side().await.is_some());
        assert!(face.side_room_for(&mebibyte, SideClass::Stream));
    }

    /// An app's send is `try_send` when it must not wait: `Full` when the face's queue has no
    /// room, and `send_ready` completes once the engine took one.
    #[tokio::test]
    async fn try_send_refuses_when_full_and_send_ready_waits_for_room() {
        let (face, handle) = InProcFace::new(FaceId(5), 2);
        handle.try_send(test_pkt(1)).unwrap();
        handle.try_send(test_pkt(2)).unwrap();
        assert!(matches!(handle.try_send(test_pkt(3)), Err(FaceError::Full)));
        let handle = std::sync::Arc::new(handle);
        let ready = tokio::spawn({
            let handle = std::sync::Arc::clone(&handle);
            async move {
                handle.send_ready().await;
                handle.try_send(test_pkt(3))
            }
        });
        tokio::task::yield_now().await;
        assert!(!ready.is_finished(), "no room yet");
        assert_eq!(face.recv_bytes().await.unwrap(), test_pkt(1));
        assert!(ready.await.unwrap().is_ok());
    }
}
