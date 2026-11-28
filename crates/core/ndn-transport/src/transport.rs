//! `Transport` — raw byte send/recv over one physical or IPC channel.
//!
//! `Face = Transport + LinkService`. NDNLPv2 framing, reliability,
//! congestion marks, and source-face tagging belong to
//! [`LinkService`](crate::link_service::LinkService).
//!
//! `Transport` uses RPIT for static dispatch; the object-safe
//! [`ErasedTransport`] is auto-implemented and is what the face table holds
//! (`Arc<dyn ErasedTransport>`).

use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;

use crate::face::{FaceAddr, FaceError, FaceId, FaceKind, FacePersistency, FaceTrust, LinkType};
use crate::side::{SideClass, SideRefused};

/// Why a `Transport::set_send_mtu` call failed.
///
/// `NotSupported` → 503, `Immutable` → 409, `OutOfRange` → 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtuError {
    NotSupported,
    Immutable,
    OutOfRange { reason: &'static str },
}

impl core::fmt::Display for MtuError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MtuError::NotSupported => f.write_str("set_send_mtu not supported by transport"),
            MtuError::Immutable => f.write_str("send MTU is immutable on this transport"),
            MtuError::OutOfRange { reason } => write!(f, "send MTU out of range: {reason}"),
        }
    }
}

impl std::error::Error for MtuError {}

/// Why a `Transport::set_persistency` call failed. Mirrors [`MtuError`]
/// variant → status-code mapping; kept separate so a transport can support
/// one knob and not the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistencyError {
    NotSupported,
    Immutable,
    OutOfRange { reason: &'static str },
}

impl core::fmt::Display for PersistencyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PersistencyError::NotSupported => {
                f.write_str("set_persistency not supported by transport")
            }
            PersistencyError::Immutable => {
                f.write_str("persistency is immutable on this transport")
            }
            PersistencyError::OutOfRange { reason } => {
                write!(f, "persistency out of range: {reason}")
            }
        }
    }
}

impl std::error::Error for PersistencyError {}

/// OS-attested identity of the process on the other end of a local
/// (Unix-domain) socket, captured when the socket was accepted or connected
/// (`SO_PEERCRED` / `getpeereid`). Used to authorize privileged management
/// verbs, and part of the evidence a socket's constructor weighs in making it
/// a program face ([`FaceTrust::Program`]): the face is a program face only
/// if the node trusts that user ([`StreamFace::program_peer`](crate::StreamFace::program_peer)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    /// Not every platform reports the peer pid (e.g. macOS `getpeereid`).
    pub pid: Option<i32>,
}

/// Raw byte send/recv over a single physical or IPC channel.
///
/// `recv_bytes` has a single consumer (the face's own task). `send_bytes`
/// may be called concurrently and must synchronise internally.
pub trait Transport: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn kind(&self) -> FaceKind;

    /// Remote URI (e.g. `udp4://192.168.1.1:6363`).
    fn remote_uri(&self) -> Option<String> {
        None
    }

    /// Per-face locality, resolved from kind + remote address. For
    /// address-derived kinds (UDP/TCP/WS/WT/WebRTC) a loopback remote is
    /// `Local`. See [`crate::face::resolve_scope`].
    fn scope(&self) -> crate::face::FaceScope {
        crate::face::resolve_scope(self.kind(), self.remote_uri().as_deref())
    }

    /// Whether the forwarder believes the Data this transport delivers
    /// without validating it. Set by the transport's constructor from how the
    /// face was opened (an in-process channel, shared memory, a Unix socket
    /// whose peer the kernel identified as a user the node trusts as its own),
    /// never from the peer's address.
    /// The default is [`FaceTrust::Validated`]: a transport must opt in to
    /// being a program face. See [`FaceTrust`].
    fn trust(&self) -> FaceTrust {
        FaceTrust::Validated
    }

    /// Local URI (e.g. `unix:///run/nfd/nfd.sock`).
    fn local_uri(&self) -> Option<String> {
        None
    }

    fn link_type(&self) -> LinkType {
        LinkType::PointToPoint
    }

    /// Maximum per-frame byte budget. `None` means stream (unbounded);
    /// `Some(n)` is the link MTU and triggers LP fragmentation above it.
    fn send_mtu(&self) -> Option<usize> {
        None
    }

    /// Send one side frame (see [`crate::side`]) on the carrier `class` asks
    /// for. The frame is sent as is: no LP header, no fragmentation, no
    /// reliability. A transport carries side frames only if it opts in by
    /// overriding [`side_frame_max`](Transport::side_frame_max) to a nonzero
    /// length: the default of 0 refuses every frame
    /// [`NotCarried`](SideRefused::NotCarried), so a transport that frames or
    /// decodes what it sends never takes a side frame into its framing by
    /// forgetting to say so. One that opted in refuses a frame that does not
    /// start with the marker [`Malformed`](SideRefused::Malformed) (so an NDN
    /// packet never takes the side path) and one longer than `side_frame_max`
    /// [`TooLarge`](SideRefused::TooLarge), and sends the rest through
    /// [`send_bytes`](Transport::send_bytes); a class the transport does not carry
    /// ([`side_carries`](Transport::side_carries)) is refused
    /// [`NotCarried`](SideRefused::NotCarried) first. A transport with more than one carrier
    /// (QUIC datagram and stream) overrides this and must enforce the same refusals.
    fn send_side(
        &self,
        frame: Bytes,
        class: SideClass,
    ) -> impl Future<Output = Result<(), SideRefused>> + Send {
        async move {
            let max = self.side_frame_max();
            if max == 0 || !self.side_carries(class) {
                return Err(SideRefused::NotCarried);
            }
            if frame.first() != Some(&crate::side::SIDE_MARKER) {
                return Err(SideRefused::Malformed);
            }
            if frame.len() > max {
                return Err(SideRefused::TooLarge {
                    size: frame.len(),
                    max,
                });
            }
            self.send_bytes(frame).await.map_err(Into::into)
        }
    }

    /// Hand one side frame to the carrier without ever waiting. A transport
    /// with a bounded queue or a non-blocking send overrides this; the
    /// default is [`Unsupported`](SideRefused::Unsupported). The forwarder's
    /// fan-out calls this from its reader task, so an override must neither
    /// block nor await.
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        let _ = (frame, class);
        Err(SideRefused::Unsupported)
    }

    /// [`forward_side`](Transport::forward_side) for a frame that arrived over
    /// face `ingress`. The forwarder calls this for every fan-out sink; a
    /// transport that delivers into an application (the in-process face) keeps
    /// the ingress so the application can say which link a frame came over.
    /// The default ignores the ingress and calls `forward_side`. Never blocks.
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        let _ = ingress;
        self.forward_side(frame, class)
    }

    /// The longest side frame [`send_side`](Transport::send_side) accepts; 0
    /// (the default) means this transport carries none. A transport that sends
    /// a frame as is (a datagram, a ring slot) opts in by returning its limit,
    /// usually [`send_mtu`](Transport::send_mtu).
    fn side_frame_max(&self) -> usize {
        0
    }

    /// Whether this transport carries side frames of `class` (see [`crate::side`]): what a
    /// sender that learns of a hop needs to know before it relies on the class. The default
    /// follows [`side_frame_max`](Transport::side_frame_max): a transport that opted in takes
    /// both classes (a frame is sent as is, in order or not, as the medium is), one that did
    /// not takes none. A transport whose medium has no ordered, reliable stream (an Ethernet
    /// segment, a lossy ring) overrides this to say `false` for [`SideClass::Stream`], and
    /// then its `send_side` and `forward_side` refuse that class
    /// [`NotCarried`](SideRefused::NotCarried). It is a fact about the medium, not about the
    /// queue's room now.
    fn side_carries(&self, class: SideClass) -> bool {
        let _ = class;
        self.side_frame_max() != 0
    }

    /// Whether a side frame of `class` handed to [`forward_side`](Transport::forward_side) now
    /// would be taken and not refused [`Full`](SideRefused::Full): what a sender that was told
    /// `Full` waits for before it tries again. A hint: room is not reserved, and a frame can
    /// still find the queue full by the time it is sent. The default is `true`, a transport
    /// with no queue to fill has nothing to wait for. It never blocks.
    fn side_room(&self, class: SideClass) -> bool {
        let _ = class;
        true
    }

    /// [`side_room`](Transport::side_room) for this `frame`: what [`forward_side`](Transport::forward_side)
    /// would answer for this frame, without taking it. A sender that is holding a frame back
    /// asks it with the frame it holds, so that a frame is held back only for what would refuse
    /// it. It matters for a face whose queue the frame may not go through whole (a radio sends
    /// a frame on the phys its policy picks for it, and the queue of a phy it does not pick is
    /// no concern of this frame) and for a face whose bound is in octets (a frame of a mebibyte
    /// is refused where one of a kilobyte is taken): **a face that bounds its queue in octets
    /// MUST override this with the test its forward makes**, since the default has no free octets
    /// to read and answers a frame it will refuse `Full` with room, and the frame is lost at
    /// the first hop that held it back for its sender. The default is `side_room(class)`, the
    /// answer for a face whose one queue every frame goes through and whose bound is in frames.
    /// A hint, as `side_room` is; it never blocks.
    fn side_room_for(&self, frame: &[u8], class: SideClass) -> bool {
        let _ = frame;
        self.side_room(class)
    }

    fn send_bytes(&self, wire: Bytes) -> impl Future<Output = Result<(), FaceError>> + Send;

    /// Send a burst of already-framed datagrams to the same peer in one shot.
    /// The default ships them one at a time; datagram transports may override
    /// with a batched syscall (`sendmmsg`). Used for a single packet's NDNLPv2
    /// fragment burst, so all entries share the destination and ordering.
    fn send_batch(&self, wires: &[Bytes]) -> impl Future<Output = Result<(), FaceError>> + Send {
        async move {
            for wire in wires {
                self.send_bytes(wire.clone()).await?;
            }
            Ok(())
        }
    }

    fn recv_bytes(&self) -> impl Future<Output = Result<Bytes, FaceError>> + Send;

    /// Receive payload + link-layer sender address. Multicast/broadcast
    /// transports override; default returns `None` for the address.
    fn recv_bytes_with_addr(
        &self,
    ) -> impl Future<Output = Result<(Bytes, Option<FaceAddr>), FaceError>> + Send {
        async { self.recv_bytes().await.map(|b| (b, None)) }
    }

    /// Receive payload + sender address + an opaque **local bearer tag**: for a
    /// multi-radio broadcast medium, which of this face's radios received the frame
    /// (`RadioId.0`). Lets a link-service feature attribute per-radio state (e.g. a
    /// reception report's RSSI) to the actual receiving radio. Default: no tag.
    fn recv_bytes_with_meta(
        &self,
    ) -> impl Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>> + Send
    {
        async { self.recv_bytes_with_addr().await.map(|(b, a)| (b, a, None)) }
    }

    /// Send wire bytes plus an in-process originating face id. Only
    /// in-process transports override; wire-level transports drop `source`
    /// (LP-encoded `IncomingFaceId` is the wire counterpart).
    fn send_bytes_with_source(
        &self,
        wire: Bytes,
        _source: FaceId,
    ) -> impl Future<Output = Result<(), FaceError>> + Send {
        self.send_bytes(wire)
    }

    /// Send framed wire bytes to a specific link-layer peer. The default
    /// **ignores `addr`** and delegates to [`send_bytes`](Transport::send_bytes),
    /// so point-to-point transports (UDP unicast, TCP, Unix, InProc) need do
    /// nothing. Shared-medium transports that can address an individual peer
    /// (`MulticastUdpFace`, the L2 multicast Ether faces) should override this
    /// to unicast the reply back to `addr` — the counterpart of the source
    /// returned by [`recv_bytes_with_addr`](Transport::recv_bytes_with_addr).
    fn send_bytes_to(
        &self,
        _addr: FaceAddr,
        wire: Bytes,
    ) -> impl Future<Output = Result<(), FaceError>> + Send {
        self.send_bytes(wire)
    }

    /// Override the effective send MTU at runtime.
    /// `Some(n)` clamps to the transport's hard maximum; `None` reverts
    /// to the default. Returns the effective MTU (`None` for streams).
    /// Transports with create-time MTU should return `Err(Immutable)`.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::NotSupported)
    }

    /// Update the persistency hint. Transports with intrinsic persistency
    /// (Shm, InProc, Internal, Ether multi-access) return `Err(Immutable)`.
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Err(PersistencyError::NotSupported)
    }

    /// Kernel-attested credentials of the connected peer process, for
    /// local socket transports that captured them at accept time. `None`
    /// for every other transport.
    fn peer_credentials(&self) -> Option<PeerCredentials> {
        None
    }
}

/// Object-safe view of [`Transport`]. Auto-implemented for every `Transport`.
#[allow(clippy::type_complexity)]
pub trait ErasedTransport: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn kind(&self) -> FaceKind;
    fn remote_uri(&self) -> Option<String>;
    fn local_uri(&self) -> Option<String>;
    fn link_type(&self) -> LinkType;
    fn send_mtu(&self) -> Option<usize>;
    fn send_side(
        &self,
        frame: Bytes,
        class: SideClass,
    ) -> Pin<Box<dyn Future<Output = Result<(), SideRefused>> + Send + '_>>;
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused>;
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused>;
    fn side_frame_max(&self) -> usize;
    fn side_carries(&self, class: SideClass) -> bool;
    fn side_room(&self, class: SideClass) -> bool;
    fn side_room_for(&self, frame: &[u8], class: SideClass) -> bool;

    fn send_bytes(
        &self,
        wire: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>>;

    fn send_bytes_with_source(
        &self,
        wire: Bytes,
        source: FaceId,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>>;

    fn send_bytes_to(
        &self,
        addr: FaceAddr,
        wire: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>>;

    fn send_batch<'a>(
        &'a self,
        wires: &'a [Bytes],
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>>;

    fn recv_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Bytes, FaceError>> + Send + '_>>;

    fn recv_bytes_with_addr(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Option<FaceAddr>), FaceError>> + Send + '_>>;

    #[allow(clippy::type_complexity)]
    fn recv_bytes_with_meta(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move { self.recv_bytes_with_addr().await.map(|(b, a)| (b, a, None)) })
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError>;
    fn set_persistency(&self, persistency: FacePersistency) -> Result<(), PersistencyError>;
    fn peer_credentials(&self) -> Option<PeerCredentials>;
    fn trust(&self) -> FaceTrust;
}

impl<T: Transport> ErasedTransport for T {
    fn id(&self) -> FaceId {
        Transport::id(self)
    }
    fn kind(&self) -> FaceKind {
        Transport::kind(self)
    }
    fn remote_uri(&self) -> Option<String> {
        Transport::remote_uri(self)
    }
    fn local_uri(&self) -> Option<String> {
        Transport::local_uri(self)
    }
    fn link_type(&self) -> LinkType {
        Transport::link_type(self)
    }
    fn send_mtu(&self) -> Option<usize> {
        Transport::send_mtu(self)
    }
    fn send_side(
        &self,
        frame: Bytes,
        class: SideClass,
    ) -> Pin<Box<dyn Future<Output = Result<(), SideRefused>> + Send + '_>> {
        Box::pin(Transport::send_side(self, frame, class))
    }
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        Transport::forward_side(self, frame, class)
    }
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        Transport::forward_side_from(self, frame, class, ingress)
    }
    fn side_frame_max(&self) -> usize {
        Transport::side_frame_max(self)
    }
    fn side_carries(&self, class: SideClass) -> bool {
        Transport::side_carries(self, class)
    }
    fn side_room(&self, class: SideClass) -> bool {
        Transport::side_room(self, class)
    }
    fn side_room_for(&self, frame: &[u8], class: SideClass) -> bool {
        Transport::side_room_for(self, frame, class)
    }

    fn send_bytes(
        &self,
        wire: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>> {
        Box::pin(Transport::send_bytes(self, wire))
    }

    fn send_bytes_with_source(
        &self,
        wire: Bytes,
        source: FaceId,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>> {
        Box::pin(Transport::send_bytes_with_source(self, wire, source))
    }

    fn send_bytes_to(
        &self,
        addr: FaceAddr,
        wire: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + '_>> {
        Box::pin(Transport::send_bytes_to(self, addr, wire))
    }

    fn send_batch<'a>(
        &'a self,
        wires: &'a [Bytes],
    ) -> Pin<Box<dyn Future<Output = Result<(), FaceError>> + Send + 'a>> {
        Box::pin(Transport::send_batch(self, wires))
    }

    fn recv_bytes(&self) -> Pin<Box<dyn Future<Output = Result<Bytes, FaceError>> + Send + '_>> {
        Box::pin(Transport::recv_bytes(self))
    }

    fn recv_bytes_with_addr(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Option<FaceAddr>), FaceError>> + Send + '_>>
    {
        Box::pin(Transport::recv_bytes_with_addr(self))
    }

    fn recv_bytes_with_meta(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(Transport::recv_bytes_with_meta(self))
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Transport::set_send_mtu(self, mtu)
    }

    fn set_persistency(&self, persistency: FacePersistency) -> Result<(), PersistencyError> {
        Transport::set_persistency(self, persistency)
    }

    fn peer_credentials(&self) -> Option<PeerCredentials> {
        Transport::peer_credentials(self)
    }

    fn trust(&self) -> FaceTrust {
        Transport::trust(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that says nothing about trust is validated: being a
    /// program face is something a constructor asserts, never a default.
    #[test]
    fn a_transport_that_says_nothing_is_validated() {
        struct Silent;
        impl Transport for Silent {
            fn id(&self) -> FaceId {
                FaceId(0)
            }
            fn kind(&self) -> FaceKind {
                FaceKind::App
            }
            async fn send_bytes(&self, _w: Bytes) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
                Err(FaceError::Closed)
            }
        }
        assert_eq!(Transport::trust(&Silent), FaceTrust::Validated);
        let erased: &dyn ErasedTransport = &Silent;
        assert_eq!(erased.trust(), FaceTrust::Validated);
    }

    #[test]
    fn mtu_default_errors_not_supported() {
        struct InertTransport;
        impl Transport for InertTransport {
            fn id(&self) -> FaceId {
                FaceId(0)
            }
            fn kind(&self) -> FaceKind {
                FaceKind::Internal
            }
            async fn send_bytes(&self, _w: Bytes) -> Result<(), FaceError> {
                Ok(())
            }
            async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
                Err(FaceError::Closed)
            }
        }
        let t = InertTransport;
        assert_eq!(
            Transport::set_send_mtu(&t, Some(8800)),
            Err(MtuError::NotSupported),
        );
        assert_eq!(
            Transport::set_send_mtu(&t, None),
            Err(MtuError::NotSupported),
        );
        assert_eq!(
            Transport::set_persistency(&t, FacePersistency::Persistent),
            Err(PersistencyError::NotSupported),
        );

        let erased: &dyn ErasedTransport = &t;
        assert_eq!(erased.set_send_mtu(Some(1500)), Err(MtuError::NotSupported));
        assert_eq!(
            erased.set_persistency(FacePersistency::Permanent),
            Err(PersistencyError::NotSupported),
        );
    }

    /// Records every `send_bytes` and answers with a fixed MTU. It carries side
    /// frames up to `side_max` octets (0: it does not opt in).
    struct Recorder {
        mtu: Option<usize>,
        side_max: usize,
        sent: std::sync::Mutex<Vec<Bytes>>,
        fail: Option<fn() -> FaceError>,
    }
    impl Recorder {
        /// A transport that says nothing about side frames.
        fn new(mtu: Option<usize>) -> Self {
            Self::carrying(mtu, 0)
        }
        fn carrying(mtu: Option<usize>, side_max: usize) -> Self {
            Self {
                mtu,
                side_max,
                sent: std::sync::Mutex::new(Vec::new()),
                fail: None,
            }
        }
    }
    impl Transport for Recorder {
        fn id(&self) -> FaceId {
            FaceId(0)
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Internal
        }
        fn send_mtu(&self) -> Option<usize> {
            self.mtu
        }
        fn side_frame_max(&self) -> usize {
            self.side_max
        }
        async fn send_bytes(&self, w: Bytes) -> Result<(), FaceError> {
            if let Some(fail) = self.fail {
                return Err(fail());
            }
            self.sent.lock().unwrap().push(w);
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            Err(FaceError::Closed)
        }
    }

    /// A transport carries side frames only because it says so: one that overrides
    /// nothing has a `side_frame_max` of 0 whatever its MTU, refuses every frame
    /// (`NotCarried`, marked or not, either class) and sends nothing, so a
    /// transport that frames or decodes what it sends cannot take a side frame
    /// into its framing by forgetting to override.
    #[tokio::test]
    async fn a_transport_that_does_not_opt_in_carries_no_side_frame() {
        for mtu in [None, Some(1452)] {
            let t = Recorder::new(mtu);
            assert_eq!(Transport::side_frame_max(&t), 0);
            let erased: &dyn ErasedTransport = &t;
            assert_eq!(erased.side_frame_max(), 0);
            for class in [SideClass::Datagram, SideClass::Stream] {
                for frame in [
                    marked(10),
                    Bytes::from_static(&[0x05, 0x01, 0x00]),
                    Bytes::new(),
                ] {
                    assert_eq!(
                        Transport::send_side(&t, frame.clone(), class).await,
                        Err(SideRefused::NotCarried),
                        "mtu {mtu:?}, {frame:02x?}"
                    );
                    assert_eq!(
                        erased.send_side(frame, class).await,
                        Err(SideRefused::NotCarried)
                    );
                }
            }
            assert!(t.sent.lock().unwrap().is_empty());
        }
    }

    fn marked(len: usize) -> Bytes {
        let mut v = vec![0xA5; len];
        v[0] = crate::side::SIDE_MARKER;
        Bytes::from(v)
    }

    /// A frame that fits `side_frame_max` reaches `send_bytes` byte-identical, with
    /// no LP wrap; one over it is refused `TooLarge` and nothing is sent. The class
    /// changes nothing.
    #[tokio::test]
    async fn send_side_sends_what_fits_as_is_and_refuses_the_rest() {
        let t = Recorder::carrying(Some(100), 100);
        for class in [SideClass::Datagram, SideClass::Stream] {
            let frame = marked(100);
            Transport::send_side(&t, frame.clone(), class)
                .await
                .unwrap();
            assert_eq!(t.sent.lock().unwrap().pop().unwrap(), frame);

            assert_eq!(
                Transport::send_side(&t, marked(101), class).await,
                Err(SideRefused::TooLarge {
                    size: 101,
                    max: 100
                })
            );
            assert!(t.sent.lock().unwrap().is_empty());
        }

        let erased: &dyn ErasedTransport = &t;
        erased
            .send_side(marked(7), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(t.sent.lock().unwrap().pop().unwrap(), marked(7));
        assert_eq!(
            erased.send_side(marked(101), SideClass::Stream).await,
            Err(SideRefused::TooLarge {
                size: 101,
                max: 100
            })
        );
    }

    /// A transport with no MTU (a stream) that opts in takes the length it says.
    #[tokio::test]
    async fn send_side_takes_the_length_the_transport_says() {
        let t = Recorder::carrying(None, 200_000);
        Transport::send_side(&t, marked(200_000), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(t.sent.lock().unwrap().len(), 1);
    }

    /// Only a marked frame goes on the side path: one that does not start with the
    /// marker (an NDN packet, an empty frame) is refused `Malformed` before the MTU is
    /// looked at, and nothing is sent.
    #[tokio::test]
    async fn send_side_refuses_a_frame_that_does_not_start_with_the_marker() {
        let t = Recorder::carrying(Some(100), 100);
        let ndn = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x41]);
        let too_long_and_unmarked = Bytes::from(vec![0x05; 101]);
        for class in [SideClass::Datagram, SideClass::Stream] {
            for frame in [ndn.clone(), Bytes::new(), too_long_and_unmarked.clone()] {
                assert_eq!(
                    Transport::send_side(&t, frame.clone(), class).await,
                    Err(SideRefused::Malformed),
                    "{frame:02x?}"
                );
                let erased: &dyn ErasedTransport = &t;
                assert_eq!(
                    erased.send_side(frame, class).await,
                    Err(SideRefused::Malformed)
                );
            }
        }
        assert!(t.sent.lock().unwrap().is_empty());
    }

    /// A `send_bytes` failure is reported as the matching refusal.
    #[tokio::test]
    async fn send_side_maps_a_send_failure_to_a_refusal() {
        let mut t = Recorder::carrying(None, 100);
        t.fail = Some(|| FaceError::Closed);
        assert_eq!(
            Transport::send_side(&t, marked(10), SideClass::Datagram).await,
            Err(SideRefused::Closed)
        );
        t.fail = Some(|| FaceError::Full);
        assert_eq!(
            Transport::send_side(&t, marked(10), SideClass::Stream).await,
            Err(SideRefused::Full)
        );
    }

    /// `forward_side` never blocks and, by default, is unsupported; the frame is
    /// not sent by another path. `side_frame_max` is what the transport says,
    /// not its MTU.
    #[test]
    fn forward_side_and_side_frame_max_defaults() {
        let t = Recorder::carrying(Some(1452), 1400);
        assert_eq!(
            Transport::forward_side(&t, marked(10), SideClass::Datagram),
            Err(SideRefused::Unsupported)
        );
        assert!(t.sent.lock().unwrap().is_empty());
        assert_eq!(Transport::side_frame_max(&t), 1400);
        assert_eq!(Transport::side_frame_max(&Recorder::new(Some(1452))), 0);

        let erased: &dyn ErasedTransport = &t;
        assert_eq!(
            erased.forward_side(marked(10), SideClass::Stream),
            Err(SideRefused::Unsupported)
        );
        assert_eq!(erased.side_frame_max(), 1400);
    }
}
