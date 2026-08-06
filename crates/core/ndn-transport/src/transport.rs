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

use crate::face::{FaceAddr, FaceError, FaceId, FaceKind, FacePersistency, LinkType};

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
    ) -> impl Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>> + Send {
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
        Box<dyn Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>> + Send + '_>,
    > {
        Box::pin(async move { self.recv_bytes_with_addr().await.map(|(b, a)| (b, a, None)) })
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError>;
    fn set_persistency(&self, persistency: FacePersistency) -> Result<(), PersistencyError>;
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
        Box<dyn Future<Output = Result<(Bytes, Option<FaceAddr>, Option<u16>), FaceError>> + Send + '_>,
    > {
        Box::pin(Transport::recv_bytes_with_meta(self))
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Transport::set_send_mtu(self, mtu)
    }

    fn set_persistency(&self, persistency: FacePersistency) -> Result<(), PersistencyError> {
        Transport::set_persistency(self, persistency)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
