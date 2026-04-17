use bytes::Bytes;
use thiserror::Error;

/// Link-layer source address returned by multicast/broadcast faces.
///
/// Kept separate from `ndn-discovery::LinkAddr` to avoid a circular dependency.
/// The engine converts `FaceAddr` into `InboundMeta` in the face reader.
#[derive(Clone, Debug)]
pub enum FaceAddr {
    Udp(std::net::SocketAddr),
    Ether([u8; 6]),
}

/// Opaque face identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaceId(pub u32);

impl FaceId {
    pub const INVALID: FaceId = FaceId(u32::MAX);
}

impl core::fmt::Display for FaceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "face#{}", self.0)
    }
}

/// Classifies a face by its transport type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum FaceKind {
    Udp,
    Tcp,
    Unix,
    Ethernet,
    EtherMulticast,
    App,
    Shm,
    Serial,
    Bluetooth,
    Wfb,
    Compute,
    Internal,
    Multicast,
    WebSocket,
    /// Management socket face (Unix domain, operator-level trust).
    ///
    /// Faces of this kind are created by the router's NFD face listener for
    /// connections to the management socket.  The Unix socket's filesystem
    /// permissions (`0600`, owned by the router user) serve as the
    /// authentication boundary — commands from `Management` faces are granted
    /// operator-level access without requiring signed Interests.
    Management,
}

impl FaceKind {
    /// Whether this face is local (same-host IPC) or non-local (network).
    pub fn scope(&self) -> FaceScope {
        match self {
            FaceKind::Unix
            | FaceKind::App
            | FaceKind::Shm
            | FaceKind::Internal
            | FaceKind::Management
            | FaceKind::WebSocket => FaceScope::Local,
            FaceKind::Udp
            | FaceKind::Tcp
            | FaceKind::Ethernet
            | FaceKind::EtherMulticast
            | FaceKind::Serial
            | FaceKind::Bluetooth
            | FaceKind::Wfb
            | FaceKind::Compute
            | FaceKind::Multicast => FaceScope::NonLocal,
        }
    }

    pub fn is_management(&self) -> bool {
        matches!(self, FaceKind::Management)
    }
}

impl core::fmt::Display for FaceKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Unix => "unix",
            Self::Ethernet => "ethernet",
            Self::EtherMulticast => "ether-multicast",
            Self::App => "app",
            Self::Shm => "shm",
            Self::Serial => "serial",
            Self::Bluetooth => "bluetooth",
            Self::Wfb => "wfb",
            Self::Compute => "compute",
            Self::Internal => "internal",
            Self::Multicast => "multicast",
            Self::WebSocket => "web-socket",
            Self::Management => "management",
        })
    }
}

impl core::str::FromStr for FaceKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "unix" => Ok(Self::Unix),
            "ethernet" => Ok(Self::Ethernet),
            "ether-multicast" => Ok(Self::EtherMulticast),
            "app" => Ok(Self::App),
            "shm" => Ok(Self::Shm),
            "serial" => Ok(Self::Serial),
            "bluetooth" => Ok(Self::Bluetooth),
            "wfb" => Ok(Self::Wfb),
            "compute" => Ok(Self::Compute),
            "internal" => Ok(Self::Internal),
            "multicast" => Ok(Self::Multicast),
            "web-socket" => Ok(Self::WebSocket),
            "management" => Ok(Self::Management),
            _ => Err(()),
        }
    }
}

/// Whether a face is local (same-host IPC) or non-local (network).
///
/// NFD uses this to enforce that `/localhost` prefixes never cross non-local
/// faces — a security boundary preventing management Interests from leaking
/// onto the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaceScope {
    Local,
    NonLocal,
}

/// Face persistence level (NFD semantics).
///
/// - `OnDemand` (0): created by a listener, destroyed on idle timeout or I/O error.
/// - `Persistent` (1): created by management command, survives I/O errors.
/// - `Permanent` (2): never destroyed, even on I/O errors (multicast, always-on links).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FacePersistency {
    OnDemand = 0,
    Persistent = 1,
    Permanent = 2,
}

/// Link type for a face — indicates the connectivity model of the underlying link.
///
/// Forwarding strategies use this to decide whether to suppress duplicate Interests
/// on the same face (multi-access suppression) and to select appropriate forwarding
/// algorithms for partially-connected topologies.
///
/// Matches the NFD link-type model:
/// - `PointToPoint`: single-peer link (unicast TCP, UDP, serial, Unix socket).
/// - `MultiAccess`: all nodes on the link receive every frame (Ethernet multicast,
///   UDP multicast on a wired LAN or Wi-Fi infrastructure AP).
/// - `AdHoc`: partially-connected wireless (Wi-Fi IBSS, MANET) — not all nodes
///   hear every frame, so multi-access suppression should be disabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum LinkType {
    #[default]
    PointToPoint,
    MultiAccess,
    AdHoc,
}

impl core::fmt::Display for LinkType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PointToPoint => "point-to-point",
            Self::MultiAccess => "multi-access",
            Self::AdHoc => "ad-hoc",
        })
    }
}

impl FacePersistency {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::OnDemand),
            1 => Some(Self::Persistent),
            2 => Some(Self::Permanent),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum FaceError {
    #[error("face closed")]
    Closed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("send buffer full")]
    Full,
}

/// The core face abstraction.
///
/// `recv` is called only from the face's own task (single consumer).
/// `send` may be called concurrently from multiple pipeline tasks (must be `&self`
/// and internally synchronised where the underlying transport requires it).
pub trait Face: Send + Sync + 'static {
    fn id(&self) -> FaceId;
    fn kind(&self) -> FaceKind;

    /// Remote URI (e.g. `udp4://192.168.1.1:6363`).
    fn remote_uri(&self) -> Option<String> {
        None
    }

    /// Local URI (e.g. `unix:///run/nfd/nfd.sock`).
    fn local_uri(&self) -> Option<String> {
        None
    }

    fn recv(&self) -> impl Future<Output = Result<Bytes, FaceError>> + Send;

    /// Receive the next packet together with the link-layer sender address.
    ///
    /// Multicast and broadcast faces override this to return the link-layer
    /// source, enabling discovery to create unicast reply faces without
    /// embedding addresses in NDN payloads.
    fn recv_with_addr(
        &self,
    ) -> impl Future<Output = Result<(Bytes, Option<FaceAddr>), FaceError>> + Send {
        async { self.recv().await.map(|b| (b, None)) }
    }

    /// Send a packet.
    ///
    /// # LP encoding convention
    ///
    /// Network-facing transports (UDP, TCP, Serial, Ethernet) wrap the raw NDN
    /// packet in an NDNLPv2 `LpPacket` envelope before writing to the wire.
    /// Local transports (Unix, App, SHM) send the raw packet as-is — the
    /// pipeline already strips LP framing before forwarding.
    ///
    /// [`StreamFace`](crate::StreamFace) makes this explicit via the `lp_encode`
    /// constructor parameter.  Custom face implementations should follow the
    /// same convention based on [`FaceKind::scope()`].
    fn send(&self, pkt: Bytes) -> impl Future<Output = Result<(), FaceError>> + Send;

    fn link_type(&self) -> LinkType {
        LinkType::PointToPoint
    }
}

use std::future::Future;
