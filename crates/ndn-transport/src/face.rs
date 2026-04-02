use bytes::Bytes;
use thiserror::Error;

/// Opaque identifier for a face. Cheap to copy; safe to use across tasks.
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

/// Classifies a face by its transport type (informational; not used for routing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaceKind {
    Udp,
    Tcp,
    Unix,
    Ethernet,
    App,
    Shm,
    Serial,
    Bluetooth,
    Wfb,
    Compute,
    Internal,
    Multicast,
}

impl FaceKind {
    /// Whether this face is local (in-process / same-host IPC) or non-local (network).
    pub fn scope(&self) -> FaceScope {
        match self {
            FaceKind::Unix | FaceKind::App | FaceKind::Shm | FaceKind::Internal => FaceScope::Local,
            FaceKind::Udp | FaceKind::Tcp | FaceKind::Ethernet | FaceKind::Serial
            | FaceKind::Bluetooth | FaceKind::Wfb | FaceKind::Compute | FaceKind::Multicast => FaceScope::NonLocal,
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
    OnDemand   = 0,
    Persistent = 1,
    Permanent  = 2,
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

    /// Remote URI (e.g. `udp4://192.168.1.1:6363`). Returns `None` for face
    /// types that don't have a meaningful remote endpoint.
    fn remote_uri(&self) -> Option<String> { None }

    /// Local URI (e.g. `unix:///tmp/ndn-faces.sock`). Returns `None` for face
    /// types that don't expose local binding info.
    fn local_uri(&self) -> Option<String> { None }

    /// Receive the next packet. Blocks until a packet arrives or the face closes.
    fn recv(&self) -> impl Future<Output = Result<Bytes, FaceError>> + Send;

    /// Send a packet. Must not block the caller; use internal buffering.
    fn send(&self, pkt: Bytes) -> impl Future<Output = Result<(), FaceError>> + Send;
}

use std::future::Future;
