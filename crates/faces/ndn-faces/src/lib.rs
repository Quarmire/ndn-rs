//! # ndn-faces — NDN face implementations
//!
//! All face transports for ndn-rs in a single crate, organised as submodules:
//!
//! | Module | Types | Feature |
//! |--------|-------|---------|
//! | [`net`] | [`UdpFace`], [`TcpFace`], [`MulticastUdpFace`], [`WebSocketFace`] | `net` / `websocket` |
//! | [`local`] | [`InProcFace`], [`InProcHandle`], [`ShmFace`], [`UnixFace`], [`IpcFace`] | `local` / `spsc-shm` |
//! | [`serial`] | [`SerialFace`], [`CobsCodec`] | `serial` |
//! | [`l2`] | [`NamedEtherFace`], [`MulticastEtherFace`], [`BleFace`], [`WfbFace`] | `l2` / `bluetooth` / `wfb` |
//!
//! ## Quick re-exports
//!
//! The most common types are re-exported at the crate root:
//!
//! ```rust,ignore
//! use ndn_faces::{UdpFace, TcpFace, InProcFace, InProcHandle};
//! ```

#![allow(missing_docs)]

/// Network interface enumeration and whitelist/blacklist filtering.
///
/// Used by the face system auto-configuration (`[face_system]` in TOML) to
/// enumerate interfaces and apply whitelist/blacklist patterns.
pub mod iface;

/// Dynamic interface add/remove watcher (Linux netlink; stubs on other platforms).
pub mod iface_watcher;

#[cfg(feature = "net")]
pub mod net;

#[cfg(feature = "local")]
pub mod local;

#[cfg(feature = "serial")]
pub mod serial;

#[cfg(feature = "l2")]
pub mod l2;

// ── Crate-root re-exports ────────────────────────────────────────────────────

#[cfg(feature = "net")]
pub use net::{
    MulticastUdpFace, TcpFace, UdpFace,
    tcp_face_connect, tcp_face_from_stream,
    LpReliability, ReliabilityConfig, RtoStrategy,
};
#[cfg(feature = "net")]
pub use ndn_packet::fragment::DEFAULT_UDP_MTU;

#[cfg(feature = "websocket")]
pub use net::WebSocketFace;

#[cfg(feature = "local")]
pub use local::{IpcFace, IpcListener, InProcFace, InProcHandle, ipc_face_connect};

#[cfg(all(unix, feature = "local"))]
pub use local::{UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream};

#[cfg(all(unix, not(any(target_os = "android", target_os = "ios")), feature = "spsc-shm"))]
pub use local::{ShmError, ShmFace, ShmHandle};

#[cfg(feature = "serial")]
pub use serial::SerialFace;
#[cfg(feature = "serial")]
pub use serial::cobs::CobsCodec;
#[cfg(all(feature = "serial", feature = "serial"))]
pub use serial::serial_face_open;

#[cfg(feature = "l2")]
pub use l2::NDN_ETHERTYPE;
#[cfg(feature = "l2")]
pub use l2::{RadioFaceMetadata, RadioTable};

#[cfg(all(feature = "l2", target_os = "linux"))]
pub use l2::{
    MacAddr, EtherNeighborDiscovery, NamedEtherFace, MulticastEtherFace,
    NeighborDiscovery, WfbFace, BleFace, get_interface_mac,
};
#[cfg(all(feature = "l2", target_os = "macos"))]
pub use l2::{NamedEtherFace, MulticastEtherFace};
#[cfg(all(feature = "l2", target_os = "windows"))]
pub use l2::{NamedEtherFace, MulticastEtherFace};
