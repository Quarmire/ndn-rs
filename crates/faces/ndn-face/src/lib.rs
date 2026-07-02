//! NDN face implementations for ndn-rs.
//!
//! | Module | Types | Feature |
//! |--------|-------|---------|
//! | [`net`] | [`UdpFace`], [`TcpFace`], [`MulticastUdpFace`] | `net` |
//! | [`local`] | [`InProcFace`], [`InProcHandle`], [`UnixFace`], [`IpcFace`] | `local` |
//! | [`l2`] | [`NamedEtherFace`], [`MulticastEtherFace`] | `l2` |
//!
//! Serial/UART faces moved to the `ndn-face-serial` extension crate.
//! | [`callback`] | [`CallbackFace`] | *(always available)* |
//!
//! [`CallbackFace`] is the NDN virtual face pattern: an in-process face that
//! satisfies Interests via an application-provided async callback, appearing
//! to the pipeline as a normal FIB next-hop.

#![allow(missing_docs)]
// One of the two OS-I/O leaf crates permitted to use `unsafe` (the workspace
// lint policy denies it everywhere else): raw sockets, sendmmsg/recvmmsg,
// AF_PACKET/ndrv/pcap FFI all live here, behind safe wrappers.
#![allow(unsafe_code)]

pub mod callback;
pub use callback::{CallbackFace, TapFace};

pub mod iface;
pub mod iface_watcher;

// net/websocket faces are native-only: tokio `net` pulls `mio`, which doesn't
// build on wasm32. The feature may still be enabled on a wasm build (via a
// consumer's default features) — the module just compiles to nothing there.
#[cfg(all(feature = "net", not(target_arch = "wasm32")))]
pub mod net;

// Reusable multicast face provisioning (enumeration + hotplug). Needs the UDP
// multicast face from `net`; the Ethernet path is additionally `l2`/Linux-only.
#[cfg(all(feature = "net", not(target_arch = "wasm32")))]
pub mod provision;

#[cfg(feature = "local")]
pub mod local;

#[cfg(feature = "l2")]
pub mod l2;

#[cfg(all(feature = "net", not(target_arch = "wasm32")))]
pub use ndn_packet::fragment::DEFAULT_UDP_MTU;
#[cfg(all(feature = "net", not(target_arch = "wasm32")))]
pub use net::{
    LpReliability, MulticastUdpFace, ReliabilityConfig, RtoStrategy, TcpFace, UdpFace,
    tcp_face_connect, tcp_face_from_stream,
};

#[cfg(feature = "local")]
pub use local::{InProcFace, InProcHandle, IpcFace, IpcListener, ipc_face_connect};

#[cfg(all(unix, feature = "local"))]
pub use local::{
    UnixFace, unix_face_connect, unix_face_from_stream, unix_management_face_from_stream,
};

#[cfg(feature = "l2")]
pub use l2::NDN_ETHERTYPE;
#[cfg(feature = "l2")]
pub use l2::{RadioFaceMetadata, RadioTable};

#[cfg(all(feature = "l2", target_os = "linux"))]
pub use l2::{MacAddr, MulticastEtherFace, NamedEtherFace, NeighborDiscovery, get_interface_mac};

#[cfg(all(feature = "l2", target_os = "macos"))]
pub use l2::{MulticastEtherFace, NamedEtherFace};
#[cfg(all(feature = "l2", target_os = "windows"))]
pub use l2::{MulticastEtherFace, NamedEtherFace};
