//! # ndn-face-l2 — Layer-2 (Ethernet and radio) faces for NDN
//!
//! Provides link-layer face implementations for NDN over raw Ethernet
//! (Ethertype `0x8624`), Wifibroadcast, and Bluetooth RFCOMM.
//!
//! ## Key types
//!
//! - [`NamedEtherFace`] / [`MulticastEtherFace`] — unicast and multicast raw Ethernet faces
//! - [`WfbFace`] — Wifibroadcast NG face for 802.11 monitor-mode injection (Linux only)
//! - [`BluetoothFace`] — BlueZ RFCOMM face (Linux only)
//! - [`RadioTable`] — metadata registry for radio-based faces
//! - [`EtherNeighborDiscovery`] — link-layer neighbor discovery (Linux only)
//!
//! ## Platform support
//!
//! - **Linux** — `AF_PACKET` raw sockets (full feature set)
//! - **macOS** — `PF_NDRV` for Ethernet faces
//! - **Windows** — Npcap/WinPcap for Ethernet faces
//! - **Android / iOS** — raw Ethernet faces are unavailable; only [`RadioTable`]
//!   and [`NDN_ETHERTYPE`] are exported. Use `UdpFace`/`TcpFace` and `AppFace`
//!   from `ndn-face-net`/`ndn-face-local` for mobile deployments.

#![allow(missing_docs)]

// AF_PACKET raw sockets, WfbFace (802.11 monitor-mode injection), and
// BluetoothFace (BlueZ RFCOMM) all require Linux kernel APIs that do not
// exist on macOS, Windows, Android, or embedded targets.
// They are compiled only when the host is Linux.
#[cfg(target_os = "linux")]
pub mod af_packet;

/// macOS raw Ethernet via PF_NDRV (Network Driver Raw).
#[cfg(target_os = "macos")]
pub mod ndrv;

/// Windows raw Ethernet via Npcap/WinPcap (`pcap` crate).
#[cfg(target_os = "windows")]
pub mod pcap_face;

#[cfg(target_os = "linux")]
pub mod ether;

#[cfg(target_os = "linux")]
pub mod multicast_ether;

/// macOS Ethernet faces (`NamedEtherFace` + `MulticastEtherFace`) over PF_NDRV.
#[cfg(target_os = "macos")]
pub mod ether_macos;

/// Windows Ethernet faces (`NamedEtherFace` + `MulticastEtherFace`) over Npcap.
#[cfg(target_os = "windows")]
pub mod ether_windows;

#[cfg(target_os = "linux")]
pub mod wfb;

#[cfg(target_os = "linux")]
pub mod bluetooth;

// NeighborDiscovery uses AF_PACKET raw sockets, so it is Linux-only.
// RadioTable is a pure data structure and compiles everywhere.
#[cfg(target_os = "linux")]
pub mod neighbor;
pub mod radio;

/// `EtherNeighborDiscovery` — implements [`ndn_discovery::DiscoveryProtocol`]
/// for raw Ethernet interfaces.
#[cfg(target_os = "linux")]
pub mod ether_nd;

#[cfg(target_os = "linux")]
pub use af_packet::MacAddr;
#[cfg(target_os = "linux")]
pub use af_packet::get_interface_mac;

#[cfg(target_os = "linux")]
pub use ether::NamedEtherFace;
#[cfg(target_os = "macos")]
pub use ether_macos::NamedEtherFace;
#[cfg(target_os = "windows")]
pub use ether_windows::NamedEtherFace;

#[cfg(target_os = "macos")]
pub use ether_macos::MulticastEtherFace;
#[cfg(target_os = "windows")]
pub use ether_windows::MulticastEtherFace;
#[cfg(target_os = "linux")]
pub use multicast_ether::MulticastEtherFace;

#[cfg(target_os = "linux")]
pub use wfb::WfbFace;

#[cfg(target_os = "linux")]
pub use bluetooth::BluetoothFace;

#[cfg(target_os = "linux")]
pub use neighbor::NeighborDiscovery;
pub use radio::{RadioFaceMetadata, RadioTable};

#[cfg(target_os = "linux")]
pub use ether_nd::EtherNeighborDiscovery;

/// IANA-assigned Ethertype for NDN over Ethernet (IEEE 802.3).
pub const NDN_ETHERTYPE: u16 = 0x8624;
