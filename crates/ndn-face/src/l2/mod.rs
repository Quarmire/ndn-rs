//! Layer-2 NDN faces: raw Ethernet (EtherType `0x8624`), Wifibroadcast NG,
//! and Bluetooth LE.
//!
//! - [`NamedEtherFace`] / [`MulticastEtherFace`] — unicast and multicast Ethernet
//! - [`WfbFace`] — Wifibroadcast NG monitor-mode injection (Linux)
//! - [`BleFace`] — NDNts `web-bluetooth-transport` GATT profile
//!   (Linux/macOS, `bluetooth` feature)
//! - [`RadioTable`] — link-metric registry for radio faces
//!
//! Backends: Linux `AF_PACKET`, macOS `PF_NDRV`, Windows Npcap. Mobile
//! targets export only [`RadioTable`] and [`NDN_ETHERTYPE`].

#![allow(missing_docs)]

#[cfg(target_os = "linux")]
pub mod af_packet;
#[cfg(target_os = "macos")]
pub mod ndrv;
#[cfg(target_os = "windows")]
pub mod pcap_face;

#[cfg(target_os = "linux")]
pub mod ether;
#[cfg(target_os = "macos")]
pub mod ether_macos;
#[cfg(target_os = "windows")]
pub mod ether_windows;
#[cfg(target_os = "linux")]
pub mod multicast_ether;

#[cfg(target_os = "linux")]
pub mod wfb;

// Peripheral (BleFace) is Linux/macOS; central (BleCentralFace) adds Windows.
#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    feature = "bluetooth"
))]
pub mod bluetooth;

#[cfg(target_os = "linux")]
pub mod neighbor;
pub mod radio;

#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub mod af_xdp;
#[cfg(all(target_os = "linux", feature = "af-xdp"))]
pub use af_xdp::AfXdpFace;

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

#[cfg(all(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    feature = "bluetooth"
))]
pub use bluetooth::{BleCentralFace, BleFraming, NdntsReassembler};
#[cfg(all(any(target_os = "linux", target_os = "macos"), feature = "bluetooth"))]
pub use bluetooth::{BleFace, BleListener};

#[cfg(target_os = "linux")]
pub use neighbor::NeighborDiscovery;
pub use radio::{RadioFaceMetadata, RadioTable};

/// IANA-assigned Ethertype for NDN over Ethernet (IEEE 802.3).
pub const NDN_ETHERTYPE: u16 = 0x8624;

/// Ethernet payload MTU. With `AF_PACKET`/`PF_NDRV` the kernel builds the
/// 14-byte Ethernet header, so this is the NDN-TLV payload the LinkService may
/// emit before NDNLPv2 fragmentation must kick in. Matches NFD's
/// `ethernet::Transport` (1500-byte standard frame payload).
pub const ETHER_PAYLOAD_MTU: usize = 1500;

/// Validate a requested Ethernet send-MTU. `None` reverts to
/// [`ETHER_PAYLOAD_MTU`]; `0` and values above the standard frame payload are
/// rejected (jumbo frames would need a larger `AF_PACKET` ring). Shared by the
/// `set_send_mtu` impls of the per-platform Ethernet faces so their bounds
/// stay identical.
#[allow(dead_code)]
pub(crate) fn clamp_ether_mtu(mtu: Option<u64>) -> Result<usize, ndn_transport::MtuError> {
    match mtu {
        None => Ok(ETHER_PAYLOAD_MTU),
        Some(0) => Err(ndn_transport::MtuError::OutOfRange {
            reason: "mtu must be > 0",
        }),
        Some(n) if n as usize > ETHER_PAYLOAD_MTU => Err(ndn_transport::MtuError::OutOfRange {
            reason: "ether-max-1500",
        }),
        Some(n) => Ok(n as usize),
    }
}
