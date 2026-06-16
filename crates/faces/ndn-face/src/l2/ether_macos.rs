//! macOS Ethernet faces over `PF_NDRV` (raw Ethernet, EtherType 0x8624).
//!
//! Mirrors the Linux `AF_PACKET` faces on top of [`super::ndrv::NdrvSocket`].
//! PF_NDRV has no per-source-MAC kernel filter, so [`NamedEtherFace`] drops
//! mismatched frames in software. Both faces emit payload-only frames: the
//! paired [`LpLinkService`](ndn_transport::LpLinkService) owns NDNLPv2 framing
//! and fragmentation (gated on [`Transport::send_mtu`]), matching the UDP and
//! Linux `AF_PACKET` faces.

#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{FaceAddr, FaceError, FaceId, FaceKind, LinkType, MtuError, Transport};

use ndn_transport::MacAddr;

use super::ndrv::NdrvSocket;
use super::radio::RadioFaceMetadata;
use super::{ETHER_PAYLOAD_MTU, clamp_ether_mtu};

pub use super::ndrv::NDN_ETHER_MCAST_MAC;

/// Unicast NDN face over raw Ethernet (`PF_NDRV` / EtherType 0x8624).
/// Requires root.
pub struct NamedEtherFace {
    id: FaceId,
    pub node_name: Name,
    peer_mac: MacAddr,
    pub radio: RadioFaceMetadata,
    socket: NdrvSocket,
    mtu: AtomicUsize,
}

impl NamedEtherFace {
    pub fn new(
        id: FaceId,
        node_name: Name,
        peer_mac: MacAddr,
        iface: impl Into<String>,
        radio: RadioFaceMetadata,
    ) -> std::io::Result<Self> {
        let socket = NdrvSocket::new(iface)?;
        Ok(Self {
            id,
            node_name,
            peer_mac,
            radio,
            socket,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        })
    }

    pub fn set_peer_mac(&mut self, mac: MacAddr) {
        self.peer_mac = mac;
    }

    pub fn peer_mac(&self) -> MacAddr {
        self.peer_mac
    }

    pub fn iface(&self) -> &str {
        self.socket.iface()
    }
}

impl Transport for NamedEtherFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Ethernet
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        loop {
            let (payload, src_mac) = self.socket.recv().await.map_err(FaceError::Io)?;
            if src_mac == self.peer_mac {
                return Ok(payload);
            }
        }
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = clamp_ether_mtu(mtu)?;
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.socket
            .send_to(&pkt, &self.peer_mac)
            .await
            .map_err(FaceError::Io)
    }
}

/// Multicast NDN face on `NDN_ETHER_MCAST_MAC`. Requires root.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    socket: NdrvSocket,
    mtu: AtomicUsize,
}

impl MulticastEtherFace {
    pub fn new(id: FaceId, iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let socket = NdrvSocket::new(&iface)?;
        Ok(Self {
            id,
            iface,
            socket,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Receive the next packet with its source MAC, used by discovery to
    /// identify hello senders without embedding the address in the packet.
    pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), FaceError> {
        self.socket.recv().await.map_err(FaceError::Io)
    }
}

impl Transport for MulticastEtherFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::EtherMulticast
    }

    fn link_type(&self) -> LinkType {
        LinkType::MultiAccess
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("ether://[{}]/{}", NDN_ETHER_MCAST_MAC, self.iface))
    }

    fn local_uri(&self) -> Option<String> {
        Some(format!("dev://{}", self.iface))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let (payload, _src) = self.socket.recv().await.map_err(FaceError::Io)?;
        Ok(payload)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (payload, src_mac) = self.socket.recv().await.map_err(FaceError::Io)?;
        Ok((payload, Some(FaceAddr::Ether(src_mac.0))))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = clamp_ether_mtu(mtu)?;
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    /// Payload-only: the paired `LpLinkService` has already LP-framed and
    /// fragmented to `send_mtu()`. Wrapping again here would double-encode the
    /// NDNLPv2 header on the wire.
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.socket.send_to_mcast(&pkt).await.map_err(FaceError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }

    #[test]
    fn new_without_root_fails() {
        let name = ndn_packet::Name::from_str("/test/node").unwrap();
        let peer = MacAddr([0u8; 6]);
        let result =
            NamedEtherFace::new(FaceId(1), name, peer, "en0", RadioFaceMetadata::default());
        if let Err(e) = result {
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EPERM || raw == libc::EACCES || raw == libc::ENOENT,
                "expected permission error, got: {e}",
            );
        }
    }
}
