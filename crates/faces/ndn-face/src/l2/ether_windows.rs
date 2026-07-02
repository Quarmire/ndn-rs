//! Windows Ethernet faces via Npcap / WinPcap (`pcap` crate).
//!
//! Mirrors the Linux/macOS faces on top of [`super::pcap_face::PcapSocket`].
//! The local MAC is resolved via `GetAdaptersAddresses`; PcapSocket installs
//! a BPF filter (`ether proto 0x8624`) and `NamedEtherFace` further filters
//! by source MAC in software. Both faces emit payload-only frames: the paired
//! [`LpLinkService`](ndn_transport::LpLinkService) owns NDNLPv2 framing and
//! fragmentation (gated on [`Transport::send_mtu`]).

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, MtuError, Transport};

use ndn_transport::MacAddr;

use super::{ETHER_PAYLOAD_MTU, clamp_ether_mtu};
use crate::pcap_face::{NDN_ETHER_MCAST_MAC, PcapSocket};
use crate::radio::RadioFaceMetadata;

pub use crate::pcap_face::NDN_ETHER_MCAST_MAC;

/// Unicast NDN face over Ethernet via Npcap. Requires Npcap installed and
/// sufficient privileges. `iface` is either an `\Device\NPF_{...}` name or the
/// adapter's friendly name (e.g. `"Ethernet"`).
pub struct NamedEtherFace {
    id: FaceId,
    pub node_name: Name,
    peer_mac: MacAddr,
    pub radio: RadioFaceMetadata,
    socket: PcapSocket,
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
        let socket = PcapSocket::new(iface)?;
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

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = clamp_ether_mtu(mtu)?;
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        loop {
            let (payload, src_mac) = self.socket.recv().await.map_err(FaceError::Io)?;
            if src_mac == self.peer_mac {
                return Ok(payload);
            }
        }
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.socket
            .send_to(&pkt, &self.peer_mac)
            .await
            .map_err(FaceError::Io)
    }
}

/// Multicast NDN face via Npcap. No explicit multicast join is required —
/// pcap captures promiscuously and the BPF filter handles EtherType selection.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    socket: PcapSocket,
    mtu: AtomicUsize,
}

impl MulticastEtherFace {
    pub fn new(id: FaceId, iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let socket = PcapSocket::new(&iface)?;
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

    #[test]
    fn mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }
}
