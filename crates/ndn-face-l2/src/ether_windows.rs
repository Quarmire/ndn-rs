//! Windows Ethernet faces using Npcap / WinPcap (`pcap` crate).
//!
//! Provides the same [`NamedEtherFace`] and [`MulticastEtherFace`] types that
//! exist on Linux (backed by `AF_PACKET`) and macOS (backed by `PF_NDRV`),
//! implemented on top of [`crate::pcap_face::PcapSocket`].
//!
//! ## Constructor
//!
//! The constructors for both face types match the Linux / macOS signatures
//! exactly: no `local_mac` parameter is required.  The MAC address is
//! resolved automatically via `GetAdaptersAddresses` in [`crate::pcap_face::get_iface_mac`].
//!
//! ## Receive filtering
//!
//! `PcapSocket` applies a BPF filter (`"ether proto 0x8624"`) so only NDN
//! frames reach the recv loop.  [`NamedEtherFace`] further filters by source
//! MAC in software.
//!
//! ## LP framing
//!
//! [`MulticastEtherFace::send`] wraps in NDNLPv2 and fragments above 1500 B.
//! [`NamedEtherFace::send`] sends raw NDN TLV (no LP wrap).

#![cfg(target_os = "windows")]

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

use ndn_discovery::MacAddr;

use crate::pcap_face::{NDN_ETHER_MCAST_MAC, PcapSocket};
use crate::radio::RadioFaceMetadata;

pub use crate::pcap_face::NDN_ETHER_MCAST_MAC;

// ─── NamedEtherFace ──────────────────────────────────────────────────────────

/// NDN face over raw Ethernet (Npcap / EtherType 0x8624) for Windows.
///
/// Sends unicast frames to `peer_mac` and discards received frames that do not
/// originate from `peer_mac`.  Requires Npcap to be installed and the process
/// to have the necessary privileges.
pub struct NamedEtherFace {
    id: FaceId,
    /// NDN node name of the remote peer.
    pub node_name: Name,
    peer_mac: MacAddr,
    /// Radio metadata for multi-radio strategies.
    pub radio: RadioFaceMetadata,
    socket: PcapSocket,
}

impl NamedEtherFace {
    /// Create a new Ethernet face on `iface`.
    ///
    /// `iface` is the Npcap device name (`\Device\NPF_{...}`) or the adapter's
    /// friendly name (e.g. `"Ethernet"`).  The local MAC address is resolved
    /// automatically via `GetAdaptersAddresses`.
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
        })
    }

    /// Update the peer MAC address.
    pub fn set_peer_mac(&mut self, mac: MacAddr) {
        self.peer_mac = mac;
    }

    /// Current peer MAC address.
    pub fn peer_mac(&self) -> MacAddr {
        self.peer_mac
    }

    /// Interface name this face is bound to.
    pub fn iface(&self) -> &str {
        self.socket.iface()
    }
}

impl Face for NamedEtherFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Ethernet
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        loop {
            let (payload, src_mac) = self.socket.recv().await.map_err(FaceError::Io)?;
            if src_mac == self.peer_mac {
                return Ok(payload);
            }
            // Frame from a different source; discard and wait for the next.
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.socket
            .send_to(&pkt, &self.peer_mac)
            .await
            .map_err(FaceError::Io)
    }
}

// ─── MulticastEtherFace ──────────────────────────────────────────────────────

/// NDN face over multicast Ethernet (Npcap / EtherType 0x8624) for Windows.
///
/// Receives all NDN Ethernet frames captured by the BPF filter; sends to
/// `NDN_ETHER_MCAST_MAC`.  No explicit multicast join is needed on Windows —
/// pcap captures promiscuously and the BPF filter handles EtherType selection.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    socket: PcapSocket,
    seq: AtomicU64,
}

impl MulticastEtherFace {
    /// Create a new multicast Ethernet face on `iface`.
    ///
    /// `iface` is the Npcap device name (`\Device\NPF_{...}`) or the adapter's
    /// friendly name (e.g. `"Ethernet"`).  The local MAC address is resolved
    /// automatically via `GetAdaptersAddresses`.
    pub fn new(id: FaceId, iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let socket = PcapSocket::new(&iface)?;
        Ok(Self {
            id,
            iface,
            socket,
            seq: AtomicU64::new(0),
        })
    }

    /// Interface name this face is bound to.
    pub fn iface(&self) -> &str {
        &self.iface
    }

    /// Receive the next NDN packet together with the sender's MAC address.
    ///
    /// Used by discovery protocols to identify the hello sender.
    pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), FaceError> {
        self.socket.recv().await.map_err(FaceError::Io)
    }
}

impl Face for MulticastEtherFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::EtherMulticast
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("ether://[{}]/{}", NDN_ETHER_MCAST_MAC, self.iface))
    }

    fn local_uri(&self) -> Option<String> {
        Some(format!("dev://{}", self.iface))
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        let (payload, _src) = self.socket.recv().await.map_err(FaceError::Io)?;
        Ok(payload)
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let wire = ndn_packet::lp::encode_lp_packet(&pkt);
        let frames = if wire.len() > 1500 {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            ndn_packet::fragment::fragment_packet(&wire, 1500, seq)
        } else {
            vec![wire]
        };
        for frame in &frames {
            self.socket
                .send_to_mcast(frame)
                .await
                .map_err(FaceError::Io)?;
        }
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }
}
