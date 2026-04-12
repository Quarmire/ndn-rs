//! macOS Ethernet faces using `PF_NDRV` (raw Ethernet, EtherType 0x8624).
//!
//! Provides the same [`NamedEtherFace`] and [`MulticastEtherFace`] types that
//! exist on Linux (backed by `AF_PACKET`), but implemented on top of
//! [`crate::ndrv::NdrvSocket`].
//!
//! ## Receive filtering
//!
//! PF_NDRV delivers **all** NDN frames arriving on the interface — there is no
//! per-source-MAC kernel filter.  [`NamedEtherFace`] therefore filters in
//! software: frames whose source MAC does not match `peer_mac` are silently
//! discarded in the `recv()` loop.  Each face opens its own `NdrvSocket` so
//! that multiple unicast faces on the same interface work independently.
//!
//! ## LP framing
//!
//! [`MulticastEtherFace::send`] wraps outgoing packets in NDNLPv2 and
//! fragments if the encoded length exceeds 1500 bytes, mirroring the Linux
//! implementation.  [`NamedEtherFace::send`] sends raw NDN TLV (no LP wrap),
//! matching the Linux `NamedEtherFace`.

#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{Face, FaceAddr, FaceError, FaceId, FaceKind, LinkType};

use ndn_transport::MacAddr;

use super::ndrv::NdrvSocket;
use super::radio::RadioFaceMetadata;

pub use super::ndrv::NDN_ETHER_MCAST_MAC;

// ─── NamedEtherFace ──────────────────────────────────────────────────────────

/// NDN face over raw Ethernet (`PF_NDRV` / EtherType 0x8624) for macOS.
///
/// Sends unicast frames to `peer_mac` and receives frames whose source MAC
/// matches `peer_mac` (other frames are discarded in software).
///
/// Requires root.
pub struct NamedEtherFace {
    id: FaceId,
    /// NDN node name of the remote peer.
    pub node_name: Name,
    peer_mac: MacAddr,
    /// Radio metadata for multi-radio strategies.
    pub radio: RadioFaceMetadata,
    socket: NdrvSocket,
}

impl NamedEtherFace {
    /// Create a new Ethernet face bound to `iface` pointing at `peer_mac`.
    ///
    /// Opens a `PF_NDRV` socket, registers EtherType 0x8624, and joins the
    /// NDN multicast group (so that multicast traffic is also visible if
    /// needed).  Requires root.
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
        })
    }

    /// Update the peer MAC address (e.g. after a mobility event).
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

/// NDN face over multicast Ethernet (`PF_NDRV` / EtherType 0x8624) for macOS.
///
/// Sends to `NDN_ETHER_MCAST_MAC` and receives all NDN Ethernet frames on the
/// interface.  The NDN multicast group is joined automatically by
/// [`NdrvSocket::new`].
///
/// Suitable for L2 neighbor discovery.  Requires root.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    socket: NdrvSocket,
    /// Monotonic sequence counter for NDNLPv2 fragmentation.
    seq: AtomicU64,
}

impl MulticastEtherFace {
    /// Create a new multicast Ethernet face on `iface`.  Requires root.
    pub fn new(id: FaceId, iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();
        let socket = NdrvSocket::new(&iface)?;
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
    /// Used by discovery protocols to identify the hello sender without
    /// embedding the address in the NDN packet.
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

    fn link_type(&self) -> LinkType {
        LinkType::MultiAccess
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

    async fn recv_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (payload, src_mac) = self.socket.recv().await.map_err(FaceError::Io)?;
        Ok((payload, Some(FaceAddr::Ether(src_mac.0))))
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
