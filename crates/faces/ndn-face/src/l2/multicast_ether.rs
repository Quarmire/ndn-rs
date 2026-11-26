//! Link-layer counterpart to `MulticastUdpFace`: joins an Ethernet multicast
//! group and sends/receives NDN packets via `AF_PACKET` + TPACKET_V2.

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_transport::{
    FaceAddr, FaceError, FaceId, FaceKind, LinkType, MtuError, SideClass, SideRefused, Transport,
};
use tokio::io::unix::AsyncFd;

use super::af_packet::{
    MacAddr, get_ifindex, open_packet_socket, setsockopt_val, setup_packet_ring,
};
use super::port::{AfPacketPort, EtherPort};
use super::{ETHER_PAYLOAD_MTU, check_side_frame, clamp_ether_mtu};
use crate::NDN_ETHERTYPE;

/// IANA-assigned NDN-over-Ethernet multicast MAC (matches NFD's
/// `EthernetFactory`).
pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);

/// L2 multicast NDN face (`AF_PACKET` `SOCK_DGRAM` + TPACKET_V2). Joins the
/// NDN multicast group on `iface`; outgoing packets are sent to the
/// multicast MAC. Requires `CAP_NET_RAW`; Linux only.
///
/// Generic over its [`EtherPort`] so that the side path is the same code over
/// the kernel ring and over a test bus; every caller uses the default,
/// [`AfPacketPort`].
pub struct MulticastEtherFace<P: EtherPort = AfPacketPort> {
    id: FaceId,
    iface: String,
    port: P,
    mtu: AtomicUsize,
}

impl MulticastEtherFace {
    pub fn new(id: FaceId, iface: impl Into<String>) -> std::io::Result<Self> {
        let iface = iface.into();

        let probe_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                NDN_ETHERTYPE.to_be() as i32,
            )
        };
        if probe_fd == -1 {
            return Err(std::io::Error::last_os_error());
        }
        let ifindex = {
            let idx = get_ifindex(probe_fd, &iface);
            unsafe {
                libc::close(probe_fd);
            }
            idx?
        };

        let fd = open_packet_socket(ifindex, NDN_ETHERTYPE)?;

        let mreq = libc::packet_mreq {
            mr_ifindex: ifindex,
            mr_type: libc::PACKET_MR_MULTICAST as u16,
            mr_alen: 6,
            mr_address: {
                let mut addr = [0u8; 8];
                addr[..6].copy_from_slice(NDN_ETHER_MCAST_MAC.as_bytes());
                addr
            },
        };
        setsockopt_val(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq,
        )?;

        let ring = setup_packet_ring(fd.as_raw_fd())?;
        let socket = AsyncFd::new(fd)?;

        Ok(Self::with_port(
            id,
            iface,
            AfPacketPort {
                ifindex,
                socket,
                ring,
            },
        ))
    }
}

impl<P: EtherPort> MulticastEtherFace<P> {
    /// A face over `port`, which must deliver the frames of the NDN multicast group.
    pub fn with_port(id: FaceId, iface: impl Into<String>, port: P) -> Self {
        Self {
            id,
            iface: iface.into(),
            port,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        }
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), ndn_transport::FaceError> {
        loop {
            if let Some(result) = self.port.try_pop_rx() {
                return Ok(result);
            }
            self.port.readable().await?;
        }
    }
}

impl<P: EtherPort> Transport for MulticastEtherFace<P> {
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
        Ok(self.recv_with_source().await?.0)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (pkt, src_mac) = self.recv_with_source().await?;
        Ok((pkt, Some(FaceAddr::Ether(src_mac.0))))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    /// A channel frame is one Ethernet payload, never fragmented.
    fn side_frame_max(&self) -> usize {
        self.mtu.load(Ordering::Relaxed)
    }

    /// Hand a channel frame to the send queue for the NDN multicast group
    /// without waiting: **one** frame for every station on the segment (a
    /// station that is no receiver sees the sealed frame and routes nothing).
    /// A frame that is not a channel frame is
    /// [`Malformed`](SideRefused::Malformed), one over the MTU
    /// [`TooLarge`](SideRefused::TooLarge) (never fragmented), and a queue with
    /// no room [`Full`](SideRefused::Full) (the caller drops the frame and counts
    /// it). Only the datagram class exists on Ethernet: the stream class is
    /// [`NotCarried`](SideRefused::NotCarried). A NIC pads a payload under 46
    /// octets, so the receiver sees a shorter frame with trailing zero octets: a
    /// frame this face is given must be self-delimiting or at least
    /// [`MIN_FRAME_LEN`](ndn_transport::side_header::MIN_FRAME_LEN) octets, which
    /// the channel codec guarantees; the face sends what it is given.
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        check_side_frame(&frame, class, self.side_frame_max())?;
        if !self.port.try_push_tx(&frame, &NDN_ETHER_MCAST_MAC) {
            return Err(SideRefused::Full);
        }
        self.port
            .flush_tx()
            .map_err(|e| SideRefused::Io(e.to_string()))
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
        self.send_to_mac(&pkt, &NDN_ETHER_MCAST_MAC).await
    }

    /// Reply-to-source: unicast `pkt` to the specific peer MAC that a prior
    /// [`recv_bytes_with_addr`](Transport::recv_bytes_with_addr) surfaced via
    /// [`FaceAddr::Ether`], instead of sending to the NDN multicast group.
    /// Mirrors [`send_bytes`](Self::send_bytes) (same TX-ring push then
    /// `sendto`); only the destination differs. A non-`Ether` `FaceAddr`
    /// cannot come from this socket, so it falls back to multicast.
    async fn send_bytes_to(&self, addr: FaceAddr, pkt: Bytes) -> Result<(), FaceError> {
        let FaceAddr::Ether(mac) = addr else {
            return self.send_bytes(pkt).await;
        };
        self.send_to_mac(&pkt, &MacAddr(mac)).await
    }
}

impl<P: EtherPort> MulticastEtherFace<P> {
    /// Queue `pkt` (waiting for room) and flush it to `dst` (shared egress for
    /// [`send_bytes`](Transport::send_bytes) and its unicast reply-to-source
    /// counterpart).
    async fn send_to_mac(&self, pkt: &[u8], dst: &MacAddr) -> Result<(), FaceError> {
        loop {
            if self.port.try_push_tx(pkt, dst) {
                break;
            }
            self.port.writable().await?;
        }
        self.port.flush_tx()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcast_mac_is_multicast() {
        assert_eq!(NDN_ETHER_MCAST_MAC.as_bytes()[0] & 0x01, 0x01);
    }

    #[tokio::test]
    async fn new_fails_without_cap_net_raw() {
        let result = MulticastEtherFace::new(FaceId(1), "lo");
        if let Err(e) = result {
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EPERM || raw == libc::EACCES,
                "expected EPERM or EACCES, got: {e}"
            );
        }
    }
}
