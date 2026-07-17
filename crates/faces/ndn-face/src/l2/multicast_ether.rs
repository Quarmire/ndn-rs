//! Link-layer counterpart to `MulticastUdpFace`: joins an Ethernet multicast
//! group and sends/receives NDN packets via `AF_PACKET` + TPACKET_V2.

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_transport::{FaceAddr, FaceError, FaceId, FaceKind, LinkType, MtuError, Transport};
use tokio::io::unix::AsyncFd;

use super::af_packet::{
    MacAddr, PacketRing, get_ifindex, make_sockaddr_ll, open_packet_socket, setsockopt_val,
    setup_packet_ring,
};
use super::{ETHER_PAYLOAD_MTU, clamp_ether_mtu};
use crate::NDN_ETHERTYPE;

/// IANA-assigned NDN-over-Ethernet multicast MAC (matches NFD's
/// `EthernetFactory`).
pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);

/// L2 multicast NDN face (`AF_PACKET` `SOCK_DGRAM` + TPACKET_V2). Joins the
/// NDN multicast group on `iface`; outgoing packets are sent to the
/// multicast MAC. Requires `CAP_NET_RAW`; Linux only.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    ifindex: i32,
    socket: AsyncFd<std::os::unix::io::OwnedFd>,
    ring: PacketRing,
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

        Ok(Self {
            id,
            iface,
            ifindex,
            socket,
            ring,
            mtu: AtomicUsize::new(ETHER_PAYLOAD_MTU),
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub async fn recv_with_source(&self) -> Result<(Bytes, MacAddr), ndn_transport::FaceError> {
        loop {
            if let Some(result) = self.ring.try_pop_rx_with_source() {
                return Ok(result);
            }
            let mut guard = self.socket.readable().await?;
            guard.clear_ready();
        }
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
        loop {
            if let Some(pkt) = self.ring.try_pop_rx() {
                return Ok(pkt);
            }
            let mut guard = self.socket.readable().await?;
            guard.clear_ready();
        }
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (pkt, src_mac) = self.recv_with_source().await?;
        Ok((pkt, Some(FaceAddr::Ether(src_mac.0))))
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
        loop {
            if self.ring.try_push_tx(&pkt) {
                break;
            }
            let mut guard = self.socket.writable().await?;
            guard.clear_ready();
        }

        let dst = make_sockaddr_ll(self.ifindex, &NDN_ETHER_MCAST_MAC, NDN_ETHERTYPE);
        self.tx_to(dst)
    }

    /// Reply-to-source: unicast `pkt` to the specific peer MAC that a prior
    /// [`recv_bytes_with_addr`](Transport::recv_bytes_with_addr) surfaced via
    /// [`FaceAddr::Ether`], instead of sending to the NDN multicast group.
    /// Mirrors [`send_bytes`](Self::send_bytes) (same TX-ring push then
    /// `sendto`); only the destination `sockaddr_ll` differs. A non-`Ether`
    /// `FaceAddr` cannot come from this socket, so it falls back to multicast.
    async fn send_bytes_to(&self, addr: FaceAddr, pkt: Bytes) -> Result<(), FaceError> {
        let FaceAddr::Ether(mac) = addr else {
            return self.send_bytes(pkt).await;
        };
        loop {
            if self.ring.try_push_tx(&pkt) {
                break;
            }
            let mut guard = self.socket.writable().await?;
            guard.clear_ready();
        }
        let dst = make_sockaddr_ll(self.ifindex, &MacAddr(mac), NDN_ETHERTYPE);
        self.tx_to(dst)
    }
}

impl MulticastEtherFace {
    /// Flush the already-queued TX frame to `dst` (shared egress syscall for
    /// [`send_bytes`](MulticastEtherFace::send_bytes) and its unicast
    /// reply-to-source counterpart).
    fn tx_to(&self, dst: libc::sockaddr_ll) -> Result<(), FaceError> {
        let fd = self.socket.get_ref().as_raw_fd();
        let ret = unsafe {
            libc::sendto(
                fd,
                std::ptr::null(),
                0,
                0,
                &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret == -1 {
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::WouldBlock {
                return Err(FaceError::Io(err));
            }
        }
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
