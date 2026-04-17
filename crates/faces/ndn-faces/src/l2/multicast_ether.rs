//! Multicast Ethernet face for L2 neighbor discovery.
//!
//! Like `MulticastUdpFace` but at the link layer — joins an Ethernet multicast
//! group and sends/receives NDN packets via `AF_PACKET + TPACKET_V2`.

use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_transport::{Face, FaceAddr, FaceError, FaceId, FaceKind, LinkType};
use tokio::io::unix::AsyncFd;

use super::af_packet::{
    MacAddr, PacketRing, get_ifindex, make_sockaddr_ll, open_packet_socket, setsockopt_val,
    setup_packet_ring,
};
use crate::NDN_ETHERTYPE;

/// NDN Ethernet multicast MAC address.
///
/// This is the IANA-assigned multicast address for NDN over Ethernet:
/// `01:00:5e:00:17:aa` (same group used by NFD's EthernetFactory).
pub const NDN_ETHER_MCAST_MAC: MacAddr = MacAddr([0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA]);

/// NDN face over multicast Ethernet (`AF_PACKET` / Ethertype 0x8624).
///
/// Joins the NDN multicast group on the specified interface so that frames
/// sent to `NDN_ETHER_MCAST_MAC` are received.  Outgoing packets are always
/// sent to the multicast address.
///
/// Suitable for L2 neighbor discovery and local-subnet NDN communication
/// without IP.  Mirrors `MulticastUdpFace` but at the link layer.
///
/// Requires `CAP_NET_RAW` or root.  Linux only.
pub struct MulticastEtherFace {
    id: FaceId,
    iface: String,
    ifindex: i32,
    socket: AsyncFd<std::os::unix::io::OwnedFd>,
    ring: PacketRing,
    seq: AtomicU64,
}

impl MulticastEtherFace {
    /// Create a new multicast Ethernet face on `iface`.
    ///
    /// Opens an `AF_PACKET + SOCK_DGRAM` socket, joins the NDN multicast
    /// group (`01:00:5e:00:17:aa`), and sets up TPACKET_V2 ring buffers.
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
            seq: AtomicU64::new(0),
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
        loop {
            if let Some(pkt) = self.ring.try_pop_rx() {
                return Ok(pkt);
            }
            let mut guard = self.socket.readable().await?;
            guard.clear_ready();
        }
    }

    async fn recv_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (pkt, src_mac) = self.recv_with_source().await?;
        Ok((pkt, Some(FaceAddr::Ether(src_mac.0))))
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
            loop {
                if self.ring.try_push_tx(frame) {
                    break;
                }
                let mut guard = self.socket.writable().await?;
                guard.clear_ready();
            }

            let dst = make_sockaddr_ll(self.ifindex, &NDN_ETHER_MCAST_MAC, NDN_ETHERTYPE);
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

    /// Opening without CAP_NET_RAW should fail with EPERM.
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
