//! What an Ethernet face needs of the wire: the [`EtherPort`] it sends and receives frames through.
//!
//! [`NamedEtherFace`](super::NamedEtherFace) and [`MulticastEtherFace`](super::MulticastEtherFace)
//! are generic over their port so that everything they decide (what the side path refuses, when a
//! send is `Full`, which station a frame is for) is the same code whether the port is the kernel's
//! `AF_PACKET` ring ([`AfPacketPort`], what the faces are built with) or, in tests, a bus of
//! stations in memory (`AF_PACKET` needs `CAP_NET_RAW`, which a test run does not have).

use std::future::Future;
use std::os::unix::io::{AsRawFd, OwnedFd};

use bytes::Bytes;
use tokio::io::unix::AsyncFd;

use super::af_packet::{MacAddr, PacketRing, make_sockaddr_ll};
use crate::NDN_ETHERTYPE;

/// A NIC as an Ethernet face sees it: a ring of frames to send and a ring of frames received.
pub trait EtherPort: Send + Sync + 'static {
    /// The next received payload and the station that sent it, if one is waiting.
    fn try_pop_rx(&self) -> Option<(Bytes, MacAddr)>;

    /// Queue one payload to be sent to `dst`; `false` when the send queue has no room. Every
    /// payload leaves for the `dst` it was queued with, whatever else is queued beside it.
    fn try_push_tx(&self, payload: &[u8], dst: &MacAddr) -> bool;

    /// Have what is queued sent now, each payload to its own destination. An error is the
    /// port's own (the interface is down); a send that would block is not one: the payloads
    /// stay queued for the kernel.
    fn flush_tx(&self) -> std::io::Result<()>;

    /// Complete when a payload may be waiting.
    fn readable(&self) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Complete when the send queue may have room.
    fn writable(&self) -> impl Future<Output = std::io::Result<()>> + Send;
}

/// The kernel's `AF_PACKET` socket and its mmap'd rings, bound to one interface for EtherType
/// `0x8624`. Needs `CAP_NET_RAW`.
pub struct AfPacketPort {
    pub(super) ifindex: i32,
    pub(super) socket: AsyncFd<OwnedFd>,
    pub(super) ring: PacketRing,
}

impl EtherPort for AfPacketPort {
    fn try_pop_rx(&self) -> Option<(Bytes, MacAddr)> {
        self.ring.try_pop_rx_with_source()
    }

    fn try_push_tx(&self, payload: &[u8], dst: &MacAddr) -> bool {
        self.ring.try_push_tx(payload, dst)
    }

    fn flush_tx(&self) -> std::io::Result<()> {
        self.ring.flush_with(|dst| {
            let dst = make_sockaddr_ll(self.ifindex, dst, NDN_ETHERTYPE);
            let ret = unsafe {
                libc::sendto(
                    self.socket.get_ref().as_raw_fd(),
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
                    return Err(err);
                }
            }
            Ok(())
        })
    }

    async fn readable(&self) -> std::io::Result<()> {
        self.socket.readable().await?.clear_ready();
        Ok(())
    }

    async fn writable(&self) -> std::io::Result<()> {
        self.socket.writable().await?.clear_ready();
        Ok(())
    }
}
