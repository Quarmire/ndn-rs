use std::os::unix::io::AsRawFd;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};
use tokio::io::unix::AsyncFd;

use crate::NDN_ETHERTYPE;
use crate::af_packet::{
    MacAddr, PacketRing, get_ifindex, make_sockaddr_ll, open_packet_socket, setup_packet_ring,
};
use crate::radio::RadioFaceMetadata;

// ─── NamedEtherFace ──────────────────────────────────────────────────────────

/// NDN face over raw Ethernet (`AF_PACKET` / Ethertype 0x8624).
///
/// Uses `SOCK_DGRAM` with a TPACKET_V2 mmap'd ring buffer for zero-copy
/// packet I/O.  The kernel strips/builds the Ethernet header automatically:
/// `recv()` returns the NDN TLV payload directly; `send()` accepts the NDN
/// TLV payload and the kernel prepends the Ethernet frame header.
///
/// The MAC address is an internal implementation detail — above the face layer
/// everything is NDN names.  The node name is stable across channel switches
/// and radio changes; only the internal MAC binding needs updating on mobility.
///
/// Requires `CAP_NET_RAW` or root.
pub struct NamedEtherFace {
    id: FaceId,
    /// NDN node name of the remote peer.
    pub node_name: Name,
    /// Resolved MAC address of the remote peer.
    peer_mac: MacAddr,
    /// Local network interface name.
    iface: String,
    /// Interface index (cached from constructor).
    ifindex: i32,
    /// Radio metadata for multi-radio strategies.
    pub radio: RadioFaceMetadata,
    /// Non-blocking AF_PACKET socket registered with tokio.
    socket: AsyncFd<std::os::unix::io::OwnedFd>,
    /// Mmap'd TPACKET_V2 RX + TX ring buffers.
    ring: PacketRing,
}

impl NamedEtherFace {
    /// Create a new Ethernet face bound to `iface`.
    ///
    /// Opens an `AF_PACKET + SOCK_DGRAM` socket, configures a TPACKET_V2 mmap
    /// ring buffer, binds to the given network interface, and registers the
    /// socket with the tokio reactor.  Requires `CAP_NET_RAW`.
    pub fn new(
        id: FaceId,
        node_name: Name,
        peer_mac: MacAddr,
        iface: impl Into<String>,
        radio: RadioFaceMetadata,
    ) -> std::io::Result<Self> {
        let iface = iface.into();

        // Temporary socket to resolve the interface index.
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

        // Set up mmap ring buffers BEFORE registering with AsyncFd.
        let ring = setup_packet_ring(fd.as_raw_fd())?;
        let socket = AsyncFd::new(fd)?;

        Ok(Self {
            id,
            node_name,
            peer_mac,
            iface,
            ifindex,
            radio,
            socket,
            ring,
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
        &self.iface
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
            if let Some(pkt) = self.ring.try_pop_rx() {
                return Ok(pkt);
            }
            let mut guard = self.socket.readable().await?;
            guard.clear_ready();
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        // Wait for an available TX frame.
        loop {
            if self.ring.try_push_tx(&pkt) {
                break;
            }
            let mut guard = self.socket.writable().await?;
            guard.clear_ready();
        }

        // Flush pending TX frames.
        let dst = make_sockaddr_ll(self.ifindex, &self.peer_mac, NDN_ETHERTYPE);
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Opening an AF_PACKET socket without CAP_NET_RAW should fail with EPERM.
    #[tokio::test]
    async fn new_fails_without_cap_net_raw() {
        let name = Name::from_str("/test/node").unwrap();
        let result = NamedEtherFace::new(
            FaceId(1),
            name,
            MacAddr::BROADCAST,
            "lo",
            RadioFaceMetadata::default(),
        );
        if let Err(e) = result {
            let raw = e.raw_os_error().unwrap_or(0);
            assert!(
                raw == libc::EPERM || raw == libc::EACCES,
                "expected EPERM or EACCES, got: {e}"
            );
        }
    }

    /// Full loopback roundtrip — requires root / CAP_NET_RAW.
    #[tokio::test]
    #[ignore = "requires CAP_NET_RAW"]
    async fn loopback_roundtrip() {
        let name = Name::from_str("/test/node").unwrap();
        let lo_mac = MacAddr::new([0; 6]);
        let face_a = NamedEtherFace::new(
            FaceId(1),
            name.clone(),
            lo_mac,
            "lo",
            RadioFaceMetadata::default(),
        )
        .expect("need CAP_NET_RAW");
        let face_b =
            NamedEtherFace::new(FaceId(2), name, lo_mac, "lo", RadioFaceMetadata::default())
                .expect("need CAP_NET_RAW");

        let pkt = Bytes::from_static(b"\x05\x03\x01\x02\x03");
        face_a.send(pkt.clone()).await.unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), face_b.recv())
            .await
            .expect("timed out")
            .unwrap();

        assert_eq!(received, pkt);
    }
}
