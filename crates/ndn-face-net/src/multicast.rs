use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::net::UdpSocket;

use ndn_packet::fragment::{DEFAULT_UDP_MTU, fragment_packet};
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// IANA-assigned NDN IPv4 link-local multicast group.
pub const NDN_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 170);

/// NDN standard UDP port.
pub const NDN_PORT: u16 = 6363;

/// NDN face over IPv4 link-local multicast.
///
/// Interests sent on this face reach all NDN-capable nodes on the local link
/// without requiring prior knowledge of their addresses. Data is returned via
/// unicast `UdpFace` to the specific responder.
///
/// ## Typical usage
///
/// 1. Start `MulticastUdpFace` at boot for neighbor discovery and prefix
///    announcements.
/// 2. On receiving a multicast Interest, create a unicast `UdpFace` back to
///    the responder's source address and register it in the FIB.
/// 3. Subsequent traffic uses the unicast face; the multicast face handles
///    only discovery and control traffic.
pub struct MulticastUdpFace {
    id: FaceId,
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    mtu: usize,
    seq: AtomicU64,
}

impl MulticastUdpFace {
    /// Bind to `port`, join `group` on interface `iface`.
    /// Use `NDN_MULTICAST_V4` and `NDN_PORT` for standard NDN.
    pub async fn new(
        iface: Ipv4Addr,
        port: u16,
        group: Ipv4Addr,
        id: FaceId,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).await?;
        socket.set_multicast_loop_v4(true)?;
        socket.join_multicast_v4(group, iface)?;
        Ok(Self {
            id,
            socket: Arc::new(socket),
            dest: SocketAddr::V4(SocketAddrV4::new(group, port)),
            mtu: DEFAULT_UDP_MTU,
            seq: AtomicU64::new(0),
        })
    }

    /// Standard NDN multicast (`224.0.23.170:6363`) on `iface`.
    pub async fn ndn_default(iface: Ipv4Addr, id: FaceId) -> std::io::Result<Self> {
        Self::new(iface, NDN_PORT, NDN_MULTICAST_V4, id).await
    }

    /// Wrap a pre-configured socket. The caller is responsible for binding and
    /// joining the multicast group. Useful when `SO_REUSEADDR` is needed.
    pub fn with_socket(id: FaceId, socket: UdpSocket, dest: SocketAddr) -> Self {
        Self {
            id,
            socket: Arc::new(socket),
            dest,
            mtu: DEFAULT_UDP_MTU,
            seq: AtomicU64::new(0),
        }
    }

    pub fn dest(&self) -> SocketAddr {
        self.dest
    }
}

impl MulticastUdpFace {
    /// Receive the next NDN packet along with the UDP source address.
    ///
    /// Used by the discovery layer to learn the sender's address and create a
    /// unicast reply face — without requiring the sender to embed their address
    /// in the Interest payload.
    pub async fn recv_with_source(&self) -> Result<(Bytes, std::net::SocketAddr), FaceError> {
        let mut buf = vec![0u8; 9000];
        let (n, src) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((Bytes::from(buf), src))
    }
}

impl Face for MulticastUdpFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::Multicast
    }

    /// Receive the next NDN packet from any sender on the multicast group.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        let (pkt, _src) = self.recv_with_source().await?;
        Ok(pkt)
    }

    /// Receive packet and expose the UDP source address to the discovery layer.
    async fn recv_with_addr(&self) -> Result<(Bytes, Option<std::net::SocketAddr>), FaceError> {
        let (pkt, src) = self.recv_with_source().await?;
        Ok((pkt, Some(src)))
    }

    /// Broadcast an NDN packet to the multicast group.
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        if pkt.len() + 4 <= self.mtu {
            let wire = ndn_packet::lp::encode_lp_packet(&pkt);
            self.socket.send_to(&wire, self.dest).await?;
        } else {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let fragments = fragment_packet(&pkt, self.mtu, seq);
            for frag in &fragments {
                match self.socket.try_send_to(frag, self.dest) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        self.socket.send_to(frag, self.dest).await?;
                    }
                    Err(e) => return Err(e.into()),
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
    fn ndn_multicast_group_is_multicast() {
        assert!(NDN_MULTICAST_V4.is_multicast());
        assert_eq!(NDN_MULTICAST_V4.octets(), [224, 0, 23, 170]);
    }

    #[test]
    fn ndn_port_is_6363() {
        assert_eq!(NDN_PORT, 6363);
    }

    #[tokio::test]
    async fn with_socket_metadata() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest: SocketAddr = "224.0.23.170:6363".parse().unwrap();
        let face = MulticastUdpFace::with_socket(FaceId(3), socket, dest);
        assert_eq!(face.id(), FaceId(3));
        assert_eq!(face.kind(), FaceKind::Multicast);
        assert_eq!(face.dest(), dest);
    }

    /// Full multicast loopback: may be skipped in sandboxed CI environments
    /// where joining multicast groups is restricted or loopback is unsupported.
    #[tokio::test]
    async fn multicast_loopback_roundtrip() {
        let group = NDN_MULTICAST_V4;
        let iface = Ipv4Addr::LOCALHOST;

        // Bind two sockets on OS-chosen ports.
        let sock_send = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let sock_recv = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let recv_port = sock_recv.local_addr().unwrap().port();

        if sock_send.set_multicast_loop_v4(true).is_err() {
            return; // multicast loop unsupported — skip
        }
        if sock_recv.join_multicast_v4(group, iface).is_err() {
            return; // multicast join unsupported — skip
        }

        let dest = SocketAddr::V4(SocketAddrV4::new(group, recv_port));
        let sender = MulticastUdpFace::with_socket(FaceId(0), sock_send, dest);
        let receiver = MulticastUdpFace::with_socket(FaceId(1), sock_recv, dest);

        let pkt = Bytes::from_static(b"\x05\x03ndn");
        if sender.send(pkt.clone()).await.is_err() {
            return; // sending to multicast unsupported — skip
        }

        let expected = ndn_packet::lp::encode_lp_packet(&pkt);

        // Wrap with a timeout — environments that route multicast away from loopback
        // will block recv() indefinitely without one.
        match tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv()).await {
            Ok(Ok(received)) => assert_eq!(received, expected),
            _ => { /* packet didn't arrive — skip */ }
        }
    }
}
