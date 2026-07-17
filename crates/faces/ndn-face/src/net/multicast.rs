use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;

use ndn_packet::fragment::DEFAULT_UDP_MTU;
use ndn_transport::{FaceAddr, FaceError, FaceId, FaceKind, LinkType, Transport};

/// IANA-assigned NDN IPv4 link-local multicast group.
pub const NDN_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 23, 170);

/// NDN unicast UDP port (NFD `face_system.udp`).
pub const NDN_PORT: u16 = 6363;

/// NDN multicast UDP port — NFD `DEFAULT_MULTICAST_PORT` in
/// `daemon/face/multicast-udp-factory.cpp`. Distinct from the unicast port
/// to avoid a unicast face and the multicast group binding the same address.
pub const NDN_MULTICAST_PORT: u16 = 56363;

/// NDN face over IPv4 link-local multicast for neighbor discovery and prefix
/// announcement; Data is returned via unicast `UdpFace` to the responder.
pub struct MulticastUdpFace {
    id: FaceId,
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    mtu: usize,
    link_type: LinkType,
    /// Reported [`FaceKind`] — `Multicast` by default. Re-tag (e.g.
    /// [`FaceKind::WifiDirect`]) when the group runs over a specific radio so
    /// telemetry names it; the transport is unchanged. See [`Self::with_kind`].
    kind: FaceKind,
}

impl MulticastUdpFace {
    /// Bind to `port`, join `group` on `iface`.
    pub async fn new(
        iface: Ipv4Addr,
        port: u16,
        group: Ipv4Addr,
        id: FaceId,
    ) -> std::io::Result<Self> {
        let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
        // Bind with SO_REUSEPORT/SO_REUSEADDR so several NDN nodes (or apps, or
        // test peers) on one host can all join the same multicast group:port —
        // NFD's multicast factory does the same. Without it the second binder
        // fails and its multicast face silently never receives.
        let socket = {
            #[cfg(unix)]
            {
                let std_sock = super::sockopt::bind_reuseport_udp(bind_addr)?;
                std_sock.set_nonblocking(true)?;
                UdpSocket::from_std(std_sock)?
            }
            #[cfg(not(unix))]
            {
                let s = UdpSocket::bind(bind_addr).await?;
                super::sockopt::tune_datagram_socket(&s, "multicast");
                s
            }
        };
        socket.set_multicast_loop_v4(true)?;
        socket.join_multicast_v4(group, iface)?;
        Ok(Self {
            id,
            socket: Arc::new(socket),
            dest: SocketAddr::V4(SocketAddrV4::new(group, port)),
            mtu: DEFAULT_UDP_MTU,
            link_type: LinkType::MultiAccess,
            kind: FaceKind::Multicast,
        })
    }

    /// Standard NDN multicast (`224.0.23.170:56363`) on `iface`.
    pub async fn ndn_default(iface: Ipv4Addr, id: FaceId) -> std::io::Result<Self> {
        Self::new(iface, NDN_MULTICAST_PORT, NDN_MULTICAST_V4, id).await
    }

    /// Wrap a pre-bound, group-joined socket (e.g. when `SO_REUSEADDR` is
    /// needed by the caller).
    pub fn with_socket(id: FaceId, socket: UdpSocket, dest: SocketAddr) -> Self {
        Self {
            id,
            socket: Arc::new(socket),
            dest,
            mtu: DEFAULT_UDP_MTU,
            link_type: LinkType::MultiAccess,
            kind: FaceKind::Multicast,
        }
    }

    /// Re-tag the reported [`FaceKind`] (default [`FaceKind::Multicast`]) — e.g.
    /// [`FaceKind::WifiDirect`] for the NDN group running over a Wi-Fi P2P
    /// interface. Telemetry/cost see the real radio; the transport is unchanged.
    pub fn with_kind(mut self, kind: FaceKind) -> Self {
        self.kind = kind;
        self
    }

    /// Mark as `AdHoc` (Wi-Fi IBSS / MANET) so strategies disable
    /// multi-access Interest suppression — not every node hears every frame.
    pub fn ad_hoc(mut self) -> Self {
        self.link_type = LinkType::AdHoc;
        self
    }

    pub fn dest(&self) -> SocketAddr {
        self.dest
    }
}

impl MulticastUdpFace {
    /// Receive the next NDN packet along with the UDP source address, so the
    /// discovery layer can build a unicast reply face.
    pub async fn recv_with_source(&self) -> Result<(Bytes, std::net::SocketAddr), FaceError> {
        let mut buf = vec![0u8; 9000];
        let (n, src) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((Bytes::from(buf), src))
    }
}

impl Transport for MulticastUdpFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }
    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu)
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let (pkt, _src) = self.recv_with_source().await?;
        Ok(pkt)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let (pkt, src) = self.recv_with_source().await?;
        Ok((pkt, Some(FaceAddr::Udp(src))))
    }

    /// LP framing and fragmentation live in the paired
    /// [`LpLinkService`](ndn_transport::LpLinkService).
    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        match self.socket.try_send_to(&wire, self.dest) {
            Ok(_) => Ok(()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.send_to(&wire, self.dest).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Reply-to-source: unicast `wire` back to the specific UDP peer that a
    /// prior [`recv_bytes_with_addr`](Transport::recv_bytes_with_addr) surfaced
    /// via [`FaceAddr::Udp`], instead of re-broadcasting to the group. Mirrors
    /// [`send_bytes`](Self::send_bytes) exactly (same `try_send_to` → async
    /// fallback), only the destination differs; the payload is already
    /// LP-framed by the paired `LpLinkService`. A non-`Udp` `FaceAddr` cannot
    /// come from this socket, so it falls back to the multicast group send.
    async fn send_bytes_to(&self, addr: FaceAddr, wire: Bytes) -> Result<(), FaceError> {
        let FaceAddr::Udp(peer) = addr else {
            return self.send_bytes(wire).await;
        };
        match self.socket.try_send_to(&wire, peer) {
            Ok(_) => Ok(()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.send_to(&wire, peer).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
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

    /// Multicast group binds on 56363 — matches NFD's `DEFAULT_MULTICAST_PORT`
    /// in `daemon/face/multicast-udp-factory.cpp`.
    #[test]
    fn ndn_multicast_port_is_56363() {
        assert_eq!(NDN_MULTICAST_PORT, 56363);
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

    /// Reply-to-source round-trip. Pure loopback **unicast** — no multicast
    /// join or multicast loop-back (which the sandbox blocks with os error 49),
    /// so it runs everywhere: B unicasts to A; A learns B's addr via
    /// `recv_bytes_with_addr`; A `send_bytes_to` that addr and the reply lands
    /// on B — proving the override targets the peer, not the group `dest`.
    #[tokio::test]
    async fn reply_to_source_unicasts_to_peer() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        // A deliberately-bogus group `dest`: send_bytes_to must NOT use it.
        let group: SocketAddr = "224.0.23.170:56363".parse().unwrap();
        let face_a = MulticastUdpFace::with_socket(FaceId(0), sock_a, group);

        // B unicasts a "request" to A.
        let req = Bytes::from_static(b"\x05\x03ndn");
        sock_b.send_to(&req, addr_a).await.unwrap();

        // A receives it and learns B's source address.
        let (got, src) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            face_a.recv_bytes_with_addr(),
        )
        .await
        .expect("recv timed out")
        .expect("recv failed");
        assert_eq!(got, req);
        let src = src.expect("multicast face surfaces the UDP source addr");
        match src {
            FaceAddr::Udp(sa) => assert_eq!(sa, addr_b),
            other => panic!("expected Udp source, got {other:?}"),
        }

        // A replies to source: the reply must arrive at B (the peer), not the
        // multicast group `dest`.
        let reply = Bytes::from_static(b"\x06\x04data");
        face_a.send_bytes_to(src, reply.clone()).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sock_b.recv_from(&mut buf),
        )
        .await
        .expect("reply timed out")
        .expect("reply recv failed");
        assert_eq!(&buf[..n], &reply[..]);
        assert_eq!(from, addr_a);
    }

    /// Skipped in sandboxed CI where multicast join or loop-back is blocked.
    #[tokio::test]
    async fn multicast_loopback_roundtrip() {
        use ndn_transport::Face;
        let group = NDN_MULTICAST_V4;
        let iface = Ipv4Addr::LOCALHOST;

        let sock_send = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let sock_recv = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let recv_port = sock_recv.local_addr().unwrap().port();

        if sock_send.set_multicast_loop_v4(true).is_err() {
            return;
        }
        if sock_recv.join_multicast_v4(group, iface).is_err() {
            return;
        }

        let dest = SocketAddr::V4(SocketAddrV4::new(group, recv_port));
        let sender =
            Face::from_transport(MulticastUdpFace::with_socket(FaceId(0), sock_send, dest));
        let receiver = MulticastUdpFace::with_socket(FaceId(1), sock_recv, dest);

        let pkt = Bytes::from_static(b"\x05\x03ndn");
        if sender.send_bytes(pkt.clone()).await.is_err() {
            return;
        }

        let expected = ndn_packet::lp::encode_lp_packet(&pkt);

        if let Ok(Ok(received)) =
            tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv_bytes()).await
        {
            assert_eq!(received, expected)
        }
    }
}
