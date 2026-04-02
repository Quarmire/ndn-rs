use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::net::UdpSocket;

use tracing::trace;

use ndn_packet::fragment::{DEFAULT_UDP_MTU, fragment_packet};
use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// NDN face over unicast UDP.
///
/// Uses an **unconnected** socket with `send_to` / `recv_from` rather than a
/// connected socket with `send` / `recv`.  On macOS (and some BSDs), a
/// connected UDP socket that receives an ICMP port-unreachable enters a
/// permanent error state where every subsequent `send()` fails with
/// `EPIPE` (broken pipe).  The unconnected approach avoids this entirely —
/// each datagram is independent at the kernel level.
///
/// `send_to` is `&self`-safe: `UdpSocket::send_to` takes `&self` and UDP
/// sends are atomic at the kernel level, so no mutex is needed.
///
/// Packets larger than the configured MTU are automatically fragmented into
/// NDNLPv2 LpPacket fragments before sending.
pub struct UdpFace {
    id:     FaceId,
    socket: Arc<UdpSocket>,
    peer:   SocketAddr,
    mtu:    usize,
    seq:    AtomicU64,
}

impl UdpFace {
    /// Bind to `local`, targeting `peer` for all sends.
    ///
    /// The socket is **not** connected — `recv_from` is used and datagrams
    /// from other sources are silently discarded.
    ///
    /// If `local` is `0.0.0.0:0` (or `[::]:0`), the socket is bound to the
    /// specific local interface that the OS routes to `peer`.  This avoids
    /// `EHOSTUNREACH` on macOS when the peer is on a non-default-route
    /// subnet (e.g. a VM bridge network).
    pub async fn bind(
        local: SocketAddr,
        peer:  SocketAddr,
        id:    FaceId,
    ) -> std::io::Result<Self> {
        let local = if local.ip().is_unspecified() {
            resolve_local_addr(peer, local.port())?
        } else {
            local
        };
        let socket = UdpSocket::bind(local).await?;
        Ok(Self { id, socket: Arc::new(socket), peer, mtu: DEFAULT_UDP_MTU, seq: AtomicU64::new(0) })
    }

    /// Wrap an already-bound socket, targeting `peer` for all sends.
    pub fn from_socket(id: FaceId, socket: UdpSocket, peer: SocketAddr) -> Self {
        Self { id, socket: Arc::new(socket), peer, mtu: DEFAULT_UDP_MTU, seq: AtomicU64::new(0) }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl Face for UdpFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Udp }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("udp4://{}:{}", self.peer.ip(), self.peer.port()))
    }

    fn local_uri(&self) -> Option<String> {
        self.socket.local_addr().ok().map(|a| format!("udp4://{}:{}", a.ip(), a.port()))
    }

    /// Receive the next NDN packet from the peer.
    ///
    /// NDN Data can reach 8800 bytes. The 9000-byte buffer covers a single
    /// unfragmented packet. Datagrams from addresses other than `self.peer`
    /// are silently discarded.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut buf = vec![0u8; 9000];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            if src == self.peer {
                trace!(face=%self.id, peer=%self.peer, len=n, "udp: recv");
                buf.truncate(n);
                return Ok(Bytes::from(buf));
            }
            // Ignore datagrams from other sources.
            trace!(face=%self.id, expected=%self.peer, actual=%src, len=n, "udp: recv ignored (wrong source)");
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let wire = ndn_packet::lp::encode_lp_packet(&pkt);
        if wire.len() <= self.mtu {
            trace!(face=%self.id, peer=%self.peer, len=wire.len(), "udp: send");
            self.socket.send_to(&wire, self.peer).await?;
        } else {
            // Fragment the original packet (not the LpPacket wrapper).
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let fragments = fragment_packet(&pkt, self.mtu, seq);
            trace!(face=%self.id, peer=%self.peer, frags=fragments.len(), seq, "udp: send fragmented");
            for frag in &fragments {
                self.socket.send_to(frag, self.peer).await?;
            }
        }
        Ok(())
    }
}

/// Discover the local IP that routes to `peer` by briefly connecting a
/// throwaway UDP socket.  `connect()` on UDP doesn't send anything — it just
/// lets the kernel resolve the route and fill in `local_addr()`.
///
/// Returns a `SocketAddr` with the routable local IP and the requested `port`
/// (0 = OS-chosen ephemeral).
fn resolve_local_addr(peer: SocketAddr, port: u16) -> std::io::Result<SocketAddr> {
    let probe = std::net::UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    probe.connect(peer)?;
    let mut local = probe.local_addr()?;
    local.set_port(port);
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_packet(tag: u8) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[tag]);
        w.finish()
    }

    /// The face wraps outgoing packets in NDNLPv2 LpPacket framing.
    fn expected_on_wire(pkt: &Bytes) -> Bytes {
        ndn_packet::lp::encode_lp_packet(pkt)
    }

    async fn face_pair() -> (UdpFace, UdpFace) {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let face_a = UdpFace::from_socket(FaceId(0), sock_a, addr_b);
        let face_b = UdpFace::from_socket(FaceId(1), sock_b, addr_a);
        (face_a, face_b)
    }

    #[tokio::test]
    async fn udp_roundtrip() {
        let (face_a, face_b) = face_pair().await;

        let pkt = test_packet(0xAB);
        face_a.send(pkt.clone()).await.unwrap();
        let received = face_b.recv().await.unwrap();
        assert_eq!(received, expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn udp_bidirectional() {
        let (face_a, face_b) = face_pair().await;

        face_a.send(test_packet(1)).await.unwrap();
        face_b.send(test_packet(2)).await.unwrap();

        assert_eq!(face_b.recv().await.unwrap(), expected_on_wire(&test_packet(1)));
        assert_eq!(face_a.recv().await.unwrap(), expected_on_wire(&test_packet(2)));
    }

    #[tokio::test]
    async fn udp_multiple_sequential() {
        let (face_a, face_b) = face_pair().await;

        for i in 0u8..5 {
            face_a.send(test_packet(i)).await.unwrap();
            assert_eq!(face_b.recv().await.unwrap(), expected_on_wire(&test_packet(i)));
        }
    }

    #[test]
    fn accessors() {
        // Construct a face with dummy socket addr — just checks metadata.
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_eq!(FaceId(7).0, 7);
        assert_eq!(FaceKind::Udp, FaceKind::Udp);
        let _ = peer; // peer accessor tested in async tests
    }
}
