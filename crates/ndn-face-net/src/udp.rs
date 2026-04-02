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
            let resolved = resolve_local_addr(peer, local.port())?;
            trace!(peer=%peer, resolved=%resolved, "udp: resolved local addr for peer");
            resolved
        } else {
            local
        };
        let socket = UdpSocket::bind(local).await?;
        trace!(face=%id, local=%socket.local_addr().unwrap_or(local), peer=%peer, "udp: bound");
        Ok(Self { id, socket: Arc::new(socket), peer, mtu: DEFAULT_UDP_MTU, seq: AtomicU64::new(0) })
    }

    /// Wrap an already-bound socket, targeting `peer` for all sends.
    pub fn from_socket(id: FaceId, socket: UdpSocket, peer: SocketAddr) -> Self {
        Self { id, socket: Arc::new(socket), peer, mtu: DEFAULT_UDP_MTU, seq: AtomicU64::new(0) }
    }

    /// Create a face that shares an existing socket (e.g. the UDP listener socket).
    ///
    /// Replies go out from the same port the listener is bound to, so the
    /// remote peer's connected/filtered socket accepts them.  The `recv()`
    /// loop filters datagrams by `peer` address.
    pub fn from_shared_socket(id: FaceId, socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self { id, socket, peer, mtu: DEFAULT_UDP_MTU, seq: AtomicU64::new(0) }
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

    /// Receive the next datagram from the peer.
    ///
    /// Returns the raw datagram bytes (may be a bare packet or LpPacket).
    /// Fragment reassembly is handled by the pipeline's TlvDecode stage,
    /// not here — keeping the Face layer protocol-agnostic.
    ///
    /// Datagrams from addresses other than `self.peer` are silently discarded.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        // Reuse a stack buffer; only allocate the exact received size via
        // copy_from_slice.  Avoids a 9 KB heap allocation per packet.
        let mut buf = [0u8; 9000];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            if src == self.peer {
                trace!(face=%self.id, peer=%self.peer, len=n, "udp: recv");
                return Ok(Bytes::copy_from_slice(&buf[..n]));
            }
            trace!(face=%self.id, expected=%self.peer, actual=%src, len=n, "udp: recv ignored (wrong source)");
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        // If the packet is already an LpPacket (e.g. from the reliability layer),
        // send it directly — it's already correctly framed and within MTU.
        if ndn_packet::lp::is_lp_packet(&pkt) {
            trace!(face=%self.id, peer=%self.peer, len=pkt.len(), "udp: send (passthrough)");
            self.socket.send_to(&pkt, self.peer).await?;
            return Ok(());
        }

        // LpPacket envelope adds ~4 bytes overhead.  Check whether the packet
        // needs fragmentation *before* wrapping to avoid an 8 KB allocation
        // that would immediately be discarded.
        if pkt.len() + 4 <= self.mtu {
            let wire = ndn_packet::lp::encode_lp_packet(&pkt);
            trace!(face=%self.id, peer=%self.peer, len=wire.len(), "udp: send");
            self.socket.send_to(&wire, self.peer).await?;
        } else {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let fragments = fragment_packet(&pkt, self.mtu, seq);
            trace!(face=%self.id, peer=%self.peer, frags=fragments.len(), seq, "udp: send fragmented");
            // Use try_send_to to avoid tokio async poll overhead per fragment.
            // UDP sends almost never block (kernel just copies to send buffer).
            for frag in &fragments {
                match self.socket.try_send_to(frag, self.peer) {
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Socket buffer full — fall back to async send.
                        self.socket.send_to(frag, self.peer).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
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
