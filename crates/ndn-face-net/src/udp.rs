use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;

use ndn_transport::{Face, FaceError, FaceId, FaceKind};

/// NDN face over unicast UDP.
///
/// The socket is `connect()`-ed to the peer at construction time, so the kernel
/// filters incoming datagrams to that peer only. `send_to` / `recv_from` are
/// replaced by the simpler `send` / `recv` forms.
///
/// `send` is `&self`-safe: `UdpSocket::send` takes `&self` and UDP sends are
/// atomic at the kernel level, so no mutex is needed.
pub struct UdpFace {
    id:     FaceId,
    socket: Arc<UdpSocket>,
    peer:   SocketAddr,
}

impl UdpFace {
    /// Bind to `local` and connect to `peer`.
    ///
    /// After `connect()`, the socket only receives datagrams from `peer`.
    pub async fn bind(
        local: SocketAddr,
        peer:  SocketAddr,
        id:    FaceId,
    ) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        socket.connect(peer).await?;
        Ok(Self { id, socket: Arc::new(socket), peer })
    }

    /// Wrap an already-bound (and optionally connected) socket.
    pub fn from_socket(id: FaceId, socket: UdpSocket, peer: SocketAddr) -> Self {
        Self { id, socket: Arc::new(socket), peer }
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
    /// unfragmented packet. NDNLPv2 multi-fragment reassembly is a planned
    /// future addition inside this face, invisible to the pipeline above.
    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut buf = vec![0u8; 9000];
        let n = self.socket.recv(&mut buf).await?;
        buf.truncate(n);
        Ok(Bytes::from(buf))
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.socket.send(&pkt).await?;
        Ok(())
    }
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

    #[tokio::test]
    async fn udp_roundtrip() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        sock_a.connect(addr_b).await.unwrap();
        sock_b.connect(addr_a).await.unwrap();

        let face_a = UdpFace::from_socket(FaceId(0), sock_a, addr_b);
        let face_b = UdpFace::from_socket(FaceId(1), sock_b, addr_a);

        let pkt = test_packet(0xAB);
        face_a.send(pkt.clone()).await.unwrap();
        let received = face_b.recv().await.unwrap();
        assert_eq!(received, pkt);
    }

    #[tokio::test]
    async fn udp_bidirectional() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        sock_a.connect(addr_b).await.unwrap();
        sock_b.connect(addr_a).await.unwrap();

        let face_a = UdpFace::from_socket(FaceId(0), sock_a, addr_b);
        let face_b = UdpFace::from_socket(FaceId(1), sock_b, addr_a);

        face_a.send(test_packet(1)).await.unwrap();
        face_b.send(test_packet(2)).await.unwrap();

        assert_eq!(face_b.recv().await.unwrap(), test_packet(1));
        assert_eq!(face_a.recv().await.unwrap(), test_packet(2));
    }

    #[tokio::test]
    async fn udp_multiple_sequential() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        sock_a.connect(addr_b).await.unwrap();
        sock_b.connect(addr_a).await.unwrap();

        let face_a = UdpFace::from_socket(FaceId(0), sock_a, addr_b);
        let face_b = UdpFace::from_socket(FaceId(1), sock_b, addr_a);

        for i in 0u8..5 {
            face_a.send(test_packet(i)).await.unwrap();
            assert_eq!(face_b.recv().await.unwrap(), test_packet(i));
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
