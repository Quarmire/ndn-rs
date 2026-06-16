use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use ndn_transport::{FaceId, FaceKind, StreamFace, TlvCodec, ip_face_uri};

/// NDN face over TCP with TLV length-prefix framing. LP-encoded as a
/// non-local egress.
pub type TcpFace = StreamFace<OwnedReadHalf, OwnedWriteHalf, TlvCodec>;

pub fn tcp_face_from_stream(id: FaceId, stream: TcpStream) -> TcpFace {
    let remote_addr = stream
        .peer_addr()
        .unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
    let (r, w) = stream.into_split();
    StreamFace::new(
        id,
        FaceKind::Tcp,
        Some(ip_face_uri("tcp", remote_addr)),
        Some(ip_face_uri("tcp", local_addr)),
        r,
        w,
        TlvCodec,
    )
}

pub async fn tcp_face_connect(id: FaceId, addr: SocketAddr) -> std::io::Result<TcpFace> {
    let stream = TcpStream::connect(addr).await?;
    Ok(tcp_face_from_stream(id, stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::{Face, FaceError, Transport};
    use tokio::net::TcpListener;

    fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(tag as u64, value);
        w.finish()
    }

    fn expected_on_wire(pkt: &Bytes) -> Bytes {
        ndn_packet::lp::encode_lp_packet(pkt)
    }

    /// Client composes `LpLinkService` so writes are LP-wrapped; server is
    /// held raw so the test can observe wire bytes directly.
    async fn loopback_pair() -> (Face, TcpFace) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = tcp_face_connect(FaceId(0), addr);
        let accept_fut = listener.accept();
        let (client, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        (
            Face::from_transport(client.unwrap()),
            tcp_face_from_stream(FaceId(1), accepted_stream),
        )
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let (client, server) = loopback_pair().await;
        let pkt = make_tlv(0x05, b"hello");
        client.send_bytes(pkt.clone()).await.unwrap();
        assert_eq!(server.recv_bytes().await.unwrap(), expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn framing_large_packet() {
        let (client, server) = loopback_pair().await;
        let payload = vec![0xABu8; 1000];
        let pkt = make_tlv(0x06, &payload);
        client.send_bytes(pkt.clone()).await.unwrap();
        assert_eq!(server.recv_bytes().await.unwrap(), expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn framing_multiple_sequential() {
        let (client, server) = loopback_pair().await;
        let pkts: Vec<Bytes> = (0u8..5).map(|i| make_tlv(0x05, &[i])).collect();
        for pkt in &pkts {
            client.send_bytes(pkt.clone()).await.unwrap();
        }
        for expected in &pkts {
            assert_eq!(
                server.recv_bytes().await.unwrap(),
                expected_on_wire(expected)
            );
        }
    }

    #[tokio::test]
    async fn recv_eof_returns_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let accept_fut = listener.accept();
        let (stream, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        let server = tcp_face_from_stream(FaceId(1), accepted_stream);
        drop(stream.unwrap());
        assert!(matches!(server.recv_bytes().await, Err(FaceError::Closed)));
    }

    #[tokio::test]
    async fn concurrent_sends_arrive_intact() {
        use std::sync::Arc;
        let (client, server) = loopback_pair().await;
        let client = Arc::new(client);

        let handles: Vec<_> = (0u8..8)
            .map(|i| {
                let c = Arc::clone(&client);
                tokio::spawn(async move {
                    c.send_bytes(make_tlv(0x05, &[i])).await.unwrap();
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }

        let mut received = Vec::new();
        for _ in 0u8..8 {
            received.push(server.recv_bytes().await.unwrap());
        }
        assert_eq!(received.len(), 8);
    }
}
