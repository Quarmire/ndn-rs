use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use ndn_transport::{FaceId, FaceKind, StreamFace, TlvCodec};

/// NDN face over TCP with TLV length-prefix framing.
///
/// Uses [`StreamFace`] with TCP read/write halves and [`TlvCodec`].
/// LP-encoding is enabled for network transport.
pub type TcpFace = StreamFace<OwnedReadHalf, OwnedWriteHalf, TlvCodec>;

/// Wrap an accepted or connected `TcpStream` into a [`TcpFace`].
pub fn tcp_face_from_stream(id: FaceId, stream: TcpStream) -> TcpFace {
    let remote_addr = stream.peer_addr().unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
    let local_addr = stream.local_addr().unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
    let (r, w) = stream.into_split();
    StreamFace::new(
        id,
        FaceKind::Tcp,
        true,
        Some(format!("tcp4://{}:{}", remote_addr.ip(), remote_addr.port())),
        Some(format!("tcp4://{}:{}", local_addr.ip(), local_addr.port())),
        r,
        w,
        TlvCodec,
    )
}

/// Open a new TCP connection to `addr` and return a [`TcpFace`].
pub async fn tcp_face_connect(id: FaceId, addr: SocketAddr) -> std::io::Result<TcpFace> {
    let stream = TcpStream::connect(addr).await?;
    Ok(tcp_face_from_stream(id, stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::{Face, FaceError};
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

    async fn loopback_pair() -> (TcpFace, TcpFace) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = tcp_face_connect(FaceId(0), addr);
        let accept_fut  = listener.accept();
        let (client, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        (client.unwrap(), tcp_face_from_stream(FaceId(1), accepted_stream))
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let (client, server) = loopback_pair().await;
        let pkt = make_tlv(0x05, b"hello");
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn framing_large_packet() {
        let (client, server) = loopback_pair().await;
        let payload = vec![0xABu8; 1000];
        let pkt = make_tlv(0x06, &payload);
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn framing_multiple_sequential() {
        let (client, server) = loopback_pair().await;
        let pkts: Vec<Bytes> = (0u8..5).map(|i| make_tlv(0x05, &[i])).collect();
        for pkt in &pkts {
            client.send(pkt.clone()).await.unwrap();
        }
        for expected in &pkts {
            assert_eq!(server.recv().await.unwrap(), expected_on_wire(expected));
        }
    }

    #[tokio::test]
    async fn recv_eof_returns_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpStream::connect(addr);
        let accept_fut  = listener.accept();
        let (stream, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        let server = tcp_face_from_stream(FaceId(1), accepted_stream);
        drop(stream.unwrap());
        assert!(matches!(server.recv().await, Err(FaceError::Closed)));
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let (client, server) = loopback_pair().await;
        client.send(make_tlv(0x05, b"interest")).await.unwrap();
        server.send(make_tlv(0x06, b"data")).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), expected_on_wire(&make_tlv(0x05, b"interest")));
        assert_eq!(client.recv().await.unwrap(), expected_on_wire(&make_tlv(0x06, b"data")));
    }

    #[tokio::test]
    async fn concurrent_sends_arrive_intact() {
        use std::sync::Arc;
        let (client, server) = loopback_pair().await;
        let client = Arc::new(client);

        let handles: Vec<_> = (0u8..8).map(|i| {
            let c = Arc::clone(&client);
            tokio::spawn(async move { c.send(make_tlv(0x05, &[i])).await.unwrap(); })
        }).collect();
        for h in handles { h.await.unwrap(); }

        let mut received = Vec::new();
        for _ in 0u8..8 {
            received.push(server.recv().await.unwrap());
        }
        assert_eq!(received.len(), 8);
    }
}
