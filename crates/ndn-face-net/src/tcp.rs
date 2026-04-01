use std::net::SocketAddr;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite};

use ndn_transport::{Face, FaceError, FaceId, FaceKind, TlvCodec};

/// NDN face over TCP with TLV length-prefix framing.
///
/// The TCP stream is split into independent read and write halves, each behind
/// its own `Mutex`:
///
/// - `reader`: locked only by the face's receive task (single consumer, never
///   actually contends).
/// - `writer`: locked by whichever pipeline task calls `send()`, serialising
///   concurrent sends on the same stream.
///
/// `TlvCodec` provides TLV length-prefix framing so the pipeline receives
/// complete NDN packets regardless of TCP segmentation.
pub struct TcpFace {
    id:          FaceId,
    remote_addr: SocketAddr,
    local_addr:  SocketAddr,
    reader:      Mutex<FramedRead<OwnedReadHalf, TlvCodec>>,
    writer:      Mutex<FramedWrite<OwnedWriteHalf, TlvCodec>>,
}

impl TcpFace {
    /// Wrap an accepted or connected `TcpStream`.
    pub fn from_stream(id: FaceId, stream: TcpStream) -> Self {
        let remote_addr = stream.peer_addr().unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
        let local_addr = stream.local_addr().unwrap_or_else(|_| ([0, 0, 0, 0], 0).into());
        let (r, w) = stream.into_split();
        Self {
            id,
            remote_addr,
            local_addr,
            reader: Mutex::new(FramedRead::new(r, TlvCodec)),
            writer: Mutex::new(FramedWrite::new(w, TlvCodec)),
        }
    }

    /// Open a new TCP connection to `addr`.
    pub async fn connect(id: FaceId, addr: SocketAddr) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self::from_stream(id, stream))
    }

    pub fn remote_addr(&self) -> SocketAddr { self.remote_addr }
    pub fn local_addr(&self) -> SocketAddr { self.local_addr }
}

impl Face for TcpFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Tcp }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("tcp4://{}:{}", self.remote_addr.ip(), self.remote_addr.port()))
    }

    fn local_uri(&self) -> Option<String> {
        Some(format!("tcp4://{}:{}", self.local_addr.ip(), self.local_addr.port()))
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut reader = self.reader.lock().await;
        reader
            .next()
            .await
            .ok_or(FaceError::Closed)?
            .map_err(FaceError::Io)
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let mut writer = self.writer.lock().await;
        writer.send(pkt).await.map_err(FaceError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(tag as u64, value);
        w.finish()
    }

    async fn loopback_pair() -> (TcpFace, TcpFace) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_fut = TcpFace::connect(FaceId(0), addr);
        let accept_fut  = listener.accept();
        let (client, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        (client.unwrap(), TcpFace::from_stream(FaceId(1), accepted_stream))
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let (client, server) = loopback_pair().await;
        let pkt = make_tlv(0x05, b"hello");
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), pkt);
    }

    #[tokio::test]
    async fn framing_large_packet() {
        let (client, server) = loopback_pair().await;
        let payload = vec![0xABu8; 1000];
        let pkt = make_tlv(0x06, &payload);
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), pkt);
    }

    #[tokio::test]
    async fn framing_multiple_sequential() {
        let (client, server) = loopback_pair().await;
        let pkts: Vec<Bytes> = (0u8..5).map(|i| make_tlv(0x05, &[i])).collect();
        for pkt in &pkts {
            client.send(pkt.clone()).await.unwrap();
        }
        for expected in &pkts {
            assert_eq!(&server.recv().await.unwrap(), expected);
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
        let server = TcpFace::from_stream(FaceId(1), accepted_stream);
        drop(stream.unwrap()); // close client side
        assert!(matches!(server.recv().await, Err(FaceError::Closed)));
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let (client, server) = loopback_pair().await;
        client.send(make_tlv(0x05, b"interest")).await.unwrap();
        server.send(make_tlv(0x06, b"data")).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), make_tlv(0x05, b"interest"));
        assert_eq!(client.recv().await.unwrap(), make_tlv(0x06, b"data"));
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
