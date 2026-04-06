//! NDN face over WebSocket (binary frames).
//!
//! WebSocket provides its own message framing, so no `TlvCodec` is needed —
//! each WebSocket binary message carries exactly one NDN packet (wrapped in
//! NDNLPv2 `LpPacket`).
//!
//! Supports both client-initiated (`connect`) and server-accepted (`from_stream`)
//! connections.  Compatible with NFD's WebSocket face.

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::trace;

use ndn_transport::{Face, FaceError, FaceId, FaceKind};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// NDN face over WebSocket with binary message framing.
///
/// The WebSocket stream is split into independent read and write halves, each
/// behind its own `Mutex` — mirroring the `TcpFace` pattern.
pub struct WebSocketFace {
    id: FaceId,
    remote_addr: String,
    local_addr: String,
    reader: Mutex<futures::stream::SplitStream<WsStream>>,
    writer: Mutex<futures::stream::SplitSink<WsStream, Message>>,
}

impl WebSocketFace {
    /// Connect to a WebSocket endpoint (client side).
    pub async fn connect(
        id: FaceId,
        url: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (ws, _response) = tokio_tungstenite::connect_async(url).await?;

        // Extract addresses from the underlying TCP stream before splitting.
        let (remote_addr, local_addr) = match ws.get_ref() {
            MaybeTlsStream::Plain(tcp) => (
                tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
                tcp.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            ),
            _ => (url.to_string(), String::new()),
        };

        let (writer, reader) = ws.split();
        Ok(Self {
            id,
            remote_addr,
            local_addr,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }

    /// Wrap an already-accepted WebSocket stream (server side).
    pub fn from_stream(
        id: FaceId,
        ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
        remote_addr: String,
        local_addr: String,
    ) -> Self {
        let (writer, reader) = ws.split();
        Self {
            id,
            remote_addr,
            local_addr,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        }
    }

    pub fn remote_addr(&self) -> &str {
        &self.remote_addr
    }
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
}

impl Face for WebSocketFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::WebSocket
    }

    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_addr.clone())
    }

    fn local_uri(&self) -> Option<String> {
        Some(self.local_addr.clone())
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut reader = self.reader.lock().await;
        loop {
            let msg = reader
                .next()
                .await
                .ok_or(FaceError::Closed)?
                .map_err(|e| FaceError::Io(std::io::Error::other(e)))?;

            match msg {
                Message::Binary(data) => {
                    trace!(face=%self.id, len=data.len(), "ws: recv binary");
                    return Ok(data);
                }
                Message::Close(_) => return Err(FaceError::Closed),
                // Skip text, ping, pong frames.
                _ => continue,
            }
        }
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let wire = ndn_packet::lp::encode_lp_packet(&pkt);
        trace!(face=%self.id, len=wire.len(), "ws: send binary");
        let mut writer = self.writer.lock().await;
        writer
            .send(Message::Binary(wire.to_vec().into()))
            .await
            .map_err(|e| FaceError::Io(std::io::Error::other(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    async fn loopback_pair() -> (WebSocketFace, WebSocketFace) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("ws://127.0.0.1:{}", addr.port());

        let accept_fut = async {
            let (stream, peer) = listener.accept().await.unwrap();
            let ws = accept_async(MaybeTlsStream::Plain(stream)).await.unwrap();
            WebSocketFace::from_stream(FaceId(1), ws, peer.to_string(), addr.to_string())
        };

        let connect_fut = WebSocketFace::connect(FaceId(0), &url);

        let (server, client) = tokio::join!(accept_fut, connect_fut);
        (client.unwrap(), server)
    }

    fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(tag as u64, value);
        w.finish()
    }

    fn expected_on_wire(pkt: &Bytes) -> Bytes {
        ndn_packet::lp::encode_lp_packet(pkt)
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let (client, server) = loopback_pair().await;
        let pkt = make_tlv(0x05, b"hello");
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let (client, server) = loopback_pair().await;
        client.send(make_tlv(0x05, b"interest")).await.unwrap();
        server.send(make_tlv(0x06, b"data")).await.unwrap();
        assert_eq!(
            server.recv().await.unwrap(),
            expected_on_wire(&make_tlv(0x05, b"interest"))
        );
        assert_eq!(
            client.recv().await.unwrap(),
            expected_on_wire(&make_tlv(0x06, b"data"))
        );
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
                    c.send(make_tlv(0x05, &[i])).await.unwrap();
                })
            })
            .collect();
        for h in handles {
            h.await.unwrap();
        }

        let mut received = Vec::new();
        for _ in 0u8..8 {
            received.push(server.recv().await.unwrap());
        }
        assert_eq!(received.len(), 8);
    }

    #[tokio::test]
    async fn close_detection() {
        let (client, server) = loopback_pair().await;
        drop(client);
        // Server should detect the close.
        let result = server.recv().await;
        assert!(result.is_err());
    }
}
