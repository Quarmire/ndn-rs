use std::path::PathBuf;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite};

use ndn_transport::{Face, FaceError, FaceId, FaceKind, TlvCodec};

/// NDN face over a Unix domain socket with TLV length-prefix framing.
///
/// Mirrors `TcpFace` but over a local Unix socket. Typically used as the
/// control-plane channel between an application and the forwarder daemon
/// (prefix registration, face management). Data-plane traffic uses `AppFace`
/// (in-process mpsc channels) for lower latency.
///
/// The stream is split into independent read/write halves, each behind its own
/// `Mutex`, for the same reasons as `TcpFace`: recv is single-consumer and
/// never contends; the writer mutex serialises concurrent sends.
pub struct UnixFace {
    id:     FaceId,
    path:   PathBuf,
    reader: Mutex<FramedRead<OwnedReadHalf, TlvCodec>>,
    writer: Mutex<FramedWrite<OwnedWriteHalf, TlvCodec>>,
}

impl UnixFace {
    /// Wrap an accepted or connected `UnixStream`.
    pub fn from_stream(id: FaceId, stream: UnixStream, path: impl Into<PathBuf>) -> Self {
        let (r, w) = stream.into_split();
        Self {
            id,
            path:   path.into(),
            reader: Mutex::new(FramedRead::new(r, TlvCodec)),
            writer: Mutex::new(FramedWrite::new(w, TlvCodec)),
        }
    }

    /// Connect to a Unix socket at `path`.
    pub async fn connect(id: FaceId, path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let stream = UnixStream::connect(&path).await?;
        Ok(Self::from_stream(id, stream, path))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Face for UnixFace {
    fn id(&self) -> FaceId { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Unix }

    fn local_uri(&self) -> Option<String> {
        Some(format!("unix://{}", self.path.display()))
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
    use tokio::net::UnixListener;

    fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(tag as u64, value);
        w.finish()
    }

    fn temp_socket_path() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "ndn_unix_test_{}_{}.sock",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    async fn loopback_pair(path: &PathBuf) -> (UnixFace, UnixFace) {
        let listener = UnixListener::bind(path).unwrap();
        // Run connect and accept concurrently; timeout guards against a mis-bound
        // listener leaving accept() blocked forever.
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connect_fut = UnixFace::connect(FaceId(0), path.clone());
            let accept_fut  = listener.accept();
            let (client, accepted) = tokio::join!(connect_fut, accept_fut);
            let (accepted_stream, _) = accepted.unwrap();
            let server = UnixFace::from_stream(FaceId(1), accepted_stream, path.clone());
            (client.unwrap(), server)
        }).await;
        result.expect("loopback_pair timed out")
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        let pkt = make_tlv(0x05, b"hello");
        client.send(pkt.clone()).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), pkt);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn framing_multiple_sequential() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        let pkts: Vec<Bytes> = (0u8..5).map(|i| make_tlv(0x05, &[i])).collect();
        for pkt in &pkts {
            client.send(pkt.clone()).await.unwrap();
        }
        for expected in &pkts {
            assert_eq!(&server.recv().await.unwrap(), expected);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        client.send(make_tlv(0x05, b"interest")).await.unwrap();
        server.send(make_tlv(0x06, b"data")).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), make_tlv(0x05, b"interest"));
        assert_eq!(client.recv().await.unwrap(), make_tlv(0x06, b"data"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn recv_eof_on_closed_stream() {
        let path = temp_socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let connect_fut = UnixStream::connect(&path);
        let accept_fut  = listener.accept();
        let (stream, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        let server = UnixFace::from_stream(FaceId(1), accepted_stream, path.clone());
        drop(stream.unwrap()); // close client side
        assert!(matches!(server.recv().await, Err(FaceError::Closed)));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn path_accessor() {
        let path = temp_socket_path();
        let (client, _server) = loopback_pair(&path).await;
        assert_eq!(client.path(), &path);
        let _ = std::fs::remove_file(&path);
    }
}
