use std::path::Path;

use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use ndn_transport::{FaceId, FaceKind, StreamFace, TlvCodec};

/// NDN face over a Unix domain socket with TLV length-prefix framing.
/// LP-encoding is disabled — local transports pass raw NDN packets.
pub type UnixFace = StreamFace<OwnedReadHalf, OwnedWriteHalf, TlvCodec>;

pub fn unix_face_from_stream(id: FaceId, stream: UnixStream, path: impl AsRef<Path>) -> UnixFace {
    let uri = format!("unix://{}", path.as_ref().display());
    let (r, w) = stream.into_split();
    StreamFace::new(id, FaceKind::Unix, None, Some(uri), r, w, TlvCodec)
}

/// Like [`unix_face_from_stream`] but tags the face `FaceKind::Management`
/// for operator-level trust at the management handler — use for connections
/// accepted on the NFD management socket.
pub fn unix_management_face_from_stream(
    id: FaceId,
    stream: UnixStream,
    path: impl AsRef<Path>,
) -> UnixFace {
    let uri = format!("unix://{}", path.as_ref().display());
    let (r, w) = stream.into_split();
    StreamFace::new(id, FaceKind::Management, None, Some(uri), r, w, TlvCodec)
}

pub async fn unix_face_connect(id: FaceId, path: impl AsRef<Path>) -> std::io::Result<UnixFace> {
    let path = path.as_ref();
    let stream = UnixStream::connect(path).await?;
    Ok(unix_face_from_stream(id, stream, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::{FaceError, Transport};
    use std::path::PathBuf;
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
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let connect_fut = unix_face_connect(FaceId(0), path);
            let accept_fut = listener.accept();
            let (client, accepted) = tokio::join!(connect_fut, accept_fut);
            let (accepted_stream, _) = accepted.unwrap();
            let server = unix_face_from_stream(FaceId(1), accepted_stream, path);
            (client.unwrap(), server)
        })
        .await;
        result.expect("loopback_pair timed out")
    }

    #[tokio::test]
    async fn send_recv_single_packet() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        let pkt = make_tlv(0x05, b"hello");
        client.send_bytes(pkt.clone()).await.unwrap();
        assert_eq!(server.recv_bytes().await.unwrap(), pkt);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn framing_multiple_sequential() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        let pkts: Vec<Bytes> = (0u8..5).map(|i| make_tlv(0x05, &[i])).collect();
        for pkt in &pkts {
            client.send_bytes(pkt.clone()).await.unwrap();
        }
        for expected in &pkts {
            assert_eq!(&server.recv_bytes().await.unwrap(), expected);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn bidirectional_exchange() {
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        client
            .send_bytes(make_tlv(0x05, b"interest"))
            .await
            .unwrap();
        server.send_bytes(make_tlv(0x06, b"data")).await.unwrap();
        assert_eq!(
            server.recv_bytes().await.unwrap(),
            make_tlv(0x05, b"interest")
        );
        assert_eq!(client.recv_bytes().await.unwrap(), make_tlv(0x06, b"data"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn recv_eof_on_closed_stream() {
        let path = temp_socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let connect_fut = UnixStream::connect(&path);
        let accept_fut = listener.accept();
        let (stream, accepted) = tokio::join!(connect_fut, accept_fut);
        let (accepted_stream, _) = accepted.unwrap();
        let server = unix_face_from_stream(FaceId(1), accepted_stream, &path);
        drop(stream.unwrap());
        assert!(matches!(server.recv_bytes().await, Err(FaceError::Closed)));
        let _ = std::fs::remove_file(&path);
    }
}
