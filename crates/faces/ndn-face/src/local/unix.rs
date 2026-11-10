use std::path::Path;

use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use ndn_transport::{FaceId, FaceKind, StreamFace, TlvCodec};

use super::operators::ProgramPeers;

/// NDN face over a Unix domain socket with TLV length-prefix framing.
/// LP-encoding is disabled — local transports pass raw NDN packets.
pub type UnixFace = StreamFace<OwnedReadHalf, OwnedWriteHalf, TlvCodec>;

/// A Unix-socket face over `stream`, carrying the peer credentials the kernel
/// reports for it. It is a program face
/// ([`ndn_transport::FaceTrust::Program`]) only when `peers` admits those
/// credentials (the daemon's user, root, a program group); every other
/// user's socket, and one the kernel reports nothing for, is validated like a
/// network face.
pub fn unix_face_from_stream(
    id: FaceId,
    stream: UnixStream,
    path: impl AsRef<Path>,
    peers: &ProgramPeers,
) -> UnixFace {
    face_from_stream(id, FaceKind::Unix, stream, path.as_ref(), peers)
}

/// Like [`unix_face_from_stream`] but tags the face `FaceKind::Management`
/// for operator-level trust at the management handler — use for connections
/// accepted on the NFD management socket. Carries the stream's peer
/// credentials so trust-changing verbs can be authorized per caller.
pub fn unix_management_face_from_stream(
    id: FaceId,
    stream: UnixStream,
    path: impl AsRef<Path>,
    peers: &ProgramPeers,
) -> UnixFace {
    face_from_stream(id, FaceKind::Management, stream, path.as_ref(), peers)
}

fn face_from_stream(
    id: FaceId,
    kind: FaceKind,
    stream: UnixStream,
    path: &Path,
    peers: &ProgramPeers,
) -> UnixFace {
    let uri = format!("unix://{}", path.display());
    let creds = super::ipc::unix_peer_credentials(&stream);
    let (r, w) = stream.into_split();
    let face =
        StreamFace::new(id, kind, None, Some(uri), r, w, TlvCodec).with_peer_credentials(creds);
    match creds {
        Some(c) if peers.contains(&c) => face.program_peer(),
        _ => face,
    }
}

/// Dial the socket at `path`. The face is a program face when the kernel says
/// its owner is this process's user or root, validated otherwise.
pub async fn unix_face_connect(id: FaceId, path: impl AsRef<Path>) -> std::io::Result<UnixFace> {
    let path = path.as_ref();
    let stream = UnixStream::connect(path).await?;
    Ok(unix_face_from_stream(
        id,
        stream,
        path,
        &ProgramPeers::this_user(),
    ))
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
        use portable_atomic::AtomicU64;
        use std::sync::atomic::Ordering;
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
            let server =
                unix_face_from_stream(FaceId(1), accepted_stream, path, &ProgramPeers::this_user());
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

    /// A Unix socket the kernel reported the peer of is a program face, on
    /// the accepting and the dialling side alike.
    #[tokio::test]
    async fn unix_faces_carry_kernel_credentials_and_are_program_faces() {
        use ndn_transport::{Face, FaceTrust};
        use std::os::unix::fs::MetadataExt;
        let path = temp_socket_path();
        let (client, server) = loopback_pair(&path).await;
        // The socket file is owned by this process's user, who is both peers.
        let me = std::fs::metadata(&path).unwrap().uid();
        for face in [Face::from_transport(client), Face::from_transport(server)] {
            assert_eq!(face.peer_credentials().expect("kernel credentials").uid, me);
            assert_eq!(face.trust(), FaceTrust::Program);
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A peer that is neither the daemon's user, nor root, nor in a program
    /// group is identified (the credentials are kept, so management can say
    /// who asked) but is not a program: its Data is validated.
    #[tokio::test]
    async fn a_user_outside_the_program_peers_gets_a_validated_face_with_credentials() {
        use ndn_transport::{Face, FaceTrust};
        use std::os::unix::fs::MetadataExt;
        let path = temp_socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let me = std::fs::metadata(&path).unwrap().uid();
        if me == 0 {
            eprintln!("skipped: running as root, who is a program peer of every daemon");
            let _ = std::fs::remove_file(&path);
            return;
        }
        let (client, accepted) = tokio::join!(UnixStream::connect(&path), listener.accept());
        let _client = client.unwrap();
        let (accepted_stream, _) = accepted.unwrap();
        let elsewhere = ProgramPeers::with_daemon_uid(me + 1, &[]);
        let server = Face::from_transport(unix_face_from_stream(
            FaceId(1),
            accepted_stream,
            &path,
            &elsewhere,
        ));
        assert_eq!(
            server.peer_credentials().expect("kernel credentials").uid,
            me
        );
        assert_eq!(server.trust(), FaceTrust::Validated);
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
        let server = unix_face_from_stream(
            FaceId(1),
            accepted_stream,
            &path,
            &ProgramPeers::this_user(),
        );
        drop(stream.unwrap());
        assert!(matches!(server.recv_bytes().await, Err(FaceError::Closed)));
        let _ = std::fs::remove_file(&path);
    }
}
