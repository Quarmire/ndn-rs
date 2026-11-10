use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::{
    FaceError, FaceId, FaceKind, FacePersistency, FaceTrust, MtuError, PeerCredentials,
    PersistencyError, Transport,
};

/// Generic stream-based `Transport` over any async read/write pair with a
/// TLV codec. Reader/writer halves each sit behind a `Mutex`; the writer
/// lock serialises concurrent `send_bytes()` calls. NDNLPv2 framing is
/// applied by the paired [`LinkService`](crate::link_service::LinkService).
///
/// **Trust.** A stream face is [`FaceTrust::Validated`] (TCP, a Unix socket
/// of any user the node does not trust as its own, a named pipe) unless its
/// constructor called [`program_peer`](Self::program_peer). The peer's
/// kernel-attested credentials ([`with_peer_credentials`](Self::with_peer_credentials))
/// are recorded either way, so the management gate can still tell who sent a
/// command, but a socket's peer being *identified* does not make it *trusted*.
pub struct StreamFace<R, W, C: Clone> {
    id: FaceId,
    kind: FaceKind,
    remote_uri: Option<String>,
    local_uri: Option<String>,
    reader: Mutex<FramedRead<R, C>>,
    writer: Mutex<FramedWrite<W, C>>,
    peer_credentials: Option<PeerCredentials>,
    trust: FaceTrust,
}

impl<R, W, C: Clone> StreamFace<R, W, C> {
    pub fn new(
        id: FaceId,
        kind: FaceKind,
        remote_uri: Option<String>,
        local_uri: Option<String>,
        reader: R,
        writer: W,
        codec: C,
    ) -> Self {
        Self {
            id,
            kind,
            remote_uri,
            local_uri,
            reader: Mutex::new(FramedRead::new(reader, codec.clone())),
            writer: Mutex::new(FramedWrite::new(writer, codec)),
            peer_credentials: None,
            trust: FaceTrust::Validated,
        }
    }

    /// Record the peer process credentials the operating system reported for
    /// the underlying local socket (reported by
    /// [`Transport::peer_credentials`]). They say *who* is on the other end;
    /// they do not make the face a program face — that is the constructor's
    /// decision ([`program_peer`](Self::program_peer)), because a local
    /// socket is reachable by every user of the host. Call it only with
    /// credentials read from the socket (`SO_PEERCRED`, `getpeereid`), never
    /// with credentials the peer or a configuration states.
    pub fn with_peer_credentials(mut self, c: Option<PeerCredentials>) -> Self {
        self.peer_credentials = c;
        self
    }

    /// Make the face a program face ([`FaceTrust::Program`]): its Data is
    /// believed without validation. Call it only when the operating system
    /// identified the peer *and* that peer is one the node's policy trusts as
    /// it trusts its own programs (the daemon's user, root, a member of a
    /// `[security] program_groups` group), or when the process itself holds
    /// both ends of the connection.
    pub fn program_peer(mut self) -> Self {
        self.trust = FaceTrust::Program;
        self
    }
}

impl<R, W, C> Transport for StreamFace<R, W, C>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    C: Decoder<Item = Bytes, Error = std::io::Error>
        + Encoder<Bytes, Error = std::io::Error>
        + Clone
        + Send
        + Sync
        + 'static,
{
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }

    fn remote_uri(&self) -> Option<String> {
        self.remote_uri.clone()
    }
    fn local_uri(&self) -> Option<String> {
        self.local_uri.clone()
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut reader = self.reader.lock().await;
        reader
            .next()
            .await
            .ok_or(FaceError::Closed)?
            .map_err(FaceError::Io)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        let mut writer = self.writer.lock().await;
        writer.send(wire).await.map_err(FaceError::Io)
    }

    /// Streams have no link MTU; the override has no wire effect today.
    fn set_send_mtu(&self, _mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        Err(MtuError::NotSupported)
    }

    /// Persistency is a face-table hint only — destruction is driven by I/O
    /// error for stream faces (matches NFD).
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Ok(())
    }

    fn peer_credentials(&self) -> Option<PeerCredentials> {
        self.peer_credentials
    }

    fn trust(&self) -> FaceTrust {
        self.trust
    }
}
