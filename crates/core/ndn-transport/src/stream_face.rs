use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::{FaceError, FaceId, FaceKind, FacePersistency, MtuError, PersistencyError, Transport};

/// Generic stream-based `Transport` over any async read/write pair with a
/// TLV codec. Reader/writer halves each sit behind a `Mutex`; the writer
/// lock serialises concurrent `send_bytes()` calls. NDNLPv2 framing is
/// applied by the paired [`LinkService`](crate::link_service::LinkService).
pub struct StreamFace<R, W, C: Clone> {
    id: FaceId,
    kind: FaceKind,
    remote_uri: Option<String>,
    local_uri: Option<String>,
    reader: Mutex<FramedRead<R, C>>,
    writer: Mutex<FramedWrite<W, C>>,
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
        }
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
}
