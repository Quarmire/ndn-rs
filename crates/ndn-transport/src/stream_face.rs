use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};

use crate::{Face, FaceError, FaceId, FaceKind};

/// Generic stream-based NDN face.
///
/// Wraps any async read/write pair with a codec into a full `Face`
/// implementation.  The stream is split into independent read and write halves,
/// each behind its own `Mutex`:
///
/// - `reader`: locked only by the face's receive task (single consumer, never
///   actually contends).
/// - `writer`: locked by whichever pipeline task calls `send()`, serialising
///   concurrent sends on the same stream.
///
/// The `lp_encode` flag controls whether `send()` wraps outgoing packets in
/// NDNLPv2 `LpPacket` framing before writing.  Network-facing transports (TCP,
/// Serial) set this to `true`; local transports (Unix) set it to `false`.
pub struct StreamFace<R, W, C: Clone> {
    id: FaceId,
    kind: FaceKind,
    lp_encode: bool,
    remote_uri: Option<String>,
    local_uri: Option<String>,
    reader: Mutex<FramedRead<R, C>>,
    writer: Mutex<FramedWrite<W, C>>,
}

impl<R, W, C: Clone> StreamFace<R, W, C> {
    /// Create a new `StreamFace` from pre-split read/write halves.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FaceId,
        kind: FaceKind,
        lp_encode: bool,
        remote_uri: Option<String>,
        local_uri: Option<String>,
        reader: R,
        writer: W,
        codec: C,
    ) -> Self {
        Self {
            id,
            kind,
            lp_encode,
            remote_uri,
            local_uri,
            reader: Mutex::new(FramedRead::new(reader, codec.clone())),
            writer: Mutex::new(FramedWrite::new(writer, codec)),
        }
    }
}

impl<R, W, C> Face for StreamFace<R, W, C>
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

    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut reader = self.reader.lock().await;
        reader
            .next()
            .await
            .ok_or(FaceError::Closed)?
            .map_err(FaceError::Io)
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        let wire = if self.lp_encode {
            ndn_packet::lp::encode_lp_packet(&pkt)
        } else {
            pkt
        };
        let mut writer = self.writer.lock().await;
        writer.send(wire).await.map_err(FaceError::Io)
    }
}
