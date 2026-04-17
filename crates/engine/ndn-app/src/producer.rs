use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use ndn_faces::local::InProcHandle;
use ndn_ipc::{ChunkedProducer, ForwarderClient, NDN_DEFAULT_SEGMENT_SIZE};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Interest, Name};

use crate::AppError;
use crate::connection::NdnConnection;
use crate::responder::Responder;

/// High-level NDN producer — serves Data in response to Interests.
pub struct Producer {
    conn: Arc<NdnConnection>,
    prefix: Name,
}

impl Producer {
    /// Connect to an external router and register a prefix.
    pub async fn connect(
        socket: impl AsRef<Path>,
        prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        let prefix = prefix.into();
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        client
            .register_prefix(&prefix)
            .await
            .map_err(AppError::Connection)?;
        Ok(Self {
            conn: Arc::new(NdnConnection::External(client)),
            prefix,
        })
    }

    /// Create from an in-process InProcHandle (embedded engine).
    pub fn from_handle(handle: InProcHandle, prefix: Name) -> Self {
        Self {
            conn: Arc::new(NdnConnection::Embedded(handle)),
            prefix,
        }
    }

    /// Run the producer loop with an async handler.
    ///
    /// The handler receives each `(Interest, Responder)` pair and must call
    /// one of [`Responder::respond`], [`Responder::respond_bytes`], or
    /// [`Responder::nack`] to reply. Dropping the `Responder` without replying
    /// silently discards the Interest.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example(mut producer: ndn_app::Producer) -> Result<(), ndn_app::AppError> {
    /// use ndn_packet::encode::DataBuilder;
    ///
    /// producer.serve(|interest, responder| async move {
    ///     let data = DataBuilder::new((*interest.name).clone(), b"42").build();
    ///     responder.respond_bytes(data).await.ok();
    /// }).await
    /// # }
    /// ```
    pub async fn serve<F, Fut>(&self, handler: F) -> Result<(), AppError>
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync,
        Fut: Future<Output = ()> + Send,
    {
        loop {
            let raw = match self.conn.recv().await {
                Some(b) => b,
                None => break,
            };

            let interest = match Interest::decode(raw.clone()) {
                Ok(i) => i,
                Err(_) => continue,
            };

            let responder = Responder::new(Arc::clone(&self.conn), raw);
            handler(interest, responder).await;
        }
        Ok(())
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Publish a large payload as a segmented NDN object.
    ///
    /// Splits `content` into chunks of at most `chunk_size` bytes (default:
    /// [`NDN_DEFAULT_SEGMENT_SIZE`] = 8 KiB), then serves each chunk as a
    /// separate Data packet at `/<prefix>/<n>` where `n` is the ASCII-decimal
    /// segment index. The last segment carries the `FinalBlockId` field so
    /// consumers can determine when reassembly is complete.
    ///
    /// Use [`Consumer::fetch_segmented`](crate::Consumer::fetch_segmented) on
    /// the receiving side to fetch and reassemble the payload.
    ///
    /// # Note
    ///
    /// This method serves one round of Interests — enough for one consumer to
    /// fetch all segments sequentially. For persistent serving (multiple
    /// consumers), embed the [`ChunkedProducer`] in a custom [`serve`](Self::serve) loop.
    pub async fn publish_large(
        &self,
        prefix: &Name,
        content: Bytes,
        chunk_size: usize,
    ) -> Result<(), AppError> {
        let seg_size = if chunk_size == 0 {
            NDN_DEFAULT_SEGMENT_SIZE
        } else {
            chunk_size
        };
        let chunked = ChunkedProducer::new(prefix.clone(), content, seg_size);
        let last_seg = chunked.segment_count().saturating_sub(1);

        for seg_idx in 0..=last_seg {
            let payload = chunked.segment(seg_idx).cloned().unwrap_or_default();
            let seg_name = prefix.clone().append(seg_idx.to_string());

            // Wait for an Interest, then reply with this segment.
            let _raw = self.conn.recv().await.ok_or(AppError::Closed)?;

            let data = if seg_idx == last_seg {
                DataBuilder::new(seg_name, &payload)
                    .final_block_id_seg(last_seg)
                    .build()
            } else {
                DataBuilder::new(seg_name, &payload).build()
            };
            self.conn.send(data).await?;
        }
        Ok(())
    }
}
