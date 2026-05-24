use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

#[cfg(not(target_arch = "wasm32"))]
use ndn_face_native::local::InProcHandle;
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::{ChunkedProducer, ForwarderClient};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Interest, Name};
use std::time::Duration;

use crate::AppError;
use crate::connection::{Connection, InProcConnection};
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::responder::Responder;

/// Default RDR segment size when the caller passes `chunk_size == 0`. Mirrors
/// `ndn_ipc::NDN_DEFAULT_SEGMENT_SIZE`; redefined here so the wasm build (which
/// can't link ndn-ipc) shares the same value.
const DEFAULT_SEGMENT_SIZE: usize = 8192;

pub struct Producer {
    conn: Arc<dyn Connection>,
    prefix: Name,
}

impl Producer {
    /// Use the `connect` / `from_handle` shortcuts when the connection
    /// shape is fixed.
    pub fn new(conn: Arc<dyn Connection>, prefix: Name) -> Self {
        Self { conn, prefix }
    }

    #[cfg(not(target_arch = "wasm32"))]
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
            conn: Arc::new(IpcConnection::new(client)),
            prefix,
        })
    }

    /// In-process handle for an embedded engine.
    pub fn from_handle(handle: InProcHandle, prefix: Name) -> Self {
        Self {
            conn: Arc::new(InProcConnection::new(handle)),
            prefix,
        }
    }

    /// Handler must call [`Responder::respond`],
    /// [`Responder::respond_bytes`], or [`Responder::nack`]. Dropping
    /// the `Responder` silently discards the Interest.
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

    /// Send a pre-built Data wire without an Interest round-trip. Pairs with a
    /// consumer's persistent Interest ([`Consumer::subscribe`](crate::Consumer::subscribe)):
    /// the forwarder matches each pushed Data to the live persistent PIT entry
    /// and streams it downstream. The caller owns naming and sequencing.
    pub async fn publish(&self, data_wire: Bytes) -> Result<(), AppError> {
        self.conn.send(data_wire).await
    }

    /// RDR-style whole-object publish. Slices `content` into
    /// `chunk_size`-byte segments under `<name>/v=<unix-millis>` and
    /// runs a serve loop answering both `<name>/32=metadata`
    /// (CanBePrefix + MustBeFresh) and `<name>/v=<ver>/seg=<n>`.
    /// Mirrors ndnd `std/object/client_produce.go:118`; pair with
    /// [`Consumer::fetch_object`](crate::Consumer::fetch_object).
    pub async fn publish_object(
        &self,
        name: Name,
        content: Bytes,
        chunk_size: usize,
    ) -> Result<(), AppError> {
        let seg_size = if chunk_size == 0 {
            DEFAULT_SEGMENT_SIZE
        } else {
            chunk_size
        };
        let prepared = crate::rdr::PreparedObject::build(name.clone(), content, seg_size);
        let metadata_keyword =
            ndn_packet::NameComponent::keyword(bytes::Bytes::from_static(crate::rdr::METADATA_KEYWORD));

        loop {
            let raw = match self.conn.recv().await {
                Some(b) => b,
                None => return Ok(()),
            };
            let interest = match Interest::decode(raw) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let i_name: &Name = &interest.name;

            if i_name.has_prefix(&name)
                && i_name
                    .components()
                    .iter()
                    .skip(name.len())
                    .any(|c| c.typ == ndn_packet::tlv_type::KEYWORD && c.value == metadata_keyword.value)
            {
                let data = DataBuilder::new(prepared.metadata_data_name.clone(), &prepared.metadata_content)
                    .freshness(Duration::from_millis(1000))
                    .final_block_id_typed_seg(0)
                    .build();
                self.conn.send(data).await?;
                continue;
            }

            if i_name.has_prefix(&prepared.versioned_name)
                && let Some(last) = i_name.components().last()
                && let Some(seg_idx_u64) = last.as_segment()
            {
                let seg_idx = seg_idx_u64 as usize;
                let Some(payload) = prepared.segments.get(seg_idx) else {
                    continue;
                };
                let seg_name = prepared.versioned_name.clone().append_segment(seg_idx_u64);
                let data = if seg_idx_u64 == prepared.last_seg {
                    DataBuilder::new(seg_name, payload.as_ref())
                        .final_block_id_typed_seg(prepared.last_seg)
                        .build()
                } else {
                    DataBuilder::new(seg_name, payload.as_ref()).build()
                };
                self.conn.send(data).await?;
                continue;
            }
        }
    }

    /// One-shot segmented publish without the RDR metadata round trip;
    /// pair with [`Consumer::fetch_segmented`](crate::Consumer::fetch_segmented).
    ///
    /// Native-only: the legacy segmentation helper (`ndn_ipc::ChunkedProducer`)
    /// lives in the native-only `ndn-ipc` crate. In the browser, use
    /// [`publish_object`](Self::publish_object) (the RDR path).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn publish_large(
        &self,
        prefix: &Name,
        content: Bytes,
        chunk_size: usize,
    ) -> Result<(), AppError> {
        let seg_size = if chunk_size == 0 {
            DEFAULT_SEGMENT_SIZE
        } else {
            chunk_size
        };
        let chunked = ChunkedProducer::new(prefix.clone(), content, seg_size);
        let last_seg = chunked.segment_count().saturating_sub(1);

        for seg_idx in 0..=last_seg {
            let payload = chunked.segment(seg_idx).cloned().unwrap_or_default();
            let seg_name = prefix.clone().append(seg_idx.to_string());

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
