use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;

#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_face::local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::{ChunkedProducer, ForwarderClient};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Interest, Name};
use ndn_security::Signer;

use crate::AppError;
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::connection::{Connection, InProcConnection};
use crate::responder::Responder;

/// Default RDR segment size when the caller passes `chunk_size == 0`. Mirrors
/// `ndn_ipc::NDN_DEFAULT_SEGMENT_SIZE`; redefined here so the wasm build (which
/// can't link ndn-ipc) shares the same value.
const DEFAULT_SEGMENT_SIZE: usize = 8192;

/// Register a prefix and serve `Data`. Most apps use [`Node`](crate::Node)
/// (`node.serve` / `node.serve_object`); reach for `Producer` for signed
/// serving or the lower-level serve loop.
pub struct Producer {
    conn: Arc<dyn Connection>,
    prefix: Name,
    signer: Option<Arc<dyn Signer>>,
}

impl Producer {
    /// Use the `connect` / `from_handle` shortcuts when the connection
    /// shape is fixed.
    pub fn new(conn: Arc<dyn Connection>, prefix: Name) -> Self {
        Self {
            conn,
            prefix,
            signer: None,
        }
    }

    /// Sign every reply with `signer` — the symmetric safe path. Configure a
    /// signer once (e.g. `keychain.signer()?`) and
    /// [`Responder::respond`](crate::Responder::respond) and
    /// [`publish_object`](Self::publish_object) emit **signed** Data instead of a
    /// bare `DigestSha256`. Without it the producer is unsigned-by-default
    /// (integrity only) — fine for forwarding tests, not for authentic content.
    pub fn with_signer(mut self, signer: Arc<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
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
            signer: None,
        })
    }

    /// In-process handle for an embedded engine.
    pub fn from_handle(handle: InProcHandle, prefix: Name) -> Self {
        Self {
            conn: Arc::new(InProcConnection::new(handle)),
            prefix,
            signer: None,
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

            let responder = Responder::new(Arc::clone(&self.conn), raw, self.signer.clone());
            handler(interest, responder).await;
        }
        Ok(())
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Start a [`Router`] that dispatches Interests under this producer's
    /// prefix to per-suffix handlers — the ndn-cxx `setInterestFilter`
    /// affordance. Instead of one `serve` closure hand-matching sub-paths:
    ///
    /// ```ignore
    /// producer
    ///     .route("/config", |i, r| async move { /* serve /app/config */ })
    ///     .route("/data",   |i, r| async move { /* serve /app/data/* */ })
    ///     .serve()
    ///     .await?;
    /// ```
    ///
    /// Each `suffix` is matched as a name prefix relative to the producer
    /// prefix; the longest (most specific) match wins. Suffixes are plain
    /// component prefixes for now (NDN regex filters are a separate gap).
    pub fn router(self) -> Router {
        Router::new(self.conn, self.prefix, self.signer)
    }

    /// Shorthand for `self.router().route(suffix, handler)` so a producer can
    /// be turned into a [`Router`] in one chained call.
    pub fn route<F, Fut>(self, suffix: impl Into<Name>, handler: F) -> Router
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.router().route(suffix, handler)
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
        let prepared = crate::rdr::PreparedObject::build(name, content, self.seg_size(chunk_size));
        self.serve_object(prepared).await
    }

    /// File-backed RDR publish: like [`publish_object`](Self::publish_object)
    /// but segments are read from `file` on demand (positioned reads), so an
    /// arbitrarily large file is served without ever loading it into memory.
    /// `size` is the file's length in bytes. Unix-only.
    #[cfg(unix)]
    pub async fn publish_object_from_file(
        &self,
        name: Name,
        file: std::fs::File,
        size: u64,
        chunk_size: usize,
    ) -> Result<(), AppError> {
        let prepared =
            crate::rdr::PreparedObject::build_from_file(name, file, size, self.seg_size(chunk_size));
        self.serve_object(prepared).await
    }

    fn seg_size(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            DEFAULT_SEGMENT_SIZE
        } else {
            chunk_size
        }
    }

    /// Serve loop shared by the in-memory and file-backed object publishers:
    /// answer each `<name>/32=metadata` / `<name>/v=<ver>/seg=<n>` Interest from
    /// `prepared` until the connection closes. The metadata + segment
    /// matching/build/sign lives in [`PreparedObject::answer_interest`], so this
    /// and the demultiplexed serve path stay in lockstep.
    async fn serve_object(&self, prepared: crate::rdr::PreparedObject) -> Result<(), AppError> {
        let signer = self.signer.as_deref();
        loop {
            let raw = match self.conn.recv().await {
                Some(b) => b,
                None => return Ok(()),
            };
            let interest = match Interest::decode(raw) {
                Ok(i) => i,
                Err(_) => continue,
            };
            if let Some(data) = prepared.answer_interest(&interest.name, signer).await? {
                self.conn.send(data).await?;
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

type RouteFut = Pin<Box<dyn Future<Output = ()> + Send>>;
type RouteHandler = Arc<dyn Fn(Interest, Responder) -> RouteFut + Send + Sync>;

/// Dispatches Interests under a producer prefix to per-suffix handlers
/// (ndn-cxx `setInterestFilter`). Build via [`Producer::router`] /
/// [`Producer::route`], chain [`route`](Self::route), then [`serve`](Self::serve).
pub struct Router {
    conn: Arc<dyn Connection>,
    prefix: Name,
    signer: Option<Arc<dyn Signer>>,
    /// `(full route name = prefix + suffix, handler)`.
    routes: Vec<(Name, RouteHandler)>,
    fallback: Option<RouteHandler>,
}

impl Router {
    fn new(conn: Arc<dyn Connection>, prefix: Name, signer: Option<Arc<dyn Signer>>) -> Self {
        Self {
            conn,
            prefix,
            signer,
            routes: Vec::new(),
            fallback: None,
        }
    }

    /// Register `handler` for Interests whose name has `prefix + suffix` as a
    /// prefix. The longest matching suffix wins, so `/data/v2` is preferred
    /// over `/data` for `/app/data/v2/...`.
    pub fn route<F, Fut>(mut self, suffix: impl Into<Name>, handler: F) -> Self
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let full = append_components(&self.prefix, &suffix.into());
        self.routes.push((
            full,
            Arc::new(move |i, r| Box::pin(handler(i, r)) as RouteFut),
        ));
        self
    }

    /// Handler for Interests under the producer prefix that no `route`
    /// matched. Without one, unmatched Interests are dropped.
    pub fn fallback<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.fallback = Some(Arc::new(move |i, r| Box::pin(handler(i, r)) as RouteFut));
        self
    }

    /// The most-specific matching handler for `name`, else the fallback.
    fn match_handler(&self, name: &Name) -> Option<&RouteHandler> {
        self.routes
            .iter()
            .filter(|(full, _)| name.has_prefix(full))
            .max_by_key(|(full, _)| full.components().len())
            .map(|(_, h)| h)
            .or(self.fallback.as_ref())
    }

    /// Serve until the connection closes, dispatching each Interest to its
    /// matched handler. The handler must answer via the [`Responder`]
    /// (dropping it discards the Interest).
    pub async fn serve(self) -> Result<(), AppError> {
        loop {
            let raw = match self.conn.recv().await {
                Some(b) => b,
                None => break,
            };
            let interest = match Interest::decode(raw.clone()) {
                Ok(i) => i,
                Err(_) => continue,
            };
            if let Some(handler) = self.match_handler(&interest.name) {
                let responder =
                    Responder::new(Arc::clone(&self.conn), raw, self.signer.clone());
                handler(interest, responder).await;
            }
        }
        Ok(())
    }
}

/// `prefix` followed by every component of `suffix` (the suffix is treated
/// as a relative component sequence, leading `/` ignored).
fn append_components(prefix: &Name, suffix: &Name) -> Name {
    let mut out = prefix.clone();
    for c in suffix.components() {
        out = out.append_component(c.clone());
    }
    out
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use ndn_packet::encode::InterestBuilder;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A connection that replays a fixed Interest queue then closes, and
    /// records nothing on send (handlers record via their own state).
    struct QueueConn {
        q: Mutex<VecDeque<Bytes>>,
    }

    #[async_trait::async_trait]
    impl Connection for QueueConn {
        async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
            Ok(())
        }
        async fn recv(&self) -> Option<Bytes> {
            self.q.lock().unwrap().pop_front()
        }
        async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn router_dispatches_by_longest_suffix_match() {
        let prefix: Name = "/app".parse().unwrap();
        let interests = VecDeque::from(vec![
            InterestBuilder::new("/app/config".parse::<Name>().unwrap()).build(),
            InterestBuilder::new("/app/data/v2/seg=0".parse::<Name>().unwrap()).build(),
            InterestBuilder::new("/app/data/v1".parse::<Name>().unwrap()).build(),
            InterestBuilder::new("/app/unmatched".parse::<Name>().unwrap()).build(),
        ]);
        let conn = Arc::new(QueueConn { q: Mutex::new(interests) });

        let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let tag = |label: &'static str, hits: Arc<Mutex<Vec<String>>>| {
            move |i: Interest, _r: Responder| {
                let hits = Arc::clone(&hits);
                async move {
                    hits.lock().unwrap().push(format!("{label}:{}", i.name));
                }
            }
        };

        Producer::new(conn, prefix)
            .route("/config", tag("config", Arc::clone(&hits)))
            // `/data` and the more specific `/data/v2` both registered: the
            // longest match must win for `/app/data/v2/...`.
            .route("/data", tag("data", Arc::clone(&hits)))
            .route("/data/v2", tag("data-v2", Arc::clone(&hits)))
            .fallback(tag("fallback", Arc::clone(&hits)))
            .serve()
            .await
            .unwrap();

        let hits = hits.lock().unwrap().clone();
        assert_eq!(
            hits,
            vec![
                "config:/app/config".to_string(),
                "data-v2:/app/data/v2/seg=0".to_string(),
                "data:/app/data/v1".to_string(),
                "fallback:/app/unmatched".to_string(),
            ]
        );
    }
}
