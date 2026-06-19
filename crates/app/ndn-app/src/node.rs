//! [`Node`] — the unified application entry point.
//!
//! One [`Node`] is a single handle to a forwarder over which every NDN
//! application pattern is available with one NDN-native vocabulary:
//!
//! - **`fetch` / `verifying` / `object`** — the consumer side (request/response).
//! - **`serve`** — answer Interests for a prefix (the "dynamic notes" Responder
//!   pattern, now first-class).
//! - **`publish` / `subscribe`** — dataset sync (SVS/PSync) producer & consumer.
//! - **`query`** — a [`Queryable`] responder stream.
//!
//! The per-pattern types ([`Consumer`], [`Producer`], [`Publisher`],
//! [`Subscriber`], [`Queryable`]) remain as lower-level building blocks reachable
//! via [`Node::connection`]; `Node` is the polished surface most apps want.
//!
//! ### One connection, with one honest exception
//!
//! `fetch` and `serve` are *multiplexed over a single connection* via
//! [`DemuxConnection`] — concurrent fetches and serves never steal each other's
//! packets. The sync patterns (`publish`/`subscribe`) and the `query` responder
//! each run a stateful protocol loop that needs exclusive read access to its
//! stream, so `Node` gives each its **own dedicated connection to the same
//! forwarder** (re-dialed transparently). This requires a `Node` that knows how
//! to re-dial — i.e. one built with [`Node::connect`]; a `Node` built from a
//! single pre-made [`Connection`] returns [`AppError::Unsupported`] from those
//! methods (use [`connection`](Node::connection) and build the type directly).
//!
//! ```no_run
//! # use ndn_app::Node;
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let node = Node::connect("/run/nfd/nfd.sock").await?;
//! // serve dynamic content (the "Responder" pattern, now first-class)
//! let _guard = node.serve("/notes", |interest, reply| async move {
//!     let _ = reply.respond((*interest.name).clone(), "hello").await;
//! }).await?;
//! // fetch on the same connection, concurrently
//! let data = node.fetch("/peer/greeting").await?;
//! # let _ = data; Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::connection::Connection;
use crate::consumer::{Consumer, VerifiedConsumer};
use crate::demux::{DemuxConnection, ServeGuard};
use crate::error::AppError;
use crate::producer::Producer;
use crate::publisher::{Publisher, PublisherConfig};
use crate::queryable::Queryable;
use crate::responder::Responder;
use crate::subscriber::{Subscriber, SubscriberConfig};
use ndn_packet::{Data, Interest, Name};
use ndn_security::validator::Validator;
use tokio_util::sync::CancellationToken;

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;

/// Supplies fresh dedicated [`Connection`]s to a [`Node`] on demand — one per
/// pattern that needs its own stream (`publish` / `subscribe` / `query` /
/// `serve_object`). [`Node::connect`] re-dials a socket internally;
/// `EngineAppExt::app_node` allocates a new in-process engine face each time.
/// Implement this to teach `Node` how to re-dial a custom transport.
#[async_trait]
pub trait ConnectionProvider: Send + Sync {
    /// Open a new connection to the same forwarder / engine.
    async fn open(&self) -> Result<Arc<dyn Connection>, AppError>;
}

/// How a [`Node`] obtains the *additional* dedicated connections that sync and
/// query need. `Socket` re-dials, `Provider` mints, `Pinned` cannot.
enum Connector {
    /// Re-dialable forwarder socket (the [`Node::connect`] path).
    #[cfg(not(target_arch = "wasm32"))]
    Socket(std::path::PathBuf),
    /// Mints fresh connections on demand (e.g. new in-process engine faces).
    Provider(Arc<dyn ConnectionProvider>),
    /// A single pre-made connection — no second stream available.
    Pinned,
}

/// The unified entry point: one connection, every pattern, NDN-native verbs.
pub struct Node {
    demux: Arc<DemuxConnection>,
    connector: Connector,
}

impl Node {
    /// Connect to a running `ndn-fwd` over its Unix socket. This is the full
    /// `Node`: it can re-dial, so every pattern — including `publish` /
    /// `subscribe` / `query` — is available.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(socket: impl AsRef<std::path::Path>) -> Result<Self, AppError> {
        let path = socket.as_ref().to_path_buf();
        let conn = Self::dial(&path).await?;
        Ok(Self {
            demux: DemuxConnection::new(conn),
            connector: Connector::Socket(path),
        })
    }

    /// Build a `Node` over any existing [`Connection`] (e.g. an in-process engine
    /// seam). `fetch`/`serve`/`object` work fully; `publish`/`subscribe`/`query`
    /// return [`AppError::Unsupported`] because they need a *separate* stream this
    /// handle can't open — use [`connection`](Self::connection) for those, or
    /// [`from_provider`](Self::from_provider) if you can mint more connections.
    pub fn from_connection(conn: Arc<dyn Connection>) -> Self {
        Self {
            demux: DemuxConnection::new(conn),
            connector: Connector::Pinned,
        }
    }

    /// Build a full `Node` whose `fetch`/`serve` run over `primary` and whose
    /// dedicated patterns (`publish`/`subscribe`/`query`/`serve_object`) mint
    /// fresh streams from `provider` — so every pattern is available without a
    /// socket. `EngineAppExt::app_node` is the in-process constructor built on
    /// this; implement [`ConnectionProvider`] to use it with a custom transport.
    pub fn from_provider(
        primary: Arc<dyn Connection>,
        provider: Arc<dyn ConnectionProvider>,
    ) -> Self {
        Self {
            demux: DemuxConnection::new(primary),
            connector: Connector::Provider(provider),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn dial(path: &std::path::Path) -> Result<Arc<dyn Connection>, AppError> {
        let client = ndn_ipc::ForwarderClient::connect(path)
            .await
            .map_err(AppError::Connection)?;
        Ok(Arc::new(IpcConnection::new(client)))
    }

    /// Open a fresh dedicated connection to the same forwarder, for a pattern
    /// (sync / query) that needs its own stream.
    async fn dedicated(&self) -> Result<Arc<dyn Connection>, AppError> {
        match &self.connector {
            #[cfg(not(target_arch = "wasm32"))]
            Connector::Socket(path) => Self::dial(path).await,
            Connector::Provider(provider) => provider.open().await,
            Connector::Pinned => Err(AppError::Unsupported(
                "this Node was built from a single connection; build the \
                 Publisher/Subscriber/Queryable directly from node.connection()"
                    .into(),
            )),
        }
    }

    /// The underlying multiplexed connection — the Tier-2 escape hatch for code
    /// that needs the lower-level [`Consumer`]/[`Producer`] or raw send/recv.
    pub fn connection(&self) -> Arc<dyn Connection> {
        Arc::clone(&self.demux) as Arc<dyn Connection>
    }

    fn consumer(&self) -> Consumer {
        Consumer::new(self.connection())
    }

    // ---- consumer side -----------------------------------------------------

    /// Fetch a single Data by name (unverified — see [`Node::verifying`]).
    pub async fn fetch(&self, name: impl Into<Name>) -> Result<Data, AppError> {
        self.consumer().fetch(name).await
    }

    /// A verifying consumer: decide trust once, then `fetch` returns [`SafeData`]
    /// (signature checked). `let safe = node.verifying(v).fetch("/x").await?;`
    ///
    /// [`SafeData`]: ndn_security::SafeData
    pub fn verifying(&self, validator: Validator) -> VerifiedConsumer {
        self.consumer().verifying(validator)
    }

    /// Begin a composable object (RDR) fetch: `node.object(name).verify(v)
    /// .hint(["/gw"]).progress(cb).fetch()`. Terminal verbs are `.fetch()`
    /// (in memory), `.stream()` (per-segment), `.to_file()` (to disk).
    pub fn object(&self, name: impl Into<Name>) -> crate::object::ObjectFetch {
        self.consumer().object(name)
    }

    /// Fetch a (possibly segmented) RDR object, reassembled into bytes — the
    /// shorthand for `node.object(name).fetch()`.
    pub async fn fetch_object(&self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        self.object(name).fetch().await
    }

    // ---- producer / responder side -----------------------------------------

    /// Serve `prefix`: register it with the forwarder and run `handler` for each
    /// matching Interest, concurrently with any fetches on this `Node`. Serving
    /// stops when the returned [`ServeGuard`] is dropped.
    ///
    /// The handler gets the [`Interest`] and a [`Responder`] reply builder — the
    /// "dynamic notes" pattern.
    pub async fn serve<F, Fut>(
        &self,
        prefix: impl Into<Name>,
        handler: F,
    ) -> Result<ServeGuard, AppError>
    where
        F: Fn(Interest, Responder) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let prefix = prefix.into();
        self.demux.register_prefix(&prefix).await?;
        Ok(self.demux.serve_scoped(prefix, handler))
    }

    // ---- sync (SVS/PSync) --------------------------------------------------

    /// A [`Publisher`] for dataset-sync group `group`, publishing under
    /// `local_name`. Runs on a dedicated connection (see the type-level note on
    /// the one-connection exception). Returns [`AppError::Unsupported`] if this
    /// `Node` can't re-dial.
    pub async fn publish(
        &self,
        group: impl Into<Name>,
        local_name: impl Into<Name>,
    ) -> Result<Publisher, AppError> {
        let group = group.into();
        let local_name = local_name.into();
        let conn = self.dedicated().await?;
        // Receive peers' Sync Interests for the group, and let their fetch
        // Interests reach this node's data (`<local_name>/<group>/<seq>`). The
        // socket `Publisher::connect` registers these too; `from_connection`
        // (sync) can't, so the embedder — here, `Node` — does it.
        conn.register_prefix(&group).await?;
        conn.register_prefix(&svs_data_prefix(&local_name, &group)).await?;
        Publisher::from_connection(conn, group, local_name, PublisherConfig::default())
    }

    /// A [`Subscriber`] for dataset-sync group `group`, identified as
    /// `local_name`. Runs on a dedicated connection. Returns
    /// [`AppError::Unsupported`] if this `Node` can't re-dial.
    pub async fn subscribe(
        &self,
        group: impl Into<Name>,
        local_name: impl Into<Name>,
    ) -> Result<Subscriber, AppError> {
        let group = group.into();
        let conn = self.dedicated().await?;
        // Receive peers' Sync Interests for the group (the subscriber fetches
        // their data on demand, so only the group prefix needs a route here).
        conn.register_prefix(&group).await?;
        Subscriber::from_connection(conn, group, local_name.into(), SubscriberConfig::default())
    }

    // ---- query responder ---------------------------------------------------

    /// A [`Queryable`] that answers Interests under `prefix` as an explicit
    /// stream of queries. Registers the prefix on its own dedicated connection.
    /// Returns [`AppError::Unsupported`] if this `Node` can't re-dial.
    pub async fn query(&self, prefix: impl Into<Name>) -> Result<Queryable, AppError> {
        let prefix = prefix.into();
        let conn = self.dedicated().await?;
        conn.register_prefix(&prefix).await?;
        Ok(Queryable::from_connection(conn, prefix))
    }

    // ---- static object serving --------------------------------------------

    /// Serve `content` as an RDR object under `name` (segmented, `<name>/v=…`),
    /// answering metadata + segment Interests in the background until the
    /// returned [`ObjectServeGuard`] is dropped. Runs on a dedicated connection
    /// (the producer counterpart to the sync/query exception). The segments are
    /// `DigestSha256` (unsigned); for signed serving build a [`Producer`] with a
    /// signer from [`connection`](Self::connection).
    pub async fn serve_object(
        &self,
        name: impl Into<Name>,
        content: impl Into<Bytes>,
    ) -> Result<ObjectServeGuard, AppError> {
        let name = name.into();
        let content = content.into();
        let producer = self.object_producer(&name).await?;
        Ok(Self::spawn_object(producer, move |p| async move {
            p.publish_object(name, content, 0).await
        }))
    }

    /// Serve a JSON-serialized `value` as an RDR object under `name` — the typed
    /// counterpart to [`ObjectFetch::fetch_as`](crate::ObjectFetch::fetch_as).
    #[cfg(feature = "serde")]
    pub async fn serve_object_typed<T: serde::Serialize>(
        &self,
        name: impl Into<Name>,
        value: &T,
    ) -> Result<ObjectServeGuard, AppError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| AppError::Protocol(format!("object JSON encode: {e}")))?;
        self.serve_object(name, Bytes::from(bytes)).await
    }

    /// Serve a file as an RDR object under `name`, reading segments on demand
    /// (positioned reads) so an arbitrarily large file is served without loading
    /// it into memory. Unix only; runs until the guard is dropped.
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    pub async fn serve_file(
        &self,
        name: impl Into<Name>,
        path: impl AsRef<std::path::Path>,
    ) -> Result<ObjectServeGuard, AppError> {
        let name = name.into();
        let file = std::fs::File::open(path)
            .map_err(|e| AppError::Protocol(format!("open file to serve: {e}")))?;
        let size = file
            .metadata()
            .map_err(|e| AppError::Protocol(format!("stat file to serve: {e}")))?
            .len();
        let producer = self.object_producer(&name).await?;
        Ok(Self::spawn_object(producer, move |p| async move {
            p.publish_object_from_file(name, file, size, 0).await
        }))
    }

    /// Open a dedicated connection, register `name`, and bind a [`Producer`].
    async fn object_producer(&self, name: &Name) -> Result<Producer, AppError> {
        let conn = self.dedicated().await?;
        conn.register_prefix(name).await?;
        Ok(Producer::new(conn, name.clone()))
    }

    /// Spawn an object serve loop bound to a fresh cancellation token; the
    /// returned guard cancels it on drop.
    fn spawn_object<F, Fut>(producer: Producer, run: F) -> ObjectServeGuard
    where
        F: FnOnce(Producer) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<(), AppError>> + Send + 'static,
    {
        let cancel = CancellationToken::new();
        let child = cancel.child_token();
        crate::rt::spawn(async move {
            let _ = child.run_until_cancelled(run(producer)).await;
        });
        ObjectServeGuard { _cancel: cancel }
    }
}

/// Keeps a [`Node::serve_object`] (or [`serve_file`](Node::serve_file)) loop
/// alive; dropping it stops serving.
pub struct ObjectServeGuard {
    _cancel: CancellationToken,
}

impl Drop for ObjectServeGuard {
    fn drop(&mut self) {
        self._cancel.cancel();
    }
}

/// Where an SVS publisher's Data lives: `<local_name>/<group>/<seq>/…`. Routing
/// fetch Interests to the publisher means registering `<local_name>/<group>`.
/// Mirrors the derivation in `Publisher::connect`.
fn svs_data_prefix(local_name: &Name, group: &Name) -> Name {
    let mut p = local_name.clone();
    for c in group.components() {
        p = p.append_component(c.clone());
    }
    p
}
