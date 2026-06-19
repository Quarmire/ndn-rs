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
//!     let _ = reply.respond(interest.name().clone(), "hello").await;
//! }).await?;
//! // fetch on the same connection, concurrently
//! let data = node.fetch("/peer/greeting").await?;
//! # let _ = data; Ok(()) }
//! ```

use std::sync::Arc;

use bytes::Bytes;

use crate::connection::Connection;
use crate::consumer::{Consumer, VerifiedConsumer};
use crate::demux::{DemuxConnection, ServeGuard};
use crate::error::AppError;
use crate::publisher::{Publisher, PublisherConfig};
use crate::queryable::Queryable;
use crate::responder::Responder;
use crate::subscriber::{Subscriber, SubscriberConfig};
use ndn_packet::{Data, Interest, Name};
use ndn_security::validator::Validator;

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;

/// How a [`Node`] obtains the *additional* dedicated connections that sync and
/// query need. `Socket` can re-dial; `Pinned` was handed a single connection and
/// cannot.
enum Connector {
    /// Re-dialable forwarder socket (the [`Node::connect`] path).
    #[cfg(not(target_arch = "wasm32"))]
    Socket(std::path::PathBuf),
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
    /// handle can't open — use [`connection`](Self::connection) for those.
    pub fn from_connection(conn: Arc<dyn Connection>) -> Self {
        Self {
            demux: DemuxConnection::new(conn),
            connector: Connector::Pinned,
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
        let conn = self.dedicated().await?;
        Publisher::from_connection(
            conn,
            group.into(),
            local_name.into(),
            PublisherConfig::default(),
        )
    }

    /// A [`Subscriber`] for dataset-sync group `group`, identified as
    /// `local_name`. Runs on a dedicated connection. Returns
    /// [`AppError::Unsupported`] if this `Node` can't re-dial.
    pub async fn subscribe(
        &self,
        group: impl Into<Name>,
        local_name: impl Into<Name>,
    ) -> Result<Subscriber, AppError> {
        let conn = self.dedicated().await?;
        Subscriber::from_connection(
            conn,
            group.into(),
            local_name.into(),
            SubscriberConfig::default(),
        )
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
}
