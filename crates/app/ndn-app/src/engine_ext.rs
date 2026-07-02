//! Ergonomic in-process registration on an embedded [`ForwarderEngine`].
//!
//! The engine's `faces()` / `fib()` accessors are deliberately low-level (a
//! real forwarder needs them), so embedding an app means a multi-step ritual:
//! allocate a face id, build an [`InProcFace`], add it, install a FIB route
//! with the *matching* id, then wrap the handle in a `Producer`. This trait
//! collapses that to one call and keeps face ids out of application code —
//! callers work in prefixes, not plumbing.
//!
//! Lives in `ndn-app` rather than `ndn-engine` because `InProcFace` is a
//! concrete face (in `ndn-face-native`) layered above the core engine; pulling it
//! into `ndn-engine` would invert the dependency.
//!
//! ```no_run
//! use ndn_app::{EngineAppExt, EngineBuilder};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn ex() -> anyhow::Result<()> {
//! let (engine, _shutdown) = EngineBuilder::new(Default::default()).build().await?;
//! let cancel = CancellationToken::new();
//! let producer = engine.register_producer("/ndn/ble/test", cancel.child_token());
//! # Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_engine::{Fib, ForwarderEngine};
// Same `InProcFace` type on both targets; the wasm path imports it straight
// from `ndn-face-local` to avoid `ndn-face-native`'s OS-socket transports.
#[cfg(not(target_arch = "wasm32"))]
use ndn_face::local::InProcFace;
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use crate::connection::{Connection, InProcConnection, LpInfo};
use crate::error::AppError;
use crate::node::ConnectionProvider;
use crate::{Consumer, Node, Producer};

/// Per-app in-process face buffer depth. Matches `MobileEngine`'s default.
const APP_FACE_BUFFER: usize = 256;

/// In-process producer/consumer registration for an embedded engine.
pub trait EngineAppExt {
    /// Allocate an in-process app face, install a FIB route for `prefix`, and
    /// return a `Producer` bound to it. `cancel` ties the face's lifetime to
    /// the caller — pass a child of the engine's shutdown token so the face
    /// goes away on shutdown.
    fn register_producer(&self, prefix: impl Into<Name>, cancel: CancellationToken) -> Producer;

    /// Allocate an in-process app face and return a `Consumer` over it.
    /// No FIB route is installed (consumers originate Interests, they don't
    /// answer them).
    fn app_consumer(&self, cancel: CancellationToken) -> Consumer;

    /// Allocate an in-process app face and return a [`Node`] over it — the
    /// unified surface for embedding and for test harnesses. The node's
    /// `register_prefix` (so `serve` / `serve_object`) installs a FIB route to
    /// this face, so two `app_node`s on one engine talk to each other with no
    /// sockets:
    ///
    /// ```no_run
    /// # use ndn_app::{EngineAppExt, EngineBuilder};
    /// # use tokio_util::sync::CancellationToken;
    /// # async fn ex() -> anyhow::Result<()> {
    /// let (engine, _sd) = EngineBuilder::new(Default::default()).build().await?;
    /// let cancel = CancellationToken::new();
    /// let alice = engine.app_node(cancel.child_token());
    /// let bob   = engine.app_node(cancel.child_token());
    /// let _g = alice.serve("/alice", |i, r| async move {
    ///     let _ = r.respond((*i.name).clone(), "hi").await;
    /// }).await?;
    /// let data = bob.fetch("/alice/greeting").await?;
    /// # let _ = data; Ok(()) }
    /// ```
    ///
    /// In-process nodes are full nodes: the dedicated-stream patterns
    /// (`publish`/`subscribe`/`query`/`serve_object`) work too, each allocating
    /// a fresh app face on this engine (tied to a child of `cancel`). No socket,
    /// every pattern.
    fn app_node(&self, cancel: CancellationToken) -> Node;
}

/// Mints fresh in-process app faces on an embedded engine so a [`Node`] can open
/// the dedicated connections that sync / query / object-serving need. Each face
/// is tied to a child of the token passed to [`EngineAppExt::app_node`].
struct EngineFaceProvider {
    engine: ForwarderEngine,
    cancel: CancellationToken,
}

impl EngineFaceProvider {
    /// Allocate a new app face on the engine and wrap it in an
    /// [`EngineConnection`] (whose `register_prefix` installs a FIB route to it).
    fn spawn_face(&self) -> Arc<dyn Connection> {
        let face_id = self.engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.engine.add_face(face, self.cancel.child_token());
        Arc::new(EngineConnection {
            inner: InProcConnection::new(handle),
            fib: self.engine.fib(),
            face_id,
        })
    }
}

#[async_trait]
impl ConnectionProvider for EngineFaceProvider {
    async fn open(&self) -> Result<Arc<dyn Connection>, AppError> {
        Ok(self.spawn_face())
    }
}

/// In-process [`Connection`] whose `register_prefix` installs a FIB route to its
/// own face — so a [`Node`] built on it can `serve` without an external mgmt
/// round trip. Send/recv delegate to the wrapped [`InProcConnection`].
struct EngineConnection {
    inner: InProcConnection,
    fib: Arc<Fib>,
    face_id: FaceId,
}

#[async_trait]
impl Connection for EngineConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.inner.send(wire).await
    }

    async fn recv(&self) -> Option<Bytes> {
        self.inner.recv().await
    }

    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        self.inner.recv_with_meta().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.fib.add_nexthop(prefix, self.face_id, 0);
        Ok(())
    }
}

impl EngineAppExt for ForwarderEngine {
    fn register_producer(&self, prefix: impl Into<Name>, cancel: CancellationToken) -> Producer {
        let prefix = prefix.into();
        let face_id = self.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.add_face(face, cancel);
        self.fib().add_nexthop(&prefix, face_id, 0);
        Producer::from_handle(handle, prefix)
    }

    fn app_consumer(&self, cancel: CancellationToken) -> Consumer {
        let face_id = self.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.add_face(face, cancel);
        Consumer::from_handle(handle)
    }

    fn app_node(&self, cancel: CancellationToken) -> Node {
        let provider = Arc::new(EngineFaceProvider {
            engine: self.clone(),
            cancel,
        });
        let primary = provider.spawn_face();
        Node::from_provider(primary, provider)
    }
}
