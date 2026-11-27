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
//! concrete face (in `ndn-face`) layered above the core engine; pulling it
//! into `ndn-engine` would invert the dependency.
//!
//! ```no_run
//! use ndn_app::{EngineAppExt, EngineBuilder};
//! use ndn_app::prelude::name;
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn ex() -> anyhow::Result<()> {
//! let (engine, _shutdown) = EngineBuilder::new(Default::default()).build().await?;
//! let cancel = CancellationToken::new();
//! let producer = engine.register_producer(name!("/ndn/ble/test"), cancel.child_token());
//! # Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_engine::rib::RibRoute;
// Same `InProcFace` type on both targets; the wasm path imports it straight
// from `ndn-face-local` to avoid `ndn-face`'s OS-socket transports.
#[cfg(not(target_arch = "wasm32"))]
use ndn_face::local::InProcFace;
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcFace;
use ndn_packet::Name;
use ndn_transport::{FaceId, SideClass, SideRefused};
use tokio_util::sync::CancellationToken;

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::connection::{Connection, InProcConnection, LpInfo, RouteEvents, side_check};
use crate::error::AppError;
use crate::node::ConnectionProvider;
use crate::{Consumer, Node, Producer};
use ndn_transport::side_header::SideHeader;

/// Yields before a sender that was refused `Full` sleeps between looks for room, and the sleep.
const ROOM_YIELDS: u32 = 256;
const ROOM_RECHECK: Duration = Duration::from_millis(1);

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

    /// Allocate an in-process app face and return a raw [`Connection`] over it,
    /// whose `register_prefix` installs a FIB route to this face. This is the
    /// building block *below* [`app_node`](Self::app_node): an embedder that
    /// drives its own protocol loop over a bare bidirectional packet channel
    /// (e.g. binding an `SvsPubSub` group to a real engine) pumps this
    /// connection's `send`/`recv` directly, rather than going through the
    /// demultiplexed fetch/serve surface. The face is tied to `cancel`.
    fn app_face(&self, cancel: CancellationToken) -> Arc<dyn Connection>;

    /// Allocate an in-process app face and return a [`Node`] over it — the
    /// unified surface for embedding and for test harnesses. The node's
    /// `register_prefix` (so `serve` / `serve_object`) installs a FIB route to
    /// this face, so two `app_node`s on one engine talk to each other with no
    /// sockets:
    ///
    /// ```no_run
    /// # use ndn_app::{EngineAppExt, EngineBuilder};
    /// # use ndn_app::prelude::name;
    /// # use tokio_util::sync::CancellationToken;
    /// # async fn ex() -> anyhow::Result<()> {
    /// let (engine, _sd) = EngineBuilder::new(Default::default()).build().await?;
    /// let cancel = CancellationToken::new();
    /// let alice = engine.app_node(cancel.child_token());
    /// let bob   = engine.app_node(cancel.child_token());
    /// let _g = alice.serve(name!("/alice"), |i, r| async move {
    ///     let _ = r.respond((*i.name).clone(), "hi").await;
    /// }).await?;
    /// let data = bob.fetch(name!("/alice/greeting")).await?;
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
            engine: self.engine.clone(),
            face_id,
            refused: Mutex::new(None),
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
    engine: ForwarderEngine,
    face_id: FaceId,
    /// The route of the datagram frame last refused `Full`: what [`Connection::side_ready`]
    /// waits for room on.
    refused: Mutex<Option<u64>>,
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

    /// Through the RIB, as a daemon's `rib/register` does for an application on a unix face
    /// (origin APP, `CHILD_INHERIT`, cost 0): the entry this makes in the FIB also carries the
    /// routes of the prefixes above it that `CHILD_INHERIT`, so a registration under a
    /// namespace a link routes (a sync group under the namespace a relay is used for) does not
    /// shadow that route. The FIB written directly held the application's face alone and the
    /// longest-prefix match stopped there: what the application sent for the group never left
    /// the forwarder. The route is no route that came up on another face
    /// ([`Connection::routes`] leaves this face out).
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        const ORIGIN_APP: u64 = 0;
        const CHILD_INHERIT: u64 = 1;
        self.engine.rib().add(
            prefix,
            RibRoute {
                face_id: self.face_id,
                origin: ORIGIN_APP,
                cost: 0,
                flags: CHILD_INHERIT,
                expires_at: None,
            },
        );
        self.engine.rib().apply_to_fib(prefix, &self.engine.fib());
        Ok(())
    }

    fn side_frame_max(&self) -> usize {
        self.inner.side_frame_max()
    }

    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), AppError> {
        self.inner.send_side(frame, class).await
    }

    /// A datagram frame goes to the engine's side table at once, from here
    /// ([`ForwarderEngine::side_send_local`]), and not through the face reader's queue, so that
    /// a link with no room for it refuses it `Full` **to this caller**, who keeps the message
    /// pending and coalescing, as it does for a link it holds itself. Through the queue the
    /// reader would have found the sink full after the caller was told `Ok`, and the frame, with
    /// the newest message of its names, was lost (counted `sink_full`, told to no one). A stream
    /// frame keeps the queue ([`send_side`](Connection::send_side)).
    fn try_send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        if class != SideClass::Datagram {
            return self.inner.try_send_side(frame, class);
        }
        side_check(&frame, self.side_frame_max())?;
        let route = SideHeader::parse(&frame).ok().map(|h| h.id());
        let sent = self.engine.side_send_local(self.face_id, frame);
        if matches!(sent, Err(SideRefused::Full)) {
            *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = route;
        }
        sent
    }

    /// After a datagram was refused `Full`, completes when a sink of its route has room
    /// ([`ForwarderEngine::side_room`]): the sink's own queue empties on another task, so this
    /// yields to it and, a few hundred yields later, sleeps a millisecond between looks, as a
    /// link's own waiting send does. Otherwise when the face's queue has room.
    async fn side_ready(&self) {
        let route = *self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(id) = route {
            let mut yields = 0;
            while !self.engine.side_room(id, SideClass::Datagram) {
                if yields < ROOM_YIELDS {
                    yields += 1;
                    tokio::task::yield_now().await;
                } else {
                    crate::rt::sleep(ROOM_RECHECK).await;
                }
            }
            let mut refused = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
            if *refused == Some(id) {
                *refused = None;
            }
        }
        self.inner.side_ready().await;
    }

    async fn recv_side(&self) -> Option<(Bytes, FaceId)> {
        self.inner.recv_side().await
    }

    /// What the engine's face says it carries ([`ForwarderEngine::face_carries_side`]).
    fn side_carries(&self, face: FaceId, class: SideClass) -> bool {
        self.engine.face_carries_side(face, class)
    }

    /// What this connection's own app face says it carries.
    fn side_carries_here(&self, class: SideClass) -> bool {
        self.engine.face_carries_side(self.face_id, class)
    }

    /// What the engine's side table says the sinks of the channel's route take now.
    fn side_sink_limit(&self, channel: u64) -> Option<usize> {
        self.engine.side_datagram_limit(channel)
    }

    /// Bar `face` in the engine's side table ([`ndn_engine::side::SideTable::bar`]): the first
    /// bar is 60 s and each repeat on the same face doubles, to an hour (a call while a bar is
    /// live changes nothing and names what is left of it). This connection's own face is
    /// refused: every channel frame of this app goes over it, so barring it would cut the app
    /// off from its own forwarder, not a link that delivered a forgery. So is a face the engine
    /// does not hold: a bar is state per face, and the id is the host's to name.
    async fn side_quarantine(&self, face: FaceId) -> Result<std::time::Duration, AppError> {
        if face == self.face_id {
            return Err(AppError::Unsupported(
                "this is the connection's own face, not a link a frame came over: a frame \
                 delivered with no ingress of another face cannot be attributed to a link, so \
                 nothing was barred"
                    .into(),
            ));
        }
        if self.engine.faces().get(face).is_none() {
            return Err(AppError::Unsupported(format!(
                "no face {face} on this forwarder, so nothing was barred: name the face the \
                 frame came over (the ingress the forwarder reported with it)"
            )));
        }
        let side = self.engine.side();
        Ok(side.bar(face, side.now()))
    }

    /// The engine RIB's routes that come up on a face that is not this one
    /// and not a local application's or a management socket's (the kinds
    /// whose scope is always local): a link, a tunnel, a radio. Those are
    /// the faces whose far end can be told of this app's state; an
    /// application registering its own prefix through the management
    /// interface is not one.
    fn routes(&self) -> Option<RouteEvents> {
        let own = self.face_id;
        let engine = self.engine.clone();
        Some(RouteEvents::new(
            self.engine.rib().route_events(),
            move |face| face != own && engine.face_reaches_off_host(face),
        ))
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

    fn app_face(&self, cancel: CancellationToken) -> Arc<dyn Connection> {
        let face_id = self.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, APP_FACE_BUFFER);
        self.add_face(face, cancel);
        Arc::new(EngineConnection {
            inner: InProcConnection::new(handle),
            engine: self.clone(),
            face_id,
            refused: Mutex::new(None),
        })
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
