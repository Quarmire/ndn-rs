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

use std::collections::HashMap;
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
/// The sleep doubles (to 16 times `ROOM_RECHECK`) after each this many looks.
const ROOM_BACKOFF_EVERY: u32 = 32;
/// The longest `side_ready` waits for room on the routes it was refused for.
const ROOM_WAIT_MAX: Duration = Duration::from_secs(1);

/// Sleep `dur` in a future that is `Send` on wasm32 as well: the connection's methods are
/// `async_trait`, and the browser's timer future is not `Send`, so the timer runs on its own
/// task there and this waits on a oneshot.
async fn pause(dur: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    crate::rt::sleep(dur).await;
    #[cfg(target_arch = "wasm32")]
    {
        let (done, woken) = futures::channel::oneshot::channel();
        crate::rt::spawn(async move {
            crate::rt::sleep(dur).await;
            let _ = done.send(());
        });
        let _ = woken.await;
    }
}

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
            refused: Mutex::default(),
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
    /// The newest datagram frame refused `Full` for each route, until its route has room for it:
    /// what [`Connection::side_ready`] waits on. At most one frame per route the side table
    /// holds with this face as its source.
    refused: Mutex<HashMap<u64, Bytes>>,
}

impl EngineConnection {
    /// Forget the routes whose sinks have room now for the frame refused them, and say whether
    /// that left nothing to wait for: no route was refused, or one of them has room.
    fn take_room(&self) -> bool {
        let refused: Vec<(u64, Bytes)> = self
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(route, frame)| (*route, frame.clone()))
            .collect();
        let roomy: Vec<u64> = refused
            .iter()
            .filter(|(_, frame)| self.engine.side_room(frame))
            .map(|(route, _)| *route)
            .collect();
        let mut held = self.refused.lock().unwrap_or_else(PoisonError::into_inner);
        for route in &roomy {
            held.remove(route);
        }
        refused.is_empty() || !roomy.is_empty()
    }
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
    /// frame keeps the queue ([`send_side`](Connection::send_side)). A frame refused `Full` is
    /// remembered under its route, the newest one each, for [`side_ready`](Connection::side_ready).
    fn try_send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        if class != SideClass::Datagram {
            return self.inner.try_send_side(frame, class);
        }
        side_check(&frame, self.side_frame_max())?;
        let route = SideHeader::parse(&frame).ok().map(|h| h.id());
        let sent = self.engine.side_send_local(self.face_id, frame.clone());
        if let (Err(SideRefused::Full), Some(route)) = (&sent, route) {
            self.refused
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(route, frame);
        }
        sent
    }

    /// After datagrams were refused `Full`, completes when a sink of **any** route refused has
    /// room for the frame refused ([`ForwarderEngine::side_room`]; that route is forgotten, a
    /// frame refused again puts it back), and **at the latest after [`ROOM_WAIT_MAX`]** (1 s),
    /// room or not. Every drain of the node runs after it returns and each tests its own route
    /// by sending, so a route whose sink never drains holds back no other: the node's one waiter
    /// has no route of its own to be stuck on. At the bound the drain of a route with no room
    /// is refused `Full` again and counts it (`full` in the channel's stats; its messages stay
    /// pending and coalesce, `replaced`), so a held-back route is neither lost nor silent. The
    /// sink's own queue empties on another task, so this yields to it and, a few hundred yields
    /// later, sleeps between looks (a millisecond, then longer: 2, 4, 8, 16 ms as the wait
    /// lengthens, so a sink that stays stuck is looked at 60 times a second, not 1,000). Then
    /// when the face's queue has room.
    async fn side_ready(&self) {
        let (mut yields, mut sleeps, mut waited) = (0, 0u32, Duration::ZERO);
        while waited < ROOM_WAIT_MAX && !self.take_room() {
            if yields < ROOM_YIELDS {
                yields += 1;
                tokio::task::yield_now().await;
            } else {
                let step = ROOM_RECHECK * (1 << (sleeps / ROOM_BACKOFF_EVERY).min(4));
                sleeps += 1;
                waited += step;
                pause(step).await;
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
            refused: Mutex::default(),
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    //! The first hop's hold-back (docs/specs/channel.md §14.4): a node's connection to its
    //! embedded forwarder is told `Full` for the datagrams of a route whose sinks have no room,
    //! and `side_ready` is what its drains wait on.

    use std::sync::atomic::{AtomicBool, Ordering};

    use ndn_engine::EngineBuilder;
    use ndn_engine::side::SideId;
    use ndn_transport::side_header::{SideHeader, SideKind};
    use ndn_transport::{FaceError, FaceKind, Transport};

    use super::*;

    /// A sink face that takes frames while `full` is clear and has no room while it is set.
    struct Gate {
        id: FaceId,
        full: Arc<AtomicBool>,
    }

    impl Transport for Gate {
        fn id(&self) -> FaceId {
            self.id
        }
        fn kind(&self) -> FaceKind {
            FaceKind::App
        }
        fn side_frame_max(&self) -> usize {
            9_000
        }
        fn side_carries(&self, _class: SideClass) -> bool {
            true
        }
        fn side_room(&self, _class: SideClass) -> bool {
            !self.full.load(Ordering::SeqCst)
        }
        fn forward_side(&self, _frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
            Err(SideRefused::Unsupported)
        }
        fn forward_side_from(
            &self,
            _frame: Bytes,
            _class: SideClass,
            _ingress: FaceId,
        ) -> Result<(), SideRefused> {
            if self.full.load(Ordering::SeqCst) {
                Err(SideRefused::Full)
            } else {
                Ok(())
            }
        }
        async fn send_bytes(&self, _wire: Bytes) -> Result<(), FaceError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            std::future::pending().await
        }
    }

    fn data_frame(route: u64) -> Bytes {
        let mut v = SideHeader::new(SideClass::Datagram, SideKind::Data, route)
            .expect("a datagram data header")
            .encode()
            .to_vec();
        v.resize(200, 0xA5);
        Bytes::from(v)
    }

    /// An engine, a node connection on it, and one sink face per route in `routes`, each the
    /// only sink of its route with the node's face as the source. The switch of each sink says
    /// whether it has room.
    async fn rig(
        routes: &[u64],
    ) -> (
        ForwarderEngine,
        Arc<dyn Connection>,
        Vec<Arc<AtomicBool>>,
        CancellationToken,
    ) {
        let (engine, shutdown) = EngineBuilder::new(Default::default())
            .build()
            .await
            .expect("an engine");
        shutdown.detach();
        let cancel = CancellationToken::new();
        let before = engine.faces().face_ids();
        let conn = engine.app_face(cancel.child_token());
        let source = engine
            .faces()
            .face_ids()
            .into_iter()
            .find(|id| !before.contains(id))
            .expect("the connection's face");
        let mut gates = Vec::new();
        for &route in routes {
            let full = Arc::new(AtomicBool::new(false));
            let id = engine.faces().alloc_id();
            engine.add_face(
                Gate {
                    id,
                    full: Arc::clone(&full),
                },
                cancel.child_token(),
            );
            engine
                .side()
                .install(SideId(route), source, id, Duration::from_secs(600))
                .expect("the route installs");
            gates.push(full);
        }
        (engine, conn, gates, cancel)
    }

    /// One route whose only sink never drains must not hold back the others: the connection
    /// was refused `Full` for route 2 first and for the stuck route 1 after, and route 2's sink
    /// has room again while route 1's has not. `side_ready` is what every drain of the node
    /// waits on, so it completes for route 2's room (a slot that kept the route refused last
    /// waited on route 1, whose sink never drains, and no other channel of the node was ever
    /// told that it could send).
    #[tokio::test]
    async fn a_route_whose_sink_never_drains_does_not_hold_back_the_datagrams_of_another() {
        let (_engine, conn, gates, _cancel) = rig(&[1, 2]).await;
        gates[1].store(true, Ordering::SeqCst);
        assert_eq!(
            conn.try_send_side(data_frame(2), SideClass::Datagram),
            Err(SideRefused::Full)
        );
        gates[0].store(true, Ordering::SeqCst);
        assert_eq!(
            conn.try_send_side(data_frame(1), SideClass::Datagram),
            Err(SideRefused::Full)
        );
        gates[1].store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), conn.side_ready())
            .await
            .expect(
                "side_ready waited on the route whose sink never drains while another route \
                 had room again",
            );
        assert_eq!(
            conn.try_send_side(data_frame(2), SideClass::Datagram),
            Ok(()),
            "the route with room again takes its frame"
        );
        assert_eq!(
            conn.try_send_side(data_frame(1), SideClass::Datagram),
            Err(SideRefused::Full),
            "the stuck route is still held back, not lost"
        );
    }

    /// The wait is bounded: with only a stuck route refused, `side_ready` still completes within
    /// [`ROOM_WAIT_MAX`], so that every drain of the node runs again (and is refused again, and
    /// counts it), and the frame stays with the node.
    #[tokio::test]
    async fn the_wait_for_room_is_bounded() {
        let (_engine, conn, gates, _cancel) = rig(&[1]).await;
        gates[0].store(true, Ordering::SeqCst);
        assert_eq!(
            conn.try_send_side(data_frame(1), SideClass::Datagram),
            Err(SideRefused::Full)
        );
        tokio::time::timeout(ROOM_WAIT_MAX + Duration::from_secs(2), conn.side_ready())
            .await
            .expect("side_ready waited without a bound on a sink that never drains");
        assert_eq!(
            conn.try_send_side(data_frame(1), SideClass::Datagram),
            Err(SideRefused::Full),
            "still refused, never lost"
        );
    }
}
