//! Transport-agnostic packet pipe used by `Consumer` and
//! `Producer`. [`InProcConnection`] talks to an embedded engine
//! through an [`InProcHandle`]; [`IpcConnection`] talks to an external
//! `ndn-fwd` over Unix socket via [`ForwarderClient`].

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_engine::RouteUp;
use tokio::sync::broadcast;

// `InProcHandle` is the same type on both targets — `ndn-face` simply
// re-exports it from `ndn-face-local`. The wasm path imports it directly so it
// doesn't pull `ndn-face`'s OS-socket transports.
#[cfg(not(target_arch = "wasm32"))]
use ndn_face::local::InProcHandle;
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_transport::FaceId;

use crate::AppError;
use crate::demux::Replies;

/// Per-packet NDNLPv2 local fields surfaced to the application — the
/// `getTag<lp::IncomingFaceIdTag>()` equivalent. `incoming_face_id` is the
/// face the packet arrived on at the forwarder (for an embedded in-process
/// app it comes from the source tag-bag); `congestion_mark` is the LP
/// CongestionMark, if any. Both `None` unless the forwarder attached them
/// (which requires the face to have LocalFields enabled).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LpInfo {
    pub incoming_face_id: Option<FaceId>,
    pub congestion_mark: Option<u64>,
}

impl LpInfo {
    /// The local fields of a decoded LP frame.
    pub(crate) fn from_lp(lp: &LpPacket) -> Self {
        Self {
            incoming_face_id: lp.incoming_face_id.map(FaceId),
            congestion_mark: lp.congestion_mark,
        }
    }
}

/// Extract LP local fields from a (possibly LP-framed) wire packet.
pub(crate) fn lp_info_from_wire(wire: &Bytes) -> LpInfo {
    if !is_lp_packet(wire) {
        return LpInfo::default();
    }
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => LpInfo::from_lp(&lp),
        Err(_) => LpInfo::default(),
    }
}

/// What a [`RouteEvents`] stream tells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteNews {
    /// A route toward `prefix` came up on a face other than the
    /// connection's own and not a local application's.
    Up(Name),
    /// The stream fell behind and lost some: any route may have come up.
    Missed,
}

/// The stream of routes coming up at a forwarder ([`Connection::routes`]):
/// the engine RIB's [`RouteUp`]s, those on faces `accept` takes.
pub struct RouteEvents {
    rx: broadcast::Receiver<RouteUp>,
    accept: Arc<dyn Fn(FaceId) -> bool + Send + Sync>,
}

impl RouteEvents {
    /// The `RouteUp`s of `rx` on faces `accept` takes.
    pub fn new(
        rx: broadcast::Receiver<RouteUp>,
        accept: impl Fn(FaceId) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            rx,
            accept: Arc::new(accept),
        }
    }

    /// The next news; `None` once the forwarder is gone.
    pub async fn next(&mut self) -> Option<RouteNews> {
        loop {
            match self.rx.recv().await {
                Ok(up) if (self.accept)(up.face) => return Some(RouteNews::Up(up.prefix)),
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => return Some(RouteNews::Missed),
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    /// The next news if some is waiting now; `None` when none is.
    pub fn next_ready(&mut self) -> Option<RouteNews> {
        loop {
            match self.rx.try_recv() {
                Ok(up) if (self.accept)(up.face) => return Some(RouteNews::Up(up.prefix)),
                Ok(_) => {}
                Err(broadcast::error::TryRecvError::Lagged(_)) => return Some(RouteNews::Missed),
                Err(_) => return None,
            }
        }
    }
}

/// Transport-agnostic packet pipe between an app
/// ([`Consumer`](crate::Consumer) / [`Producer`](crate::Producer)) and a
/// forwarder — an embedded engine via [`InProcConnection`] or an external
/// `ndn-fwd` over a Unix socket via [`IpcConnection`].
///
/// `&self` everywhere so `Arc<dyn Connection>` can be shared across
/// concurrent send- and receive-half tasks.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Pre-encoded NDN wire packet (Interest, Data, or LpPacket).
    async fn send(&self, wire: Bytes) -> Result<(), AppError>;

    /// `None` when the channel is closed.
    async fn recv(&self) -> Option<Bytes>;

    /// Like [`recv`](Self::recv) but also surfaces the packet's NDNLPv2 local
    /// fields ([`LpInfo`]). Default decodes any LP frame on the wire; the
    /// in-process connection additionally fills `incoming_face_id` from the
    /// source tag-bag.
    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        self.recv().await.map(|wire| {
            let lp = lp_info_from_wire(&wire);
            (wire, lp)
        })
    }

    /// External connections turn this into `/localhost/nfd/rib/register`;
    /// embedded connections no-op (the embedder writes the engine FIB
    /// directly).
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError>;

    /// A stream that receives exactly the replies to the Interests registered
    /// on it ([`Replies::expect`]), matched by NDN rules, when this connection
    /// demultiplexes its inbound packets ([`DemuxConnection`]). Every
    /// [`Consumer`](crate::Consumer) fetch uses it when present, so any number
    /// of fetches can share the connection without taking each other's
    /// replies. `None` (the default) means the connection has one receive
    /// queue: a fetch then reads [`recv`](Self::recv) itself, which is correct
    /// only while it is the connection's single reader.
    ///
    /// [`DemuxConnection`]: crate::DemuxConnection
    fn replies(&self) -> Option<Replies> {
        None
    }

    /// The routes that come up at this connection's forwarder (see
    /// [`RouteEvents`]), when it can tell: an embedded engine's connection
    /// ([`EngineAppExt::app_face`](crate::EngineAppExt::app_face)) can, as
    /// its RIB announces every route that gets into the FIB. `None` (the
    /// default) for one that cannot: [`IpcConnection`] has no such stream
    /// (the daemon's `/localhost/nfd/rib/notifications` tells only the
    /// registrations made through its management interface, not the routes
    /// its link layer, its configuration or its routing protocols install),
    /// and a bare [`InProcConnection`] knows no engine, only its own face.
    /// A caller that wants to act on a face coming up and gets `None` keeps
    /// its periodic work, which is correct and slower.
    fn routes(&self) -> Option<RouteEvents> {
        None
    }
}

/// Talks to an external `ndn-fwd` over a Unix socket via [`ForwarderClient`].
/// Native-only — the browser reaches its engine through [`InProcConnection`].
#[cfg(not(target_arch = "wasm32"))]
pub struct IpcConnection {
    client: ForwarderClient,
}

#[cfg(not(target_arch = "wasm32"))]
impl IpcConnection {
    pub fn new(client: ForwarderClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &ForwarderClient {
        &self.client
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl Connection for IpcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.client.send(wire).await.map_err(AppError::Connection)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.client.recv().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.client
            .register_prefix(prefix)
            .await
            .map_err(AppError::Connection)
    }
}

/// App owns one end of an [`InProcHandle`] pair; the engine owns the
/// matching `InProcFace`. Same Tokio (or wasm-bindgen-futures) runtime.
pub struct InProcConnection {
    handle: InProcHandle,
}

impl InProcConnection {
    pub fn new(handle: InProcHandle) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> &InProcHandle {
        &self.handle
    }
}

#[async_trait]
impl Connection for InProcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.handle.send(wire).await.map_err(|_| AppError::Closed)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.handle.recv().await
    }

    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        let tagged = self.handle.recv_tagged().await?;
        let mut lp = lp_info_from_wire(&tagged.wire);
        // In-process delivery carries the ingress face in the tag-bag (the
        // NFD IncomingFaceIdTag equivalent), not on the bare wire.
        if lp.incoming_face_id.is_none() {
            lp.incoming_face_id = tagged.source_face;
        }
        Some((tagged.wire, lp))
    }

    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_face::local::InProcFace;
    use ndn_packet::encode::DataBuilder;
    use ndn_transport::Transport;

    /// An embedded app reads `incoming_face_id` from the in-process source
    /// tag-bag (the NFD IncomingFaceIdTag equivalent), surfaced via `LpInfo`.
    #[tokio::test]
    async fn in_proc_recv_with_meta_surfaces_source_as_incoming_face_id() {
        let (face, handle) = InProcFace::new(FaceId(7), 4);
        // Engine side delivers a Data tagged with the face it arrived on.
        let data = DataBuilder::new(ndn_packet::name!("/m/d"), b"x").sign_digest_sha256();
        face.send_bytes_with_source(data, FaceId(42)).await.unwrap();

        let conn = InProcConnection::new(handle);
        let (_wire, lp) = conn.recv_with_meta().await.expect("recv");
        assert_eq!(
            lp.incoming_face_id,
            Some(FaceId(42)),
            "incoming_face_id must reflect the ingress face from the tag-bag"
        );
    }

    /// A face of a kind that is no local application's, as a link is.
    struct Link(FaceId);

    impl Transport for Link {
        fn id(&self) -> FaceId {
            self.0
        }
        fn kind(&self) -> ndn_transport::FaceKind {
            ndn_transport::FaceKind::Quic
        }
        async fn send_bytes(&self, _wire: Bytes) -> Result<(), ndn_transport::FaceError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<Bytes, ndn_transport::FaceError> {
            std::future::pending().await
        }
    }

    fn route(face: FaceId) -> ndn_engine::RibRoute {
        ndn_engine::RibRoute {
            face_id: face,
            origin: 255,
            cost: 0,
            flags: 1,
            expires_at: None,
        }
    }

    /// An embedded engine's connection tells the routes that come up on a
    /// link and none of its own registration, nor a local application's
    /// (through the RIB, as the management interface does): a storm of
    /// local registrations is no face coming up for a sync group.
    #[tokio::test]
    async fn an_engine_connection_tells_a_link_coming_up_and_not_local_registrations() {
        use crate::EngineAppExt;
        let (engine, _shutdown) = ndn_engine::EngineBuilder::new(Default::default())
            .build()
            .await
            .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let conn = engine.app_face(cancel.child_token());
        let mut routes = conn.routes().expect("an engine's connection tells routes");
        let group = ndn_packet::name!("/alice/32=sync");

        // Its own registration: the FIB, no RIB route.
        conn.register_prefix(&group).await.unwrap();
        assert_eq!(routes.next_ready(), None, "its own registration");

        // Another application's, through the RIB.
        let (face, _handle) = InProcFace::new(engine.faces().alloc_id(), 4);
        let local = face.id();
        engine.add_face(face, cancel.child_token());
        engine.rib().add(&group, route(local));
        engine.rib().apply_to_fib(&group, &engine.fib());
        assert_eq!(routes.next_ready(), None, "a local application's route");

        // A link's.
        let link = engine.faces().alloc_id();
        engine.add_face(Link(link), cancel.child_token());
        engine.rib().add(&group, route(link));
        engine.rib().apply_to_fib(&group, &engine.fib());
        assert_eq!(
            routes.next_ready(),
            Some(RouteNews::Up(group.clone())),
            "a link's route"
        );
        assert_eq!(routes.next_ready(), None, "told once");

        // A route toward a face the engine does not hold is nobody's link.
        engine.rib().add(&group, route(FaceId(9999)));
        engine.rib().apply_to_fib(&group, &engine.fib());
        assert_eq!(routes.next_ready(), None, "a face that is gone");
        cancel.cancel();
    }

    /// A subscriber that falls behind is told it missed some, not left
    /// believing it has seen everything.
    #[tokio::test]
    async fn a_subscriber_that_falls_behind_is_told_it_missed_some() {
        let (tx, rx) = broadcast::channel(2);
        let mut routes = RouteEvents::new(rx, |_| true);
        for i in 0..5u64 {
            let _ = tx.send(RouteUp {
                prefix: ndn_packet::name!("/a"),
                face: FaceId(i),
            });
        }
        assert_eq!(routes.next().await, Some(RouteNews::Missed));
        assert!(matches!(routes.next().await, Some(RouteNews::Up(_))));
        drop(tx);
        while routes.next().await.is_some() {}
    }

    /// A connection that knows no engine tells no routes: its holder keeps
    /// its periodic work.
    #[test]
    fn a_bare_in_process_connection_tells_no_routes() {
        let (_face, handle) = InProcFace::new(FaceId(1), 4);
        assert!(InProcConnection::new(handle).routes().is_none());
    }
}
