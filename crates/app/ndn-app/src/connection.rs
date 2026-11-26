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
use ndn_packet::lp::{LpHeaders, LpPacket, encode_lp_with_headers, is_lp_packet};
use ndn_transport::{FaceId, SideClass, SideRefused};

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
/// the engine RIB's [`RouteUp`]s, those on faces `accept` takes, or the news
/// of a forwarder's stream followed over IPC ([`IpcConnection`]).
pub struct RouteEvents {
    source: RouteSource,
}

enum RouteSource {
    Engine {
        rx: broadcast::Receiver<RouteUp>,
        accept: Arc<dyn Fn(FaceId) -> bool + Send + Sync>,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Pushed(tokio::sync::mpsc::Receiver<RouteNews>),
}

impl RouteEvents {
    /// The `RouteUp`s of `rx` on faces `accept` takes.
    pub fn new(
        rx: broadcast::Receiver<RouteUp>,
        accept: impl Fn(FaceId) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            source: RouteSource::Engine {
                rx,
                accept: Arc::new(accept),
            },
        }
    }

    /// The news a task following a remote forwarder's stream pushes.
    #[cfg(not(target_arch = "wasm32"))]
    fn pushed(rx: tokio::sync::mpsc::Receiver<RouteNews>) -> Self {
        Self {
            source: RouteSource::Pushed(rx),
        }
    }

    /// The next news; `None` once the forwarder is gone.
    pub async fn next(&mut self) -> Option<RouteNews> {
        match &mut self.source {
            RouteSource::Engine { rx, accept } => loop {
                match rx.recv().await {
                    Ok(up) if accept(up.face) => return Some(RouteNews::Up(up.prefix)),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => return Some(RouteNews::Missed),
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            },
            #[cfg(not(target_arch = "wasm32"))]
            RouteSource::Pushed(rx) => rx.recv().await,
        }
    }

    /// The next news if some is waiting now; `None` when none is.
    pub fn next_ready(&mut self) -> Option<RouteNews> {
        match &mut self.source {
            RouteSource::Engine { rx, accept } => loop {
                match rx.try_recv() {
                    Ok(up) if accept(up.face) => return Some(RouteNews::Up(up.prefix)),
                    Ok(_) => {}
                    Err(broadcast::error::TryRecvError::Lagged(_)) => {
                        return Some(RouteNews::Missed);
                    }
                    Err(_) => return None,
                }
            },
            #[cfg(not(target_arch = "wasm32"))]
            RouteSource::Pushed(rx) => rx.try_recv().ok(),
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

    /// Send `wire` (a bare Data, Interest or Nack) wrapped in an NDNLPv2 packet that carries
    /// `headers`: a Data that goes out with `CachePolicy = NoCache`, or with a
    /// [`SideRoute`](ndn_packet::lp::SideRoute) that makes each forwarder on its reverse path
    /// route the channel frames that follow. A connection that carries LP packets (every one
    /// here does) needs nothing but this default.
    async fn send_with(&self, wire: Bytes, headers: LpHeaders) -> Result<(), AppError> {
        self.send(encode_lp_with_headers(&wire, &headers)).await
    }

    /// The longest side frame (a channel frame: [`ndn_transport::SIDE_MARKER`] first) this
    /// connection carries to its forwarder, `0` for one that carries none (the default).
    fn side_frame_max(&self) -> usize {
        0
    }

    /// Send one side frame into the forwarder, which routes it by its channel id
    /// (`ndn_engine::side::SideTable`); `class` is the carrier the frame asks for, which the
    /// sink faces honour. Waits for room in the connection's queue. A connection that carries
    /// no side frames refuses with [`AppError::Unsupported`], which says what to do instead.
    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), AppError> {
        let _ = (frame, class);
        Err(AppError::Unsupported(NO_SIDE.into()))
    }

    /// [`send_side`](Self::send_side) that never waits: [`SideRefused::Full`] when the queue
    /// has no room (wait for [`side_ready`](Self::side_ready) and try again),
    /// [`SideRefused::NotCarried`] for a connection that carries none (the default),
    /// [`SideRefused::TooLarge`] over [`side_frame_max`](Self::side_frame_max).
    fn try_send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        let _ = (frame, class);
        Err(SideRefused::NotCarried)
    }

    /// Completes when [`try_send_side`](Self::try_send_side) may take a frame again (at once
    /// if it may now). Room is not reserved.
    async fn side_ready(&self) {}

    /// The next side frame the forwarder routed to this connection, with the id of the face it
    /// arrived over at the forwarder (a link's, for a frame from afar): what a heap node's
    /// receiver reads. `None` when the connection is closed. A connection that carries no side
    /// frames never yields one (it waits, as an idle one does); check
    /// [`side_frame_max`](Self::side_frame_max) first.
    async fn recv_side(&self) -> Option<(Bytes, FaceId)> {
        std::future::pending().await
    }

    /// Bar `face` from carrying channel frames (the forwarder's quarantine: 60 s, doubling on
    /// each repeat to an hour; NDN traffic over the face is untouched) and return how long.
    /// Used when a node holds evidence that a frame that came over `face` was forged. A
    /// connection that cannot ask its forwarder refuses with [`AppError::Unsupported`].
    async fn side_quarantine(&self, face: FaceId) -> Result<std::time::Duration, AppError> {
        let _ = face;
        Err(AppError::Unsupported(NO_QUARANTINE.into()))
    }

    /// Whether the forwarder's face `face` (the one an Interest came in over, as
    /// [`LpInfo::incoming_face_id`] says) carries side frames of `class`: what that face's
    /// medium can do, not whether it has room now. A sender asks it of the first hop toward a
    /// receiver before it relies on [`SideClass::Stream`], which an Ethernet segment lacks. An
    /// embedded engine's connection answers from the face ([`Face::side_carries`]; `false`
    /// for a face the engine no longer holds). The default, for a connection that cannot see
    /// its forwarder's faces, is `true`: it says nothing against the path, and a frame that
    /// does not get through is counted at the hop that refused it.
    fn side_carries(&self, face: FaceId, class: SideClass) -> bool {
        let _ = (face, class);
        true
    }

    /// Whether this connection's own face on its forwarder carries side frames of `class`:
    /// what a node's carrier over it can promise before it knows any receiver. The default
    /// follows [`side_frame_max`](Self::side_frame_max) (a connection that carries side frames
    /// at all takes both classes); an embedded engine's connection answers from its face
    /// ([`Face::side_carries`]).
    fn side_carries_here(&self, class: SideClass) -> bool {
        let _ = class;
        self.side_frame_max() != 0
    }

    /// The routes that come up at this connection's forwarder (see
    /// [`RouteEvents`]), when it can tell: an embedded engine's connection
    /// ([`EngineAppExt::app_face`](crate::EngineAppExt::app_face)) can, as
    /// its RIB announces every route that gets into the FIB; so can
    /// [`IpcConnection`], which follows the daemon's
    /// `/localhost/nfd/rib/notifications` stream (local to the host, as every
    /// `/localhost` name is: it is no way for a remote face to learn the
    /// daemon's routes). Both tell only the routes on faces that reach off
    /// the host. `None` (the default) for one that cannot: a bare
    /// [`InProcConnection`] knows no engine, only its own face. A caller
    /// that wants to act on a face coming up and gets `None` keeps its
    /// periodic work, which is correct and slower.
    fn routes(&self) -> Option<RouteEvents> {
        None
    }
}

/// Why a connection carries no side frames, and what to do.
const NO_SIDE: &str = "this connection carries no channel frames: it does not reach a forwarder \
     that routes them. Run the heap node over a connection to an embedded engine \
     (`EngineAppExt::app_face`), or over a forwarder face that carries marked frames";

/// Why a connection cannot bar a face, and what to do.
const NO_QUARANTINE: &str = "this connection cannot ask its forwarder to bar a face: it has no \
     handle on the forwarder's side table. Use `EngineAppExt::app_face` (an embedded engine) or \
     the forwarder's `side/quarantine` management command";

/// Whether `frame` may go on the side path of a connection whose limit is `max`: it starts with
/// the marker, so an NDN packet never takes the side path by mistake, and fits.
pub(crate) fn side_check(frame: &Bytes, max: usize) -> Result<(), SideRefused> {
    if frame.first() != Some(&ndn_transport::SIDE_MARKER) {
        return Err(SideRefused::Malformed);
    }
    if frame.len() > max {
        return Err(SideRefused::TooLarge {
            size: frame.len(),
            max,
        });
    }
    Ok(())
}

/// A refused side frame as the error of an awaiting send.
pub(crate) fn side_error(refused: SideRefused) -> AppError {
    match refused {
        SideRefused::Closed => AppError::Closed,
        other => AppError::Protocol(format!("side frame refused: {other}")),
    }
}

/// How many [`RouteNews`] an [`IpcConnection`]'s follower of the daemon's
/// stream holds for the one that takes them before it waits for room (the
/// daemon's stream holds the events meanwhile, and says so when it dropped
/// some).
#[cfg(not(target_arch = "wasm32"))]
const ROUTE_NEWS: usize = 64;

/// How long one request of the daemon's route stream waits for an event
/// before it is sent again.
#[cfg(not(target_arch = "wasm32"))]
const ROUTE_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// Follow the daemon's `/localhost/nfd/rib/notifications` stream on `client`
/// (a management client of its own on the connection) and hand each route
/// that came up to `news`: from the first notice (the stream's own number,
/// nothing to tell) on, a `route-up` is a [`RouteNews::Up`], and a stream
/// that lost events (it no longer holds the one asked for, or the daemon's
/// feed fell behind) is a [`RouteNews::Missed`]. Ends when `news` is
/// dropped, or when the daemon cannot be asked (the connection is gone, or
/// it answers what this client cannot read): the receiver is then closed and
/// its holder keeps its periodic work.
#[cfg(not(target_arch = "wasm32"))]
async fn follow_route_stream(
    client: ndn_ipc::MgmtClient,
    news: tokio::sync::mpsc::Sender<RouteNews>,
) {
    use ndn_ipc::events::{EventSubscription, Notice};
    use ndn_mgmt_wire::events::RibEvent;

    let mut stream = EventSubscription::<RibEvent>::resume(client, 0);
    let mut started = false;
    loop {
        let notice = tokio::select! {
            _ = news.closed() => return,
            notice = stream.next(ROUTE_POLL) => notice,
        };
        let tell = match notice {
            Ok(None) => None,
            // Asking from 0 is answered at once with the number to follow
            // from: the baseline. Any later one is an event the stream no
            // longer holds.
            Ok(Some(Notice::Resync { .. })) => {
                std::mem::replace(&mut started, true).then_some(RouteNews::Missed)
            }
            Ok(Some(Notice::Event { event, .. })) => match event {
                RibEvent::RouteUp { name, .. } => Some(match name.parse::<Name>() {
                    Ok(prefix) => RouteNews::Up(prefix),
                    Err(_) => RouteNews::Missed,
                }),
                RibEvent::RoutesMissed => Some(RouteNews::Missed),
                RibEvent::Register { .. } | RibEvent::Unregister { .. } | RibEvent::Unknown => None,
            },
            Err(e) => {
                tracing::warn!(error = %e, "the daemon's route stream cannot be followed: routes coming up are not told");
                return;
            }
        };
        if let Some(tell) = tell
            && news.send(tell).await.is_err()
        {
            return;
        }
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

    /// The routes the daemon's RIB tells on
    /// `/localhost/nfd/rib/notifications`, followed from now on by a task
    /// that lives as long as the returned stream, over this connection's
    /// own control face. Call it from within a Tokio runtime.
    fn routes(&self) -> Option<RouteEvents> {
        let (news, rx) = tokio::sync::mpsc::channel(ROUTE_NEWS);
        crate::rt::spawn(follow_route_stream(self.client.event_client(), news));
        Some(RouteEvents::pushed(rx))
    }

    /// A channel frame does not travel on this connection: the daemon's unix-socket and
    /// shared-memory faces carry NDN packets, framed as TLV, and a side frame (first octet
    /// `0x00`) is none. Nothing is sent.
    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), AppError> {
        let _ = (frame, class);
        Err(AppError::Unsupported(
            "this connection to an ndn-fwd daemon carries NDN packets only: its socket and \
             shared-memory faces frame what they carry as TLV packets, which a channel frame \
             (marker octet 0x00) is not. Run the heap node over an embedded engine \
             (`EngineAppExt::app_face`), or inside the daemon's own process"
                .into(),
        ))
    }

    /// The bar is the daemon's `side/quarantine` management command, which is signed: this
    /// connection holds no management key.
    async fn side_quarantine(&self, face: FaceId) -> Result<std::time::Duration, AppError> {
        let _ = face;
        Err(AppError::Unsupported(
            "this connection cannot bar a face of the daemon: `side/quarantine` is a signed \
             management command and this connection holds no management key. Send it with a \
             management client that has one"
                .into(),
        ))
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

    fn side_frame_max(&self) -> usize {
        ndn_transport::side_header::STREAM_FRAME_GRANT
    }

    async fn send_side(&self, frame: Bytes, _class: SideClass) -> Result<(), AppError> {
        side_check(&frame, self.side_frame_max()).map_err(side_error)?;
        self.handle.send(frame).await.map_err(|_| AppError::Closed)
    }

    fn try_send_side(&self, frame: Bytes, _class: SideClass) -> Result<(), SideRefused> {
        side_check(&frame, self.side_frame_max())?;
        self.handle.try_send(frame).map_err(SideRefused::from)
    }

    async fn side_ready(&self) {
        self.handle.send_ready().await;
    }

    async fn recv_side(&self) -> Option<(Bytes, FaceId)> {
        self.handle.recv_side().await
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

    fn marked(n: u8) -> Bytes {
        Bytes::from(vec![
            ndn_transport::SIDE_MARKER,
            0x20,
            n,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ])
    }

    /// A marked frame the app sends reaches the face reader unchanged (where the engine peels it),
    /// and one the engine routes to the app comes back through `recv_side` with the face it
    /// arrived over, never through `recv`.
    #[tokio::test]
    async fn side_frames_go_out_to_the_face_reader_and_come_back_with_their_ingress() {
        let (face, handle) = InProcFace::new(FaceId(7), 4);
        let conn = InProcConnection::new(handle);
        assert_eq!(
            conn.side_frame_max(),
            ndn_transport::side_header::STREAM_FRAME_GRANT
        );
        conn.send_side(marked(1), SideClass::Datagram)
            .await
            .unwrap();
        conn.try_send_side(marked(2), SideClass::Stream).unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), marked(1));
        assert_eq!(face.recv_bytes().await.unwrap(), marked(2));

        face.forward_side_from(marked(3), SideClass::Datagram, FaceId(42))
            .unwrap();
        assert_eq!(conn.recv_side().await, Some((marked(3), FaceId(42))));
        let data = DataBuilder::new(ndn_packet::name!("/m/d"), b"x").sign_digest_sha256();
        face.send_bytes(data.clone()).await.unwrap();
        assert_eq!(conn.recv().await, Some(data), "NDN packets stay on recv");
    }

    /// What does not belong on the side path is refused before it is sent: an NDN packet (the
    /// marker decides), a frame over the limit; and a full queue is `Full`, with `side_ready`
    /// completing once the engine took a packet.
    #[tokio::test]
    async fn side_sends_refuse_ndn_packets_and_say_full_when_the_queue_is_full() {
        let (face, handle) = InProcFace::new(FaceId(7), 1);
        let conn = InProcConnection::new(handle);
        let ndn = DataBuilder::new(ndn_packet::name!("/m/d"), b"x").sign_digest_sha256();
        assert_eq!(
            conn.try_send_side(ndn.clone(), SideClass::Datagram),
            Err(SideRefused::Malformed)
        );
        assert!(matches!(
            conn.send_side(ndn, SideClass::Datagram).await,
            Err(AppError::Protocol(m)) if m.contains("not a side frame")
        ));
        let mut huge = vec![0u8; conn.side_frame_max() + 1];
        huge[0] = ndn_transport::SIDE_MARKER;
        assert!(matches!(
            conn.try_send_side(Bytes::from(huge), SideClass::Stream),
            Err(SideRefused::TooLarge { .. })
        ));
        conn.try_send_side(marked(1), SideClass::Datagram).unwrap();
        assert_eq!(
            conn.try_send_side(marked(2), SideClass::Datagram),
            Err(SideRefused::Full)
        );
        let waiting =
            tokio::time::timeout(std::time::Duration::from_millis(50), conn.side_ready()).await;
        assert!(waiting.is_err(), "no room yet");
        face.recv_bytes().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), conn.side_ready())
            .await
            .expect("room after the engine took one");
        conn.try_send_side(marked(2), SideClass::Datagram).unwrap();
    }

    /// A connection that does not reach a forwarder with a side table says so and what to do:
    /// nothing is faked, nothing is sent.
    #[tokio::test]
    async fn a_connection_that_carries_no_side_frames_refuses_and_names_the_next_step() {
        struct Plain;
        #[async_trait]
        impl Connection for Plain {
            async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
                Ok(())
            }
            async fn recv(&self) -> Option<Bytes> {
                None
            }
            async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
                Ok(())
            }
        }
        let conn = Plain;
        assert_eq!(conn.side_frame_max(), 0);
        assert!(matches!(
            conn.send_side(marked(1), SideClass::Datagram).await,
            Err(AppError::Unsupported(m)) if m.contains("app_face")
        ));
        assert_eq!(
            conn.try_send_side(marked(1), SideClass::Datagram),
            Err(SideRefused::NotCarried)
        );
        assert!(matches!(
            conn.side_quarantine(FaceId(3)).await,
            Err(AppError::Unsupported(m)) if m.contains("side/quarantine")
        ));
    }

    /// `send_with` puts the Data in an LpPacket that carries the headers, so the forwarder
    /// reads the route label (and the `NoCache`) off the wire.
    #[tokio::test]
    async fn send_with_wraps_the_data_with_the_headers() {
        use ndn_packet::lp::SideRoute;
        let (face, handle) = InProcFace::new(FaceId(7), 4);
        let conn = InProcConnection::new(handle);
        let data = DataBuilder::new(ndn_packet::name!("/m/d"), b"x").sign_digest_sha256();
        let headers = LpHeaders {
            cache_policy: Some(ndn_packet::CachePolicyType::NoCache),
            side_route: Some(SideRoute {
                id: 0x0102_0304_0506_0708,
                ttl_secs: 30,
            }),
            ..LpHeaders::default()
        };
        conn.send_with(data.clone(), headers).await.unwrap();
        let lp = LpPacket::decode(face.recv_bytes().await.unwrap()).unwrap();
        assert_eq!(
            lp.side_route,
            Some(SideRoute {
                id: 0x0102_0304_0506_0708,
                ttl_secs: 30
            })
        );
        assert_eq!(lp.fragment, Some(data));
    }

    /// A `DemuxConnection` (what a node's `connection()` is) hands the side calls to its
    /// connection, and its own `recv` is not where side frames appear.
    #[tokio::test]
    async fn a_demux_connection_carries_the_side_calls_of_the_connection_under_it() {
        let (face, handle) = InProcFace::new(FaceId(7), 4);
        let conn = crate::DemuxConnection::new(Arc::new(InProcConnection::new(handle)));
        assert_eq!(
            conn.side_frame_max(),
            ndn_transport::side_header::STREAM_FRAME_GRANT
        );
        conn.send_side(marked(1), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(face.recv_bytes().await.unwrap(), marked(1));
        face.forward_side_from(marked(2), SideClass::Stream, FaceId(9))
            .unwrap();
        assert_eq!(conn.recv_side().await, Some((marked(2), FaceId(9))));
    }

    /// An embedded engine's connection bars a face in the engine's side table (60 s the first
    /// time; a call while the bar is live names what is left, a repeat after it doubles), and
    /// NDN traffic is not part of it; a bare in-process connection, which knows no engine,
    /// refuses and says where to go.
    #[tokio::test]
    async fn an_engine_connection_bars_a_face_in_the_engines_side_table() {
        use crate::EngineAppExt;
        let (engine, _shutdown) = ndn_engine::EngineBuilder::new(Default::default())
            .build()
            .await
            .unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let conn = engine.app_face(cancel.child_token());
        let link = FaceId(4242);
        let (link_face, _link_handle) = InProcFace::new(link, 4);
        engine.add_face(link_face, cancel.child_token());
        let side = engine.side();
        assert!(!side.is_quarantined(link, side.now()));
        let first = conn.side_quarantine(link).await.unwrap();
        assert_eq!(first, std::time::Duration::from_secs(60));
        assert!(side.is_quarantined(link, side.now()));
        let live = conn.side_quarantine(link).await.unwrap();
        assert!(
            live <= std::time::Duration::from_secs(60) && live > std::time::Duration::from_secs(59),
            "a call while the bar is live names what is left of it: {live:?}"
        );
        side.lift(link);
        let second = conn.side_quarantine(link).await.unwrap();
        assert_eq!(
            second,
            std::time::Duration::from_secs(120),
            "a repeat after the bar ended doubles"
        );

        let (_face, handle) = InProcFace::new(FaceId(1), 4);
        assert!(matches!(
            InProcConnection::new(handle).side_quarantine(link).await,
            Err(AppError::Unsupported(m)) if m.contains("side/quarantine")
        ));
    }

    /// A face the engine does not hold is refused, and nothing is created for it: the id is
    /// the host's to choose, and a bar is state per face.
    #[tokio::test]
    async fn an_engine_connection_refuses_to_bar_a_face_the_engine_does_not_hold() {
        use crate::EngineAppExt;
        let (engine, _shutdown) = ndn_engine::EngineBuilder::new(Default::default())
            .build()
            .await
            .unwrap();
        let conn = engine.app_face(tokio_util::sync::CancellationToken::new());
        let gone = FaceId(4242);
        let refused = conn.side_quarantine(gone).await;
        assert!(
            matches!(&refused, Err(AppError::Unsupported(m)) if m.contains("4242")),
            "a face the engine does not hold was barred: {refused:?}"
        );
        assert!(engine.side().quarantined().is_empty());
        assert!(!engine.side().is_quarantined(gone, engine.side().now()));
    }
}
