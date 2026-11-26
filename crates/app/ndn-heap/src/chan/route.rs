//! A node on an in-process forwarder: its frames leave through the forwarder's side table and
//! the ones routed to it come back through the app face's side inbox (docs/specs/channel.md, The
//! forwarder's side table; SHAPES-CHANNEL.md §8).
//!
//! [`NodeHandle::attach_forwarder`] gives a node that serves and fetches over a [`Connection`]
//! reaching a forwarder (an embedded engine) everything stage 4 needs, over that one connection:
//!
//! * **The sender.** The session Data carries `SideRoute { id: channel id, ttl: SIDE_TTL }` (the
//!   answer goes out through `Responder::respond_bytes_with`), so each forwarder on its reverse
//!   path installs a route. Frames leave through a [`ConnectionCarrier`]: a datagram is
//!   `Connection::try_send_side`, a stream frame `Connection::send_side`, so the sender pays a
//!   queue push and the forwarder one lookup per hop. A stream frame (`HELLO`, a reliable
//!   channel's data) waits, at most [`ROUTE_WAIT`] and only for the channel's first one, until
//!   a receiver's first `UP Keep` came back through the forwarder: a marked frame is peeled in
//!   the face reader and can overtake the Data that is still in the pipeline installing the
//!   route, and a `Keep` that reached the sender proves that every hop holds the route. A channel
//!   that got none in that time sends no stream frame until one comes (**no route, no send**).
//!   A receiver asks over some face of the sender's forwarder; the sender asks the connection
//!   whether that face carries the stream ([`Connection::side_carries`]) and refuses a mode that
//!   needs one, `NoStream`, or answers a `Latest` ask with a session that offers none.
//! * **The receiver.** One task reads `Connection::recv_side` and hands each frame to the node
//!   ([`deliver_frame`](NodeHandle::deliver_frame), with the forwarder's face id as the ingress):
//!   the engine's face reader never calls it, so the wait of a blocked `Reliable` queue stalls
//!   this task, not the forwarder. The inbox is bounded and counts what it dropped.
//! * **Keep and Unsub.** Every [`KEEP_EVERY`] (10 s) the node sends an `UP Keep` for each session
//!   it holds, the first at once; the forwarder keeps the node's sink [`SIDE_TTL`] seconds after
//!   the last one. When the session ends, is replaced or is removed, and when the last `Items`
//!   that takes it is dropped (which ends the session), the node sends `UP Unsub` and no
//!   `Keep` follows.
//! * **No path.** A session that offers a stream and whose `HELLO` has not come [`NO_PATH_AFTER`]
//!   (2 s) after it was installed tells every `Items` that takes it `LiveEnded(NoPath)`: a
//!   forwarder between the two does not carry channel frames, or the first `Keep` or the session
//!   was lost or held up and the sender dropped its `HELLO` (the text says both: update, or ask
//!   again). A session that offers none (the first hop toward this node, judged by the sender,
//!   has no stream) is sent no `HELLO` and
//!   is told nothing.
//! * **The bar.** [`ConnectionBar`] asks the forwarder to bar a face
//!   (`Connection::side_quarantine`) when a frame that came over it was shown to be forged.
//!
//! A node that attached no forwarder does none of this: nothing is sent, kept or told.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection};
use ndn_foundation_types::Name;
use ndn_packet::lp::{LpHeaders, SideRoute};
use ndn_transport::side_header::{SideHeader, SideKind, UpOp, UpRecord};
use ndn_transport::{FaceId, SideClass, SideRefused};
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::bar::IngressBar;
use super::carrier::{Carrier, CarrierFuture, CarrierRefused};
use super::error::ChanError;
use super::items::Sink;
use super::sessions::{Asking, EndReason, RecvSession};
use super::verbs::LiveEnd;
use super::wire::ChannelMode;
use crate::error::HeapError;
use crate::host::NodeHandle;
use crate::node::NodeInner;
use crate::rt::{self, Instant};

/// How long (seconds) a forwarder keeps a sink after its last `Keep`: the `ttl` the session Data
/// carries in its `SideRoute`. The forwarder clamps it to its own maximum (300 s).
pub const SIDE_TTL: u16 = 30;

/// How often a receiver sends an `UP Keep` for a session it holds: a third of [`SIDE_TTL`],
/// so that two lost ones still leave the sink alive.
pub(crate) const KEEP_EVERY: Duration = Duration::from_secs(10);

/// How long after a session was installed its `HELLO` may take before the path is declared
/// missing.
pub(crate) const NO_PATH_AFTER: Duration = Duration::from_secs(2);

/// How long the stream frames of a channel wait for the `Keep` of a receiver just judged in
/// (below [`NO_PATH_AFTER`], so a receiver that waited is not yet told it has no path).
pub(crate) const ROUTE_WAIT: Duration = Duration::from_secs(1);

/// The largest datagram frame a `ConnectionCarrier` reports by default: what one QUIC
/// datagram carries at the smallest path MTU (the figure a session names in its answer),
/// because the sinks of a route may be links. A frame over what a sink takes is refused there
/// and counted, and a larger message goes on the stream instead. A host whose sinks are all
/// local may raise it ([`NodeHandle::attach_forwarder_with`]).
pub const DATAGRAM_FRAME_MAX: usize = 1_200;

/// The most channels whose first `Keep` a node remembers (the forwarder's own route limit).
const UP_CHANNELS_MAX: usize = 4096;

/// How many `Keep`s came back for a channel, and how many a receiver judged in is owed.
#[derive(Clone, Copy, Default)]
struct KeepCount {
    seen: u64,
    owed: u64,
}

/// What the sender side knows of the routes of its channels.
#[derive(Default)]
struct Upstream {
    chans: HashMap<u64, KeepCount>,
    /// Channels whose first stream frame waited [`ROUTE_WAIT`] in vain: none is sent until a
    /// `Keep` comes.
    waited_out: HashSet<u64>,
}

/// One held session's keeping.
struct Keeping {
    /// When the last `Keep` was sent; `None`: none yet.
    last: Option<Instant>,
    /// `NoPath` was told (or `HELLO` came): not told again.
    path_settled: bool,
}

/// What a node keeps of its forwarder routes.
#[derive(Default)]
pub(crate) struct Routes {
    conn: Mutex<Option<Arc<dyn Connection>>>,
    up: Mutex<Upstream>,
    keeping: Mutex<HashMap<u64, Keeping>>,
    /// A `Keep` came back for some channel.
    kept: Notify,
    /// Stream frames a carrier let go without a route.
    pub(crate) unrouted: super::hub::Counter,
    /// Keeps sent / Unsubs sent.
    pub(crate) keeps: super::hub::Counter,
    pub(crate) unsubs: super::hub::Counter,
}

impl Routes {
    /// Attach `conn`; `false` if one is attached already (nothing changed).
    fn attach(&self, conn: Arc<dyn Connection>) -> bool {
        let mut slot = self.conn.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(conn);
        true
    }

    fn conn(&self) -> Option<Arc<dyn Connection>> {
        self.conn.lock().clone()
    }

    /// Whether the first hop toward a receiver, the forwarder's face `face` that its ask came
    /// in over, carries the stream class ([`Connection::side_carries`]). `true` when no
    /// forwarder is attached (the node's carrier is a link of its own, and the ask's face is
    /// not where its frames go) or the connection cannot see the face.
    pub(crate) fn path_carries_stream(&self, face: FaceId) -> bool {
        self.conn()
            .is_none_or(|conn| conn.side_carries(face, SideClass::Stream))
    }

    /// A receiver's `Keep` for channel `id` reached this node: every hop holds its route.
    pub(super) fn note_keep(&self, id: u64) {
        {
            let mut up = self.up.lock();
            if up.chans.len() >= UP_CHANNELS_MAX && !up.chans.contains_key(&id) {
                return;
            }
            up.waited_out.remove(&id);
            up.chans.entry(id).or_default().seen += 1;
        }
        self.kept.notify_waiters();
    }

    /// A receiver of channel `id` was judged in and is being answered: the stream frames that
    /// follow its session wait for the next `Keep` (its own, which the forwarders pass on at
    /// once), for [`ROUTE_WAIT`] at most.
    pub(super) fn receiver_added(&self, id: u64) {
        let mut up = self.up.lock();
        if up.chans.len() >= UP_CHANNELS_MAX && !up.chans.contains_key(&id) {
            return;
        }
        let count = up.chans.entry(id).or_default();
        count.owed = count.owed.max(count.seen + 1);
    }

    /// Whether a stream frame of channel `id` may go now: a `Keep` came back for every receiver
    /// judged in, or it is waited for (at most [`ROUTE_WAIT`]). The wait that runs out for a
    /// channel that never got a `Keep` drops the frame, and every later one until a `Keep`
    /// comes (no route, no send); for a channel that had some it only stops waiting for that
    /// receiver, and the frame goes: the receivers that are routed need it.
    async fn gate(&self, id: u64) -> bool {
        let state = |up: &Upstream| {
            let count = up.chans.get(&id).copied().unwrap_or_default();
            if count.seen >= count.owed.max(1) {
                Some(true)
            } else if count.seen == 0 && up.waited_out.contains(&id) {
                Some(false)
            } else {
                None
            }
        };
        let wait = async {
            loop {
                let mut notified = std::pin::pin!(self.kept.notified());
                notified.as_mut().enable();
                if let Some(open) = state(&self.up.lock()) {
                    return open;
                }
                notified.await;
            }
        };
        match rt::timeout(ROUTE_WAIT, wait).await {
            Ok(open) => open,
            Err(_) => {
                let mut up = self.up.lock();
                let count = up.chans.entry(id).or_default();
                if count.seen > 0 {
                    count.owed = count.seen;
                    return true;
                }
                if up.waited_out.len() < UP_CHANNELS_MAX {
                    up.waited_out.insert(id);
                }
                false
            }
        }
    }
}

/// The id a channel frame names, if it has a header.
fn frame_id(frame: &Bytes) -> Option<u64> {
    SideHeader::parse(frame).ok().map(|h| h.id())
}

/// A node's way to send channel frames over its connection to a forwarder: the node's
/// [`Carrier`] ([`NodeHandle::attach_forwarder`]).
pub(crate) struct ConnectionCarrier {
    conn: Arc<dyn Connection>,
    routes: Arc<Routes>,
    datagram_max: usize,
    stream: bool,
    ready: Arc<Mutex<Ready>>,
}

/// The closures waiting for room, and whether the task that calls them runs.
#[derive(Default)]
struct Ready {
    waiting: Vec<Box<dyn FnOnce() + Send>>,
    running: bool,
}

impl ConnectionCarrier {
    pub(crate) fn new(
        conn: Arc<dyn Connection>,
        routes: Arc<Routes>,
        datagram_max: usize,
    ) -> ConnectionCarrier {
        let stream = conn.side_carries_here(SideClass::Stream);
        ConnectionCarrier {
            conn,
            routes,
            datagram_max,
            stream,
            ready: Arc::new(Mutex::new(Ready::default())),
        }
    }
}

fn refused(e: SideRefused, max: usize) -> CarrierRefused {
    match e {
        SideRefused::Full => CarrierRefused::Full,
        SideRefused::TooLarge { max, .. } => CarrierRefused::TooLarge { max },
        SideRefused::Closed | SideRefused::NotCarried | SideRefused::Unsupported => {
            CarrierRefused::Closed
        }
        SideRefused::Malformed | SideRefused::PeerLacksChannels | SideRefused::Io(_) => {
            CarrierRefused::TooLarge { max }
        }
    }
}

impl Carrier for ConnectionCarrier {
    fn datagram_max(&self) -> usize {
        self.conn.side_frame_max().min(self.datagram_max)
    }

    /// Whether the node's own face on its forwarder carries the stream class (read once: it is
    /// a fact about the face's medium). The hop toward each receiver is judged when the
    /// receiver asks ([`Routes::path_carries_stream`]), and a receiver behind a hop with no
    /// stream is given a session that offers none.
    fn has_stream(&self) -> bool {
        self.stream
    }

    fn stream_frame_max(&self) -> usize {
        self.conn.side_frame_max()
    }

    fn try_send_datagram(&self, frame: Bytes) -> Result<(), CarrierRefused> {
        self.conn
            .try_send_side(frame, SideClass::Datagram)
            .map_err(|e| refused(e, self.conn.side_frame_max()))
    }

    fn send_stream(&self, frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>> {
        Box::pin(async move {
            if let Some(id) = frame_id(&frame)
                && !self.routes.gate(id).await
            {
                // No receiver's `Keep` came: nothing is sent, and the sender is told nothing
                // went wrong, as a datagram a link dropped is no error.
                self.routes.unrouted.bump();
                return Ok(());
            }
            self.conn
                .send_side(frame, SideClass::Stream)
                .await
                .map_err(|e| match e {
                    AppError::Closed => CarrierRefused::Closed,
                    _ => CarrierRefused::TooLarge {
                        max: self.conn.side_frame_max(),
                    },
                })
        })
    }

    fn receiver_added(&self, channel: u64) {
        self.routes.receiver_added(channel);
    }

    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>) {
        let mut ready = self.ready.lock();
        ready.waiting.push(drain);
        if ready.running {
            return;
        }
        ready.running = true;
        drop(ready);
        let (conn, state) = (Arc::clone(&self.conn), Arc::clone(&self.ready));
        rt::spawn(async move {
            loop {
                conn.side_ready().await;
                let batch = std::mem::take(&mut state.lock().waiting);
                for drain in batch {
                    drain();
                }
                let mut ready = state.lock();
                if ready.waiting.is_empty() {
                    ready.running = false;
                    return;
                }
            }
        });
    }
}

/// [`IngressBar`] over a connection: the bar is the forwarder's quarantine of the face
/// ([`Connection::side_quarantine`]), asked in a task of its own because a bar never blocks. The
/// outcome is the answer's: the face is barred for the time the forwarder says, or it is not and
/// the log says why (the connection's own face, which is never barred; a face the forwarder does
/// not hold; a connection that cannot ask its forwarder).
pub(crate) struct ConnectionBar {
    conn: Arc<dyn Connection>,
}

impl IngressBar for ConnectionBar {
    fn bar(&self, ingress: u64) {
        let face = ingress;
        let conn = Arc::clone(&self.conn);
        rt::spawn(async move {
            match conn.side_quarantine(FaceId(face)).await {
                Ok(length) => tracing::warn!(
                    face,
                    barred_secs = length.as_secs(),
                    "a face delivered a forged channel frame: the forwarder barred it from channel \
                     frames (barred for {} s from now at most: NDN traffic over it is untouched)",
                    length.as_secs()
                ),
                Err(e) => tracing::warn!(
                    face,
                    "a face delivered a forged channel frame and could NOT be barred, so channel \
                     frames still come over it: {e}; bar that link at the forwarder \
                     (`side/quarantine`) if it should be"
                ),
            }
        });
    }
}

/// The `Keep` or `Unsub` record of channel `id`.
fn up_frame(id: u64, op: UpOp) -> Bytes {
    Bytes::copy_from_slice(&UpRecord { id, op }.encode())
}

impl NodeInner {
    /// One frame the forwarder routed to this node's app face.
    async fn chan_side_frame(&self, frame: Bytes, ingress: FaceId) {
        // The forwarder's own maintenance record: a receiver's `Keep` came back for the id.
        if let Ok(header) = SideHeader::parse(&frame)
            && header.kind() == SideKind::Up
        {
            if let Ok(UpRecord { id, op: UpOp::Keep }) = UpRecord::parse(&frame) {
                self.chan.route.note_keep(id);
            }
            return;
        }
        self.chan_deliver(frame, ingress.0, Instant::now()).await;
    }

    /// The first `Keep` of a session just installed, at once (the sender holds its stream frames
    /// until it arrives); the maintenance pass sends the rest.
    pub(crate) fn chan_route_installed(&self, session: &RecvSession) {
        let routes = &self.chan.route;
        let Some(conn) = routes.conn() else { return };
        let mut keeping = routes.keeping.lock();
        let entry = keeping.entry(session.id()).or_insert(Keeping {
            last: None,
            path_settled: false,
        });
        if entry.last.is_none()
            && conn
                .try_send_side(up_frame(session.id(), UpOp::Keep), SideClass::Datagram)
                .is_ok()
        {
            entry.last = Some(Instant::now());
            routes.keeps.bump();
        }
    }

    /// `sink`, an `Items`, was dropped: each session it took that no other `Items` takes lapses
    /// (ended as [`EndReason::Left`] and dropped), its `Unsub` goes upstream at once, and no
    /// `Keep` follows. Does nothing on a node that attached no forwarder. A later `live` over
    /// the same sender needs a new ask, which brings a new route.
    pub(crate) fn chan_route_release(&self, sink: &Sink) {
        if self.chan.route.conn().is_none() {
            return;
        }
        // The channel is let go for every ask that began before: its answer installs nothing.
        for mode in ChannelMode::ALL {
            if sink.takes(&sink.space, mode) && !self.chan.rx.wanted(&sink.space, mode) {
                self.chan.sessions.released(&sink.space, mode);
            }
        }
        for session in self.chan.sessions.all() {
            let (space, mode) = (session.space(), session.mode());
            if sink.takes(space, mode) && !self.chan.rx.wanted(space, mode) {
                self.chan_let_go(&session);
            }
        }
        self.chan_route_tick(Instant::now());
    }

    /// The answer to an ask that began before the channel was let go is discarded
    /// ([`ChanError::Superseded`]); the route it laid at the forwarders on its way here is given
    /// up with an `Unsub`, unless another ask of the channel is on its way (its answer lays the
    /// route again and an `Unsub` now could take that one) or a session holds the channel. The
    /// `Unsub` is best effort: a route left standing lapses at its TTL, and nothing the receiver
    /// does next depends on it.
    pub(crate) fn chan_route_abandon(
        &self,
        id: u64,
        sender: &Name,
        asking: &Asking<'_>,
    ) -> ChanError {
        let routes = &self.chan.route;
        if let Some(conn) = routes.conn()
            && asking.alone()
            && self.chan.sessions.get(id).is_none()
            && conn
                .try_send_side(up_frame(id, UpOp::Unsub), SideClass::Datagram)
                .is_ok()
        {
            routes.unsubs.bump();
        }
        ChanError::Superseded {
            sender: sender.clone(),
        }
    }

    /// An announce-driven ask (one that began after the last `Items` was dropped, since one that
    /// began before is stale, [`Asking`](super::sessions::Asking)) installed a session that no
    /// `Items` takes: it is let go as [`Self::chan_route_release`] lets one go. Left held, it
    /// would be a session nobody takes, with its route and `Keep` entry standing, and the next
    /// ask of that sender would be made as a renewal (no `ASK_NEW`), so the sender would send no
    /// `HELLO`.
    pub(crate) fn chan_release_unwanted(&self, session: &RecvSession) {
        if self.chan.route.conn().is_none() || self.chan.rx.wanted(session.space(), session.mode())
        {
            return;
        }
        self.chan_let_go(session);
        self.chan_route_tick(Instant::now());
    }

    /// End `session` as left and drop it; nobody is told it ended, since an `Items` made later has
    /// not seen the session it would be told of.
    fn chan_let_go(&self, session: &RecvSession) {
        session.end(EndReason::Left);
        self.chan.sessions.remove(session.id());
        self.chan.rx.release_channel(session.id());
    }

    /// The route maintenance of one pass of the node's task at `now`: `Keep`s due, the `Unsub`
    /// of every session that is gone, `NoPath`.
    pub(crate) fn chan_route_tick(&self, now: Instant) {
        let routes = &self.chan.route;
        let Some(conn) = routes.conn() else { return };
        let sessions = self.chan.sessions.all();
        let mut keeping = routes.keeping.lock();
        let mut told = Vec::new();
        for session in &sessions {
            let id = session.id();
            if session.ended().is_some() {
                continue;
            }
            let entry = keeping.entry(id).or_insert(Keeping {
                last: None,
                path_settled: false,
            });
            let wanted = self.chan.rx.wanted(session.space(), session.mode());
            if entry
                .last
                .is_none_or(|at| now.saturating_duration_since(at) >= KEEP_EVERY)
                && conn
                    .try_send_side(up_frame(id, UpOp::Keep), SideClass::Datagram)
                    .is_ok()
            {
                entry.last = Some(now);
                routes.keeps.bump();
            }
            if !entry.path_settled {
                // A session that offers no stream is sent no `HELLO` (the path from the sender
                // carries datagrams only): there is nothing to wait for, and a quiet sender is
                // not a missing path.
                if self.chan.rx.path_seen(id) || !session.offers_stream() {
                    entry.path_settled = true;
                } else if now.saturating_duration_since(session.installed()) >= NO_PATH_AFTER
                    && wanted
                {
                    entry.path_settled = true;
                    told.push((
                        session.space().clone(),
                        session.mode(),
                        id,
                        session.sender().clone(),
                    ));
                }
            }
        }
        // Every session that is gone: one `Unsub`, retried while the connection has no room.
        let held: HashSet<u64> = self
            .chan
            .sessions
            .all()
            .iter()
            .filter(|s| s.ended().is_none())
            .map(|s| s.id())
            .collect();
        keeping.retain(|id, _| {
            if held.contains(id) {
                return true;
            }
            match conn.try_send_side(up_frame(*id, UpOp::Unsub), SideClass::Datagram) {
                Err(SideRefused::Full) => true,
                Ok(()) => {
                    routes.unsubs.bump();
                    false
                }
                Err(_) => false,
            }
        });
        drop(keeping);
        for (space, mode, id, sender) in told {
            self.chan
                .rx
                .tell_no_path(&space, mode, id, no_path(&sender, id));
        }
    }
}

/// What `LiveEnded(NoPath)` says: why, and what to do. Two causes end here and the device cannot
/// tell them apart: a forwarder that does not carry channel frames (update it), and a first
/// `Keep` of this device, or the session itself, lost or held up past the sender's wait for it
/// (the sender then dropped its `HELLO`: ask again).
fn no_path(sender: &Name, id: u64) -> String {
    format!(
        "no frame of {sender}'s channel {id:016x} reached this device within {} s of its session: \
         either a forwarder between you and the sender does not carry channel frames: update it; \
         or this device's first Keep or the session was lost or held up on the way (loss or \
         delay), so the sender dropped its first frame: ask again",
        NO_PATH_AFTER.as_secs()
    )
}

impl LiveEnd {
    /// What the caller can do about the end, in the heap's vocabulary: a missing path is a
    /// forwarder to update ([`NextStep::FixLocal`](crate::error::NextStep::FixLocal)); a session
    /// that ended is a fact, and asking again is the caller's choice.
    pub fn next(&self) -> crate::error::NextStep {
        match self {
            LiveEnd::NoPath { .. } => crate::error::NextStep::FixLocal,
            LiveEnd::Ended { .. } => crate::error::NextStep::RetryLater,
        }
    }
}

impl NodeHandle {
    /// Run this node's channels through its connection's forwarder: the session Data carries the
    /// route label, frames leave through the forwarder's side table and the ones routed to the
    /// node come back through the app face (see the module docs of the channel routes). Needs a connection
    /// that carries side frames (an embedded engine's `app_face`); with `datagram_max`
    /// [`DATAGRAM_FRAME_MAX`]. Calling it again changes nothing.
    ///
    /// # Errors
    ///
    /// [`HeapError::Local`]: the connection carries no side frames; the reason names what to
    /// use instead.
    pub fn attach_forwarder(&self) -> Result<(), HeapError> {
        self.attach_forwarder_with(DATAGRAM_FRAME_MAX)
    }

    /// [`attach_forwarder`](Self::attach_forwarder) with the largest datagram frame the sinks of
    /// the node's routes take: [`DATAGRAM_FRAME_MAX`] when any is a QUIC link, up to the
    /// channel's own 9,000 when all are local.
    pub fn attach_forwarder_with(&self, datagram_max: usize) -> Result<(), HeapError> {
        let inner = &self.inner;
        let conn = Arc::clone(&inner.conn);
        if conn.side_frame_max() == 0 {
            return Err(HeapError::local(
                "this node's connection carries no channel frames: it does not reach a forwarder \
                 that routes them; start the node over `EngineAppExt::app_face` of an embedded \
                 engine, or use `attach_carrier` for a link of your own",
            ));
        }
        if !inner.chan.route.attach(Arc::clone(&conn)) {
            return Ok(());
        }
        let routes = Arc::clone(&inner.chan.route);
        inner.chan.tx.carrier.set(Arc::new(ConnectionCarrier::new(
            Arc::clone(&conn),
            routes,
            datagram_max,
        )));
        self.attach_bar(Arc::new(ConnectionBar {
            conn: Arc::clone(&conn),
        }));
        let node: Weak<NodeInner> = Arc::downgrade(inner);
        inner.tasks.spawn(async move {
            while let Some((frame, ingress)) = conn.recv_side().await {
                let Some(inner) = node.upgrade() else { return };
                inner.chan_side_frame(frame, ingress).await;
            }
        });
        Ok(())
    }
}

/// The LP headers the setup answer goes out with: never cached, and the route label of the
/// channel `id`.
pub(crate) fn setup_headers(id: Option<u64>) -> LpHeaders {
    LpHeaders {
        cache_policy: Some(ndn_packet::CachePolicyType::NoCache),
        side_route: id.map(|id| SideRoute {
            id,
            ttl_secs: SIDE_TTL,
        }),
        ..LpHeaders::default()
    }
}
