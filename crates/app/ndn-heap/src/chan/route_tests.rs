//! Stage 4 in the heap: nodes on one real forwarder whose side table routes their channel frames
//! (docs/specs/channel.md, The forwarder's side table): the session Data carries the route label,
//! frames leave through the sender's app face and come back through the receivers', a receiver
//! keeps and ends its route, a path that does not carry frames is told, a forged frame bars its
//! link.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt, LpInfo};
use ndn_engine::side::SideId;
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_foundation_types::Name;
use ndn_packet::lp::{LpHeaders, LpPacket, encode_lp_with_headers, is_lp_packet};
use ndn_runtime::{BoxFuture, Instant as RtInstant, Now, Runtime, Sleep, Spawn, TokioRuntime};
use ndn_transport::side_header::{SideHeader, SideKind};
use ndn_transport::{FaceId, SideClass, SideRefused};
use tokio_util::sync::CancellationToken;

use super::carrier::{Carrier, CarrierRefused};
use super::items::Items;
use super::route::{ConnectionCarrier, DATAGRAM_FRAME_MAX, NO_PATH_AFTER, ROUTE_WAIT, Routes};
use super::rx_tests::eventually;
use super::standing::{Who, gate};
use super::verbs::{EmitOptions, GetNotice, GetOptions, Got, LiveEnd, Select};
use crate::error::NextStep;
use crate::fold::Readers;
use crate::node::tests::{Dev, cfg, space, world};
use crate::node::{Config, Node, Transport};
use crate::rt::Instant;
use crate::space::{MembersChange, Share};
use crate::test_kit::n;

/// An engine clock that a test moves: real time plus an offset.
#[derive(Default)]
struct Offset(AtomicU64);

impl Spawn for Offset {
    fn spawn(&self, fut: BoxFuture) {
        TokioRuntime.spawn(fut);
    }
}
impl Sleep for Offset {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        TokioRuntime.sleep(dur)
    }
}
impl Now for Offset {
    fn now(&self) -> RtInstant {
        TokioRuntime.now()
    }
    fn unix_nanos(&self) -> u64 {
        TokioRuntime.unix_nanos() + self.0.load(Ordering::Relaxed)
    }
}
impl Runtime for Offset {}

/// A node's connection, with switches: it strips the route label off what it sends (the
/// forwarder between that predates the header), cuts every side frame (a receiver that cannot or
/// will not send `Keep` or `Unsub`), carries no side frames at all, or says that its own face
/// (`no_stream_here`) or the first hop toward each receiver (`no_stream_hop`) has no stream.
struct Switch {
    inner: Arc<dyn Connection>,
    strip: AtomicBool,
    cut: AtomicBool,
    no_side: AtomicBool,
    no_stream_hop: AtomicBool,
    no_stream_here: AtomicBool,
}

impl Switch {
    fn new(inner: Arc<dyn Connection>) -> Arc<Switch> {
        Arc::new(Switch {
            inner,
            strip: AtomicBool::new(false),
            cut: AtomicBool::new(false),
            no_side: AtomicBool::new(false),
            no_stream_hop: AtomicBool::new(false),
            no_stream_here: AtomicBool::new(false),
        })
    }
}

/// `wire` without a route label, as a forwarder that predates the header passes it on.
fn without_route(wire: Bytes) -> Bytes {
    if is_lp_packet(&wire)
        && let Ok(lp) = LpPacket::decode(wire.clone())
        && lp.side_route.is_some()
        && let Some(fragment) = lp.fragment
    {
        return encode_lp_with_headers(
            &fragment,
            &LpHeaders {
                cache_policy: Some(ndn_packet::CachePolicyType::NoCache),
                ..LpHeaders::default()
            },
        );
    }
    wire
}

#[async_trait]
impl Connection for Switch {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let wire = if self.strip.load(Ordering::SeqCst) {
            without_route(wire)
        } else {
            wire
        };
        self.inner.send(wire).await
    }
    async fn recv(&self) -> Option<Bytes> {
        self.inner.recv().await
    }
    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        self.inner.recv_with_meta().await
    }
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.inner.register_prefix(prefix).await
    }
    fn side_frame_max(&self) -> usize {
        if self.no_side.load(Ordering::SeqCst) {
            0
        } else {
            self.inner.side_frame_max()
        }
    }
    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), AppError> {
        if self.cut.load(Ordering::SeqCst) {
            return Err(AppError::Closed);
        }
        self.inner.send_side(frame, class).await
    }
    fn try_send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        if self.cut.load(Ordering::SeqCst) {
            return Err(SideRefused::Closed);
        }
        self.inner.try_send_side(frame, class)
    }
    async fn side_ready(&self) {
        self.inner.side_ready().await;
    }
    async fn recv_side(&self) -> Option<(Bytes, FaceId)> {
        self.inner.recv_side().await
    }
    async fn side_quarantine(&self, face: FaceId) -> Result<Duration, AppError> {
        self.inner.side_quarantine(face).await
    }
    /// What the engine's faces say, unless `no_stream_hop` says the first hop toward every
    /// receiver is an Ethernet segment: datagrams only.
    fn side_carries(&self, face: FaceId, class: SideClass) -> bool {
        if class == SideClass::Stream && self.no_stream_hop.load(Ordering::SeqCst) {
            return false;
        }
        self.inner.side_carries(face, class)
    }
    /// What this connection's own face says, unless `no_stream_here` says it has none.
    fn side_carries_here(&self, class: SideClass) -> bool {
        if class == SideClass::Stream && self.no_stream_here.load(Ordering::SeqCst) {
            return false;
        }
        self.inner.side_carries_here(class)
    }
}

fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

struct Rig {
    engine: ForwarderEngine,
    offset: Arc<Offset>,
    nodes: Vec<Node>,
    links: Vec<Arc<Switch>>,
    cancel: CancellationToken,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Rig {
    fn alice(&self) -> &Node {
        &self.nodes[0]
    }
    fn bob(&self) -> &Node {
        &self.nodes[1]
    }
    fn carol(&self) -> &Node {
        &self.nodes[2]
    }
    fn dave(&self) -> &Node {
        &self.nodes[3]
    }
    /// Move the engine's clock on by `by`.
    fn advance(&self, by: Duration) {
        self.offset
            .0
            .fetch_add(by.as_nanos() as u64, Ordering::SeqCst);
    }
    fn sinks(&self, channel: u64) -> usize {
        self.engine.side().sinks(SideId(channel))
    }
}

/// Alice (the owner), bob (the writer), carol and dave (readers) on one engine; every node's
/// forwarder attached if `attach`.
async fn rig(attach: bool) -> Rig {
    let devs: Vec<Dev> = world(&[
        "/alice/laptop",
        "/bob/phone",
        "/carol/tablet",
        "/dave/watch",
    ])
    .await;
    let offset = Arc::new(Offset::default());
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .runtime(Arc::clone(&offset) as Arc<dyn Runtime>)
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    for dev in &devs {
        let ns = Name::from_components(dev.name.components()[..1].iter().cloned());
        ndn_namespace::sync_group::carry(&engine, &ns);
    }
    let cancel = CancellationToken::new();
    let (mut nodes, mut links) = (Vec::new(), Vec::new());
    for dev in &devs {
        let sync = engine.app_face(cancel.child_token());
        let link = Switch::new(engine.app_face(cancel.child_token()));
        links.push(Arc::clone(&link));
        let node = Node::start(
            Transport {
                node: ndn_app::Node::from_connection(link as Arc<dyn Connection>),
                sync,
            },
            dev.name.clone(),
            Arc::clone(&dev.keys),
            Arc::clone(&dev.validator),
            Arc::clone(&dev.store),
            fast(),
        )
        .await
        .expect("the node starts");
        if attach {
            node.attach_forwarder()
                .expect("the engine's face carries channel frames");
        }
        nodes.push(node);
    }
    let rig = Rig {
        engine,
        offset,
        nodes,
        links,
        cancel,
    };
    shared(&rig).await;
    rig
}

fn ready(node: &Node) -> bool {
    node.inner.space_of(&space()).is_some_and(|held| {
        let log = held.log.lock();
        gate(&log, &node.inner.judge, Who::Listed, "test").is_ok()
            && (!log.sealed() || log.fold.in_force().is_some())
    })
}

/// A sealed space owned by alice, written by bob, read by carol and dave.
async fn shared(rig: &Rig) {
    let share = Share {
        readers: Readers::Persons(vec![n("/bob"), n("/carol"), n("/dave")]),
        writers: vec![n("/bob")],
    };
    rig.alice().create(&space(), share).await.unwrap();
    for node in &rig.nodes[1..] {
        node.open(&space()).await.unwrap();
    }
    eventually("the nodes hold the record", || {
        rig.nodes
            .iter()
            .filter(|n| n.space(&space()).is_some())
            .all(ready)
    })
    .await;
}

fn live(node: &Node) -> Items {
    node.space(&space())
        .unwrap()
        .live(Select::Prefix(Name::root()), GetOptions::default())
        .expect("a member")
}

async fn next(items: &mut Items) -> Result<Got, GetNotice> {
    tokio::time::timeout(Duration::from_secs(10), items.next())
        .await
        .expect("an item within 10 s")
        .expect("the stream is open")
}

async fn emit(node: &Node, path: &str, bytes: &'static [u8]) {
    node.space(&space())
        .unwrap()
        .emit(&n(path), Bytes::from_static(bytes), EmitOptions::latest())
        .await
        .expect("bob is a writer");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_data_reaches_the_receiver_with_its_route_and_frames_then_flow_through_the_forwarder()
 {
    let rig = rig(true).await;
    let mut items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .expect("bob answers");

    // The Data that answered carried the label: the engine holds the route, and carol's app face
    // is its one sink.
    assert_eq!(rig.sinks(info.channel), 1);
    let routes = rig.engine.side().list();
    let route = routes
        .iter()
        .find(|r| r.id == info.channel)
        .expect("the route");
    assert_eq!(route.sinks.len(), 1);

    // `HELLO` came down the stream through the forwarder: the path works. (It is held back at the
    // sender until carol's first `Keep` came back through every hop, so it cannot overtake the
    // Data that installs the route.)
    eventually("HELLO", || items.hello_seen()).await;
    // A pass after the `HELLO` says nothing of a path.
    rig.carol()
        .inner
        .chan_route_tick(Instant::now() + 3 * NO_PATH_AFTER);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), items.next())
            .await
            .is_err(),
        "a path that works is no `NoPath`"
    );

    emit(rig.bob(), "/a", b"x").await;
    let got = next(&mut items).await.expect("an item");
    assert_eq!(got.path.to_string(), "/a");
    assert_eq!(&got.bytes[..], b"x");
    assert_eq!(&got.writer, rig.bob().name());
    assert!(
        rig.engine.side().stats().frames_out >= 2,
        "HELLO and the emission"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_receivers_on_one_forwarder_each_get_the_frame_and_the_sender_sent_one_frame() {
    let rig = rig(true).await;
    let (mut carol, mut dave) = (live(rig.carol()), live(rig.dave()));
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    let again = rig
        .dave()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    assert_eq!(info.channel, again.channel, "one channel, two receivers");
    assert_eq!(rig.sinks(info.channel), 2);
    eventually("HELLO at both", || carol.hello_seen() && dave.hello_seen()).await;

    let tx = &rig.bob().inner.chan.tx.stats;
    let sent = tx.datagram_frames.get();
    let before = rig.engine.side().stats();
    let (out, frames_in) = (before.frames_out, before.frames_in);
    emit(rig.bob(), "/a", b"once").await;
    for items in [&mut carol, &mut dave] {
        let got = next(items).await.expect("an item");
        assert_eq!(&got.bytes[..], b"once");
    }
    assert_eq!(
        tx.datagram_frames.get() - sent,
        1,
        "the sender handed its forwarder one frame, not one per receiver"
    );
    // The forwarder copied every frame that came in (the emission, and the checkpoint that follows
    // it) to each of the two sinks, and to nothing else.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let stats = rig.engine.side().stats();
    let came_in = stats.frames_in - frames_in;
    assert!(came_in >= 1);
    assert_eq!(stats.frames_out - out, 2 * came_in);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_items_sends_unsub_and_the_route_goes() {
    let rig = rig(true).await;
    let items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    assert_eq!(rig.sinks(info.channel), 1);
    assert!(rig.carol().inner.chan.sessions.get(info.channel).is_some());

    drop(items);
    eventually("the route is gone", || rig.sinks(info.channel) == 0).await;
    assert!(
        rig.carol().inner.chan.sessions.get(info.channel).is_none(),
        "the session lapsed with its last taker"
    );
    assert_eq!(
        rig.carol().inner.chan.route.unsubs.get(),
        1,
        "one Unsub, once"
    );
    let stats = rig.engine.side().stats();
    assert_eq!(stats.unsubs, 1);
    assert_eq!(stats.sinks_lapsed, 0, "it did not wait for the ttl");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keep_refreshes_the_route_past_its_ttl() {
    let rig = rig(true).await;
    let items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    eventually("HELLO", || items.hello_seen()).await;
    let carol = &rig.carol().inner;
    // Only this test's passes move the maintenance.
    carol.chan.tick_paused.store(true, Ordering::SeqCst);
    let kept = rig.engine.side().stats().keeps;
    assert!(kept >= 1, "the first Keep went out at install");

    // 5 s on: no Keep is due (every 10 s), so none is sent.
    rig.advance(Duration::from_secs(5));
    carol.chan_route_tick(Instant::now() + Duration::from_secs(5));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rig.engine.side().stats().keeps, kept);

    // 25 s on: a Keep is due, the forwarder refreshes the sink to 25 s + the 30 s ttl.
    rig.advance(Duration::from_secs(20));
    carol.chan_route_tick(Instant::now() + Duration::from_secs(25));
    eventually("the Keep reached the forwarder", || {
        rig.engine.side().stats().keeps > kept
    })
    .await;

    // 40 s on is past the ttl of the first Keep (30 s): the sink stands because of the second.
    rig.advance(Duration::from_secs(15));
    rig.engine.side().sweep(rig.engine.side().now());
    assert_eq!(rig.sinks(info.channel), 1, "kept past its ttl");

    // No more Keeps: 31 s after the last one the sink lapses and the route goes with it.
    rig.advance(Duration::from_secs(31));
    rig.engine.side().sweep(rig.engine.side().now());
    assert_eq!(rig.sinks(info.channel), 0, "lapsed without a Keep");
    assert!(rig.engine.side().stats().sinks_lapsed >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarder_without_the_header_leaves_no_path_and_the_receiver_says_which_next_step() {
    let rig = rig(true).await;
    // Bob's Data reaches the forwarders without the label, as it does past one that predates it.
    rig.links[1].strip.store(true, Ordering::SeqCst);
    let mut items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    assert_eq!(rig.sinks(info.channel), 0, "nothing installed the route");
    rig.carol()
        .inner
        .chan
        .tick_paused
        .store(true, Ordering::SeqCst);

    // Before 2 s it is early, not a missing path.
    rig.carol()
        .inner
        .chan_route_tick(Instant::now() + NO_PATH_AFTER / 2);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), items.next())
            .await
            .is_err()
    );
    // Past 2 s with no `HELLO`: the `Items` is told, with the step.
    rig.carol()
        .inner
        .chan_route_tick(Instant::now() + NO_PATH_AFTER + Duration::from_millis(50));
    let GetNotice::LiveEnded(end) = next(&mut items).await.unwrap_err() else {
        panic!("a notice");
    };
    let LiveEnd::NoPath { why } = &end else {
        panic!("{end:?}");
    };
    assert!(
        why.contains(
            "a forwarder between you and the sender does not carry channel frames: update it"
        ),
        "{why}"
    );
    assert_eq!(end.next(), NextStep::FixLocal);
    assert!(!items.hello_seen());
    // Said once.
    rig.carol()
        .inner
        .chan_route_tick(Instant::now() + 2 * NO_PATH_AFTER);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), items.next())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_receivers_keeps_stop_and_its_route_lapses() {
    let rig = rig(true).await;
    let items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    eventually("HELLO", || items.hello_seen()).await;
    assert_eq!(rig.sinks(info.channel), 1);
    // Carol sends nothing from here on: she is the member who cannot, or will not, say `Unsub`.
    rig.links[2].cut.store(true, Ordering::SeqCst);

    rig.alice()
        .space(&space())
        .unwrap()
        .change(MembersChange {
            remove: vec![n("/carol")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol's node drops the session", || {
        rig.carol().inner.chan.sessions.get(info.channel).is_none()
    })
    .await;

    // A pass long after: nothing is held, so no `Keep` is made (`keeps` counts those sent).
    let sent = rig.carol().inner.chan.route.keeps.get();
    rig.carol()
        .inner
        .chan
        .tick_paused
        .store(true, Ordering::SeqCst);
    rig.carol()
        .inner
        .chan_route_tick(Instant::now() + Duration::from_secs(25));
    assert_eq!(
        rig.carol().inner.chan.route.keeps.get(),
        sent,
        "no Keep after the removal"
    );
    // And the route lapses at its ttl.
    rig.advance(Duration::from_secs(31));
    rig.engine.side().sweep(rig.engine.side().now());
    assert_eq!(rig.sinks(info.channel), 0);
    assert!(rig.engine.side().stats().sinks_lapsed >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bar_call_reaches_the_forwarders_side_table() {
    let rig = rig(true).await;
    let bar = rig
        .carol()
        .inner
        .chan
        .bar
        .get()
        .expect("attaching the forwarder attached the bar");
    let side = rig.engine.side();
    let link = FaceId(4_242);
    assert!(!side.is_quarantined(link, side.now()));
    bar.bar(link.0);
    eventually("the face is barred", || {
        side.is_quarantined(link, side.now())
    })
    .await;
    // The bar is the table's doubling: the next one on the same face is twice as long.
    assert_eq!(side.bar(link, side.now()), Duration::from_secs(120));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_carries_no_side_frames_is_refused_with_the_next_step() {
    let rig = rig(false).await;
    rig.links[2].no_side.store(true, Ordering::SeqCst);
    let refused = rig.carol().attach_forwarder().unwrap_err();
    let text = refused.to_string();
    assert!(
        text.contains("carries no channel frames") && text.contains("app_face"),
        "{text}"
    );
    // Nothing was attached: no carrier, no bar.
    assert!(rig.carol().inner.chan.bar.get().is_none());
    assert!(rig.carol().inner.chan.tx.carrier.get().is_none());
}

/// A connection that records what it is given, for the carrier on its own.
struct Rec {
    sent: parking_lot::Mutex<Vec<Bytes>>,
}

#[async_trait]
impl Connection for Rec {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        None
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
    fn side_frame_max(&self) -> usize {
        100_000
    }
    async fn send_side(&self, frame: Bytes, _class: SideClass) -> Result<(), AppError> {
        self.sent.lock().push(frame);
        Ok(())
    }
}

fn frame_of(id: u64) -> Bytes {
    let mut v = SideHeader::new(SideClass::Stream, SideKind::Data, id)
        .unwrap()
        .encode()
        .to_vec();
    v.resize(64, 0);
    Bytes::from(v)
}

#[tokio::test(start_paused = true)]
async fn a_stream_frame_waits_for_the_first_keep_and_a_channel_that_got_none_sends_none() {
    let conn = Arc::new(Rec {
        sent: Default::default(),
    });
    let routes = Arc::new(Routes::default());
    let carrier = Arc::new(ConnectionCarrier::new(
        Arc::clone(&conn) as Arc<dyn Connection>,
        Arc::clone(&routes),
        DATAGRAM_FRAME_MAX,
    ));

    // A `Keep` for channel 7 arrives while the first frame waits: the frame goes.
    let waiting = tokio::spawn({
        let carrier = Arc::clone(&carrier);
        async move { carrier.send_stream(frame_of(7)).await }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(conn.sent.lock().is_empty(), "held until a Keep");
    routes.note_keep(7);
    waiting.await.unwrap().unwrap();
    assert_eq!(conn.sent.lock().len(), 1);
    carrier.send_stream(frame_of(7)).await.unwrap();
    assert_eq!(
        conn.sent.lock().len(),
        2,
        "later frames of a kept channel go at once"
    );

    // Channel 8 never gets one: the first frame waits `ROUTE_WAIT`, is dropped and counted, and
    // the next is dropped without waiting.
    let started = tokio::time::Instant::now();
    carrier.send_stream(frame_of(8)).await.unwrap();
    assert!(started.elapsed() >= ROUTE_WAIT);
    carrier.send_stream(frame_of(8)).await.unwrap();
    assert!(started.elapsed() < ROUTE_WAIT + Duration::from_millis(10));
    assert_eq!(conn.sent.lock().len(), 2, "nothing was sent for channel 8");
    assert_eq!(routes.unrouted.get(), 2);
    // A Keep that comes later opens it.
    routes.note_keep(8);
    carrier.send_stream(frame_of(8)).await.unwrap();
    assert_eq!(conn.sent.lock().len(), 3);
}

#[tokio::test]
async fn the_carrier_says_full_and_calls_back_once_the_face_took_a_frame() {
    use ndn_face_local::InProcFace;
    use ndn_transport::Transport as _;
    let (face, handle) = InProcFace::new(FaceId(9), 1);
    let conn: Arc<dyn Connection> = Arc::new(ndn_app::InProcConnection::new(handle));
    let carrier = ConnectionCarrier::new(conn, Arc::new(Routes::default()), DATAGRAM_FRAME_MAX);
    assert_eq!(
        carrier.datagram_max(),
        DATAGRAM_FRAME_MAX,
        "the frame a QUIC datagram takes"
    );
    assert!(carrier.has_stream());
    let marked = |n: u8| {
        let mut v = vec![0u8; 64];
        v[1] = n;
        Bytes::from(v)
    };
    carrier.try_send_datagram(marked(1)).unwrap();
    assert_eq!(
        carrier.try_send_datagram(marked(2)),
        Err(CarrierRefused::Full)
    );
    let called = Arc::new(AtomicBool::new(false));
    carrier.on_ready({
        let called = Arc::clone(&called);
        Box::new(move || called.store(true, Ordering::SeqCst))
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!called.load(Ordering::SeqCst), "no room yet");
    assert_eq!(face.recv_bytes().await.unwrap(), marked(1));
    eventually("the drain was called", || called.load(Ordering::SeqCst)).await;
    carrier.try_send_datagram(marked(2)).unwrap();
}

/// An extension that answers with a route label of its own.
struct Routed {
    node: crate::host::NodeHandle,
}

impl crate::host::Extension for Routed {
    fn keywords(&self) -> &'static [&'static str] {
        &["routed"]
    }

    fn answer<'a>(&'a self, interest: &'a ndn_packet::Interest) -> crate::host::AnswerFuture<'a> {
        Box::pin(async move {
            let wire = self
                .node
                .sign_packet(ndn_packet::encode::DataBuilder::new(
                    (*interest.name).clone(),
                    b"hi",
                ))
                .ok()?;
            Some(crate::host::Answer::routed(wire, 0xABCD, 30))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_extension_answer_can_carry_a_route_label() {
    let rig = rig(true).await;
    rig.bob()
        .extend(Arc::new(Routed {
            node: rig.bob().handle(),
        }))
        .unwrap();
    let ask = |what: &str| {
        let name = n(what);
        let mut consumer = rig.carol().consumer();
        async move {
            consumer
                .fetch_with(
                    ndn_packet::encode::InterestBuilder::new(name).lifetime(Duration::from_secs(2)),
                )
                .await
        }
    };
    let data = ask("/bob/phone/32=routed/x").await.expect("answered");
    assert_eq!(&data.content().unwrap()[..], b"hi");
    assert_eq!(
        rig.sinks(0xABCD),
        1,
        "the label installed carol's face as a sink"
    );
    assert_eq!(rig.engine.side().list().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_items_made_after_the_last_one_let_go_is_not_told_that_the_session_ended() {
    let rig = rig(true).await;
    let items = live(rig.carol());
    let info = rig
        .carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    eventually("HELLO", || items.hello_seen()).await;
    drop(items);
    eventually("the route is gone", || rig.sinks(info.channel) == 0).await;

    // A new `Items` over the same sender: the session it never had ended before it existed, and
    // the maintenance passes that follow (every 250 ms) tell it nothing.
    let mut again = live(rig.carol());
    let told = tokio::time::timeout(Duration::from_millis(900), again.next()).await;
    assert!(
        told.is_err(),
        "a new Items is told of the end of a session it never took: {told:?}"
    );
    // It takes the channel again with a new ask: the sender's HELLO and a frame reach it.
    rig.carol()
        .ask_channel(&space(), rig.bob().name())
        .await
        .unwrap();
    eventually("HELLO again", || again.hello_seen()).await;
    emit(rig.bob(), "/b", b"y").await;
    let got = next(&mut again).await.expect("an item");
    assert_eq!(&got.bytes[..], b"y");
}

/// An ask of a sender, signed and answered by it, whose answer is not handed to the asker yet: what
/// an ask that is still on its way holds. Returns the ask's name, the answer, the judges'
/// generation read before the ask went out and the ask's ticket.
async fn ask_in_flight<'a>(
    asker: &'a Node,
    sender: &Node,
) -> (Name, ndn_packet::Data, u64, super::sessions::Asking<'a>) {
    use super::answer::ChanAnswer;
    use super::wire::{ChanAsk, ChannelMode, carrier};
    let asking = asker
        .inner
        .chan
        .sessions
        .asking(&space(), ChannelMode::Latest);
    let ask = ChanAsk {
        space: space(),
        prefix: Name::root(),
        mode: ChannelMode::Latest,
        recipient: asker.recipient().public(),
        carriers: vec![carrier::DATAGRAM, carrier::STREAM],
        lifetime: 3600,
        epoch: None,
        since: None,
        new: false,
        chain: asker.inner.signer_chain(),
    };
    let wire = asker
        .inner
        .sign_ask(sender.name(), &ask.encode().unwrap())
        .unwrap();
    let interest = ndn_packet::Interest::decode(wire).unwrap();
    let generation = asker.inner.judge.generation();
    let ChanAnswer::Session { wire, .. } = sender.inner.chan_answer(&interest, None).await else {
        panic!("a member's ask is answered");
    };
    (
        (*interest.name).clone(),
        ndn_packet::Data::decode(wire).unwrap(),
        generation,
        asking,
    )
}

/// Case B of a receiver that lets the channel go while an ask of it is on its way (the ask an
/// announce started, answered after the test's own): the last `Items` is dropped, a new one is
/// made, and the old ask's answer comes. That answer is for `Items` that are gone and its route
/// is no longer the one the new `Items` will ask for: it installs no session, so the next ask is
/// made as a new one (`ASK_NEW`), the sender sends its `HELLO` again and the new `Items` sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_to_an_ask_made_before_the_channel_was_let_go_installs_no_session() {
    use super::wire::ChannelMode;
    let rig = rig(true).await;
    let (carol, bob) = (rig.carol(), rig.bob());
    let items = live(carol);
    let info = carol.ask_channel(&space(), bob.name()).await.unwrap();
    eventually("HELLO", || items.hello_seen()).await;

    // An ask goes out, and is answered, while the session is held.
    let (name, data, generation, asking) = ask_in_flight(carol, bob).await;

    // The last `Items` is dropped (the session and its route go), a new one is made.
    drop(items);
    eventually("the route is gone", || rig.sinks(info.channel) == 0).await;
    let mut again = live(carol);
    let unsubs = carol.inner.chan.route.unsubs.get();

    // The answer of the ask that began before comes now.
    let late = carol
        .inner
        .chan_take_answer(
            &space(),
            bob.name(),
            ChannelMode::Latest,
            &name,
            data,
            generation,
            &asking,
        )
        .await;
    assert!(
        matches!(late, Err(super::error::ChanError::Superseded { .. })),
        "an answer to an ask made before the channel was let go: {late:?}"
    );
    assert_eq!(
        carol.inner.chan.route.unsubs.get(),
        unsubs + 1,
        "no other ask is on its way: the route the answer laid is given up"
    );
    assert!(
        carol.inner.chan.sessions.get(info.channel).is_none(),
        "the stale answer left a session nobody asked for"
    );

    // The next ask is a new one: HELLO and a frame reach the new `Items`.
    carol.ask_channel(&space(), bob.name()).await.unwrap();
    eventually("HELLO again", || again.hello_seen()).await;
    emit(bob, "/late", b"z").await;
    let got = next(&mut again).await.expect("an item");
    assert_eq!(&got.bytes[..], b"z");
}

/// The first hop toward a receiver is an Ethernet segment: it carries datagrams only. The sender
/// learns that from the forwarder's face when the receiver asks, so a `Reliable` or `Window` ask
/// is refused `NoStream` there (with what to do), instead of being answered and ending in
/// `NoPath` two seconds on, once the hop dropped the stream frames. A `Latest` ask over the same
/// hop is answered with a session that offers no stream: it is sent no `HELLO` and told no
/// `NoPath`, its messages name themselves, and a standing value, which needs the stream, is
/// refused at the emission while that receiver holds the channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reliable_ask_over_a_hop_with_no_stream_is_refused_no_stream_and_latest_still_works() {
    use super::error::ChanError;
    use super::verbs::EmitError;
    use super::wire::{ChannelMode, RefusalCode};
    let rig = rig(true).await;
    let (carol, bob) = (rig.carol(), rig.bob());
    rig.links[1].no_stream_hop.store(true, Ordering::SeqCst);

    for mode in [ChannelMode::Reliable, ChannelMode::Window] {
        let refused = carol
            .ask_channel_in(&space(), bob.name(), mode)
            .await
            .expect_err("no stream reaches this receiver");
        let ChanError::Refused { code, text, .. } = &refused else {
            panic!("a signed refusal, not {refused:?}");
        };
        assert_eq!(*code, RefusalCode::NoStream, "{mode:?}");
        assert!(
            text.contains("no ordered stream") && text.contains("Latest") && text.contains("put"),
            "the refusal says why and what to do: {text}"
        );
        assert_eq!(refused.next(), NextStep::FixRequest);
    }
    assert_eq!(
        rig.engine.side().stats().routes,
        0,
        "a refusal lays no route"
    );

    // `Latest` over the same hop is answered, with no stream on offer.
    let mut items = live(carol);
    let info = carol
        .ask_channel(&space(), bob.name())
        .await
        .expect("a Latest ask is answered");
    let session = carol.inner.chan.sessions.get(info.channel).expect("held");
    assert!(!session.offers_stream(), "the session offers no stream");
    assert_eq!(info.checkpoint, None, "no stream, no checkpoints");
    emit(bob, "/a", b"x").await;
    let got = next(&mut items).await.expect("a datagram arrives");
    assert_eq!(
        (got.path.to_string(), &got.bytes[..]),
        ("/a".into(), &b"x"[..])
    );
    assert!(
        !items.hello_seen(),
        "no HELLO is sent over a hop with no stream"
    );
    // Nothing is waited for: a quiet path is no missing path.
    carol
        .inner
        .chan_route_tick(Instant::now() + 3 * NO_PATH_AFTER);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), items.next())
            .await
            .is_err(),
        "a session with no stream is told no `NoPath`"
    );

    // What needs the stream cannot reach this receiver: refused at the emission, with the next
    // step, not sent to be dropped at the hop.
    let standing = EmitOptions::latest().standing(Duration::from_secs(60));
    let refused = bob
        .space(&space())
        .unwrap()
        .emit(&n("/s"), Bytes::from_static(b"v"), standing)
        .await
        .expect_err("a standing value needs the stream");
    assert_eq!(
        refused,
        EmitError::NoStream {
            what: "a standing value"
        }
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
}

/// A node whose own face on its forwarder has no stream says so at the carrier: `Reliable`,
/// `Window` and a standing value are refused `NoStream` at the emission, with no receiver asked
/// yet, and `Latest` goes on working.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emit_reliable_over_a_face_with_no_stream_is_refused_no_stream_and_latest_still_works() {
    use super::verbs::EmitError;
    let rig = rig(false).await;
    rig.links[1].no_stream_here.store(true, Ordering::SeqCst);
    rig.bob().attach_forwarder().expect("side frames");
    let heap = rig.bob().space(&space()).unwrap();

    let refused = heap
        .emit(&n("/a"), Bytes::from_static(b"x"), EmitOptions::reliable())
        .await
        .expect_err("Reliable needs the stream");
    assert_eq!(refused, EmitError::NoStream { what: "Reliable" });
    assert_eq!(refused.next(), NextStep::FixRequest);
    let said = refused.to_string();
    assert!(
        said.contains("no ordered stream") && said.contains("emit with Mode::Latest, or put"),
        "{said}"
    );
    heap.emit(&n("/a"), Bytes::from_static(b"x"), EmitOptions::latest())
        .await
        .expect("Latest needs no stream");
}
