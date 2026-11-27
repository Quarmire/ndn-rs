//! Tests of the receiver (`rx.rs`, `items.rs`): frames sealed by hand under the key of a real
//! sender's channel and handed to a real receiving node, so every refusal, count and notice is
//! the one the node gives.

use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use ndn_app::EngineAppExt;
use ndn_engine::EngineBuilder;
use ndn_foundation_types::Name;
use ndn_transport::side_header;
use ndn_transport::{SideClass, SideKind};
use tokio_util::sync::CancellationToken;

use super::aead::FrameCipher;
use super::alloc_probe::{count_allocations, live_bytes};
use super::carrier_kit::{Link, LinkConfig};
use super::channels::SendKey;
use super::control::Control;
use super::frame::open;
use super::frame::{Header, seal};
use super::items::Items;
use super::limits::{
    FRAME_OVERHEAD, MESSAGE_DEFAULT, MIN_FRAME_LEN, STREAM_FRAME_DEFAULT, STREAM_FRAME_MAX,
};
use super::message::{MessageWriter, Origin, OutMessage, PAD};
use super::replay::SEQ_JUMP_MAX;
use super::rx::{Delivery, Dropped, RxStats};
use super::sessions::{ChannelInfo, EndReason};
use super::standing::{Who, gate};
use super::verbs::EmitOptions;
use super::verbs::{Congestion, GetNotice, GetOptions, Got, Kind, LiveEnd, Select};
use super::wire::ChannelMode;
use crate::fold::Readers;
use crate::node::tests::{Dev, cfg, space, world};
use crate::node::{Config, Node, Transport};
use crate::rt::Instant;
use crate::space::{Heap, MembersChange, Share};
use crate::test_kit::n;

/// `/a` and `/a/b` as a Name TLV's value.
const A: &[u8] = b"\x08\x01a";
const AB: &[u8] = b"\x08\x01a\x08\x01b";
const B: &[u8] = b"\x08\x01b";
/// Fourteen names: `/a`, `/b`, `/a/b`, `/c` ... `/m`.
const NAMES: [&[u8]; 14] = [
    A,
    B,
    AB,
    b"\x08\x01c",
    b"\x08\x01d",
    b"\x08\x01e",
    b"\x08\x01f",
    b"\x08\x01g",
    b"\x08\x01h",
    b"\x08\x01i",
    b"\x08\x01j",
    b"\x08\x01k",
    b"\x08\x01l",
    b"\x08\x01m",
];

pub(super) fn handle(node: &Node) -> crate::host::NodeHandle {
    crate::host::NodeHandle::of(std::sync::Arc::clone(&node.inner))
}

fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

pub(super) async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within 15 s: {what}");
}

pub(super) struct Rig {
    pub(super) nodes: Vec<Node>,
    cancel: CancellationToken,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub(super) async fn rig_of(devs: Vec<Dev>) -> Rig {
    rig_with(devs, super::config::ChannelConfig::default()).await
}

/// A rig whose nodes are tuned by `channel` (the checkpoint period).
pub(super) async fn rig_with(devs: Vec<Dev>, channel: super::config::ChannelConfig) -> Rig {
    rig_tuned(devs, |config| config.channel = channel).await
}

/// A rig whose nodes' configuration `tune` changes.
pub(super) async fn rig_tuned(devs: Vec<Dev>, tune: impl Fn(&mut Config)) -> Rig {
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    for dev in &devs {
        let ns = Name::from_components(dev.name.components()[..1].iter().cloned());
        ndn_namespace::sync_group::carry(&engine, &ns);
    }
    let cancel = CancellationToken::new();
    let mut nodes = Vec::new();
    for dev in &devs {
        let sync = engine.app_face(cancel.child_token());
        let mut config = fast();
        tune(&mut config);
        nodes.push(
            Node::start(
                Transport {
                    node: engine.app_node(cancel.child_token()),
                    sync,
                },
                dev.name.clone(),
                std::sync::Arc::clone(&dev.keys),
                std::sync::Arc::clone(&dev.validator),
                std::sync::Arc::clone(&dev.store),
                config,
            )
            .await
            .expect("the node starts"),
        );
    }
    Rig { nodes, cancel }
}

fn ready(node: &Node) -> bool {
    node.inner.space_of(&space()).is_some_and(|held| {
        let log = held.log.lock();
        gate(&log, &node.inner.judge, Who::Listed, "test").is_ok()
            && (!log.sealed() || log.fold.in_force().is_some())
    })
}

/// A space owned by the first device, written by `/bob`, read by `/carol` (a sealed space: a
/// public one lists no reader and channels need a listed person).
pub(super) async fn shared(rig: &Rig) -> Heap {
    let share = Share {
        readers: Readers::Persons(vec![n("/bob"), n("/carol")]),
        writers: vec![n("/bob")],
    };
    let heap = rig.nodes[0].create(&space(), share).await.unwrap();
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
    heap
}

/// Bob sends, Carol receives: a channel of `mode` set up by the real ask, an `Items` of Carol's
/// over everything, and bob's key to seal frames by hand.
struct Fx {
    rig: Rig,
    owner: Heap,
    info: ChannelInfo,
    send: SendKey,
    cipher: FrameCipher,
    items: Items,
}

async fn fixture(mode: ChannelMode, opts: GetOptions, select: Select) -> Fx {
    let rig = rig_of(world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await).await;
    let owner = shared(&rig).await;
    let (bob, carol) = (&rig.nodes[1], &rig.nodes[2]);
    let info = carol
        .ask_channel_in(&space(), bob.name(), mode)
        .await
        .expect("bob is a writer");
    let send = bob
        .inner
        .chan
        .channels
        .current(&space(), mode)
        .expect("bob opened the channel when it answered");
    let session = carol.inner.chan.sessions.get(info.channel).unwrap();
    let cipher = FrameCipher::new(&send.frame_key, session.terms().aead);
    let items = carol
        .space(&space())
        .unwrap()
        .get(
            select,
            GetOptions {
                kept: false,
                ..opts
            },
        )
        .expect("carol is a member");
    Fx {
        rig,
        owner,
        info,
        send,
        cipher,
        items,
    }
}

fn everything() -> Select {
    Select::Prefix(Name::root())
}

async fn latest() -> Fx {
    fixture(ChannelMode::Latest, GetOptions::default(), everything()).await
}

async fn reliable(congestion: Congestion) -> Fx {
    fixture(
        ChannelMode::Reliable,
        GetOptions {
            congestion,
            ..GetOptions::default()
        },
        everything(),
    )
    .await
}

fn msg(id: u64, payload: &[u8]) -> OutMessage<'_> {
    OutMessage::new(id, payload)
}

fn named<'a>(id: u64, name: &'a [u8], payload: &'a [u8]) -> OutMessage<'a> {
    let mut m = OutMessage::new(id, payload);
    m.name = Some(name);
    m
}

impl Fx {
    fn bob(&self) -> &Node {
        &self.rig.nodes[1]
    }

    fn carol(&self) -> &Node {
        &self.rig.nodes[2]
    }

    fn stats(&self) -> &RxStats {
        &self.carol().inner.chan.stats.rx
    }

    fn epoch(&self) -> u8 {
        self.send.key_epoch as u8
    }

    fn data(&self, class: SideClass, seq0: u64, messages: &[OutMessage<'_>]) -> Bytes {
        self.data_at(class, seq0, self.epoch(), messages)
    }

    fn data_at(
        &self,
        class: SideClass,
        seq0: u64,
        epoch: u8,
        messages: &[OutMessage<'_>],
    ) -> Bytes {
        let limit = match class {
            SideClass::Datagram => 1_200,
            SideClass::Stream => STREAM_FRAME_DEFAULT,
        };
        let mut w = MessageWriter::new(
            class,
            self.info.channel,
            epoch,
            seq0,
            limit,
            1_200,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        for m in messages {
            w.push(m).unwrap();
        }
        w.seal(&self.cipher).unwrap()
    }

    fn control(&self, seq0: u64, control: Control) -> Bytes {
        let header = Header::new(
            SideClass::Stream,
            SideKind::Control,
            self.info.channel,
            self.epoch(),
            seq0,
            0,
        )
        .unwrap();
        seal(&self.cipher, &header, &control.encode().unwrap()).unwrap()
    }

    async fn deliver(&self, frame: Bytes) -> Delivery {
        self.carol().deliver_frame(frame, 7).await
    }

    async fn deliver_at(&self, frame: Bytes, now: Instant) -> Delivery {
        self.carol().inner.chan_deliver(frame, 7, now).await
    }

    /// `frame` handed over as read from face `ingress`.
    async fn deliver_from(&self, frame: Bytes, ingress: u64, now: Instant) -> Delivery {
        self.carol().inner.chan_deliver(frame, ingress, now).await
    }

    /// Keep the node's own maintenance pass from running. A test that hands frames in at a clock
    /// of its own, or counts what only a frame should do, is not the pass's to disturb: the pass
    /// reads the real clock and looks sessions up.
    fn pause_tick(&self) {
        self.carol()
            .inner
            .chan
            .tick_paused
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The datagram frame limit the session says (`S_FRAME_MAX`).
    fn frame_max(&self) -> usize {
        let terms = self
            .carol()
            .inner
            .chan
            .sessions
            .get(self.info.channel)
            .unwrap()
            .terms();
        usize::try_from(terms.frame_max).unwrap()
    }

    /// The sequence the sender's next message takes: where this receiver's stream begins.
    fn start(&self) -> u64 {
        self.carol()
            .inner
            .chan
            .sessions
            .get(self.info.channel)
            .unwrap()
            .terms()
            .seq
    }
}

/// What the `Items` hold now, items only.
fn queued(items: &mut Items) -> Vec<Got> {
    let mut buf = Vec::new();
    items.next_batch(&mut buf);
    buf
}

async fn next(items: &mut Items) -> Result<Got, GetNotice> {
    tokio::time::timeout(Duration::from_secs(5), items.next())
        .await
        .expect("an item within 5 s")
        .expect("the stream goes on")
}

/// Nothing is queued: a poll would wait.
fn nothing(items: &mut Items) -> bool {
    items.next().now_or_never().is_none()
}

fn seq_of(got: &Got) -> u64 {
    match &got.kind {
        Kind::Emitted(e) => e.seq,
        other => panic!("not an emission: {other:?}"),
    }
}

fn payload(got: &Got) -> &[u8] {
    &got.bytes
}

// -- Before any cryptography -------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_replay_window_marks_only_after_the_aead_verified() {
    let mut fx = latest().await;
    let genuine = fx.data(SideClass::Datagram, 10, &[named(1, A, b"x")]);
    // A forged copy of the genuine frame: the same header and `seq0`, an octet of the body
    // changed. It must be refused by the AEAD and must not burn `seq0` 10.
    let mut forged = genuine.to_vec();
    forged[24] ^= 0x01;
    let forged = Bytes::from(forged);
    assert_eq!(
        fx.deliver(forged.clone()).await,
        Delivery::Dropped(Dropped::Unauthentic)
    );
    assert_eq!(fx.stats().aead_attempts.get(), 1);
    // The genuine frame is delivered: its sequence was not burned.
    assert_eq!(
        fx.deliver(genuine.clone()).await,
        Delivery::Delivered { messages: 1 }
    );
    let got = next(&mut fx.items).await.unwrap();
    assert_eq!((seq_of(&got), payload(&got)), (10, &b"x"[..]));
    // Now `seq0` is marked: a copy of either is dropped before the AEAD is tried.
    assert_eq!(
        fx.deliver(genuine).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    assert_eq!(
        fx.deliver(forged).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    assert_eq!(
        fx.stats().aead_attempts.get(),
        2,
        "the repeats cost no attempt"
    );
    assert_eq!(fx.stats().replayed.get(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sequence_below_the_window_is_dropped_before_the_aead() {
    let fx = latest().await;
    let top = 100_000;
    fx.deliver(fx.data(SideClass::Datagram, top, &[named(1, A, b"x")]))
        .await;
    let attempts = fx.stats().aead_attempts.get();
    let old = fx.data(SideClass::Datagram, top - 4_096, &[msg(1, b"old")]);
    assert_eq!(fx.deliver(old).await, Delivery::Dropped(Dropped::TooOld));
    assert_eq!(fx.stats().aead_attempts.get(), attempts);
    // The oldest sequence still inside the window is taken.
    let edge = fx.data(SideClass::Datagram, top - 4_095, &[msg(1, b"edge")]);
    assert!(matches!(
        fx.deliver(edge).await,
        Delivery::Delivered { messages: 1 }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_is_dropped_before_any_cryptography() {
    let fx = latest().await;
    let genuine = fx.data(SideClass::Datagram, 1, &[named(1, A, b"x")]);
    let patched = |at: usize, value: u8| {
        let mut v = genuine.to_vec();
        v[at] = value;
        Bytes::from(v)
    };
    let padded = |len: usize| {
        let mut v = genuine.to_vec();
        v.resize(len, 0);
        Bytes::from(v)
    };
    let cases: Vec<(&str, Bytes, Dropped)> = vec![
        (
            "under 46 octets",
            Bytes::from(vec![0u8; 45]),
            Dropped::Short,
        ),
        (
            "an NDN packet, not a side frame",
            patched(0, 0x06),
            Dropped::NotASideFrame,
        ),
        ("version 3", patched(1, 0x60), Dropped::Version),
        (
            "a kind that is not assigned",
            patched(1, 0x27),
            Dropped::Kind,
        ),
        (
            "a CHECKPOINT on a datagram",
            patched(1, 0x21),
            Dropped::Kind,
        ),
        ("an UP is not sealed", patched(1, 0x24), Dropped::Kind),
        (
            "a DATA frame that counts no messages",
            patched(19, 0),
            Dropped::Count,
        ),
        (
            "a sequence at 2^63",
            {
                let mut v = genuine.to_vec();
                v[11] = 0x80;
                Bytes::from(v)
            },
            Dropped::Sequence,
        ),
        (
            "over every limit",
            Bytes::from(vec![0u8; STREAM_FRAME_MAX + 1]),
            Dropped::Oversize,
        ),
        (
            "a datagram over the session's frame limit",
            padded(fx.frame_max() + 1),
            Dropped::Oversize,
        ),
    ];
    for (what, frame, why) in cases {
        assert_eq!(fx.deliver(frame).await, Delivery::Dropped(why), "{what}");
    }
    // A channel nobody holds: a stream frame is kept for the session that may be coming, a
    // datagram is lost, and neither is opened by anyone.
    assert_eq!(
        fx.deliver(patched(5, genuine[5] ^ 0xff)).await,
        Delivery::Dropped(Dropped::UnknownChannel),
        "a datagram of a channel nobody holds"
    );
    assert_eq!(
        fx.deliver(early(&fx, SideClass::Stream, 5, 0)).await,
        Delivery::Held,
        "a stream frame of a channel nobody holds"
    );
    assert_eq!(
        fx.stats().aead_attempts.get(),
        0,
        "no junk reached the AEAD"
    );
    assert_eq!(fx.stats().accepted.get(), 0);
}

/// A frame sealed under the channel's own key (what a key holder can send) whose routing octet
/// names a kind the channel does not carry: `Header::new` builds none, so it is sealed by hand.
fn sealed_as(fx: &Fx, octet: u8, seq0: u64) -> Bytes {
    let mut frame = vec![0u8; MIN_FRAME_LEN];
    // A header with count 0 (QUERY and ANSWER are not counted frames); the kind octet is patched.
    let header = Header::new(
        SideClass::Stream,
        SideKind::Checkpoint,
        fx.info.channel,
        fx.epoch(),
        seq0,
        0,
    )
    .unwrap();
    frame[..20].copy_from_slice(&header.encode());
    frame[1] = octet;
    let (head, rest) = frame.split_at_mut(20);
    let (body, tag) = rest.split_at_mut(MIN_FRAME_LEN - 20 - 16);
    tag.copy_from_slice(&fx.cipher.seal_detached(header.nonce(), head, body));
    Bytes::from(frame)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_or_an_answer_is_refused_before_the_aead_and_burns_no_sequence() {
    let fx = latest().await;
    let genuine = fx.data(SideClass::Datagram, 7, &[named(1, A, b"x")]);
    // QUERY and ANSWER have a layout of their own; the forwarder routes them, the channel
    // receiver does not take them as sealed frames, even from a holder of the key.
    for (what, octet) in [
        ("a QUERY", side_header::QUERY),
        ("an ANSWER datagram", side_header::ANSWER_DATAGRAM),
        ("an ANSWER stream", side_header::ANSWER_STREAM),
    ] {
        assert_eq!(
            fx.deliver(sealed_as(&fx, octet, 7)).await,
            Delivery::Dropped(Dropped::Kind),
            "{what}"
        );
    }
    assert_eq!(fx.stats().kind.get(), 3, "counted `kind`");
    assert_eq!(fx.stats().aead_attempts.get(), 0, "no AEAD was tried");
    // Sequence 7 was not marked: the genuine frame at it is delivered.
    assert_eq!(
        fx.deliver(genuine).await,
        Delivery::Delivered { messages: 1 }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_under_an_unknown_key_epoch_costs_no_aead_attempt_and_asks_once_a_second() {
    let fx = latest().await;
    let other = fx.epoch().wrapping_add(1);
    for seq0 in [1, 2, 3] {
        let frame = fx.data_at(SideClass::Datagram, seq0, other, &[named(1, A, b"x")]);
        assert_eq!(
            fx.deliver(frame).await,
            Delivery::Dropped(Dropped::UnknownEpoch)
        );
    }
    let s = fx.stats();
    assert_eq!(
        s.aead_attempts.get(),
        0,
        "an epoch it does not hold is never tried"
    );
    assert_eq!(s.unknown_epoch.get(), 3);
    assert_eq!(s.epoch_asks.get(), 1, "the sender is asked again once");
    assert_eq!(s.epoch_limited.get(), 2, "and not again within a second");
}

// -- The hold of an unknown bare id -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_bare_id_is_held_50_ms_and_dropped() {
    let mut fx = latest().await;
    fx.pause_tick();
    let t0 = Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);

    // The datagram overtook its bind: held. The bind (a stream CONTROL frame) comes 49 ms later.
    let bare = fx.data(SideClass::Datagram, 1, &[msg(7, b"early")]);
    assert_eq!(
        fx.deliver_at(bare, t0).await,
        Delivery::Delivered { messages: 1 }
    );
    assert!(
        nothing(&mut fx.items),
        "nothing is delivered before its bind"
    );
    let rx = fx.carol().inner.chan.rx.channel(fx.info.channel).unwrap();
    assert_eq!(rx.held(), 1);
    let bind = fx.control(
        2,
        Control::Bind {
            id: 7,
            name: Bytes::from_static(A),
        },
    );
    assert_eq!(fx.deliver_at(bind, at(49)).await, Delivery::Control);
    let got = queued(&mut fx.items);
    assert_eq!(got.len(), 1, "held 49 ms, then delivered with its name");
    assert_eq!(
        (got[0].path.to_string(), payload(&got[0])),
        ("/a".into(), &b"early"[..])
    );
    assert_eq!(rx.held(), 0);
    assert_eq!(fx.stats().unknown_name.get(), 0);

    // Held again, and the bind comes at 50 ms: too late, dropped and counted.
    let bare = fx.data(SideClass::Datagram, 3, &[msg(8, b"late")]);
    fx.deliver_at(bare, at(100)).await;
    let bind = fx.control(
        4,
        Control::Bind {
            id: 8,
            name: Bytes::from_static(B),
        },
    );
    assert_eq!(fx.deliver_at(bind, at(150)).await, Delivery::Control);
    assert!(nothing(&mut fx.items), "a message held 50 ms is dropped");
    assert_eq!(fx.stats().unknown_name.get(), 1);
    assert_eq!(rx.held(), 0);

    // Held and never bound: a later frame of the channel sweeps it at 50 ms, not before.
    let bare = fx.data(SideClass::Datagram, 5, &[msg(9, b"never")]);
    fx.deliver_at(bare, at(200)).await;
    let other = fx.data(SideClass::Datagram, 6, &[named(1, A, b"x")]);
    fx.deliver_at(other, at(249)).await;
    assert_eq!(rx.held(), 1, "49 ms is inside the hold");
    let sweeper = fx.data(SideClass::Datagram, 7, &[named(1, A, b"y")]);
    fx.deliver_at(sweeper, at(251)).await;
    // The frame at 251 ms swept what had been held 51 ms; no timer ran.
    assert_eq!(rx.held(), 0);
    assert_eq!(fx.stats().unknown_name.get(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_most_64_unknown_bare_ids_are_held_per_channel() {
    let fx = latest().await;
    let t0 = Instant::now();
    let rx_of = || fx.carol().inner.chan.rx.channel(fx.info.channel);
    for i in 0..70u64 {
        let id = 100 + i;
        let frame = fx.data(SideClass::Datagram, 1 + i, &[msg(id, b"?")]);
        fx.deliver_at(frame, t0).await;
    }
    assert_eq!(rx_of().unwrap().held(), 64, "no more than 64 are held");
    assert_eq!(fx.stats().hold_full.get(), 6);
    assert_eq!(
        fx.stats().unknown_name.get(),
        6,
        "the rest were dropped at once and counted"
    );
}

// -- Latest ------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latest_expects_gaps_and_never_delivers_an_older_frame_after_a_newer() {
    let mut fx = latest().await;
    // Frame 20 arrives before frame 10 (reordered), and a gap lies between them: no notice.
    fx.deliver(fx.data(SideClass::Datagram, 20, &[named(1, A, b"new")]))
        .await;
    fx.deliver(fx.data(SideClass::Datagram, 10, &[named(1, A, b"old")]))
        .await;
    let got = queued(&mut fx.items);
    assert_eq!(got.len(), 1);
    assert_eq!((seq_of(&got[0]), payload(&got[0])), (20, &b"new"[..]));
    assert!(nothing(&mut fx.items), "no Lagged: Latest expects gaps");
    // Even after the newer was read, the older one stays out.
    fx.deliver(fx.data(SideClass::Datagram, 11, &[msg(1, b"older")]))
        .await;
    assert!(nothing(&mut fx.items));
    assert_eq!(fx.stats().gaps.get(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_message_replaces_an_unread_older_one_of_its_name() {
    let mut fx = latest().await;
    fx.deliver(fx.data(
        SideClass::Datagram,
        1,
        &[named(1, A, b"a1"), named(2, B, b"b1"), msg(1, b"a2")],
    ))
    .await;
    let got = queued(&mut fx.items);
    let seen: Vec<(String, &[u8], u64)> = got
        .iter()
        .map(|g| (g.path.to_string(), payload(g), seq_of(g)))
        .collect();
    assert_eq!(
        seen,
        [
            ("/a".to_string(), &b"a2"[..], 3),
            ("/b".to_string(), &b"b1"[..], 2)
        ],
        "the newest per name, each in the turn of its first"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn next_batch_returns_everything_queued_in_one_call() {
    let mut fx = latest().await;
    for f in 0..3u64 {
        let msgs: Vec<OutMessage<'_>> = (1..=4u64)
            .map(|id| {
                if f == 0 {
                    named(id, NAMES[id as usize - 1], b"v")
                } else {
                    msg(id, b"v")
                }
            })
            .collect();
        fx.deliver(fx.data(SideClass::Datagram, 1 + f * 4, &msgs))
            .await;
    }
    let mut buf = Vec::new();
    assert_eq!(
        fx.items.next_batch(&mut buf),
        4,
        "one per name: all in one call"
    );
    assert_eq!(fx.items.next_batch(&mut buf), 0, "and nothing is left");
    assert_eq!(buf.iter().map(seq_of).collect::<Vec<_>>(), [9, 10, 11, 12]);
}

// -- Reliable and Window -----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_with_a_gap_says_lagged_in_its_place() {
    let mut fx = reliable(Congestion::Block).await;
    let base = fx.start();
    let s = |seq0, msgs: &[OutMessage<'_>]| fx.data(SideClass::Stream, seq0, msgs);
    // HELLO says where the stream begins; two messages follow; then the stream skips 2.
    fx.deliver(fx.control(base, Control::Hello { seq: base + 1 }))
        .await;
    fx.deliver(s(base + 1, &[named(1, A, b"one"), msg(1, b"two")]))
        .await;
    fx.deliver(s(base + 5, &[msg(1, b"six")])).await;
    fx.deliver(s(base + 6, &[msg(1, b"seven")])).await;
    let mut seen = Vec::new();
    for _ in 0..5 {
        seen.push(match next(&mut fx.items).await {
            Ok(g) => format!("{}@{}", String::from_utf8_lossy(payload(&g)), seq_of(&g)),
            Err(GetNotice::Lagged { missed }) => format!("lagged {missed}"),
            Err(other) => panic!("{other:?}"),
        });
    }
    assert_eq!(
        seen,
        [
            format!("one@{}", base + 1),
            format!("two@{}", base + 2),
            "lagged 2".to_string(),
            format!("six@{}", base + 5),
            format!("seven@{}", base + 6),
        ],
        "a gap is never silent, and it stands where the messages are missing"
    );
    assert_eq!(fx.stats().gaps.get(), 1);
    assert_eq!(fx.stats().reasks.get(), 0, "only Window asks again");
    assert!(fx.items.hello_seen());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reliable_channel_refuses_a_datagram() {
    let fx = reliable(Congestion::Block).await;
    let frame = fx.data(SideClass::Datagram, fx.start(), &[named(1, A, b"x")]);
    assert_eq!(
        fx.deliver(frame).await,
        Delivery::Dropped(Dropped::WrongClass)
    );
    assert_eq!(fx.stats().aead_attempts.get(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_reliable_queue_stalls_the_stream_until_the_consumer_reads() {
    let mut fx = reliable(Congestion::Block).await;
    let base = fx.start();
    let big = vec![7u8; 400 * 1024];
    let frame = |i: u64| {
        let m = if i == 0 {
            named(1, A, &big)
        } else {
            msg(1, &big)
        };
        fx.data(SideClass::Stream, base + i, &[m])
    };
    // 1 MiB: two 400 KiB messages fit, the third fills it, the fourth waits.
    for i in 0..3 {
        assert!(matches!(
            fx.deliver(frame(i)).await,
            Delivery::Delivered { messages: 1 }
        ));
    }
    let (carol, fourth_frame) = (handle(fx.carol()), frame(3));
    let mut fourth = Box::pin(async move { carol.deliver_frame(fourth_frame, 7).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut fourth)
            .await
            .is_err(),
        "the stream is not taken while the queue is full: back pressure"
    );
    assert_eq!(fx.stats().accepted.get(), 3);
    // The consumer reads one: the queue is below its bound and the stream goes on.
    let first = next(&mut fx.items).await.unwrap();
    assert_eq!(seq_of(&first), base);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), fourth)
            .await
            .expect("the stream goes on once there is room"),
        Delivery::Delivered { messages: 1 }
    ));
    assert_eq!(fx.stats().accepted.get(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_items_frees_a_stalled_stream() {
    let fx = reliable(Congestion::Block).await;
    let base = fx.start();
    let big = vec![7u8; 600 * 1024];
    for i in 0..2 {
        let m = if i == 0 {
            named(1, A, &big)
        } else {
            msg(1, &big)
        };
        fx.deliver(fx.data(SideClass::Stream, base + i, &[m])).await;
    }
    let third = fx.data(SideClass::Stream, base + 2, &[msg(1, b"x")]);
    let carol = handle(fx.carol());
    let mut stalled = Box::pin(async move { carol.deliver_frame(third, 7).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut stalled)
            .await
            .is_err(),
        "the queue is over its bound: the stream waits"
    );
    let Fx { items, .. } = fx;
    drop(items);
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), stalled)
            .await
            .expect("with the Items gone nothing waits"),
        Delivery::Delivered { messages: 1 }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reliable_queue_that_drops_keeps_its_bound_and_counts_what_it_dropped() {
    let mut fx = reliable(Congestion::Drop).await;
    let base = fx.start();
    let big = vec![7u8; 400 * 1024];
    for i in 0..5 {
        let m = if i == 0 {
            named(1, A, &big)
        } else {
            msg(1, &big)
        };
        assert!(
            matches!(
                fx.deliver(fx.data(SideClass::Stream, base + i, &[m])).await,
                Delivery::Delivered { messages: 1 }
            ),
            "Drop never stalls the stream"
        );
    }
    // Five arrived, at most two fit the 1 MiB bound with their weight: the oldest were dropped,
    // and the notice stands first, where they were.
    let mut missed = 0;
    let mut kept = Vec::new();
    loop {
        match fx.items.next().now_or_never() {
            Some(Some(Ok(g))) => kept.push(seq_of(&g)),
            Some(Some(Err(GetNotice::Lagged { missed: m }))) => {
                assert!(kept.is_empty(), "the notice is where the dropped were");
                missed += m;
            }
            _ => break,
        }
    }
    assert!(missed >= 3, "{missed} missed, {kept:?} kept");
    assert_eq!(
        missed + kept.len() as u64,
        5,
        "every message is delivered or counted"
    );
    assert_eq!(
        kept.last(),
        Some(&(base + 4)),
        "the newest are the ones kept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_asks_again_from_the_first_missing_sequence() {
    let mut fx = fixture(ChannelMode::Window, GetOptions::default(), everything()).await;
    let base = fx.start();
    fx.deliver(fx.control(base, Control::Hello { seq: base + 1 }))
        .await;
    fx.deliver(fx.data(SideClass::Stream, base + 1, &[named(1, A, b"one")]))
        .await;
    fx.deliver(fx.data(SideClass::Stream, base + 4, &[msg(1, b"four")]))
        .await;
    assert_eq!(fx.stats().gaps.get(), 1);
    assert_eq!(
        fx.stats().reasks.get(),
        1,
        "Window asks for the range again"
    );
    let mut seen = Vec::new();
    for _ in 0..3 {
        seen.push(next(&mut fx.items).await);
    }
    assert!(
        matches!(seen[1], Err(GetNotice::Lagged { missed: 2 })),
        "{seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_message_is_delivered_once_and_only_if_its_original_was_not() {
    let mut fx = fixture(ChannelMode::Window, GetOptions::default(), everything()).await;
    let base = fx.start();
    fx.deliver(fx.control(base, Control::Hello { seq: base + 1 }))
        .await;
    // Live: original sequence base+1.
    fx.deliver(fx.data(SideClass::Stream, base + 1, &[named(1, A, b"live")]))
        .await;
    // The replay carries the window: base+1 (already delivered) and an older one, base-3.
    let mut dup = named(1, A, b"live again");
    dup.origin = Some(Origin::Replayed(base + 1));
    let mut old = named(1, A, b"older");
    old.origin = Some(Origin::Replayed(base.saturating_sub(3)));
    fx.deliver(fx.data(SideClass::Stream, base + 2, &[dup, old]))
        .await;
    let got = [
        next(&mut fx.items).await.unwrap(),
        next(&mut fx.items).await.unwrap(),
    ];
    assert_eq!(payload(&got[0]), b"live");
    assert_eq!(payload(&got[1]), b"older");
    assert_eq!(
        seq_of(&got[1]),
        base.saturating_sub(3),
        "a replay says the original sequence"
    );
    assert!(nothing(&mut fx.items));
    assert_eq!(fx.stats().duplicates.get(), 1);
}

// -- HELLO, standing, END ----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hello_is_recorded_and_items_can_say_the_path_works() {
    let fx = latest().await;
    assert!(!fx.items.hello_seen());
    assert_eq!(
        fx.deliver(fx.control(5, Control::Hello { seq: 6 })).await,
        Delivery::Control
    );
    assert!(fx.items.hello_seen());
    let rx = fx.carol().inner.chan.rx.channel(fx.info.channel).unwrap();
    assert_eq!(rx.hello(), Some(6));
    assert_eq!(rx.last_ingress(), 7, "the face it came over is kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_standing_value_is_delivered_inside_its_bracket_with_what_is_left() {
    let mut fx = latest().await;
    let mut standing = named(1, A, b"stands");
    standing.origin = Some(Origin::Standing(3));
    standing.stand_secs = Some(30);
    let strayed = {
        let mut m = named(2, B, b"stray");
        m.origin = Some(Origin::Standing(4));
        m.stand_secs = Some(5);
        m
    };
    fx.deliver(fx.control(10, Control::StandingBegin)).await;
    fx.deliver(fx.data(SideClass::Stream, 11, &[standing]))
        .await;
    fx.deliver(fx.control(12, Control::StandingEnd)).await;
    fx.deliver(fx.data(SideClass::Stream, 13, &[strayed])).await;
    let got = next(&mut fx.items).await.unwrap();
    assert_eq!(payload(&got), b"stands");
    match got.kind {
        Kind::Emitted(e) => {
            assert_eq!(e.seq, 3, "the original sequence");
            assert_eq!(e.stands, Some(Duration::from_secs(30)));
        }
        other => panic!("{other:?}"),
    }
    assert!(
        nothing(&mut fx.items),
        "a standing value outside its bracket is dropped"
    );
    assert_eq!(fx.stats().standing_stray.get(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_name_bound_again_after_an_unbind_is_another_name() {
    let mut fx = latest().await;
    fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"a")]))
        .await;
    fx.deliver(fx.control(2, Control::Unbind { id: 1 })).await;
    fx.deliver(fx.data(SideClass::Datagram, 3, &[named(1, B, b"b")]))
        .await;
    fx.deliver(fx.data(SideClass::Datagram, 4, &[msg(1, b"b2")]))
        .await;
    let got = queued(&mut fx.items);
    let seen: Vec<_> = got
        .iter()
        .map(|g| (g.path.to_string(), seq_of(g)))
        .collect();
    assert_eq!(seen, [("/a".to_string(), 1), ("/b".to_string(), 4)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_senders_end_ends_the_session_and_tells_the_items_after_what_is_queued() {
    let mut fx = latest().await;
    fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"last")]))
        .await;
    assert_eq!(
        fx.deliver(fx.control(2, Control::End)).await,
        Delivery::Ended(EndReason::Closed)
    );
    assert_eq!(payload(&next(&mut fx.items).await.unwrap()), b"last");
    match next(&mut fx.items).await {
        Err(GetNotice::LiveEnded(LiveEnd::Ended { writer, reason })) => {
            assert_eq!(&writer, fx.bob().name());
            assert_eq!(reason, EndReason::Closed);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        fx.deliver(fx.data(SideClass::Datagram, 3, &[msg(1, b"after")]))
            .await,
        Delivery::Dropped(Dropped::UnknownChannel)
    );
}

// -- Filters, removal ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_filter_keeps_only_what_it_matches() {
    let mut fx = fixture(
        ChannelMode::Latest,
        GetOptions::default(),
        Select::Path(n("/a")),
    )
    .await;
    fx.deliver(fx.data(
        SideClass::Datagram,
        1,
        &[
            named(1, A, b"yes"),
            named(2, B, b"no"),
            named(3, AB, b"deeper"),
        ],
    ))
    .await;
    let got = queued(&mut fx.items);
    assert_eq!(got.len(), 1);
    assert_eq!(payload(&got[0]), b"yes");
    // A prefix keeps what is below it too.
    let mut prefix = fx
        .carol()
        .space(&space())
        .unwrap()
        .get(
            Select::Prefix(n("/a")),
            GetOptions {
                kept: false,
                ..GetOptions::default()
            },
        )
        .unwrap();
    fx.deliver(fx.data(
        SideClass::Datagram,
        4,
        &[msg(1, b"a again"), msg(2, b"b again"), msg(3, b"ab again")],
    ))
    .await;
    let got = queued(&mut prefix);
    assert_eq!(
        got.iter().map(|g| g.path.to_string()).collect::<Vec<_>>(),
        ["/a", "/a/b"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_items_are_told_a_sender_was_removed_whichever_pass_notices_first() {
    let mut fx = latest().await;
    fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"fine")]))
        .await;
    assert_eq!(payload(&next(&mut fx.items).await.unwrap()), b"fine");

    // The owner removes bob. Frames go on, one after another, until one is refused.
    let owner = fx.owner.clone();
    let removal = tokio::spawn(async move {
        owner
            .change(MembersChange {
                remove: vec![n("/bob")],
                ..MembersChange::default()
            })
            .await
    });
    let started = std::time::Instant::now();
    let carol = fx.carol().inner.clone();
    let mut seq = 2;
    let refused = loop {
        // Once the record this node holds no longer lists bob as a writer, the next frame must be
        // refused, whatever the node's own pass has done by then.
        let removed = !carol
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .is_writer(&n("/bob"));
        let frame = fx.data(SideClass::Datagram, seq, &[named(1, A, b"still")]);
        seq += 1;
        match fx.deliver(frame).await {
            Delivery::Delivered { .. } => {
                assert!(
                    !removed,
                    "frame {} was delivered after the removal was held",
                    seq - 1
                );
            }
            other => break other,
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "bob was not removed"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    removal.await.unwrap().unwrap();
    match &refused {
        Delivery::Ended(EndReason::NotMember { why }) => {
            assert!(why.contains("writer"), "{why}");
            assert_eq!(
                fx.stats().not_member.get(),
                1,
                "refused by the generation check"
            );
        }
        // The node's own pass judged the sender between two frames: the session is gone, the
        // datagram finds no session and is lost. The `Items` are told either way.
        Delivery::Dropped(Dropped::UnknownChannel) => {}
        other => panic!("the first frame after the removal must be refused, not {other:?}"),
    }
    let refused_seq = seq - 1;
    // What was delivered before the refusal is read, the refused frame is not among it, and the
    // end is told.
    let mut last_seq = 0;
    loop {
        match next(&mut fx.items).await {
            Ok(got) => last_seq = last_seq.max(seq_of(&got)),
            Err(GetNotice::LiveEnded(LiveEnd::Ended { writer, reason })) => {
                assert_eq!(&writer, fx.bob().name());
                assert!(matches!(reason, EndReason::NotMember { .. }), "{reason:?}");
                break;
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(
        last_seq < refused_seq,
        "the refused frame {refused_seq} was delivered: {last_seq}"
    );
    // The session is gone: nothing more is taken.
    assert_eq!(
        fx.deliver(fx.data(SideClass::Datagram, seq, &[msg(1, b"after")]))
            .await,
        Delivery::Dropped(Dropped::UnknownChannel)
    );
}

/// The node's own pass is paused, so only the frame layer can notice the removal: the first frame
/// after the node holds the removing record is refused, and the `Items` say why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_frame_after_a_removal_is_refused_and_the_items_say_not_a_member() {
    let mut fx = latest().await;
    fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"fine")]))
        .await;
    assert_eq!(payload(&next(&mut fx.items).await.unwrap()), b"fine");
    let carol = fx.carol().inner.clone();
    // Let any pass under way finish, then keep it from running.
    carol
        .chan
        .tick_paused
        .store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await;
    fx.owner
        .change(MembersChange {
            remove: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol holds the record that removes bob", || {
        !carol
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .is_writer(&n("/bob"))
    })
    .await;
    let session = carol.chan.sessions.get(fx.info.channel).unwrap();
    assert!(!session.is_current(), "the verdict on bob is stale");
    assert!(
        session.ended().is_none(),
        "and nothing but a frame has noticed"
    );

    // The first frame after the record is held, sealed under the key bob still holds.
    let refused = fx
        .deliver(fx.data(SideClass::Datagram, 2, &[named(1, A, b"too late")]))
        .await;
    match refused {
        Delivery::Ended(EndReason::NotMember { why }) => assert!(why.contains("writer"), "{why}"),
        other => panic!("the first frame after the removal must be refused: {other:?}"),
    }
    assert_eq!(fx.stats().not_member.get(), 1);
    assert!(
        carol.chan.sessions.get(fx.info.channel).is_none(),
        "the session is dropped"
    );
    // Nothing of the refused frame was queued; the end is told.
    match next(&mut fx.items).await {
        Err(GetNotice::LiveEnded(LiveEnd::Ended { writer, reason })) => {
            assert_eq!(&writer, fx.bob().name());
            assert!(matches!(reason, EndReason::NotMember { .. }), "{reason:?}");
        }
        other => panic!("the Items must say the sender is no member: {other:?}"),
    }
    assert!(
        nothing(&mut fx.items),
        "the refused frame's message was not delivered"
    );
    assert_eq!(
        fx.deliver(fx.data(SideClass::Datagram, 3, &[msg(1, b"after")]))
            .await,
        Delivery::Dropped(Dropped::UnknownChannel)
    );
}

// -- Cost ------------------------------------------------------------------------------------

/// A frame is read in a bounded number of allocations whatever its message count, and a message
/// costs none: the allocations of a frame of 14 messages equal those of a frame of 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_costs_no_allocation_and_a_frame_a_fixed_few() {
    let mut fx = latest().await;
    let payload = [0x5au8; 64];
    let msgs = |count: u64, bind: bool| -> Vec<OutMessage<'_>> {
        (1..=count)
            .map(|id| {
                if bind {
                    named(id, NAMES[id as usize - 1], &payload)
                } else {
                    msg(id, &payload)
                }
            })
            .collect()
    };
    // Warm up: bind 14 names, grow every buffer to its working size, read it all.
    let mut seq = 1;
    fx.deliver(fx.data(SideClass::Datagram, seq, &msgs(14, true)))
        .await;
    seq += 14;
    let mut buf: Vec<Got> = Vec::with_capacity(64);
    for _ in 0..4 {
        fx.deliver(fx.data(SideClass::Datagram, seq, &msgs(14, false)))
            .await;
        seq += 14;
        fx.items.next_batch(&mut buf);
        buf.clear();
    }
    let cost = |count: u64, seq: &mut u64| {
        let frame = fx.data(SideClass::Datagram, *seq, &msgs(count, false));
        *seq += count;
        let carol = handle(fx.carol());
        let (delivery, allocations) = count_allocations(|| deliver_polling(&carol, frame));
        assert_eq!(
            delivery,
            Delivery::Delivered {
                messages: count as usize
            }
        );
        allocations
    };
    let two = cost(2, &mut seq);
    let fourteen = cost(14, &mut seq);
    let fourteen_again = cost(14, &mut seq);
    assert_eq!(
        (two, fourteen_again),
        (fourteen, fourteen),
        "the allocations of a frame do not depend on how many messages it carries"
    );
    assert_eq!(
        fourteen, 1,
        "a frame costs one allocation (the shared header its buffer takes once messages are \
         sliced from it) and a message none; measured {fourteen}"
    );
    // The consumer's side: taking a batch into a buffer with room costs none.
    buf.clear();
    let (taken, allocations) = count_allocations(|| fx.items.next_batch(&mut buf));
    assert_eq!(taken, 14);
    assert_eq!(allocations, 0, "next_batch allocates nothing");
}

// -- What a queued message pins ---------------------------------------------------------------

/// `deliver_frame` driven by hand: it waits for nothing, but hands the executor back once in a
/// while ([`super::rx`]'s `COOPERATE_OCTETS`), which a poll loop with no executor takes as a
/// `Pending` and polls again. Allocates nothing itself.
fn deliver_polling(node: &crate::host::NodeHandle, frame: Bytes) -> Delivery {
    let mut delivering = std::pin::pin!(node.deliver_frame(frame, 7));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(delivery) = delivering.as_mut().poll(&mut cx) {
            return delivery;
        }
    }
}

/// A stream frame of `total` octets whose one message is named by `id` and has a one-octet
/// payload: everything else is zero padding, which a receiver accepts after the messages.
fn padded_frame(fx: &Fx, seq0: u64, id: u64, total: usize) -> Bytes {
    let name = [0x08, 0x02, b'p', b'a' + id as u8];
    let mut plain = vec![0x01, id as u8, name.len() as u8];
    plain.extend_from_slice(&name);
    plain.extend_from_slice(&[1, b'x', PAD]);
    plain.resize(total - FRAME_OVERHEAD, 0);
    let header = Header::new(
        SideClass::Stream,
        SideKind::Data,
        fx.info.channel,
        fx.epoch(),
        seq0,
        1,
    )
    .unwrap();
    seal(&fx.cipher, &header, &plain).unwrap()
}

/// Hand `frames` frames of 1 MiB with a one-octet message each to the receiver and return the
/// octets of allocation the receiver and its `Items` hold afterwards.
fn pinned_by_padded_frames(fx: &Fx, frames: u64) -> i64 {
    let carol = handle(fx.carol());
    let start = fx.start();
    let ((), live) = live_bytes(|| {
        for i in 0..frames {
            let frame = padded_frame(fx, start + i, i + 1, 1 << 20);
            let delivery = deliver_polling(&carol, frame);
            assert_eq!(delivery, Delivery::Delivered { messages: 1 });
        }
    });
    live
}

/// A message sealed in a frame padded to 1 MiB weighs one octet and its payload must not keep
/// the frame alive: what the queues hold is what they are charged for (H3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn padded_frames_with_tiny_messages_are_bounded_by_pinned_bytes_in_latest() {
    let mut fx = latest().await;
    let live = pinned_by_padded_frames(&fx, 24);
    assert_eq!(
        queued(&mut fx.items).len(),
        24,
        "every name's message queued"
    );
    assert!(
        live < 256 * 1024,
        "24 one-octet messages in frames of 1 MiB hold {live} octets of allocation"
    );
}

/// The same in a `Reliable` channel, where a queue charged 65 octets a message would take
/// 16,000 such frames before it blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn padded_frames_with_tiny_messages_are_bounded_by_pinned_bytes_in_reliable() {
    let mut fx = reliable(Congestion::Block).await;
    let live = pinned_by_padded_frames(&fx, 24);
    assert_eq!(queued(&mut fx.items).len(), 24, "every message queued");
    assert!(
        live < 256 * 1024,
        "24 one-octet messages in frames of 1 MiB hold {live} octets of allocation"
    );
}

/// A data frame of one message that stands for `secs`, sealed by hand (a writer would refuse to
/// build it).
fn standing_frame(fx: &Fx, seq0: u64, secs: u64) -> Bytes {
    let mut plain = vec![0x01 | 0x02, 1, 3, 0x08, 0x01, b'a'];
    super::varint::write(&mut plain, secs).unwrap();
    plain.extend_from_slice(&[1, b'x']);
    let header = Header::new(
        SideClass::Datagram,
        SideKind::Data,
        fx.info.channel,
        fx.epoch(),
        seq0,
        1,
    )
    .unwrap();
    seal(&fx.cipher, &header, &plain).unwrap()
}

/// A message that stands for more than the hour a sender may stand one for is refused with its
/// frame, counted, and nothing of it is queued; an hour is taken (security review L8).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_that_stands_for_more_than_an_hour_is_refused_with_its_frame() {
    let mut fx = latest().await;
    let start = fx.start();
    for (i, secs) in [3_601u64, 1 << 40, super::varint::MAX]
        .into_iter()
        .enumerate()
    {
        let frame = standing_frame(&fx, start + i as u64, secs);
        assert_eq!(
            fx.deliver(frame).await,
            Delivery::Dropped(Dropped::Malformed),
            "{secs} s"
        );
    }
    assert_eq!(fx.stats().malformed.get(), 3);
    assert!(
        nothing(&mut fx.items),
        "nothing of the refused frames was queued"
    );
    let frame = standing_frame(&fx, start + 3, 3_600);
    assert_eq!(fx.deliver(frame).await, Delivery::Delivered { messages: 1 });
    let got = queued(&mut fx.items);
    match &got[0].kind {
        Kind::Emitted(e) => assert_eq!(e.stands, Some(Duration::from_secs(3_600))),
        other => panic!("not an emission: {other:?}"),
    }
}

// -- A key holder's sequences (security review M7) --------------------------------------------

/// One authentic frame of a huge `seq0` used to set the replay window's `highest`, and every
/// genuine frame after it was `TooOld`. A frame more than 2^24 above what the window has seen
/// and the sender's last answer said is refused (and not marked); the genuine frames go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authentic_frame_with_a_huge_seq0_does_not_make_later_genuine_frames_too_old() {
    let mut fx = latest().await;
    let start = fx.start();
    let first = fx.data(SideClass::Datagram, start, &[named(1, A, b"first")]);
    assert_eq!(fx.deliver(first).await, Delivery::Delivered { messages: 1 });
    // A holder of the key seals frames far above anything the sender has sent.
    let bound = SEQ_JUMP_MAX;
    for (n, forged) in [1u64 << 62, (1 << 63) - 10, start + bound + 1]
        .into_iter()
        .enumerate()
    {
        let frame = fx.data(SideClass::Datagram, forged, &[msg(1, b"forged")]);
        assert_eq!(
            fx.deliver(frame).await,
            Delivery::Dropped(Dropped::TooFar),
            "seq0 {forged} (forgery {n})"
        );
    }
    assert_eq!(fx.stats().too_far.get(), 3);
    assert_eq!(fx.stats().too_old.get(), 0);
    // The genuine frames are still taken, in order and out of order.
    let second = fx.data(SideClass::Datagram, start + 1, &[msg(1, b"second")]);
    assert_eq!(
        fx.deliver(second).await,
        Delivery::Delivered { messages: 1 }
    );
    // The most a frame may jump is taken: a quiet stretch of 2^24 sequences, then a frame.
    let at_the_bound = fx.data(
        SideClass::Datagram,
        start + 1 + bound,
        &[msg(1, b"after a gap")],
    );
    assert_eq!(
        fx.deliver(at_the_bound).await,
        Delivery::Delivered { messages: 1 }
    );
    let got = queued(&mut fx.items);
    assert_eq!(got.len(), 1, "Latest keeps the newest message of the name");
    assert_eq!(&got[0].bytes[..], b"after a gap");
}

/// A receiver cut off for more than 2^24 sequences sees an authentic frame it must refuse; the
/// refusal asks the sender again, and the answer's `S_SEQ` moves the floor, so the next frame
/// is taken: the receiver is not stuck until the session ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_receiver_cut_off_beyond_the_bound_takes_the_senders_sequence_from_its_next_answer() {
    let mut fx = latest().await;
    let start = fx.start();
    let tx = fx
        .bob()
        .inner
        .chan
        .tx
        .get(&space(), ChannelMode::Latest)
        .expect("bob's sender exists once he answered");
    let gone = 3 * SEQ_JUMP_MAX;
    tx.skip_sequences(gone);
    let frame = fx.data(SideClass::Datagram, start + gone, &[named(1, A, b"back")]);
    assert_eq!(
        fx.deliver(frame.clone()).await,
        Delivery::Dropped(Dropped::TooFar)
    );
    let session = fx.carol().inner.chan.sessions.get(fx.info.channel).unwrap();
    eventually("the sender's answer moved the floor", || {
        session.seq() >= start + gone
    })
    .await;
    assert_eq!(
        fx.deliver(frame).await,
        Delivery::Delivered { messages: 1 },
        "the same frame is taken once the answer said where the sender is"
    );
    assert_eq!(queued(&mut fx.items).len(), 1);
}

/// The same bound for `Latest`'s per-name comparison: a replayed or standing message whose
/// original sequence is a number no genuine message has yet reached is refused with its frame,
/// so it cannot mute the name for the genuine messages that follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_original_sequence_does_not_mute_a_name_in_latest() {
    let mut fx = latest().await;
    let start = fx.start();
    let mut plain = vec![0x01 | 0x08];
    super::varint::write(&mut plain, 1 << 60).unwrap();
    plain.extend_from_slice(&[1, 3, 0x08, 0x01, b'a', 1, b'x']);
    let header = Header::new(
        SideClass::Datagram,
        SideKind::Data,
        fx.info.channel,
        fx.epoch(),
        start,
        1,
    )
    .unwrap();
    let forged = seal(&fx.cipher, &header, &plain).unwrap();
    assert_eq!(
        fx.deliver(forged).await,
        Delivery::Dropped(Dropped::Malformed)
    );
    let genuine = fx.data(SideClass::Datagram, start + 1, &[named(1, A, b"genuine")]);
    assert_eq!(
        fx.deliver(genuine).await,
        Delivery::Delivered { messages: 1 }
    );
    let got = queued(&mut fx.items);
    assert_eq!(got.len(), 1);
    assert_eq!(&got[0].bytes[..], b"genuine");
}

// -- End to end: the real sender over a carrier that loses, duplicates and reorders -------------

/// Bob's node sends over a [`Link`]; Carol's receives what the test hands over from it.
pub(super) struct Wire {
    pub(super) rig: Rig,
    pub(super) link: std::sync::Arc<Link>,
}

async fn wire(cfg: LinkConfig) -> Wire {
    let rig = rig_of(world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await).await;
    shared(&rig).await;
    let link = Link::new(cfg);
    rig.nodes[1].attach_carrier(link.clone());
    Wire { rig, link }
}

impl Wire {
    pub(super) fn bob(&self) -> Heap {
        self.rig.nodes[1].space(&space()).unwrap()
    }

    pub(super) fn carol(&self) -> &Node {
        &self.rig.nodes[2]
    }

    /// Stop bob's maintenance pass. It announces a channel that was never announced, and carol,
    /// listening, answers an announce with an ask made as new while her own ask is in flight:
    /// the sender welcomes it as a claim, which takes the channel's one replay a second
    /// (channel.md 13.7), so a re-ask for a gap in the same second is answered without a replay.
    /// A test that counts on its own asks keeps the pass still.
    fn pause_bob_tick(&self) {
        self.rig.nodes[1]
            .inner
            .chan
            .tick_paused
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn items(&self, opts: GetOptions) -> Items {
        self.carol()
            .space(&space())
            .unwrap()
            .get(
                everything(),
                GetOptions {
                    kept: false,
                    ..opts
                },
            )
            .unwrap()
    }

    /// Carol asks bob for his channel of `mode`.
    pub(super) async fn join(&self, mode: ChannelMode) -> ChannelInfo {
        self.carol()
            .ask_channel_in(&space(), self.rig.nodes[1].name(), mode)
            .await
            .expect("bob is a writer")
    }

    /// What opens the frames of bob's channel of `mode`: lets the test see what reached Carol.
    fn cipher(&self, mode: ChannelMode, channel: u64) -> FrameCipher {
        let key = self.rig.nodes[1]
            .inner
            .chan
            .channels
            .current(&space(), mode)
            .unwrap();
        let aead = self
            .carol()
            .inner
            .chan
            .sessions
            .get(channel)
            .unwrap()
            .terms()
            .aead;
        FrameCipher::new(&key.frame_key, aead)
    }

    /// Hand Carol every frame the link holds (the stream first, then the datagrams), as `seen`
    /// lets each be looked at on its way. Returns how many.
    pub(super) async fn pump(&self, mut seen: impl FnMut(&Bytes)) -> usize {
        let mut count = 0;
        while let Some(frame) = self.link.pop_stream() {
            seen(&frame);
            self.carol().deliver_frame(frame, 1).await;
            count += 1;
        }
        while let Some(frame) = self.link.pop_datagram() {
            seen(&frame);
            self.carol().deliver_frame(frame, 1).await;
            count += 1;
        }
        count
    }
}

/// The (name index, value) pairs of a `DATA` frame's messages: a message's payload is the index of
/// its name and a counter.
fn values_of(cipher: &FrameCipher, frame: &Bytes) -> Vec<(u8, u64)> {
    if frame.get(1).map(|b| b & 0x0f) != Some(0) {
        return Vec::new();
    }
    let opened = open(cipher, frame.clone(), STREAM_FRAME_DEFAULT).expect("a frame bob sealed");
    opened
        .messages(MESSAGE_DEFAULT)
        .unwrap()
        .map(|m| {
            let m = m.unwrap();
            (
                m.payload[0],
                u64::from_le_bytes(m.payload[1..9].try_into().unwrap()),
            )
        })
        .collect()
}

fn value_payload(index: u8, value: u64) -> Bytes {
    let mut v = vec![index];
    v.extend_from_slice(&value.to_le_bytes());
    Bytes::from(v)
}

fn value_of(got: &Got) -> (u8, u64) {
    (
        got.bytes[0],
        u64::from_le_bytes(got.bytes[1..9].try_into().unwrap()),
    )
}

/// The profile of the e8 case: 20 % of the datagrams lost, 10 % duplicated, 30 % reordered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latest_delivers_the_newest_per_name_under_loss_duplication_and_reorder() {
    let w = wire(LinkConfig {
        seed: 7,
        loss: 200,
        duplicate: 100,
        reorder: 300,
        ..LinkConfig::default()
    })
    .await;
    let mut items = w.items(GetOptions::default());
    let info = w.join(ChannelMode::Latest).await;
    let cipher = w.cipher(ChannelMode::Latest, info.channel);
    let bob = w.bob();
    let names: Vec<Name> = (0..5).map(|i| n(&format!("/cursor/{i}"))).collect();

    let mut arrived: Vec<(u8, u64)> = Vec::new();
    let mut delivered: Vec<Vec<u64>> = vec![Vec::new(); 5];
    let mut counter = [0u64; 5];
    for round in 0..60usize {
        for k in 0..8usize {
            let index = (round * 8 + k) % 5;
            counter[index] += 1;
            bob.emit(
                &names[index],
                value_payload(index as u8, counter[index]),
                EmitOptions::latest(),
            )
            .await
            .unwrap();
        }
        w.pump(|frame| arrived.extend(values_of(&cipher, frame)))
            .await;
        while let Some(Some(item)) = items.next().now_or_never() {
            let got = item.expect("Latest says nothing of gaps");
            let (index, value) = value_of(&got);
            assert_eq!(
                got.path, names[index as usize],
                "the name of the id is the name sent"
            );
            delivered[index as usize].push(value);
        }
    }

    let stats = w.link.stats();
    assert!(
        stats.lost > 0 && stats.duplicated > 0 && stats.reordered > 0,
        "the link misbehaved: {stats:?}"
    );
    for index in 0..5u8 {
        let seen = &delivered[index as usize];
        assert!(!seen.is_empty(), "name {index} delivered nothing");
        for pair in seen.windows(2) {
            assert!(
                pair[0] < pair[1],
                "name {index}: {} came after {}: an older or repeated value was delivered",
                pair[1],
                pair[0]
            );
        }
        let newest = arrived
            .iter()
            .filter(|(i, _)| *i == index)
            .map(|(_, v)| *v)
            .max();
        assert_eq!(
            seen.last().copied(),
            newest,
            "name {index}: the last value delivered is the newest that reached the receiver"
        );
        for value in seen {
            assert!(
                arrived.contains(&(index, *value)),
                "{value} never reached the receiver"
            );
        }
    }
    assert!(
        w.carol().inner.chan.stats.rx.replayed.get() > 0,
        "the duplicated frames were dropped before the AEAD"
    );
}

/// `Drop` at the sender: the oldest queued messages are discarded, their sequences are never sent,
/// and the receiver says exactly how many are missing, in the place they are missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_with_drop_reports_a_gap() {
    let w = wire(LinkConfig {
        stream_window: 1,
        ..LinkConfig::default()
    })
    .await;
    let mut items = w.items(GetOptions::default());
    w.join(ChannelMode::Reliable).await;
    let bob = w.bob();
    let path = n("/big");
    let emitted = 8u8;
    for i in 0..emitted {
        let mut bytes = vec![i];
        bytes.resize(400 * 1024, 0);
        bob.emit(
            &path,
            Bytes::from(bytes),
            EmitOptions::reliable().on_congestion(Congestion::Drop),
        )
        .await
        .unwrap();
    }
    let started = std::time::Instant::now();
    let (mut got, mut missed) = (Vec::new(), 0u64);
    while !got.contains(&(emitted - 1)) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "got {got:?}, missed {missed}"
        );
        w.pump(|_| {}).await;
        while let Some(Some(item)) = items.next().now_or_never() {
            match item {
                Ok(g) => got.push(g.bytes[0]),
                Err(GetNotice::Lagged { missed: m }) => missed += m,
                Err(other) => panic!("{other:?}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        missed >= 1,
        "the sender dropped messages and the receiver did not say so: {got:?}"
    );
    assert!(
        got.windows(2).all(|p| p[0] < p[1]),
        "in the channel's order: {got:?}"
    );
    assert_eq!(
        got.len() as u64 + missed,
        u64::from(emitted),
        "every message was delivered or counted missing: delivered {got:?}, missed {missed}"
    );
}

/// A joiner gets the window on the stream before live frames, and a frame lost inside what follows
/// is asked for again and recovered once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn window_replays_to_a_late_joiner_and_a_gap_inside_it_is_recovered() {
    let w = wire(LinkConfig::default()).await;
    w.pause_bob_tick();
    let bob = w.bob();
    let path = n("/chat");
    let opts = EmitOptions::window(super::verbs::Window::DEFAULT);
    // Five lines are said before anybody listens: the window keeps them.
    for i in 0..5u8 {
        bob.emit(&path, Bytes::from(vec![b'w', i]), opts)
            .await
            .unwrap();
    }
    let mut items = w.items(GetOptions::default());
    w.join(ChannelMode::Window).await;
    w.pump(|_| {}).await;
    let mut lines = Vec::new();
    while let Some(Some(item)) = items.next().now_or_never() {
        let got = item.expect("no gap in the replay");
        lines.push((got.bytes[1], seq_of(&got)));
    }
    assert_eq!(
        lines.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
        [0, 1, 2, 3, 4],
        "the window is replayed in order to the joiner"
    );
    assert!(
        lines.windows(2).all(|p| p[0].1 < p[1].1),
        "with their original sequences: {lines:?}"
    );

    // Three live lines: the stream loses the middle one on its way.
    let mut frames = Vec::new();
    for i in 5..8u8 {
        bob.emit(&path, Bytes::from(vec![b'w', i]), opts)
            .await
            .unwrap();
        let waited = std::time::Instant::now();
        loop {
            if let Some(frame) = w.link.pop_stream() {
                frames.push(frame);
                break;
            }
            assert!(
                waited.elapsed() < Duration::from_secs(5),
                "the line {i} never left"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    assert_eq!(frames.len(), 3, "one frame a line when the link is idle");
    w.carol().deliver_frame(frames[0].clone(), 1).await;
    w.carol().deliver_frame(frames[2].clone(), 1).await;
    // The gap is told, in its place, and Carol asks bob for it again.
    let mut seen = Vec::new();
    let started = std::time::Instant::now();
    while !seen.contains(&"w6".to_string()) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "recovered nothing: {seen:?}"
        );
        w.pump(|_| {}).await;
        while let Some(Some(item)) = items.next().now_or_never() {
            seen.push(match item {
                Ok(g) => format!("w{}", g.bytes[1]),
                Err(GetNotice::Lagged { missed }) => format!("lagged {missed}"),
                Err(other) => panic!("{other:?}"),
            });
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Let a duplicate replay (the window sent again from the gap) arrive and be dropped.
    tokio::time::sleep(Duration::from_millis(200)).await;
    w.pump(|_| {}).await;
    while let Some(Some(item)) = items.next().now_or_never() {
        seen.push(match item {
            Ok(g) => format!("w{}", g.bytes[1]),
            Err(GetNotice::Lagged { missed }) => format!("lagged {missed}"),
            Err(other) => panic!("{other:?}"),
        });
    }
    assert_eq!(
        seen,
        ["w5", "lagged 1", "w7", "w6"],
        "the gap is told where it is; the lost line comes back once, with the line after it not twice"
    );
    assert!(w.carol().inner.chan.stats.rx.reasks.get() >= 1);
}

/// The receiver half: a datagram that passed its `BIND` carries its name, so it is delivered with
/// the stream still unread; and a bare id that follows is known by what the datagram bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_that_overtakes_its_bind_carries_its_name() {
    let w = wire(LinkConfig::default()).await;
    let mut items = w.items(GetOptions::default());
    w.join(ChannelMode::Latest).await;
    let bob = w.bob();
    let path = n("/pointer/x");
    for i in 0..3u8 {
        bob.emit(&path, value_payload(0, u64::from(i)), EmitOptions::latest())
            .await
            .unwrap();
    }
    // The datagrams reach Carol; the stream (HELLO, BIND) has not been read yet.
    let mut datagrams = 0;
    while let Some(frame) = w.link.pop_datagram() {
        w.carol().deliver_frame(frame, 1).await;
        datagrams += 1;
    }
    assert!(datagrams >= 1);
    let got = queued(&mut items);
    assert!(
        !got.is_empty(),
        "the datagrams were delivered before the stream was read"
    );
    assert!(
        got.iter().all(|g| g.path == path),
        "each carries its name: {got:?}"
    );
    assert_eq!(value_of(got.last().unwrap()).1, 2, "the newest");
    assert_eq!(w.carol().inner.chan.stats.rx.unknown_name.get(), 0);

    // Past the 200 ms the sender names messages in full, a message goes bare. Its id is bound
    // already (by the datagram's own name), and the late BIND on the stream changes nothing.
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob.emit(&path, value_payload(0, 3), EmitOptions::latest())
        .await
        .unwrap();
    while let Some(frame) = w.link.pop_datagram() {
        w.carol().deliver_frame(frame, 1).await;
    }
    while let Some(frame) = w.link.pop_stream() {
        w.carol().deliver_frame(frame, 1).await;
    }
    let got = queued(&mut items);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].path.clone(), value_of(&got[0]).1), (path, 3));
    assert_eq!(w.carol().inner.chan.stats.rx.unknown_name.get(), 0);
    assert!(
        w.carol().inner.chan.stats.rx.hellos.get() >= 1,
        "the stream said hello"
    );
}

// -- The sender's END ------------------------------------------------------------------------------

/// Hand `carol` what `link` holds (the datagrams first, then the stream) until the `Items` say the
/// live part ended, and return what they yielded: `m<first octet>` for a message, the notice for
/// the end.
async fn until_ended(link: &Link, carol: &Node, items: &mut Items) -> Vec<String> {
    let started = std::time::Instant::now();
    let mut told = Vec::new();
    loop {
        while let Some(frame) = link.pop_datagram() {
            carol.deliver_frame(frame, 1).await;
        }
        while let Some(frame) = link.pop_stream() {
            carol.deliver_frame(frame, 1).await;
        }
        while let Some(Some(item)) = items.next().now_or_never() {
            match item {
                Ok(got) => told.push(format!("m{}", got.bytes[0])),
                Err(GetNotice::LiveEnded(LiveEnd::Ended { writer, reason })) => {
                    told.push(format!("ended {writer} {reason:?}"));
                    return told;
                }
                Err(other) => panic!("{other:?}"),
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the live part did not end within 5 s of the sender's close (the sender sent no END); \
             told so far: {told:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// What a close of bob's channel of `mode` says to a receiver: what was sent first, then the end.
async fn a_close_is_told_after_the_queued_messages(mode: ChannelMode, opts: EmitOptions) {
    let w = wire(LinkConfig::default()).await;
    let mut items = w.items(GetOptions::default());
    w.join(mode).await;
    let bob = w.bob();
    for i in 0..3u8 {
        bob.emit(&n(&format!("/m/{i}")), Bytes::from(vec![i]), opts)
            .await
            .unwrap();
    }
    assert!(w.rig.nodes[1].inner.chan_close(&space(), mode));
    let told = until_ended(&w.link, w.carol(), &mut items).await;
    assert_eq!(
        told,
        ["m0", "m1", "m2", "ended /bob/phone Closed"],
        "the messages first, then the end with its reason"
    );
    assert!(
        w.carol().inner.chan.sessions.all().is_empty(),
        "the receiver's session is gone"
    );
    assert!(w.carol().inner.chan.stats.rx.controls.get() >= 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_a_latest_channel_ends_the_receivers_live_part_after_its_messages() {
    a_close_is_told_after_the_queued_messages(ChannelMode::Latest, EmitOptions::latest()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_a_reliable_channel_ends_the_receivers_live_part_after_its_messages() {
    a_close_is_told_after_the_queued_messages(ChannelMode::Reliable, EmitOptions::reliable()).await;
}

/// Every channel of a space ends with one `END` each (a device that is no writer any more ends
/// its channels of the space).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_a_space_ends_each_of_its_channels_with_an_end() {
    let w = wire(LinkConfig::default()).await;
    let mut latest = w.items(GetOptions::default());
    w.join(ChannelMode::Latest).await;
    w.join(ChannelMode::Reliable).await;
    w.rig.nodes[1].inner.chan_close_space(&space());
    let told = until_ended(&w.link, w.carol(), &mut latest).await;
    assert_eq!(told, ["ended /bob/phone Closed"]);
    let started = std::time::Instant::now();
    while !w.carol().inner.chan.sessions.all().is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a channel of the space got no END"
        );
        while let Some(frame) = w.link.pop_stream() {
            w.carol().deliver_frame(frame, 1).await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Closing the sender's node tells its receivers, returns, and leaves no task behind: `close`
/// returns once every task of the node has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_senders_node_ends_its_channels_with_end_and_returns() {
    let mut w = wire(LinkConfig::default()).await;
    let mut items = w.items(GetOptions::default());
    w.join(ChannelMode::Reliable).await;
    let bob = w.bob();
    for i in 0..2u8 {
        bob.emit(&n("/m"), Bytes::from(vec![i]), EmitOptions::reliable())
            .await
            .unwrap();
    }
    drop(bob);
    let node = w.rig.nodes.remove(1);
    tokio::time::timeout(Duration::from_secs(10), node.close())
        .await
        .expect("close returns when every task of the node has ended, END or not");
    let told = until_ended(&w.link, &w.rig.nodes[1], &mut items).await;
    assert_eq!(told, ["m0", "m1", "ended /bob/phone Closed"]);
}

// -- Frames that overtake the session --------------------------------------------------------------

/// The sender queues `HELLO`, the binds, the standing values and the window's replay when it builds
/// the session Data, and the stream carries them on its own path: they can reach the receiver
/// before it has installed the session. A `Window` joiner that lost them has lost them for good (a
/// stream frame cannot be asked for again), so the receiver holds the frames of a channel it holds
/// no session of yet, and takes them in order when the session is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_frames_that_overtake_the_session_are_not_lost_to_a_window_joiner() {
    use ndn_packet::{Data, Interest};

    use super::answer::ChanAnswer;
    use super::wire::{ChanAsk, carrier};

    let w = wire(LinkConfig::default()).await;
    let bob = w.bob();
    let opts = EmitOptions::window(super::verbs::Window::DEFAULT);
    for i in 0..3u8 {
        bob.emit(&n("/chat"), Bytes::from(vec![b'w', i]), opts)
            .await
            .unwrap();
    }
    bob.emit(
        &n("/who"),
        Bytes::from_static(b"here"),
        opts.standing(Duration::from_secs(30)),
    )
    .await
    .unwrap();
    let mut items = w.items(GetOptions::default());

    // Carol's ask, answered by Bob; the Data is not handed to Carol yet.
    let (bob_node, carol) = (&w.rig.nodes[1], w.carol());
    let ask = ChanAsk {
        space: space(),
        prefix: Name::root(),
        mode: ChannelMode::Window,
        recipient: carol.recipient().public(),
        carriers: vec![carrier::DATAGRAM, carrier::STREAM],
        lifetime: 3600,
        epoch: None,
        since: None,
        new: false,
        chain: carol.inner.signer_chain(),
    };
    let wire_ask = carol
        .inner
        .sign_ask(bob_node.name(), &ask.encode().unwrap())
        .unwrap();
    let interest = Interest::decode(wire_ask).unwrap();
    let name = (*interest.name).clone();
    let generation = carol.inner.judge.generation();
    let ChanAnswer::Session { wire: answer, .. } =
        bob_node.inner.chan_answer(&interest, None).await
    else {
        panic!("a member's ask is answered");
    };
    let data = Data::decode(answer).unwrap();

    // What Bob queued with the answer reaches Carol first.
    let sender = bob_node
        .inner
        .chan
        .tx
        .get(&space(), ChannelMode::Window)
        .expect("bob's sender of the channel");
    let started = std::time::Instant::now();
    while !sender.is_idle() {
        assert!(started.elapsed() < Duration::from_secs(5), "bob wrote it");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let mut early = 0;
    while let Some(frame) = w.link.pop_stream() {
        carol.deliver_frame(frame, 1).await;
        early += 1;
    }
    assert!(
        early >= 3,
        "hello, the binds, the standing bracket and the replay: {early} frames"
    );
    assert!(
        queued(&mut items).is_empty(),
        "no session yet: nothing delivered"
    );

    // The session Data arrives.
    carol
        .inner
        .chan_take_answer(
            &space(),
            bob_node.name(),
            ChannelMode::Window,
            &name,
            data,
            generation,
            &carol
                .inner
                .chan
                .sessions
                .asking(&space(), ChannelMode::Window),
        )
        .await
        .expect("the session is installed");
    let mut got: Vec<(String, Vec<u8>)> = queued(&mut items)
        .into_iter()
        .map(|g| (g.path.to_string(), g.bytes.to_vec()))
        .collect();
    got.sort();
    got.dedup();
    let stats = &carol.inner.chan.stats.rx;
    assert_eq!(
        got,
        [
            ("/chat".to_string(), vec![b'w', 0]),
            ("/chat".to_string(), vec![b'w', 1]),
            ("/chat".to_string(), vec![b'w', 2]),
            ("/who".to_string(), b"here".to_vec()),
        ],
        "the joiner got the window's replay and the standing value that came before its session \
         (early {early}; held expired {}, full {}, evicted {}; unknown_channel {}, replayed {}, \
         too_old {}, unauthentic {}, malformed {}, accepted {}, messages {}, unknown_epoch {})",
        stats.held_unknown_expired.get(),
        stats.held_unknown_full.get(),
        stats.held_unknown_evicted.get(),
        stats.unknown_channel.get(),
        stats.replayed.get(),
        stats.too_old.get(),
        stats.unauthentic.get(),
        stats.malformed.get(),
        stats.accepted.get(),
        stats.messages.get(),
        stats.unknown_epoch.get(),
    );
    assert!(items.hello_seen(), "and the HELLO");
    assert_eq!(
        (
            stats.held_unknown_full.get(),
            stats.held_unknown_expired.get()
        ),
        (0, 0)
    );
    assert_eq!(
        carol.inner.chan.rx.unknown_held(),
        (0, 0),
        "the hold is empty"
    );
}

/// The hold of frames of an unknown channel is bounded in frames (per face and in all) and in
/// time, and a frame of a session this device holds never goes into it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_of_an_unknown_channel_are_held_in_bounds_and_expire() {
    let fx = latest().await;
    fx.pause_tick();
    let genuine = fx.data(SideClass::Datagram, 1, &[named(1, A, b"x")]);
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    let t0 = Instant::now();

    // Four faces hold their 16 frames each: 64 in all. A face's 17th is dropped and counted.
    let mut id = 0u64;
    for face in 1..=4u64 {
        for _ in 0..16 {
            id += 1;
            assert_eq!(
                fx.deliver_from(early(&fx, SideClass::Stream, id, 0), face, t0)
                    .await,
                Delivery::Held,
                "frame {id} of face {face}"
            );
        }
    }
    assert_eq!(rx.unknown_held().0, 64);
    assert_eq!(
        fx.deliver_from(early(&fx, SideClass::Stream, 65, 0), 1, t0)
            .await,
        Delivery::Dropped(Dropped::UnknownChannel)
    );
    assert_eq!(stats.held_unknown_full.get(), 1);
    assert_eq!(rx.unknown_held().0, 64, "the hold did not grow");
    assert_eq!(stats.aead_attempts.get(), 0, "a held frame is never opened");

    // A frame of the session this device holds is not held: it is taken.
    assert!(matches!(
        fx.deliver_at(genuine.clone(), t0 + Duration::from_secs(1))
            .await,
        Delivery::Delivered { .. }
    ));
    assert_eq!(rx.unknown_held().0, 64);

    // Past 2 s each is dropped and counted, swept by the next frame.
    let later = t0 + Duration::from_secs(3);
    assert_eq!(
        fx.deliver_from(early(&fx, SideClass::Stream, 100, 0), 1, later)
            .await,
        Delivery::Held
    );
    assert_eq!(stats.held_unknown_expired.get(), 64);
    assert_eq!(rx.unknown_held().0, 1);
}

/// A frame of a channel nobody holds, as the stream carries it: the id patched into a sealed
/// frame's header and the frame padded to `len` (a held frame is never opened).
fn early(fx: &Fx, class: SideClass, id: u64, len: usize) -> Bytes {
    let mut v = fx.data(class, 1, &[named(1, A, b"x")]).to_vec();
    assert_ne!(id, fx.info.channel, "an id nobody holds");
    v[2..10].copy_from_slice(&id.to_be_bytes());
    v.resize(len.max(v.len()), 0);
    Bytes::from(v)
}

/// One face that floods the node with frames of unknown channels must not stop another face's
/// early frames from being held (security review M3): the hold is shared by faces fairly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_from_one_face_does_not_stop_another_faces_early_frames() {
    let fx = latest().await;
    fx.pause_tick();
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    let t0 = Instant::now();
    // Face 1 sends 200 frames of random channel ids: 1 KiB each.
    for id in 1_000..1_200u64 {
        fx.deliver_from(early(&fx, SideClass::Stream, id, 1_024), 1, t0)
            .await;
    }
    // Face 2's session comes, and its HELLO, a bind and a standing value come ahead of the Data.
    for seq in 0..8u64 {
        assert_eq!(
            fx.deliver_from(early(&fx, SideClass::Stream, 5, 200 + seq as usize), 2, t0)
                .await,
            Delivery::Held,
            "face 2's early frame {seq}, behind face 1's flood of {} held and {} refused",
            rx.unknown_held().0,
            stats.held_unknown_full.get()
        );
    }
    assert!(
        stats.held_unknown_full.get() > 0,
        "face 1's flood was refused, not all held"
    );
}

/// A datagram that is early is lost, as a datagram may be: the hold is for the stream's frames,
/// which cannot be asked for again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_datagram_of_an_unknown_channel_is_dropped_not_held() {
    let fx = latest().await;
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    assert_eq!(
        fx.deliver(early(&fx, SideClass::Datagram, 5, 0)).await,
        Delivery::Dropped(Dropped::UnknownChannel)
    );
    assert_eq!(rx.unknown_held(), (0, 0), "nothing was held");
    assert_eq!(stats.unknown_channel.get(), 1);
    assert_eq!(
        stats.held_unknown_full.get(),
        0,
        "it was not refused for room"
    );
}

/// The hold covers the frame the faces grant the stream (1 MiB): a window's replay is a frame of
/// that size, and the sender packs to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_frame_of_the_grant_can_be_held() {
    let fx = latest().await;
    fx.pause_tick();
    let rx = &fx.carol().inner.chan.rx;
    let grant = ndn_transport::side_header::STREAM_FRAME_GRANT;
    assert_eq!(
        fx.deliver(early(&fx, SideClass::Stream, 5, grant)).await,
        Delivery::Held,
        "a frame of {grant} octets"
    );
    assert_eq!(rx.unknown_held(), (1, grant));
}

/// One face holds at most 16 frames and 2 MiB, whatever room the node has left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_face_holds_at_most_16_frames_and_two_grants() {
    let fx = latest().await;
    fx.pause_tick();
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    let t0 = Instant::now();
    let grant = ndn_transport::side_header::STREAM_FRAME_GRANT;
    for id in 1_000..1_020u64 {
        fx.deliver_from(early(&fx, SideClass::Stream, id, 200), 1, t0)
            .await;
    }
    assert_eq!(rx.unknown_held_by(1).0, 16, "16 of 20 frames of one face");
    assert_eq!(stats.held_unknown_full.get(), 4, "the other 4 were refused");
    assert_eq!(
        stats.held_unknown_evicted.get(),
        0,
        "and nothing was pushed out"
    );
    // Another face: 2 MiB in frames of the grant, the third is refused.
    let mut verdicts = Vec::new();
    for id in 2_000..2_003u64 {
        let frame = early(&fx, SideClass::Stream, id, grant);
        verdicts.push(fx.deliver_from(frame, 2, t0).await);
    }
    assert_eq!(
        verdicts,
        [
            Delivery::Held,
            Delivery::Held,
            Delivery::Dropped(Dropped::UnknownChannel)
        ],
        "face 2's three frames of {grant} octets"
    );
    assert_eq!(rx.unknown_held_by(2), (2, 2 * grant));
}

/// The node's hold is full: a frame of a face that holds less pushes out the oldest frame of the
/// face that holds most; a frame of a face that holds as much as any other is the one refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_hold_pushes_out_the_oldest_frame_of_the_face_that_holds_most() {
    let fx = latest().await;
    fx.pause_tick();
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    let t0 = Instant::now();
    let mut id = 1_000u64;
    // Faces 1 to 4 hold 15 frames each and face 5 four: 64, the node's bound.
    for (face, frames) in [(1u64, 15), (2, 15), (3, 15), (4, 15), (5, 4)] {
        for _ in 0..frames {
            id += 1;
            let held = fx
                .deliver_from(early(&fx, SideClass::Stream, id, 200), face, t0)
                .await;
            assert_eq!(held, Delivery::Held, "face {face}");
        }
    }
    assert_eq!(rx.unknown_held().0, 64);
    let mut send = async |face: u64| {
        id += 1;
        fx.deliver_from(early(&fx, SideClass::Stream, id, 200), face, t0)
            .await
    };
    // Face 1 holds as much as any face: its own frame is the one refused.
    assert_eq!(send(1).await, Delivery::Dropped(Dropped::UnknownChannel));
    assert_eq!(
        (
            stats.held_unknown_full.get(),
            stats.held_unknown_evicted.get()
        ),
        (1, 0)
    );
    // Face 5 holds 4: its frame pushes out the oldest frame of the faces that hold 15, face 1's.
    assert_eq!(send(5).await, Delivery::Held);
    assert_eq!(stats.held_unknown_evicted.get(), 1);
    assert_eq!(
        [1, 2, 3, 4, 5].map(|face| rx.unknown_held_by(face).0),
        [14, 15, 15, 15, 5]
    );
    // Face 1 holds 14, below faces 2 to 4: its frame pushes out face 2's oldest.
    assert_eq!(send(1).await, Delivery::Held);
    assert_eq!(stats.held_unknown_evicted.get(), 2);
    assert_eq!(
        [1, 2, 3, 4, 5].map(|face| rx.unknown_held_by(face).0),
        [15, 14, 15, 15, 5]
    );
    assert_eq!(rx.unknown_held().0, 64, "the hold stayed at its bound");
    assert_eq!(stats.aead_attempts.get(), 0, "a held frame is never opened");
}

/// The same in octets: the node holds 4 MiB, and a frame of the grant from a third face gets room
/// by pushing out one of the two frames of a face that holds 2 MiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_hold_in_octets_makes_room_for_a_frame_of_the_grant() {
    let fx = latest().await;
    fx.pause_tick();
    let (stats, rx) = (fx.stats(), &fx.carol().inner.chan.rx);
    let t0 = Instant::now();
    let grant = ndn_transport::side_header::STREAM_FRAME_GRANT;
    let mut id = 1_000u64;
    for face in [1u64, 2] {
        for _ in 0..2 {
            id += 1;
            let held = fx
                .deliver_from(early(&fx, SideClass::Stream, id, grant), face, t0)
                .await;
            assert_eq!(held, Delivery::Held, "face {face}");
        }
    }
    assert_eq!(rx.unknown_held(), (4, 4 * grant));
    assert_eq!(
        fx.deliver_from(early(&fx, SideClass::Stream, 5, grant), 3, t0)
            .await,
        Delivery::Held,
        "a frame of the grant from a face that holds nothing"
    );
    assert_eq!(stats.held_unknown_evicted.get(), 1);
    assert_eq!(rx.unknown_held(), (4, 4 * grant));
    assert_eq!(
        [1, 2, 3].map(|face| rx.unknown_held_by(face).0),
        [1, 2, 1],
        "face 1 held the oldest of the largest shares"
    );
}

/// While the frames held for a session are taken in, a stream frame that arrives queues behind
/// them: the channel takes frames directly only once the held ones are in, so the order of
/// arrival is kept. A datagram would overtake them, so it is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_that_arrives_while_held_frames_are_taken_in_queues_behind_them() {
    let mut fx = latest().await;
    let (node, channel) = (std::sync::Arc::clone(&fx.carol().inner), fx.info.channel);
    let rx = &node.chan.rx;
    let replay = rx.begin_replay(channel);
    assert_eq!(
        fx.deliver(fx.data(SideClass::Stream, 1, &[named(1, A, b"after")]))
            .await,
        Delivery::Held,
        "queued behind the replay, though the session is held"
    );
    assert_eq!(
        fx.deliver(fx.data(SideClass::Datagram, 2, &[named(1, A, b"overtaking")]))
            .await,
        Delivery::Dropped(Dropped::UnknownChannel),
        "a datagram is not queued: it is lost, as a datagram may be"
    );
    assert!(nothing(&mut fx.items), "and not delivered yet");
    node.chan_replay_held(channel, replay).await;
    assert_eq!(payload(&next(&mut fx.items).await.unwrap()), b"after");
    assert!(
        nothing(&mut fx.items),
        "the datagram was not delivered after it"
    );
    assert_eq!(rx.unknown_held(), (0, 0));
    // The replay is over: frames are taken directly again.
    assert!(matches!(
        fx.deliver(fx.data(SideClass::Datagram, 3, &[msg(1, b"direct")]))
            .await,
        Delivery::Delivered { .. }
    ));
}

// -- The steady state: no lookup per frame --------------------------------------------------

/// Once a channel has taken a frame, the next ones of it are taken with no lookup of the session
/// (the receiver keeps the channel while the sessions held stand still).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_steady_stream_of_frames_takes_no_session_lookup() {
    let fx = latest().await;
    fx.pause_tick();
    let sessions = &fx.carol().inner.chan.sessions;
    assert!(matches!(
        fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"x")]))
            .await,
        Delivery::Delivered { .. }
    ));
    let looked_up = sessions.lookups();
    for seq in 2..42 {
        assert!(matches!(
            fx.deliver(fx.data(SideClass::Datagram, seq, &[msg(1, b"y")]))
                .await,
            Delivery::Delivered { .. }
        ));
    }
    assert_eq!(
        sessions.lookups(),
        looked_up,
        "40 frames of a known channel looked the session up {} times",
        sessions.lookups() - looked_up
    );
}

/// What the receiver kept does not outlive the session: once it is dropped from the store the
/// next frame of its channel is one of an unknown channel, not taken: a stream frame is held, a
/// datagram is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_session_takes_no_frame_though_the_channel_was_kept() {
    let fx = latest().await;
    assert!(matches!(
        fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"x")]))
            .await,
        Delivery::Delivered { .. }
    ));
    fx.carol().inner.chan.sessions.remove(fx.info.channel);
    assert_eq!(
        fx.deliver(fx.data(SideClass::Stream, 2, &[msg(1, b"late")]))
            .await,
        Delivery::Held,
        "a stream frame of a channel whose session is gone is held, not delivered"
    );
    assert_eq!(
        fx.deliver(fx.data(SideClass::Datagram, 3, &[msg(1, b"later")]))
            .await,
        Delivery::Dropped(Dropped::UnknownChannel),
        "a datagram is lost, not delivered"
    );
}

/// A session installed over the held one (the same channel, renewed) is the one frames go to:
/// the channel kept for the old one is not used again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_installed_over_the_held_one_is_taken_up_by_the_next_frame() {
    let fx = latest().await;
    let sessions = &fx.carol().inner.chan.sessions;
    assert!(matches!(
        fx.deliver(fx.data(SideClass::Datagram, 1, &[named(1, A, b"x")]))
            .await,
        Delivery::Delivered { .. }
    ));
    let held = sessions.get(fx.info.channel).unwrap();
    let before = sessions.lookups();
    sessions
        .insert(held)
        .expect("the id is held by nobody else");
    assert!(matches!(
        fx.deliver(fx.data(SideClass::Datagram, 2, &[msg(1, b"again")]))
            .await,
        Delivery::Delivered { .. }
    ));
    assert!(
        sessions.lookups() > before,
        "the frame after an install looked the sessions up again"
    );
}

// -- A far-ahead frame on a channel with no checkpoints (security review M4) --------------------

/// One authentic frame at `highest + 2^24 - 1` (inside the jump bound) moved the replay window's
/// `highest` past every genuine frame still to come, and on a channel that sends no checkpoints
/// nothing ended it: no silence clock, no `TooFar` re-ask, every genuine frame `TooOld` until
/// the sender passed `highest - 4095` (hours at a thousand frames a second). The refusal of
/// genuine frames now asks the sender where it stands (its answer is signed); an answer that
/// puts the sender below the window's highest puts the window back at the sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_far_authentic_frame_does_not_mute_a_channel_without_checkpoints_for_good() {
    let fx = latest().await;
    let start = fx.start();
    let first = fx.data(SideClass::Datagram, start, &[named(1, A, b"first")]);
    assert_eq!(fx.deliver(first).await, Delivery::Delivered { messages: 1 });
    // A holder of the key seals one frame as far ahead as the bound lets it: it is taken.
    let far = fx.data(
        SideClass::Datagram,
        start + SEQ_JUMP_MAX - 1,
        &[msg(1, b"forged")],
    );
    assert_eq!(fx.deliver(far).await, Delivery::Delivered { messages: 1 });
    // The sender's own next frame is refused as too old at first; the receiver asks the sender
    // where it stands, and takes the frame once the answer put the window back.
    let genuine = fx.data(SideClass::Datagram, start + 1, &[named(1, A, b"second")]);
    let mut last = fx.deliver(genuine.clone()).await;
    for _ in 0..300 {
        if matches!(last, Delivery::Delivered { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        last = fx.deliver(genuine.clone()).await;
    }
    assert_eq!(
        last,
        Delivery::Delivered { messages: 1 },
        "the sender's next frame was refused for 15 s after one authentic far-ahead frame (too_old {})",
        fx.stats().too_old.get()
    );
    assert!(fx.stats().too_old.get() >= 1);
}
