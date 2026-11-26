//! The sender's frame layer without a node: a [`TxChannel`] over an in-memory [`Link`], its frames
//! opened with the channel's own key (docs/specs/channel.md, Batching, The name-id table, Modes,
//! Standing). The node-level tests are in `stage3_tests.rs`.

use std::collections::{BTreeMap, HashMap};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::{SideClass, SideKind};

use super::aead::{Aead, FrameCipher};
use super::alloc_probe::count_allocations;
use super::carrier::{Carrier, CarrierFuture, CarrierRefused, CarrierSlot};
use super::carrier_kit::{Link, LinkConfig};
use super::channels::{Live, SendKey};
use super::control::Control;
use super::frame;
use super::key::ChannelKey;
use super::limits::{MESSAGE_DEFAULT, MESSAGE_MAX, STREAM_FRAME_MAX};
use super::message::{Message, Origin};
use super::table::name_octets;
use super::tx::{
    BURST_GAP, KeySource, QUEUE_BYTES, Refused, SEQ_END, SINCE_REPLAY_EVERY, TxChannel, TxStats,
};
use super::verbs::{Congestion, EmitError, EmitOptions, Window};
use super::wire::ChannelMode;
use crate::rt::{Instant, Tasks};

const CHANNEL: u64 = 0x1122_3344_5566_7788;

struct Keys {
    key: SendKey,
    exhausted: AtomicBool,
}

impl KeySource for Keys {
    fn current(&self) -> Option<SendKey> {
        Some(self.key.clone())
    }
    fn exhausted(&self) {
        self.exhausted.store(true, Ordering::SeqCst);
    }
}

struct Rig {
    tx: Arc<TxChannel>,
    link: Arc<Link>,
    live: Arc<Live>,
    keys: Arc<Keys>,
    stats: Arc<TxStats>,
    dec: Decoder,
    t0: Instant,
}

/// Opens frames with the channel's key and remembers the names the frames bind.
struct Decoder {
    cipher: FrameCipher,
    names: HashMap<u64, Bytes>,
}

#[derive(Debug)]
enum Seen {
    Data {
        class: SideClass,

        count: u8,
        messages: Vec<Message>,
    },
    Control {
        seq: u64,
        control: Control,
    },
}

impl Decoder {
    fn read(&mut self, frame: Bytes) -> Seen {
        let opened =
            frame::open(&self.cipher, frame, STREAM_FRAME_MAX).expect("a frame that opens");
        let header = *opened.header();
        match header.kind {
            SideKind::Data => {
                let messages: Vec<Message> = opened
                    .messages(MESSAGE_MAX)
                    .expect("data")
                    .collect::<Result<_, _>>()
                    .expect("messages that parse");
                for m in &messages {
                    if let Some(name) = &m.name {
                        self.names.insert(m.name_id, name.clone());
                    }
                }
                Seen::Data {
                    class: header.class,

                    count: header.count,
                    messages,
                }
            }
            SideKind::Control => {
                let control = Control::decode(opened.plaintext()).expect("a control record");
                match &control {
                    Control::Bind { id, name } => {
                        self.names.insert(*id, name.clone());
                    }
                    Control::Unbind { id } => {
                        self.names.remove(id);
                    }
                    _ => {}
                }
                Seen::Control {
                    seq: header.seq0,
                    control,
                }
            }
            other => panic!("a {other:?} frame"),
        }
    }

    fn all(&mut self, frames: Vec<Bytes>) -> Vec<Seen> {
        frames.into_iter().map(|f| self.read(f)).collect()
    }
}

fn rig(mode: ChannelMode, cfg: LinkConfig) -> Rig {
    let live = Arc::new(Live::default());
    live.receivers.store(1, Ordering::SeqCst);
    let key = ChannelKey::random().frame_key(CHANNEL, 0);
    let send = SendKey {
        id: CHANNEL,
        key_epoch: 0,
        frame_key: key.clone(),
        live: Arc::clone(&live),
    };
    let link = Link::new(cfg);
    let slot = Arc::new(CarrierSlot::default());
    slot.set(link.clone());
    let keys = Arc::new(Keys {
        key: send.clone(),
        exhausted: AtomicBool::new(false),
    });
    let stats = Arc::new(TxStats::default());
    let tx = TxChannel::new(
        mode,
        &send,
        keys.clone(),
        Tasks::new(),
        slot,
        Arc::clone(&stats),
        Arc::new(AtomicU64::new(0)),
    );
    Rig {
        tx,
        link,
        live,
        keys,
        stats,
        dec: Decoder {
            cipher: FrameCipher::new(&key, Aead::preferred()),
            names: HashMap::new(),
        },
        t0: Instant::now(),
    }
}

fn name(i: usize) -> Name {
    Name::root().append(format!("n{i}"))
}

fn at(rig: &Rig, secs: u64) -> Instant {
    rig.t0 + Duration::from_secs(secs)
}

async fn settle(tx: &Arc<TxChannel>) {
    for _ in 0..500 {
        if tx.is_idle() {
            return;
        }
        tx.call_back();
        tokio::task::yield_now().await;
    }
    panic!("the channel did not go idle: {} waiting", tx.pending());
}

async fn send(rig: &Rig, path: &Name, payload: &[u8], opts: &EmitOptions, now: Instant) {
    rig.tx
        .emit(path, &Bytes::copy_from_slice(payload), opts, now)
        .await
        .expect("the emission is taken");
}

/// Use each name four times, so the next message under it is bare and the binds are written.
async fn prebind(rig: &mut Rig, names: std::ops::Range<usize>) {
    for i in names {
        for k in 0..4 {
            send(rig, &name(i), b"", &EmitOptions::latest(), at(rig, k)).await;
            let _ = rig.link.take_datagrams();
        }
    }
    settle(&rig.tx).await;
    let _ = rig.link.take_stream();
}

fn error_of(r: Result<(), Refused>) -> EmitError {
    match r {
        Err(Refused::Error(e)) => e,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn datagrams(rig: &mut Rig) -> Vec<Seen> {
    let frames = rig.link.take_datagrams();
    rig.dec.all(frames)
}

fn stream(rig: &mut Rig) -> Vec<Seen> {
    let frames = rig.link.take_stream();
    rig.dec.all(frames)
}

fn data_counts(seen: &[Seen]) -> Vec<u8> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Data { count, .. } => Some(*count),
            _ => None,
        })
        .collect()
}

fn messages(seen: &[Seen]) -> Vec<&Message> {
    seen.iter()
        .flat_map(|s| match s {
            Seen::Data { messages, .. } => messages.iter().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect()
}

fn controls(seen: &[Seen]) -> Vec<(u64, &Control)> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Control { seq, control } => Some((*seq, control)),
            _ => None,
        })
        .collect()
}

// ---- batching ------------------------------------------------------------------------------

#[tokio::test]
async fn one_message_leaves_alone_when_idle_and_messages_pack_when_busy() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    // Idle: every message leaves alone, as a frame of one, inline (the call returned with the
    // frame already on the link).
    for i in 0..10 {
        send(&rig, &name(i), b"hello", &latest, rig.t0).await;
        assert_eq!(
            rig.link.queued_datagrams(),
            1,
            "left inline, before the call returned"
        );
        let seen = datagrams(&mut rig);
        assert_eq!(data_counts(&seen), [1], "idle: a frame of one");
    }
    settle(&rig.tx).await;
    let frames = rig.stats.datagram_frames.get() + rig.stats.stream_frames.get();
    assert_eq!(
        rig.tx.sent_frames() as u64,
        frames,
        "every frame sent is in the ring"
    );

    // Busy: 600 names that were used four times already (so their messages are bare, 4 octets
    // with an empty payload) wait while the carrier is full, and leave packed.
    for round in 0..4 {
        for i in 0..600 {
            send(&rig, &name(100 + i), b"", &latest, at(&rig, round)).await;
            let _ = rig.link.take_datagrams();
        }
    }
    settle(&rig.tx).await;
    let _ = rig.link.take_stream();
    rig.link.set_full(true);
    for i in 0..600 {
        send(&rig, &name(100 + i), b"", &latest, at(&rig, 10)).await;
    }
    assert_eq!(
        rig.link.queued_datagrams(),
        0,
        "the carrier is full: nothing left"
    );
    rig.link.set_full(false);
    let seen = datagrams(&mut rig);
    assert_eq!(
        data_counts(&seen),
        [255, 255, 90],
        "up to 255 messages a frame, in the order of the sequences"
    );
    assert!(rig.link.stats().by_count.contains_key(&255));
    // Busy with a payload: frames fill the carrier's room.
    prebind(&mut rig, 1000..1300).await;
    rig.link.set_full(true);
    for i in 0..300 {
        send(&rig, &name(1000 + i), &[0u8; 64], &latest, at(&rig, 20)).await;
    }
    rig.link.set_full(false);
    let seen = datagrams(&mut rig);
    let counts = data_counts(&seen);
    assert_eq!(counts.iter().map(|c| *c as usize).sum::<usize>(), 300);
    assert!(
        counts[..counts.len() - 1].iter().all(|c| *c > 1),
        "a busy writer packs: {counts:?}"
    );
}

/// An emitter that does not stop between two emissions (a loop) must not make a frame of one for
/// each: the first leaves at once, the second (it follows within `BURST_GAP`) leaves too and asks
/// the carrier to call back, and the rest wait for that call and leave together. (An idle link
/// keeps its one-message latency and asks for nothing; a loop gets the batch.)
#[tokio::test]
async fn emissions_made_back_to_back_leave_in_one_frame_behind_the_first_two() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    prebind(&mut rig, 0..14).await;
    for i in 0..14 {
        send(&rig, &name(i), &[7u8; 64], &latest, at(&rig, 10)).await;
    }
    assert_eq!(
        rig.link.queued_datagrams(),
        2,
        "the first two left inline; the other 12 wait for the carrier to call back"
    );
    assert_eq!(rig.link.waiting_drains(), 1, "one call back is asked for");
    let seen = datagrams(&mut rig);
    assert_eq!(
        data_counts(&seen),
        [1, 1, 12],
        "the first two alone, then the rest in one frame"
    );
    assert_eq!(rig.link.waiting_drains(), 0);
    // And after the carrier called back, the next emission is a first again: inline.
    send(&rig, &name(0), &[7u8; 64], &latest, at(&rig, 11)).await;
    assert_eq!(rig.link.queued_datagrams(), 1);
    assert_eq!(data_counts(&datagrams(&mut rig)), [1]);
}

/// The cost of an emission is bounded by what the design says: the path is hashed once by the
/// name table, not once to find the id and again to use it.
#[tokio::test]
async fn an_emission_hashes_its_path_once() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    prebind(&mut rig, 0..1).await;
    let before = rig.tx.table_lookups();
    for k in 0..10 {
        send(&rig, &name(0), &[7u8; 64], &latest, at(&rig, 10 + k)).await;
        settle(&rig.tx).await;
    }
    assert_eq!(
        rig.tx.table_lookups() - before,
        10,
        "one hash of the path for each of 10 emissions"
    );
}

#[tokio::test]
async fn latest_never_blocks_and_block_is_refused_for_it() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    rig.link.set_full(true);
    let path = name(1);
    for i in 0..10_000u32 {
        let payload = Bytes::from(i.to_string());
        let mut call = pin!(rig.tx.emit(&path, &payload, &latest, rig.t0));
        assert!(
            matches!(futures::poll!(call.as_mut()), Poll::Ready(Ok(()))),
            "a Latest emission is done at its first poll, whatever the carrier does ({i})"
        );
    }
    assert_eq!(rig.stats.replaced.get(), 9_999, "one slot per name");
    rig.link.set_full(false);
    settle(&rig.tx).await;
    let seen = datagrams(&mut rig);
    let sent = messages(&seen);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].payload, Bytes::from_static(b"9999"), "the newest");

    let block = EmitOptions::latest().on_congestion(Congestion::Block);
    let refused = error_of(rig.tx.emit(&path, &Bytes::new(), &block, rig.t0).await);
    assert!(matches!(&refused, EmitError::FixRequest { why } if why.contains("Use Reliable")));
    assert_eq!(refused.next(), crate::NextStep::FixRequest);
}

#[tokio::test]
async fn reliable_blocks_the_sender_when_the_stream_is_full() {
    let mut rig = rig(
        ChannelMode::Reliable,
        LinkConfig {
            stream_window: 64 * 1024,
            ..LinkConfig::default()
        },
    );
    let opts = EmitOptions::reliable();
    let big = |i: u8| Bytes::from(vec![i; 100 * 1024]);
    let path = name(1);
    // 10 messages of 100 KiB fit the queue of 1 MiB.
    for i in 0..10u8 {
        rig.tx.emit(&path, &big(i), &opts, rig.t0).await.unwrap();
    }
    let payload = big(10);
    let mut eleventh = Box::pin(rig.tx.emit(&path, &payload, &opts, rig.t0));
    assert!(
        futures::poll!(eleventh.as_mut()).is_pending(),
        "the queue is full"
    );
    // The stream window is 64 KiB and holds the bind: the writer waits, so the sender does.
    for _ in 0..20 {
        tokio::task::yield_now().await;
        assert!(
            futures::poll!(eleventh.as_mut()).is_pending(),
            "still blocked on the stream"
        );
    }
    assert!(rig.link.queued_stream_bytes() < 64 * 1024);
    // The receiver reads the stream; the writer goes on; the sender is released.
    let mut got = Vec::new();
    let mut released = false;
    for _ in 0..200 {
        got.extend(rig.link.take_stream());
        tokio::task::yield_now().await;
        if !released && futures::poll!(eleventh.as_mut()).is_ready() {
            released = true;
        }
        if released && rig.tx.is_idle() {
            break;
        }
    }
    assert!(
        released,
        "the blocked emission completed once the stream moved"
    );
    settle(&rig.tx).await;
    got.extend(rig.link.take_stream());
    let seen = rig.dec.all(got);
    let all = messages(&seen);
    assert_eq!(all.len(), 11, "every message, none dropped");
    for (i, m) in all.iter().enumerate() {
        assert_eq!(m.payload[0], i as u8, "in order");
        assert_eq!(
            m.seq,
            2 + i as u64,
            "contiguous sequences after the bind (1)"
        );
    }
    assert_eq!(rig.stats.dropped.get(), 0);
}

#[tokio::test]
async fn reliable_with_drop_leaves_a_gap_and_says_congested_when_nothing_can_be_dropped() {
    let mut rig = rig(ChannelMode::Reliable, LinkConfig::default());
    let opts = EmitOptions::reliable().on_congestion(Congestion::Drop);
    let path = name(1);
    // Twelve of 100 KiB before the writer runs: the oldest two are dropped to make room.
    for i in 0..12u8 {
        rig.tx
            .emit(&path, &Bytes::from(vec![i; 100 * 1024]), &opts, rig.t0)
            .await
            .unwrap();
    }
    assert_eq!(rig.stats.dropped.get(), 2);
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let all = messages(&seen);
    assert_eq!(all.len(), 10);
    assert_eq!(all[0].payload[0], 2, "messages 0 and 1 were dropped");
    assert_eq!(
        all[0].seq, 4,
        "the bind took 1, the dropped messages 2 and 3: the gap a receiver sees"
    );
    let seqs: Vec<u64> = all.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, (4..14).collect::<Vec<_>>());

    // A frame in flight cannot be dropped: with the stream stalled and a 1 MiB message in it,
    // another one that does not fit is refused, with when to try again.
    let rig = self::rig(
        ChannelMode::Reliable,
        LinkConfig {
            stream_window: 1_000,
            ..LinkConfig::default()
        },
    );
    rig.tx
        .emit(
            &path,
            &Bytes::from(vec![1u8; MESSAGE_DEFAULT]),
            &opts,
            rig.t0,
        )
        .await
        .unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let refused = error_of(
        rig.tx
            .emit(&path, &Bytes::from(vec![0u8; 2_048]), &opts, rig.t0)
            .await,
    );
    assert!(
        matches!(refused, EmitError::Congested { retry_after } if retry_after > Duration::ZERO)
    );
    assert_eq!(refused.next(), crate::NextStep::RetryLater);
    // The refusal changed nothing: the stream frees, and the one message arrives alone.
    for _ in 0..50 {
        let _ = rig.link.take_stream();
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.stats.dropped.get(), 0);
}

#[tokio::test]
async fn an_oversize_latest_message_goes_on_the_stream_and_still_replaces_an_unsent_older_one() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    let big = vec![9u8; 3_000];
    let (a, b) = (name(1), name(2));
    // A small one waits (the carrier is full); an oversize one of its name replaces it.
    rig.link.set_full(true);
    send(&rig, &a, b"small", &latest, rig.t0).await;
    send(&rig, &b, b"other", &latest, rig.t0).await;
    send(&rig, &a, &big, &latest, rig.t0).await;
    rig.link.set_full(false);
    settle(&rig.tx).await;
    let dgrams = datagrams(&mut rig);
    let dgram_payloads: Vec<&[u8]> = messages(&dgrams).iter().map(|m| &m.payload[..]).collect();
    assert_eq!(dgram_payloads, [&b"other"[..]], "the small A never left");
    let streamed = stream(&mut rig);
    let on_stream: Vec<&Message> = messages(&streamed);
    assert_eq!(on_stream.len(), 1);
    assert_eq!(on_stream[0].payload.len(), 3_000);
    assert!(matches!(
        &streamed.last(),
        Some(Seen::Data {
            class: SideClass::Stream,
            ..
        })
    ));

    // The other way: an oversize one that is not sent yet is replaced by a small one of its name,
    // which goes as a datagram; the oversize one is never sent.
    send(&rig, &a, &big, &latest, at(&rig, 1)).await;
    send(&rig, &a, b"newer", &latest, at(&rig, 1)).await;
    settle(&rig.tx).await;
    let dgrams = datagrams(&mut rig);
    let payloads: Vec<&[u8]> = messages(&dgrams).iter().map(|m| &m.payload[..]).collect();
    assert_eq!(payloads, [&b"newer"[..]]);
    assert!(
        messages(&stream(&mut rig)).is_empty(),
        "the oversize one was replaced"
    );
    assert!(rig.stats.replaced.get() >= 2);
}

#[tokio::test]
async fn emissions_do_not_ask_the_carrier_for_the_paths_size_message_by_message() {
    let rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    // The carrier is full: the emissions queue, so only emissions ask anything.
    rig.link.set_full(true);
    for i in 0..200 {
        send(&rig, &name(i), b"payload", &latest, at(&rig, 1)).await;
    }
    let reads = rig.link.stats().datagram_max_reads;
    assert!(
        reads <= 3,
        "200 emissions made the carrier say the path's size {reads} times (a frame attempt and the first message read it, no more)"
    );
}

#[tokio::test]
async fn a_path_that_grew_takes_the_message_the_kept_size_refused_as_a_datagram() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_max: 400,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    let big = vec![5u8; 800];
    // The path takes 400: an 800 octet message goes on the stream.
    send(&rig, &name(1), &big, &latest, at(&rig, 1)).await;
    settle(&rig.tx).await;
    assert_eq!(messages(&stream(&mut rig)).len(), 1);
    assert!(messages(&datagrams(&mut rig)).is_empty());
    // The path grows to 1,400 with nothing refused: the next one asks again and is a datagram.
    rig.link.set_datagram_max(1_400);
    send(&rig, &name(1), &big, &latest, at(&rig, 2)).await;
    settle(&rig.tx).await;
    assert_eq!(messages(&datagrams(&mut rig)).len(), 1);
    assert!(messages(&stream(&mut rig)).is_empty());
}

#[tokio::test]
async fn a_frame_the_paths_size_fell_under_is_repacked_once_under_new_sequences_then_goes_on_the_stream()
 {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    // Ten messages of about 100 octets wait, then the path shrinks to 600 under the first frame.
    prebind(&mut rig, 0..10).await;
    rig.link.set_full(true);
    for i in 0..10 {
        send(&rig, &name(i), &[i as u8; 100], &latest, at(&rig, 10)).await;
    }
    rig.link.shrink_on_next_send(600);
    rig.link.set_full(false);
    let seen = datagrams(&mut rig);
    let all = messages(&seen);
    assert_eq!(all.len(), 10, "nothing was lost");
    assert!(rig.stats.resized.get() >= 10, "{}", rig.stats.resized.get());
    // New sequences: the ten took 1 to 10 (and the binds 11 to 20 are not in their order: binds
    // came first), the re-pack took greater ones, and no sequence went out twice.
    let mut seqs: Vec<u64> = all.iter().map(|m| m.seq).collect();
    assert!(seqs.iter().all(|s| *s > 60), "re-packed: {seqs:?}");
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), 10);
    for s in &seen {
        if let Seen::Data { .. } = s {}
    }
    // Twice in a row: the messages go to the stream.
    let mut rig = self::rig(ChannelMode::Latest, LinkConfig::default());
    prebind(&mut rig, 0..5).await;
    rig.link.set_full(true);
    for i in 0..5 {
        send(&rig, &name(i), &[i as u8; 100], &latest, at(&rig, 10)).await;
    }
    rig.link.shrink_on_next_send(600);
    rig.link.shrink_on_next_send(400);
    rig.link.set_full(false);
    settle(&rig.tx).await;
    assert!(datagrams(&mut rig).is_empty(), "the frame fell twice");
    let streamed = stream(&mut rig);
    assert_eq!(
        messages(&streamed).len(),
        5,
        "its messages went on the stream"
    );
    assert!(rig.stats.resized.get() >= 5);
}

// ---- names ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_datagram_that_overtakes_its_bind_carries_its_name() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    let path = name(7);
    // The first three messages under a new id are named, whenever they are sent; within 200 ms of
    // the bind every message is; after that they are bare.
    let times = [0u64, 1_000, 2_000, 3_000, 3_100];
    let mut sent = Vec::new();
    for ms in times {
        rig.tx
            .emit(
                &path,
                &Bytes::from_static(b"v"),
                &latest,
                rig.t0 + Duration::from_millis(ms),
            )
            .await
            .unwrap();
        sent.extend(datagrams(&mut rig));
    }
    let named: Vec<bool> = messages(&sent).iter().map(|m| m.name.is_some()).collect();
    assert_eq!(named, [true, true, true, false, false]);
    assert_eq!(
        messages(&sent)[0].name.as_deref(),
        Some(&name_octets(&path)[..]),
        "the name the bind says"
    );
    settle(&rig.tx).await;
    let control = stream(&mut rig);
    let binds = controls(&control);
    assert_eq!(binds.len(), 1, "one bind, on the stream");
    assert!(matches!(binds[0].1, Control::Bind { id: 1, name } if *name == name_octets(&path)));
    // A burst within 200 ms of a bind is all named.
    let other = name(8);
    for ms in [0u64, 10, 50, 150, 199] {
        rig.tx
            .emit(
                &other,
                &Bytes::from_static(b"v"),
                &latest,
                at(&rig, 10) + Duration::from_millis(ms),
            )
            .await
            .unwrap();
    }
    let burst = datagrams(&mut rig);
    assert!(messages(&burst).iter().all(|m| m.name.is_some()));
}

#[tokio::test]
async fn the_table_holds_4096_names_refuses_the_next_and_frees_the_idle_at_90_percent() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    for i in 0..4096 {
        send(
            &rig,
            &name(i),
            b"x",
            &latest,
            rig.t0 + Duration::from_micros(i as u64),
        )
        .await;
    }
    assert_eq!(rig.tx.names(), 4096);
    let refused = error_of(
        rig.tx
            .emit(&name(5000), &Bytes::from_static(b"x"), &latest, at(&rig, 1))
            .await,
    );
    assert_eq!(
        refused,
        EmitError::TooLarge {
            what: "names in one channel",
            size: 4097,
            max: 4096
        }
    );
    assert_eq!(refused.next(), crate::NextStep::FixRequest);
    assert_eq!(rig.tx.names(), 4096, "a refusal changes nothing");
    settle(&rig.tx).await;
    let _ = datagrams(&mut rig);
    let before = stream(&mut rig);
    assert_eq!(controls(&before).len(), 4096, "a bind each, on the stream");
    // A minute and a second later nothing was used: the new name frees the idle ids first.
    send(&rig, &name(5000), b"x", &latest, at(&rig, 61)).await;
    settle(&rig.tx).await;
    let after = stream(&mut rig);
    let ops = controls(&after);
    let unbinds = ops
        .iter()
        .filter(|(_, c)| matches!(c, Control::Unbind { .. }))
        .count();
    assert_eq!(unbinds, 4096, "every idle id was freed");
    assert!(
        matches!(ops.last().unwrap().1, Control::Bind { .. }),
        "then the new name's bind"
    );
    assert_eq!(rig.tx.names(), 1);
    assert_eq!(rig.stats.unbinds.get(), 4096);
}

// ---- modes ---------------------------------------------------------------------------------

#[tokio::test]
async fn window_keeps_at_most_its_limits_and_replays_them_to_a_joiner() {
    let w = |messages, bytes, secs| {
        EmitOptions::window(Window {
            messages,
            bytes,
            age: Duration::from_secs(secs),
        })
    };
    // Messages: the default window keeps 256 of 300.
    let mut rig = rig(ChannelMode::Window, LinkConfig::default());
    for i in 0..300u32 {
        send(
            &rig,
            &name(1),
            &i.to_be_bytes(),
            &EmitOptions::window(Window::DEFAULT),
            rig.t0,
        )
        .await;
        settle(&rig.tx).await;
        let _ = rig.link.take_stream();
    }
    let terms = rig.tx.welcome(true, false, None, true, rig.t0).unwrap();
    assert_eq!(terms.window.unwrap().messages, 256);
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let replayed: Vec<&Message> = messages(&seen);
    assert_eq!(replayed.len(), 256);
    let originals: Vec<u64> = replayed
        .iter()
        .map(|m| match m.origin {
            Some(Origin::Replayed(s)) => s,
            other => panic!("not a replay: {other:?}"),
        })
        .collect();
    assert_eq!(
        originals,
        (46..=301).collect::<Vec<u64>>(),
        "the last 256, original sequences"
    );
    assert!(
        replayed.iter().all(|m| m.name.is_some()),
        "a replay names itself"
    );
    let ops = controls(&seen);
    assert!(
        matches!(ops[0].1, Control::Hello { .. }),
        "HELLO comes first"
    );
    // The replay takes new sequences, after HELLO's.
    assert!(replayed[0].seq > ops[0].0);
    // `since` names the start: a re-ask by a receiver that is not new gets only the replay.
    let terms = rig
        .tx
        .welcome(false, false, Some(300), true, rig.t0)
        .unwrap();
    let _ = terms;
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    assert!(controls(&seen).is_empty(), "no HELLO for a known receiver");
    let from: Vec<u64> = messages(&seen)
        .iter()
        .map(|m| match m.origin {
            Some(Origin::Replayed(s)) => s,
            _ => 0,
        })
        .collect();
    assert_eq!(from, [300, 301]);

    // Bytes: ten of 100 octets in a window of 1,000.
    let mut rig = self::rig(ChannelMode::Window, LinkConfig::default());
    for i in 0..30u8 {
        send(&rig, &name(1), &[i; 100], &w(1000, 1000, 10), rig.t0).await;
        settle(&rig.tx).await;
        let _ = rig.link.take_stream();
    }
    rig.tx.welcome(true, false, None, true, rig.t0).unwrap();
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    assert_eq!(messages(&seen).len(), 10);
    // Age: eleven seconds later none of a 10 s window is left.
    rig.tx
        .welcome(true, false, None, true, at(&rig, 11))
        .unwrap();
    settle(&rig.tx).await;
    assert!(messages(&stream(&mut rig)).is_empty());
    // A window over its maximum is clamped, not refused.
    send(
        &rig,
        &name(1),
        b"x",
        &w(1 << 30, 1 << 40, 86_400),
        at(&rig, 12),
    )
    .await;
    let terms = rig
        .tx
        .welcome(false, false, None, true, at(&rig, 12))
        .unwrap();
    let window = terms.window.unwrap();
    assert_eq!(
        (window.messages, window.bytes, window.ms),
        (4096, 16 << 20, 300_000)
    );
}

/// A `Window` channel that sent `messages` messages of `size` octets under one name, a joiner
/// not yet welcomed, and a stream that takes one small frame and then stalls.
async fn stalled_window(messages: usize, size: usize) -> Rig {
    let rig = rig(
        ChannelMode::Window,
        LinkConfig {
            stream_window: 16 * 1024,
            ..LinkConfig::default()
        },
    );
    let window = EmitOptions::window(Window {
        messages,
        bytes: QUEUE_BYTES,
        age: Duration::from_secs(3_600),
    });
    for i in 0..messages {
        send(&rig, &name(1), &vec![i as u8; size], &window, rig.t0).await;
        settle(&rig.tx).await;
        let _ = rig.link.take_stream();
    }
    // The first welcome binds the name and fills the stalled stream.
    rig.tx.welcome(true, false, None, true, rig.t0).unwrap();
    rig
}

/// A receiver that asks again and again with `ASK_SINCE` must not grow the sender's FIFO past
/// `queue_bytes`, whatever the pace of its asks and however long the stream is stalled (M4).
#[tokio::test]
async fn repeated_since_asks_do_not_grow_the_fifo_past_queue_bytes() {
    let rig = stalled_window(256, 4_000).await;
    for second in 1..=100u64 {
        rig.tx
            .welcome(false, false, Some(0), true, at(&rig, 2 * second))
            .unwrap();
        tokio::task::yield_now().await;
    }
    let queued = rig.tx.queued_bytes();
    assert!(
        queued <= QUEUE_BYTES,
        "100 asks for a window of {} octets (a stalled stream) left {queued} octets in a queue \
         of {QUEUE_BYTES}",
        256 * 4_000
    );
    assert!(
        rig.stats.replay_refused.get() > 0,
        "and the refusals are counted"
    );
}

/// At most one `since` replay a second per channel: the second ask within the second is given
/// the session and no replay, counted, and the next second's is replayed again.
#[tokio::test]
async fn a_since_replay_is_given_once_a_second_per_channel() {
    let mut rig = rig(ChannelMode::Window, LinkConfig::default());
    for i in 0..20u8 {
        send(
            &rig,
            &name(1),
            &[i; 10],
            &EmitOptions::window(Window::DEFAULT),
            rig.t0,
        )
        .await;
        settle(&rig.tx).await;
        let _ = rig.link.take_stream();
    }
    let replayed = |rig: &mut Rig| messages(&stream(rig)).len();
    let asked = |rig: &mut Rig, at: Instant| {
        rig.tx.welcome(false, false, Some(0), true, at).unwrap();
        replayed(rig)
    };
    let t = rig.t0 + Duration::from_secs(5);
    rig.tx.welcome(false, false, Some(0), true, t).unwrap();
    settle(&rig.tx).await;
    assert_eq!(replayed(&mut rig), 20, "the first ask is replayed");
    let again = asked(&mut rig, t + SINCE_REPLAY_EVERY / 2);
    settle(&rig.tx).await;
    assert_eq!(
        again + replayed(&mut rig),
        0,
        "a second ask within the second is not"
    );
    assert_eq!(rig.stats.replay_refused.get(), 1);
    rig.tx
        .welcome(false, false, Some(0), true, t + SINCE_REPLAY_EVERY)
        .unwrap();
    settle(&rig.tx).await;
    assert_eq!(
        replayed(&mut rig),
        20,
        "a second later it is replayed again"
    );
    // A joiner that was not a receiver before is given its replay whenever it comes.
    rig.tx
        .welcome(true, false, None, true, t + SINCE_REPLAY_EVERY)
        .unwrap();
    settle(&rig.tx).await;
    assert_eq!(replayed(&mut rig), 20);
}

/// A `Window` channel that sent 20 messages and has one receiver (welcomed at `t0`), its stream
/// drained.
async fn window_with_a_receiver() -> Rig {
    let mut rig = rig(ChannelMode::Window, LinkConfig::default());
    for i in 0..20u8 {
        send(
            &rig,
            &name(1),
            &[i; 10],
            &EmitOptions::window(Window::DEFAULT),
            rig.t0,
        )
        .await;
        settle(&rig.tx).await;
        let _ = rig.link.take_stream();
    }
    rig.tx.welcome(true, false, None, true, rig.t0).unwrap();
    settle(&rig.tx).await;
    let _ = stream(&mut rig);
    rig
}

fn hellos(seen: &[Seen]) -> usize {
    controls(seen)
        .iter()
        .filter(|(_, c)| matches!(c, Control::Hello { .. }))
        .count()
}

/// `ASK_NEW` from a device the sender lists is a claim ("I let the channel go"): the sender
/// cannot check it, and its welcome goes to every receiver on the route. In a burst of eight, one
/// is welcomed (one `HELLO`, one replay of the window, one arming of the stream's gate) and the
/// others are refused with the time to wait, queue nothing and arm nothing. The claim is judged
/// by the limiter an `ASK_SINCE` is (once a second per channel), and what it queued is not
/// replayed again until the second has passed.
#[tokio::test]
async fn a_burst_of_claims_is_welcomed_once_a_second_and_arms_the_gate_once() {
    let mut rig = window_with_a_receiver().await;
    let armed = rig.link.stats().receivers_added;
    let t = at(&rig, 5);
    let mut told = Vec::new();
    for k in 0..8u64 {
        let at = t + Duration::from_millis(k * 10);
        if let Err(refused) = rig.tx.welcome(false, true, None, true, at) {
            told.push(refused);
        }
        settle(&rig.tx).await;
    }
    let seen = stream(&mut rig);
    assert_eq!(
        (hellos(&seen), messages(&seen).len()),
        (1, 20),
        "8 claims in 70 ms: one HELLO and one replay of the 20 messages"
    );
    assert_eq!(told.len(), 7, "the other seven are refused");
    for refused in &told {
        assert!(refused.soon);
        assert!(
            refused.retry_ms > 0 && refused.retry_ms <= SINCE_REPLAY_EVERY.as_millis() as u64,
            "{refused:?}"
        );
    }
    assert_eq!(rig.stats.replay_refused.get(), 7);
    assert_eq!(
        rig.link.stats().receivers_added - armed,
        1,
        "a refused claim does not arm the stream's gate"
    );
    assert!(rig.tx.queued_bytes() <= QUEUE_BYTES);

    // A second after the one that was welcomed the next claim is.
    rig.tx
        .welcome(false, true, None, true, t + SINCE_REPLAY_EVERY)
        .expect("a second on");
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    assert_eq!((hellos(&seen), messages(&seen).len()), (1, 20));
    // A device that was never a receiver is welcomed whenever it comes, whatever the claims.
    rig.tx
        .welcome(true, false, None, true, t + SINCE_REPLAY_EVERY)
        .unwrap();
    settle(&rig.tx).await;
    assert_eq!(hellos(&stream(&mut rig)), 1);
}

/// Claims against a stalled stream: the FIFO holds the welcome of the first receiver, so a claim
/// that would not fit under `queue_bytes` is refused (with a second to wait), however many come
/// and however far apart.
#[tokio::test]
async fn claims_do_not_grow_the_fifo_past_queue_bytes() {
    let rig = stalled_window(256, 4_000).await;
    let armed = rig.link.stats().receivers_added;
    for second in 1..=20u64 {
        let refused = rig
            .tx
            .welcome(false, true, None, true, at(&rig, 2 * second))
            .expect_err("the queue has no room for the replay");
        assert!(!refused.soon, "{refused:?}");
        tokio::task::yield_now().await;
    }
    let queued = rig.tx.queued_bytes();
    assert!(
        queued <= QUEUE_BYTES,
        "20 claims for a window of {} octets (a stalled stream) left {queued} octets in a queue \
         of {QUEUE_BYTES}",
        256 * 4_000
    );
    assert_eq!(rig.stats.replay_refused.get(), 20);
    assert_eq!(
        rig.link.stats().receivers_added,
        armed,
        "refused claims arm nothing"
    );
}

/// A claim after a real release, the first for a while, is welcomed like a new receiver: `HELLO`,
/// the binds, the replay.
#[tokio::test]
async fn a_claim_the_limiter_admits_gets_its_hello_binds_and_replay() {
    let mut rig = window_with_a_receiver().await;
    rig.tx
        .welcome(false, true, None, true, at(&rig, 8))
        .expect("the first claim in a while");
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    assert_eq!(hellos(&seen), 1, "HELLO");
    assert_eq!(messages(&seen).len(), 20, "the window");
}

#[tokio::test]
async fn stand_is_limited_and_replays_between_its_brackets_with_what_is_left() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let stand = |secs| EmitOptions::latest().standing(Duration::from_secs(secs));
    // A lifetime over an hour is refused.
    let refused = error_of(
        rig.tx
            .emit(&name(0), &Bytes::from_static(b"x"), &stand(3601), rig.t0)
            .await,
    );
    assert!(matches!(
        refused,
        EmitError::TooLarge {
            what: "stand lifetime in seconds",
            size: 3601,
            max: 3600
        }
    ));
    // What stands: a, b; c does not.
    send(&rig, &name(1), b"va", &stand(100), rig.t0).await;
    send(&rig, &name(2), b"vb", &stand(50), rig.t0).await;
    send(&rig, &name(3), b"vc", &EmitOptions::latest(), rig.t0).await;
    settle(&rig.tx).await;
    let _ = datagrams(&mut rig);
    let _ = stream(&mut rig);
    rig.tx
        .welcome(true, false, None, true, at(&rig, 20))
        .unwrap();
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let ops = controls(&seen);
    let kinds: Vec<&Control> = ops.iter().map(|(_, c)| *c).collect();
    assert!(matches!(kinds[0], Control::Hello { .. }));
    assert!(matches!(kinds[1], Control::StandingBegin));
    assert!(matches!(kinds[2], Control::StandingEnd));
    let standing = messages(&seen);
    assert_eq!(standing.len(), 2, "c did not stand");
    assert_eq!(standing[0].payload, Bytes::from_static(b"va"));
    assert_eq!(standing[0].stand_secs, Some(80), "what is left of 100 s");
    assert_eq!(standing[1].stand_secs, Some(30));
    assert!(
        matches!(standing[0].origin, Some(Origin::Standing(2))),
        "{:?}",
        standing[0].origin
    );
    assert!(matches!(standing[1].origin, Some(Origin::Standing(4))));
    // Between the brackets, in the order of the sequences: BEGIN < a < b < END.
    assert!(ops[1].0 < standing[0].seq && standing[1].seq < ops[2].0);
    // b is gone a minute later; the replay carries a alone.
    rig.tx
        .welcome(true, false, None, true, at(&rig, 60))
        .unwrap();
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    assert_eq!(messages(&seen).len(), 1);
    assert_eq!(messages(&seen)[0].stand_secs, Some(40));
    // A later emission that does not stand takes the standing value of its name away.
    send(&rig, &name(1), b"new", &EmitOptions::latest(), at(&rig, 61)).await;
    rig.tx
        .welcome(true, false, None, true, at(&rig, 62))
        .unwrap();
    settle(&rig.tx).await;
    assert!(messages(&stream(&mut rig)).is_empty());

    // 256 names, and no 257th.
    let rig2 = self::rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 100_000,
            ..LinkConfig::default()
        },
    );
    for i in 0..256 {
        send(&rig2, &name(i), b"x", &stand(60), rig2.t0).await;
    }
    let refused = error_of(
        rig2.tx
            .emit(&name(256), &Bytes::from_static(b"x"), &stand(60), rig2.t0)
            .await,
    );
    assert_eq!(
        refused,
        EmitError::TooLarge {
            what: "standing names in one channel",
            size: 257,
            max: 256
        }
    );
    // 64 KiB of payloads.
    let rig3 = self::rig(ChannelMode::Latest, LinkConfig::default());
    send(&rig3, &name(1), &vec![0u8; 40 * 1024], &stand(60), rig3.t0).await;
    let refused = error_of(
        rig3.tx
            .emit(
                &name(2),
                &Bytes::from(vec![0u8; 40 * 1024]),
                &stand(60),
                rig3.t0,
            )
            .await,
    );
    assert_eq!(
        refused,
        EmitError::TooLarge {
            what: "standing octets in one channel",
            size: 80 * 1024,
            max: 64 * 1024
        }
    );
}

#[tokio::test]
async fn a_path_with_no_stream_refuses_the_modes_that_need_one() {
    let nostream = LinkConfig {
        has_stream: false,
        ..LinkConfig::default()
    };
    for (mode, what) in [
        (ChannelMode::Reliable, "Reliable"),
        (ChannelMode::Window, "Window"),
    ] {
        let rig = rig(mode, nostream.clone());
        let opts = if mode == ChannelMode::Reliable {
            EmitOptions::reliable()
        } else {
            EmitOptions::window(Window::DEFAULT)
        };
        let refused = error_of(
            rig.tx
                .emit(&name(1), &Bytes::from_static(b"x"), &opts, rig.t0)
                .await,
        );
        assert_eq!(refused, EmitError::NoStream { what });
        assert_eq!(refused.next(), crate::NextStep::FixRequest);
    }
    let mut rig = rig(ChannelMode::Latest, nostream);
    let stand = EmitOptions::latest().standing(Duration::from_secs(5));
    let refused = error_of(
        rig.tx
            .emit(&name(1), &Bytes::from_static(b"x"), &stand, rig.t0)
            .await,
    );
    assert_eq!(
        refused,
        EmitError::NoStream {
            what: "a standing value"
        }
    );
    // Latest works, every message names itself (there is no stream to bind on), and a message that
    // fits no datagram is refused.
    for i in 0..5 {
        send(
            &rig,
            &name(1),
            b"x",
            &EmitOptions::latest(),
            at(&rig, 10 + i),
        )
        .await;
    }
    let seen = datagrams(&mut rig);
    assert!(messages(&seen).iter().all(|m| m.name.is_some()));
    let refused = error_of(
        rig.tx
            .emit(
                &name(1),
                &Bytes::from(vec![0u8; 3_000]),
                &EmitOptions::latest(),
                rig.t0,
            )
            .await,
    );
    assert!(matches!(refused, EmitError::TooLarge { .. }), "{refused:?}");
    assert!(rig.link.take_stream().is_empty());
}

/// One receiver of a channel is behind a hop with no stream (it was welcomed with
/// `stream_path` false): it is sent no stream frame and its session announces no checkpoints;
/// while it holds the channel every message names itself (it is given no `BIND`), and what needs
/// the stream, a standing value or a message that fits no datagram, is refused at the emission.
/// The carrier itself has a stream: the others on the channel keep it.
#[tokio::test]
async fn a_receiver_behind_a_hop_with_no_stream_degrades_the_channel_to_what_it_can_take() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let stand = EmitOptions::latest().standing(Duration::from_secs(60));
    // Before it joined, a name was bound and a value stood.
    send(&rig, &name(1), b"a", &stand, rig.t0).await;
    settle(&rig.tx).await;
    let _ = (datagrams(&mut rig), stream(&mut rig));

    let terms = rig
        .tx
        .welcome(true, false, None, false, at(&rig, 1))
        .unwrap();
    rig.live.datagram_only.store(1, Ordering::SeqCst);
    settle(&rig.tx).await;
    assert_eq!(terms.ckpt_ms, 0, "its session announces no checkpoint");
    assert!(
        stream(&mut rig).is_empty(),
        "no HELLO, no bind, no standing value: they would be dropped at the hop"
    );

    // Every message names itself, even long after the bind.
    for i in 0..5 {
        send(
            &rig,
            &name(1),
            b"x",
            &EmitOptions::latest(),
            at(&rig, 10 + i),
        )
        .await;
    }
    let seen = datagrams(&mut rig);
    assert!(messages(&seen).iter().all(|m| m.name.is_some()));

    // What needs the stream is refused, with the next step.
    let refused = error_of(
        rig.tx
            .emit(&name(2), &Bytes::from_static(b"v"), &stand, at(&rig, 20))
            .await,
    );
    assert_eq!(
        refused,
        EmitError::NoStream {
            what: "a standing value"
        }
    );
    assert_eq!(refused.next(), crate::NextStep::FixRequest);
    let refused = error_of(
        rig.tx
            .emit(
                &name(1),
                &Bytes::from(vec![0u8; 3_000]),
                &EmitOptions::latest(),
                at(&rig, 21),
            )
            .await,
    );
    assert!(matches!(refused, EmitError::TooLarge { .. }), "{refused:?}");

    // It left: the channel has its stream again.
    rig.live.datagram_only.store(0, Ordering::SeqCst);
    send(&rig, &name(2), b"v", &stand, at(&rig, 22)).await;
}

#[tokio::test]
async fn a_sender_with_no_receiver_sends_nothing_and_keeps_what_a_joiner_needs() {
    let mut rig = rig(ChannelMode::Window, LinkConfig::default());
    rig.live.receivers.store(0, Ordering::SeqCst);
    for i in 0..3u8 {
        send(
            &rig,
            &name(1),
            &[i],
            &EmitOptions::window(Window::DEFAULT),
            rig.t0,
        )
        .await;
    }
    // Latest on another channel: nothing at all.
    assert_eq!(rig.link.queued_datagrams(), 0);
    assert!(rig.link.take_stream().is_empty());
    assert_eq!(rig.tx.sent_frames(), 0);
    assert_eq!(rig.stats.unrouted.get(), 3);
    // A receiver joins: the window is replayed.
    rig.live.receivers.store(1, Ordering::SeqCst);
    rig.tx.welcome(true, false, None, true, rig.t0).unwrap();
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let payloads: Vec<u8> = messages(&seen).iter().map(|m| m.payload[0]).collect();
    assert_eq!(payloads, [0, 1, 2]);

    let mut lat = self::rig(ChannelMode::Latest, LinkConfig::default());
    lat.live.receivers.store(0, Ordering::SeqCst);
    send(&lat, &name(1), b"x", &EmitOptions::latest(), lat.t0).await;
    assert_eq!(lat.link.queued_datagrams(), 0);
    assert!(lat.link.take_stream().is_empty());
    assert_eq!(lat.tx.next_seq(), 1, "nothing took a sequence");
    assert_eq!(lat.tx.sent_frames(), 0);
    assert!(datagrams(&mut lat).is_empty());
}

#[tokio::test]
async fn the_last_sequence_ends_the_channel_cleanly() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    rig.tx.set_next_seq(SEQ_END - 8);
    let latest = EmitOptions::latest();
    let mut last = Ok(());
    let mut taken = 0;
    for _ in 0..10 {
        last = rig
            .tx
            .emit(&name(1), &Bytes::from_static(b"x"), &latest, rig.t0)
            .await;
        if last.is_err() {
            break;
        }
        taken += 1;
    }
    assert_eq!(error_of(last), EmitError::SequenceExhausted);
    assert!(taken >= 2, "it sent up to its limit: {taken}");
    assert!(
        rig.keys.exhausted.load(Ordering::SeqCst),
        "the channel was asked to end"
    );
    assert!(
        matches!(
            rig.tx.emit(&name(1), &Bytes::new(), &latest, rig.t0).await,
            Err(Refused::Gone)
        ),
        "an ended channel takes nothing: the caller makes another"
    );
    // The channel said so on the stream: after what it bound, one END, in the sequences kept
    // for it.
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let ends: Vec<u64> = controls(&seen)
        .into_iter()
        .filter_map(|(seq, c)| matches!(c, Control::End).then_some(seq))
        .collect();
    assert_eq!(ends.len(), 1, "exactly one END on the stream: {seen:?}");
    assert!(ends[0] < SEQ_END, "the END took a sequence below the limit");
    assert!(
        matches!(controls(&seen).last(), Some((_, Control::End))),
        "and it is the last thing on the stream"
    );
}

/// The `END` of a channel is sealed under the key in force when it ended, whatever key the sender
/// had last refreshed to: a close takes the key before the channel's own copy is gone.
#[tokio::test]
async fn the_end_is_sealed_under_the_key_given_when_the_channel_ended() {
    let rig = rig(ChannelMode::Reliable, LinkConfig::default());
    let newer = ChannelKey::random().frame_key(CHANNEL, 1);
    let key = SendKey {
        id: CHANNEL,
        key_epoch: 1,
        frame_key: newer.clone(),
        live: Arc::clone(&rig.live),
    };
    rig.tx.end(&key);
    settle(&rig.tx).await;
    let frames = rig.link.take_stream();
    assert_eq!(frames.len(), 1, "one END frame");
    let cipher = FrameCipher::new(&newer, Aead::preferred());
    let opened = frame::open(&cipher, frames[0].clone(), STREAM_FRAME_MAX)
        .expect("the END opens under the key given when the channel ended");
    assert_eq!(opened.header().key_epoch, 1);
    assert_eq!(
        Control::decode(opened.plaintext()).unwrap(),
        Control::End,
        "and it says END"
    );
    // A second end says nothing more, and an emission is refused as a channel that ended.
    rig.tx.end(&key);
    settle(&rig.tx).await;
    assert!(rig.link.take_stream().is_empty(), "END is sent once");
    assert!(matches!(
        rig.tx
            .emit(&name(1), &Bytes::new(), &EmitOptions::reliable(), rig.t0)
            .await,
        Err(Refused::Gone)
    ));
}

/// Nobody to tell, no stream to tell it on, or a key of another channel: no `END` goes, and the
/// channel is over all the same.
#[tokio::test]
async fn no_end_is_sent_with_no_receiver_no_stream_or_a_foreign_key() {
    let rig_with = |cfg: LinkConfig| rig(ChannelMode::Latest, cfg);
    // No receiver holds the channel.
    let quiet = rig_with(LinkConfig::default());
    quiet.live.receivers.store(0, Ordering::SeqCst);
    quiet.tx.end(&quiet.keys.key);
    settle(&quiet.tx).await;
    assert!(quiet.link.take_stream().is_empty(), "no receiver, no END");
    // The carrier has no stream.
    let datagram_only = rig_with(LinkConfig {
        has_stream: false,
        ..LinkConfig::default()
    });
    datagram_only.tx.end(&datagram_only.keys.key);
    settle(&datagram_only.tx).await;
    assert!(
        datagram_only.link.take_stream().is_empty(),
        "no stream, no END"
    );
    // A key of another channel is not this channel's to seal under.
    let foreign = rig_with(LinkConfig::default());
    let other = SendKey {
        id: CHANNEL + 1,
        ..foreign.keys.key.clone()
    };
    foreign.tx.end(&other);
    settle(&foreign.tx).await;
    assert!(
        foreign.link.take_stream().is_empty(),
        "another channel's key"
    );
    for r in [&quiet, &datagram_only, &foreign] {
        assert!(matches!(
            r.tx.emit(&name(1), &Bytes::new(), &EmitOptions::latest(), r.t0)
                .await,
            Err(Refused::Gone)
        ));
    }
}

// ---- the invariant ---------------------------------------------------------------------------

/// Every message that was emitted is sent, replaced by a newer one of its name, or counted
/// dropped; the newest of each name always arrives; an older one never follows a newer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_pending_is_always_eventually_written_or_counted_dropped() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 8,
            ..LinkConfig::default()
        },
    );
    rig.tx.set_next_seq(1);
    let tx = Arc::clone(&rig.tx);
    let link = Arc::clone(&rig.link);
    let handle = tokio::runtime::Handle::current();
    let t0 = rig.t0;
    let done = Arc::new(AtomicBool::new(false));
    let emitted = Arc::new(AtomicU64::new(0));
    let finals: Arc<parking_lot::Mutex<BTreeMap<usize, u64>>> = Arc::default();
    // The receiver drains the link while the carrier flaps between full and not.
    let received: Arc<parking_lot::Mutex<Vec<Bytes>>> = Arc::default();
    std::thread::scope(|scope| {
        for thread in 0..4usize {
            let (tx, emitted, finals) =
                (Arc::clone(&tx), Arc::clone(&emitted), Arc::clone(&finals));
            let enter = handle.clone();
            scope.spawn(move || {
                let _enter = enter.enter();
                let mut rng = 0x9E37_79B9_7F4A_7C15u64 ^ (thread as u64 + 1);
                for n in 0..5_000u64 {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    // Each thread has its own names, so the newest of each is known.
                    let slot = (rng % 6) as usize;
                    let path = name(thread * 10 + slot);
                    let payload = Bytes::copy_from_slice(&n.to_be_bytes());
                    futures::executor::block_on(tx.emit(
                        &path,
                        &payload,
                        &EmitOptions::latest(),
                        t0,
                    ))
                    .expect("taken");
                    emitted.fetch_add(1, Ordering::SeqCst);
                    finals.lock().insert(thread * 10 + slot, n);
                }
            });
        }
        let (link2, done2, received2) =
            (Arc::clone(&link), Arc::clone(&done), Arc::clone(&received));
        let enter = handle.clone();
        scope.spawn(move || {
            let _enter = enter.enter();
            let (link, done, received) = (link2, done2, received2);
            let mut rng = 0xD1B5_4A32_D192_ED03u64;
            while !done.load(Ordering::SeqCst) {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                link.set_full(rng.is_multiple_of(3));
                if rng.is_multiple_of(5) {
                    received.lock().extend(link.take_datagrams());
                }
                std::thread::yield_now();
            }
        });
        // The writers end first; then the carrier stops flapping.
        while emitted.load(Ordering::SeqCst) < 20_000 {
            std::thread::yield_now();
        }
        done.store(true, Ordering::SeqCst);
    });
    link.set_full(false);
    received.lock().extend(link.take_datagrams());
    received.lock().extend(link.take_datagrams());
    settle(&rig.tx).await;
    assert!(rig.tx.is_idle(), "{} waiting", rig.tx.pending());
    received.lock().extend(rig.link.take_datagrams());
    assert_eq!(rig.link.waiting_drains(), 0, "no drain left registered");
    // Account for every message.
    let frames = std::mem::take(&mut *received.lock());
    let seen = rig.dec.all(frames);
    let delivered = messages(&seen).len() as u64;
    let replaced = rig.stats.replaced.get();
    let dropped = rig.stats.dropped.get();
    assert_eq!(
        delivered + replaced + dropped,
        20_000,
        "delivered {delivered} + replaced {replaced} + dropped {dropped} = emitted"
    );
    // The newest message of every name arrived, and per name the sequences only rise.
    let mut by_name: HashMap<Bytes, (u64, Bytes)> = HashMap::new();
    let mut ids: HashMap<u64, Bytes> = HashMap::new();
    for m in messages(&seen) {
        if let Some(n) = &m.name {
            ids.insert(m.name_id, n.clone());
        }
    }
    for m in messages(&seen) {
        let n = ids
            .get(&m.name_id)
            .cloned()
            .unwrap_or_else(|| rig.dec.names[&m.name_id].clone());
        if let Some((seq, _)) = by_name.get(&n) {
            assert!(m.seq > *seq, "an older message followed a newer one");
        }
        by_name.insert(n, (m.seq, m.payload.clone()));
    }
    for (slot, last) in finals.lock().iter() {
        let key = name_octets(&name(*slot));
        assert_eq!(
            by_name[&key].1,
            Bytes::copy_from_slice(&last.to_be_bytes()),
            "the newest message of {slot} arrived"
        );
    }
}

// ---- cost ----------------------------------------------------------------------------------

/// A carrier that takes a datagram and forgets it, so the test counts only what the sender
/// allocates.
struct Void {
    full: AtomicBool,
    ready: parking_lot::Mutex<Vec<Box<dyn FnOnce() + Send>>>,
}

impl Void {
    /// The carrier is ready: call the drains it was given.
    fn fire(&self) {
        // Those waiting now: a drain that asks again (the carrier is full again) waits for the
        // next call, and the lock is not held while a drain runs.
        let waiting = self.ready.lock().len();
        for _ in 0..waiting {
            let next = self.ready.lock().pop();
            let Some(drain) = next else { break };
            drain();
        }
    }
}

impl Carrier for Void {
    fn datagram_max(&self) -> usize {
        1_400
    }
    fn has_stream(&self) -> bool {
        true
    }
    fn stream_frame_max(&self) -> usize {
        super::limits::STREAM_FRAME_DEFAULT
    }
    fn try_send_datagram(&self, _frame: Bytes) -> Result<(), CarrierRefused> {
        if self.full.load(Ordering::SeqCst) {
            Err(CarrierRefused::Full)
        } else {
            Ok(())
        }
    }
    fn send_stream(&self, _frame: Bytes) -> CarrierFuture<'_, Result<(), CarrierRefused>> {
        Box::pin(async { Ok(()) })
    }
    fn on_ready(&self, drain: Box<dyn FnOnce() + Send>) {
        self.ready.lock().push(drain);
    }
}

fn poll_once<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the emission waited"),
    }
}

#[tokio::test]
async fn the_64_byte_latest_path_allocates_nothing_per_message_beyond_the_frame() {
    let rig = rig(ChannelMode::Latest, LinkConfig::default());
    let void = Arc::new(Void {
        full: AtomicBool::new(false),
        ready: parking_lot::Mutex::default(),
    });
    let slot = Arc::new(CarrierSlot::default());
    slot.set(void.clone());
    let tx = TxChannel::new(
        ChannelMode::Latest,
        &SendKey {
            id: CHANNEL,
            key_epoch: 0,
            frame_key: ChannelKey::random().frame_key(CHANNEL, 0),
            live: Arc::clone(&rig.live),
        },
        rig.keys.clone(),
        Tasks::new(),
        slot,
        Arc::new(TxStats::default()),
        Arc::new(AtomicU64::new(0)),
    );
    let (path, payload, latest) = (name(1), Bytes::from(vec![7u8; 64]), EmitOptions::latest());
    // Warm up: the name is bound, the slots and queues have their room, the bind is written.
    for i in 0..20 {
        tx.emit(&path, &payload, &latest, rig.t0 + Duration::from_secs(i))
            .await
            .unwrap();
        void.fire();
    }
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    let now = rig.t0 + Duration::from_secs(100);
    // One message, idle: one frame, which is two allocations (its buffer, and the shared header
    // `Bytes` that freezing it adds), and nothing for the call back (an isolated message asks for
    // none): nothing for the message, the queue, the ring or the seal.
    let (_, one) = count_allocations(|| poll_once(tx.emit(&path, &payload, &latest, now)).unwrap());
    assert_eq!(
        one, 2,
        "an idle 64 B message allocates exactly its frame (2) and no call back"
    );
    void.fire();
    // A busy writer: 14 distinct names wait while the carrier is full, then leave in one frame:
    // still two allocations for all 14 messages.
    let names: Vec<Name> = (10..24).map(name).collect();
    for n in &names {
        for i in 0..4 {
            tx.emit(n, &payload, &latest, rig.t0 + Duration::from_secs(200 + i))
                .await
                .unwrap();
        }
    }
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    // A first busy spell gives the queue its room (the queue grows once, like the slots did).
    void.full.store(true, Ordering::SeqCst);
    let warm = rig.t0 + Duration::from_secs(250);
    for n in &names {
        poll_once(tx.emit(n, &payload, &latest, warm)).unwrap();
    }
    void.full.store(false, Ordering::SeqCst);
    void.fire();
    void.full.store(true, Ordering::SeqCst);
    let later = rig.t0 + Duration::from_secs(300);
    poll_once(tx.emit(&names[0], &payload, &latest, later)).unwrap();
    // The first call hits Full once (it is the writer and gives up); the rest only queue.
    let (_, queued) = count_allocations(|| {
        for n in &names {
            poll_once(tx.emit(n, &payload, &latest, later)).unwrap();
        }
    });
    assert_eq!(
        queued, 0,
        "queueing 14 messages while the carrier is full allocates nothing"
    );
    void.full.store(false, Ordering::SeqCst);
    let (_, drained) = count_allocations(|| void.fire());
    // 14 names waiting, plus the one replaced: one frame of 14 messages.
    assert_eq!(
        drained, 2,
        "14 messages in one frame: two allocations in all"
    );
}

#[tokio::test]
async fn a_message_over_the_limit_or_a_name_over_255_octets_is_refused_before_anything_changes() {
    let rig = rig(ChannelMode::Latest, LinkConfig::default());
    let refused = error_of(
        rig.tx
            .emit(
                &name(1),
                &Bytes::from(vec![0u8; (1 << 20) + 1]),
                &EmitOptions::latest(),
                rig.t0,
            )
            .await,
    );
    assert!(
        matches!(
            refused,
            EmitError::TooLarge {
                what: "message",
                ..
            }
        ),
        "{refused:?}"
    );
    let long = Name::root().append(vec![b'x'; 300]);
    let refused = error_of(
        rig.tx
            .emit(&long, &Bytes::new(), &EmitOptions::latest(), rig.t0)
            .await,
    );
    assert!(
        matches!(
            refused,
            EmitError::TooLarge {
                what: "name",
                max: 255,
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(rig.tx.next_seq(), 1, "no sequence was taken, no name bound");
    assert_eq!(rig.tx.names(), 0);
}

/// A stream that takes less than the channel's default frame: the writer packs to what the
/// carrier says it takes. A flood of 8 KiB messages over 256 names makes frames of as many as
/// fit; a frame over the limit was refused whole, and every later emission rebuilt one, so
/// nothing ever left.
#[tokio::test]
async fn a_stream_frame_is_never_built_over_what_the_carrier_takes() {
    const NAMES: usize = 256;
    const TAKES: usize = 1 << 19;
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_max: 1_414,
            stream_window: 300_000,
            stream_frame_max: TAKES,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    prebind(&mut rig, 0..NAMES).await;
    let big = Bytes::from(vec![0xA5u8; 8_192]);
    let mut delivered = 0usize;
    for _ in 0..40 {
        for i in 0..NAMES {
            rig.tx
                .emit(&name(i), &big, &latest, at(&rig, 10))
                .await
                .expect("the emission is taken");
        }
        tokio::task::yield_now().await;
        for frame in rig.link.take_stream() {
            assert!(frame.len() <= TAKES, "a frame of {} octets", frame.len());
            if let Seen::Data { messages, .. } = rig.dec.read(frame) {
                delivered += messages.len();
            }
        }
    }
    assert!(
        delivered >= 40 * 60,
        "the stream wrote {delivered} messages in 40 passes (lost {})",
        rig.stats.lost_closed.get()
    );
    assert_eq!(
        rig.stats.lost_closed.get(),
        0,
        "nothing was lost to a refusal"
    );
}

/// A message whose frame fits no frame the stream takes is refused at `emit`, saying what the
/// stream takes; no sequence is taken.
#[tokio::test]
async fn a_message_that_fits_no_frame_the_stream_takes_is_refused_before_anything_changes() {
    let rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_max: 1_414,
            stream_frame_max: 100_000,
            ..LinkConfig::default()
        },
    );
    let refused = error_of(
        rig.tx
            .emit(
                &name(1),
                &Bytes::from(vec![0u8; 100_000]),
                &EmitOptions::latest(),
                rig.t0,
            )
            .await,
    );
    assert!(
        matches!(
            refused,
            EmitError::TooLarge {
                what: "message that fits no frame of the stream",
                max: 100_000,
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(rig.tx.next_seq(), 1, "no sequence was taken");
}

/// The channel's default message limit is what the face's stream grant carries: a message of
/// exactly the default maximum is taken at `emit` and its frame is within what the stream takes
/// (the face grants 1,048,576 octets a frame; the channel's default once allowed a payload of
/// 1 MiB, whose frame was refused by the face, an `emit` error for a size the channel itself
/// advertised).
#[tokio::test]
async fn a_message_of_the_default_limit_fits_a_frame_the_face_grants() {
    const FACE_GRANT: usize = 1_048_576;
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_max: 1_414,
            stream_window: 4 << 20,
            stream_frame_max: FACE_GRANT,
            ..LinkConfig::default()
        },
    );
    let payload = Bytes::from(vec![0x5Au8; MESSAGE_DEFAULT]);
    rig.tx
        .emit(&name(1), &payload, &EmitOptions::latest(), rig.t0)
        .await
        .expect("a message at the default limit is taken");
    tokio::task::yield_now().await;
    let frames = rig.link.take_stream();
    assert!(!frames.is_empty(), "the frame left on the stream");
    for frame in frames {
        assert!(
            frame.len() <= FACE_GRANT,
            "a frame of {} octets",
            frame.len()
        );
        if let Seen::Data { messages, .. } = rig.dec.read(frame) {
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].payload.len(), MESSAGE_DEFAULT);
        }
    }
}

/// An isolated message leaves inline and asks the carrier for nothing (a call back is a wake of
/// the carrier's writer task, which an idle message does not need); a message that follows
/// another inline one within [`BURST_GAP`] is a loop of emissions, and asks, so that the ones
/// after it queue and leave together.
#[tokio::test]
async fn an_isolated_message_asks_no_call_back_and_a_burst_does() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    send(&rig, &name(0), b"hello", &latest, rig.t0).await;
    assert_eq!(rig.link.queued_datagrams(), 1, "left inline");
    assert_eq!(
        rig.link.waiting_drains(),
        0,
        "an idle message asks for no call back"
    );
    let _ = datagrams(&mut rig);

    // Quiet for a second: isolated again.
    send(&rig, &name(1), b"hello", &latest, at(&rig, 1)).await;
    assert_eq!(
        rig.link.waiting_drains(),
        0,
        "after a quiet second: still none"
    );
    let _ = datagrams(&mut rig);

    // The next one follows within the gap: it leaves inline too, and asks.
    send(
        &rig,
        &name(2),
        b"hello",
        &latest,
        at(&rig, 1) + BURST_GAP / 2,
    )
    .await;
    assert_eq!(rig.link.queued_datagrams(), 1, "still left inline");
    assert_eq!(rig.link.waiting_drains(), 1, "a burst asks for a call back");

    // Queued behind the call back, and out with it.
    send(
        &rig,
        &name(3),
        b"hello",
        &latest,
        at(&rig, 1) + BURST_GAP / 2,
    )
    .await;
    assert_eq!(
        rig.link.queued_datagrams(),
        1,
        "the third waits for the call back"
    );
    let seen = datagrams(&mut rig);
    assert_eq!(seen.len(), 2);
    settle(&rig.tx).await;
}

/// An inline writer whose frame left nothing waiting releases the lane under the same lock that
/// took the frame out of the queue (it used to look again: a second pack and a third lock round
/// per message): when `emit` returns the channel is idle, an isolated message asked for no call
/// back, one that followed within `BURST_GAP` asked for exactly one, and the next emission is
/// written inline by its own caller again.
#[tokio::test]
async fn an_inline_writer_that_left_nothing_waiting_is_idle_when_emit_returns() {
    let mut rig = rig(
        ChannelMode::Latest,
        LinkConfig {
            datagram_capacity: 1_000_000,
            ..LinkConfig::default()
        },
    );
    let latest = EmitOptions::latest();
    prebind(&mut rig, 0..13).await;
    for i in 0..5u64 {
        send(&rig, &name(i as usize), b"x", &latest, at(&rig, 10 + i)).await;
        assert!(rig.tx.is_idle(), "the lane was released by the writer");
        assert_eq!(
            rig.link.waiting_drains(),
            0,
            "an isolated message asks for nothing"
        );
        assert_eq!(datagrams(&mut rig).len(), 1, "left inline");
    }
    // A loop of emissions: the second follows the first within the gap.
    send(&rig, &name(10), b"x", &latest, at(&rig, 100)).await;
    send(
        &rig,
        &name(11),
        b"x",
        &latest,
        at(&rig, 100) + BURST_GAP / 2,
    )
    .await;
    assert!(rig.tx.is_idle());
    assert_eq!(
        rig.link.waiting_drains(),
        1,
        "a burst asks for one call back"
    );
    assert_eq!(datagrams(&mut rig).len(), 2);
    settle(&rig.tx).await;
    send(&rig, &name(12), b"x", &latest, at(&rig, 200)).await;
    assert_eq!(
        rig.link.queued_datagrams(),
        1,
        "written inline by its own caller"
    );
}

#[tokio::test]
async fn a_kept_sender_is_given_only_while_the_node_still_holds_it() {
    use super::tx::{SenderCache, Tx};
    let (first, second) = (
        rig(ChannelMode::Latest, LinkConfig::default()).tx,
        rig(ChannelMode::Latest, LinkConfig::default()).tx,
    );
    let (tx, cache, space) = (Tx::default(), SenderCache::default(), name(0));
    let latest = ChannelMode::Latest;
    let given = |tx: &Tx, mode| cache.with(tx, mode, Arc::clone);
    assert!(given(&tx, latest).is_none(), "nothing kept yet");

    let before = tx.epoch();
    let held = tx.get_or_make(&space, latest, CHANNEL, || first.clone());
    assert!(Arc::ptr_eq(&held, &first));
    // The lookup raced no replacement of another sender: but `before` was read before this one
    // was made, so the entry is stale at birth (conservative, never wrong).
    cache.keep(before, latest, &held);
    assert!(given(&tx, latest).is_none());
    cache.keep(tx.epoch(), latest, &held);
    assert!(Arc::ptr_eq(&given(&tx, latest).unwrap(), &first));
    // Asking for the same channel again replaces nothing.
    let again = tx.get_or_make(&space, latest, CHANNEL, || unreachable!("held"));
    assert!(Arc::ptr_eq(&again, &first));
    assert!(Arc::ptr_eq(&given(&tx, latest).unwrap(), &first));
    // Another mode is another slot.
    assert!(given(&tx, ChannelMode::Reliable).is_none());

    // The node makes another sender (a new channel id): the kept one is no longer given.
    let replaced = tx.get_or_make(&space, latest, CHANNEL + 1, || second.clone());
    assert!(Arc::ptr_eq(&replaced, &second));
    assert!(
        given(&tx, latest).is_none(),
        "a kept sender the node replaced is never used"
    );
}

#[tokio::test]
async fn emit_taking_takes_the_payload_it_queues_and_leaves_one_it_refuses() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let latest = EmitOptions::latest();
    let mut payload = Bytes::from(vec![0xC3u8; 200]);
    rig.tx
        .emit_taking(&name(1), &mut payload, &latest, rig.t0)
        .await
        .unwrap();
    assert!(payload.is_empty(), "the queued message holds the payload");
    settle(&rig.tx).await;
    let seen = datagrams(&mut rig);
    let sent = messages(&seen);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        &sent[0].payload[..],
        &[0xC3u8; 200][..],
        "the same bytes leave"
    );
    // A message over the limit is refused, and the caller still has it.
    let mut too_big = Bytes::from(vec![1u8; MESSAGE_MAX + 1]);
    let refused = rig
        .tx
        .emit_taking(&name(1), &mut too_big, &latest, rig.t0)
        .await;
    assert!(matches!(
        refused,
        Err(Refused::Error(EmitError::TooLarge { .. }))
    ));
    assert_eq!(
        too_big.len(),
        MESSAGE_MAX + 1,
        "a refusal leaves the payload"
    );
}

#[tokio::test]
async fn a_plain_emission_ends_the_standing_value_of_its_path_though_it_carries_no_name() {
    let mut rig = rig(ChannelMode::Latest, LinkConfig::default());
    let stand = EmitOptions::latest().standing(Duration::from_secs(100));
    prebind(&mut rig, 1..3).await;
    // Past its first messages and its bind window a message under the path is bare: it carries
    // no name, and still must end what stood under that name.
    send(&rig, &name(1), b"stands", &stand, at(&rig, 10)).await;
    send(&rig, &name(2), b"stays", &stand, at(&rig, 10)).await;
    send(
        &rig,
        &name(1),
        b"plain",
        &EmitOptions::latest(),
        at(&rig, 11),
    )
    .await;
    settle(&rig.tx).await;
    let _ = datagrams(&mut rig);
    let _ = stream(&mut rig);
    rig.tx
        .welcome(true, false, None, true, at(&rig, 20))
        .unwrap();
    settle(&rig.tx).await;
    let seen = stream(&mut rig);
    let standing = messages(&seen);
    assert_eq!(standing.len(), 1, "only the second path still stands");
    assert_eq!(standing[0].payload, Bytes::from_static(b"stays"));
}

#[tokio::test]
async fn the_carrier_the_node_attaches_in_place_of_another_gets_the_next_emissions_frames() {
    let rig = rig(ChannelMode::Latest, LinkConfig::default());
    let (first, second) = (
        Link::new(LinkConfig::default()),
        Link::new(LinkConfig::default()),
    );
    let slot = Arc::new(CarrierSlot::default());
    slot.set(first.clone());
    let tx = TxChannel::new(
        ChannelMode::Latest,
        &SendKey {
            id: CHANNEL,
            key_epoch: 0,
            frame_key: ChannelKey::random().frame_key(CHANNEL, 0),
            live: Arc::clone(&rig.live),
        },
        rig.keys.clone(),
        Tasks::new(),
        Arc::clone(&slot),
        Arc::new(TxStats::default()),
        Arc::new(AtomicU64::new(0)),
    );
    let latest = EmitOptions::latest();
    tx.emit(&name(1), &Bytes::from_static(b"one"), &latest, rig.t0)
        .await
        .unwrap();
    settle(&tx).await;
    assert_eq!(
        (first.queued_datagrams(), second.queued_datagrams()),
        (1, 0)
    );
    // A second emission under the same carrier reads it from the channel's own copy.
    tx.emit(&name(1), &Bytes::from_static(b"two"), &latest, at(&rig, 1))
        .await
        .unwrap();
    settle(&tx).await;
    assert_eq!(
        (first.queued_datagrams(), second.queued_datagrams()),
        (2, 0)
    );
    // Another carrier is attached: the next frame goes to it, and no more to the first.
    slot.set(second.clone());
    tx.emit(
        &name(1),
        &Bytes::from_static(b"three"),
        &latest,
        at(&rig, 2),
    )
    .await
    .unwrap();
    settle(&tx).await;
    assert_eq!(
        (first.queued_datagrams(), second.queued_datagrams()),
        (2, 1)
    );
}
