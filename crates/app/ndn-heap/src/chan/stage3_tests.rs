//! The sender through real nodes (docs/specs/channel.md, The verbs, The name-id table, Standing):
//! who may emit, what an ask is given besides the key, and what follows the session on the stream.
//! The receiver's half of these, and the cases that need both ends over a bad carrier, are in
//! `rx_tests.rs`; the writer's own cases are in `tx_tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::aead::{Aead, FrameCipher};
use super::carrier_kit::{Link, LinkConfig};
use super::control::Control;
use super::frame::open;
use super::limits::{MESSAGE_MAX, STREAM_FRAME_MAX};
use super::message::{Message, Origin};
use super::rx_tests::{Rig, eventually, rig_of, shared};
use super::tx::FRAME_CAP;
use super::verbs::{Congestion, EmitError, EmitOptions, Mode, Window};
use super::wire::ChannelMode;
use crate::error::NextStep;
use crate::node::tests::{space, world};
use crate::space::Heap;
use crate::test_kit::n;
use ndn_transport::SideKind;

async fn three() -> Rig {
    let rig = rig_of(world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await).await;
    shared(&rig).await;
    rig
}

fn heap(rig: &Rig, who: usize) -> Heap {
    rig.nodes[who].space(&space()).expect("the space is open")
}

/// Bob (a writer) sends over `link`.
fn carrier(rig: &Rig) -> Arc<Link> {
    let link = Link::new(LinkConfig {
        datagram_capacity: 100_000,
        ..LinkConfig::default()
    });
    rig.nodes[1].attach_carrier(link.clone());
    link
}

/// What opens bob's frames of `mode`.
fn cipher(rig: &Rig, mode: ChannelMode) -> FrameCipher {
    let key = rig.nodes[1]
        .inner
        .chan
        .channels
        .current(&space(), mode)
        .expect("bob has a channel");
    FrameCipher::new(&key.frame_key, Aead::preferred())
}

#[derive(Debug)]
enum Seen {
    Control(Control),
    Data(Vec<Message>),
}

/// Everything on the stream until it is quiet.
async fn stream_of(link: &Link, cipher: &FrameCipher) -> Vec<Seen> {
    let mut frames = Vec::new();
    let mut quiet = 0;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let more = link.take_stream();
        if more.is_empty() {
            quiet += 1;
            if quiet >= 3 && !frames.is_empty() {
                break;
            }
        } else {
            quiet = 0;
            frames.extend(more);
        }
    }
    frames
        .into_iter()
        .map(|f| {
            let opened = open(cipher, f, STREAM_FRAME_MAX).expect("a frame bob sealed");
            match opened.header().kind {
                SideKind::Control => {
                    Seen::Control(Control::decode(opened.plaintext()).expect("a control record"))
                }
                SideKind::Data => Seen::Data(
                    opened
                        .messages(MESSAGE_MAX)
                        .expect("data")
                        .collect::<Result<_, _>>()
                        .expect("messages"),
                ),
                other => panic!("a {other:?} frame on the stream"),
            }
        })
        .collect()
}

fn controls(seen: &[Seen]) -> Vec<&Control> {
    seen.iter()
        .filter_map(|s| match s {
            Seen::Control(c) => Some(c),
            Seen::Data(_) => None,
        })
        .collect()
}

fn messages(seen: &[Seen]) -> Vec<&Message> {
    seen.iter()
        .flat_map(|s| match s {
            Seen::Data(m) => m.iter().collect::<Vec<_>>(),
            Seen::Control(_) => Vec::new(),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_writer_emits_and_a_space_not_yet_held_is_not_ready() {
    let rig = rig_of(world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await).await;
    // Bob opened the space; the record has not reached him: he is nothing of it yet.
    let early = rig.nodes[1].open(&space()).await.unwrap();
    let refused = early
        .emit(&n("/a"), Bytes::from_static(b"x"), EmitOptions::latest())
        .await
        .unwrap_err();
    assert!(matches!(refused, EmitError::NotReady { .. }), "{refused:?}");
    assert_eq!(refused.next(), NextStep::RetryLater);

    shared(&rig).await;
    // Carol reads: she is told to ask the owner.
    let reader = heap(&rig, 2);
    let refused = reader
        .emit(&n("/a"), Bytes::from_static(b"x"), EmitOptions::latest())
        .await
        .unwrap_err();
    assert!(
        matches!(refused, EmitError::NotWriter { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);
    assert!(
        reader.node.chan.channels.modes(&space()).is_empty(),
        "a refusal opens no channel"
    );

    // `Latest` with `Block` is refused at the call, whoever asks.
    let block = EmitOptions::latest().on_congestion(Congestion::Block);
    for who in [1, 2] {
        let refused = heap(&rig, who)
            .emit(&n("/a"), Bytes::new(), block)
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, EmitError::FixRequest { why } if why.contains("Use Reliable")),
            "{refused:?}"
        );
    }
    // A writer's emission is taken, opens the channel so asks can be answered, and with no
    // receiver sends nothing.
    let link = carrier(&rig);
    let bob = heap(&rig, 1);
    bob.emit(
        &n("/cursor"),
        Bytes::from_static(b"1,2"),
        EmitOptions::latest(),
    )
    .await
    .unwrap();
    assert_eq!(
        rig.nodes[1].inner.chan.channels.modes(&space()),
        [ChannelMode::Latest]
    );
    assert_eq!(link.queued_datagrams(), 0);
    assert_eq!(link.queued_stream_bytes(), 0);
    assert_eq!(rig.nodes[1].inner.chan.tx.stats.unrouted.get(), 1);
    // The second mode opens its own channel; a `Reliable` emission on a carrier with no stream is
    // refused `NoStream`.
    let nostream = Link::new(LinkConfig {
        has_stream: false,
        ..LinkConfig::default()
    });
    rig.nodes[1].attach_carrier(nostream);
    let refused = bob
        .emit(&n("/a"), Bytes::new(), EmitOptions::reliable())
        .await
        .unwrap_err();
    assert_eq!(refused, EmitError::NoStream { what: "Reliable" });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_receiver_is_given_hello_then_the_binds_the_session_could_not_hold_then_what_stands()
{
    let rig = three().await;
    let link = carrier(&rig);
    let bob = heap(&rig, 1);
    // Before anyone listens: a value that stands, and one that does not.
    let stands = EmitOptions::latest().standing(Duration::from_secs(60));
    bob.emit(&n("/status"), Bytes::from_static(b"online"), stands)
        .await
        .unwrap();
    bob.emit(
        &n("/cursor"),
        Bytes::from_static(b"1,2"),
        EmitOptions::latest(),
    )
    .await
    .unwrap();
    // Carol asks: the first frames on the stream after her session are HELLO, then the standing
    // value between its brackets.
    let info = rig.nodes[2]
        .ask_channel_in(&space(), rig.nodes[1].name(), ChannelMode::Latest)
        .await
        .expect("bob answers carol");
    let cipher = cipher(&rig, ChannelMode::Latest);
    let seen = stream_of(&link, &cipher).await;
    let session = rig.nodes[2].inner.chan.sessions.get(info.channel).unwrap();
    let terms = session.terms();
    assert!(
        terms.table.is_empty(),
        "nothing was bound while nobody listened"
    );
    assert_eq!(terms.frame_max, FRAME_CAP as u64);
    let ops = controls(&seen);
    assert!(matches!(ops[0], Control::Hello { .. }), "{ops:?}");
    assert!(
        matches!(ops[1], Control::Bind { id: 1, .. }),
        "the standing value's name is bound before its bracket: {ops:?}"
    );
    assert!(matches!(ops[2], Control::StandingBegin));
    assert!(matches!(ops[3], Control::StandingEnd));
    let standing = messages(&seen);
    assert_eq!(standing.len(), 1, "only /status stood");
    assert_eq!(standing[0].payload, Bytes::from_static(b"online"));
    assert!(matches!(standing[0].origin, Some(Origin::Standing(_))));
    assert!(
        standing[0]
            .stand_secs
            .is_some_and(|s| (1..=60).contains(&s))
    );
    assert!(standing[0].name.is_some(), "a replay names itself");

    // Now 71 names are bound (/status by the replay, 70 paths): the next receiver's session holds
    // 64 binds, and the other 7 follow as BIND frames right after HELLO.
    for i in 0..70 {
        bob.emit(
            &n(&format!("/p{i}")),
            Bytes::from_static(b"v"),
            EmitOptions::latest(),
        )
        .await
        .unwrap();
    }
    let _ = link.take_datagrams();
    let _ = stream_of(&link, &cipher).await;
    let info = rig.nodes[0]
        .ask_channel_in(&space(), rig.nodes[1].name(), ChannelMode::Latest)
        .await
        .expect("bob answers the owner");
    let seen = stream_of(&link, &cipher).await;
    let session = rig.nodes[0].inner.chan.sessions.get(info.channel).unwrap();
    assert_eq!(
        session.terms().table.len(),
        64,
        "at most 64 binds in the session"
    );
    let ids: Vec<u64> = session.terms().table.iter().map(|b| b.id).collect();
    assert_eq!(ids, (1..=64).collect::<Vec<u64>>(), "ids from 1, in order");
    let ops = controls(&seen);
    assert!(matches!(ops[0], Control::Hello { .. }));
    let rest: Vec<u64> = ops
        .iter()
        .filter_map(|c| match c {
            Control::Bind { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(
        rest,
        (65..=71).collect::<Vec<u64>>(),
        "the rest follow as BIND"
    );
    assert!(
        ops.iter()
            .position(|c| matches!(c, Control::Bind { .. }))
            .unwrap()
            < ops
                .iter()
                .position(|c| matches!(c, Control::StandingBegin))
                .unwrap(),
        "binds come before the standing values"
    );
    // A renewal (a known receiver asking again) is given no second HELLO.
    rig.nodes[0]
        .ask_channel_in(&space(), rig.nodes[1].name(), ChannelMode::Latest)
        .await
        .expect("bob answers again");
    assert!(
        stream_of(&link, &cipher).await.is_empty(),
        "a known receiver is welcomed once"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_session_names_the_window_and_is_replayed_the_recent_past() {
    let rig = three().await;
    let link = carrier(&rig);
    let bob = heap(&rig, 1);
    let window = Window {
        messages: 10,
        bytes: 1 << 20,
        age: Duration::from_secs(10),
    };
    let opts = EmitOptions::window(window);
    assert!(matches!(opts.mode, Mode::Window(_)));
    for i in 0..15u8 {
        bob.emit(&n("/line"), Bytes::from(vec![i]), opts)
            .await
            .unwrap();
    }
    assert_eq!(
        link.queued_stream_bytes(),
        0,
        "nobody listens: nothing is sent"
    );
    let info = rig.nodes[2]
        .ask_channel_in(&space(), rig.nodes[1].name(), ChannelMode::Window)
        .await
        .expect("bob answers carol");
    let session = rig.nodes[2].inner.chan.sessions.get(info.channel).unwrap();
    let said = session
        .terms()
        .window
        .expect("a window channel says its window");
    assert_eq!((said.messages, said.bytes, said.ms), (10, 1 << 20, 10_000));
    let cipher = cipher(&rig, ChannelMode::Window);
    let seen = stream_of(&link, &cipher).await;
    assert!(matches!(controls(&seen)[0], Control::Hello { .. }));
    let replay = messages(&seen);
    let values: Vec<u8> = replay.iter().map(|m| m.payload[0]).collect();
    assert_eq!(
        values,
        (5..15).collect::<Vec<u8>>(),
        "the last ten, oldest first"
    );
    assert!(
        replay
            .iter()
            .all(|m| matches!(m.origin, Some(Origin::Replayed(_))))
    );
    // Live messages follow the replay, in the channel's order.
    bob.emit(&n("/line"), Bytes::from_static(b"\x63"), opts)
        .await
        .unwrap();
    eventually("the live message is on the stream", || {
        link.queued_stream_bytes() > 0
    })
    .await;
    let live = stream_of(&link, &cipher).await;
    let live = messages(&live);
    assert_eq!(live.len(), 1);
    assert!(live[0].origin.is_none());
    assert!(live[0].seq > replay.last().unwrap().seq);
    eventually("eventually quiet", || eventually_idle(&rig)).await;
}

fn eventually_idle(rig: &Rig) -> bool {
    rig.nodes[1]
        .inner
        .chan
        .tx
        .get(&space(), ChannelMode::Window)
        .is_some_and(|tx| tx.is_idle())
}
