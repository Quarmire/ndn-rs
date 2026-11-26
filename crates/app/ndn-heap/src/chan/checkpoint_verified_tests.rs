//! What a receiver does with frames no verified checkpoint has covered yet (docs/specs/channel.md,
//! Checkpoints, The receiver): `Trust::Verified` holds delivery until a checkpoint that lists the
//! frame verified, a checkpoint that never comes does not stall it forever, and silence is not
//! trust for a `Prompt` receiver either. Frames and checkpoints are sealed by hand under bob's
//! channel key and signed by bob's device key (the `Ck` kit of `checkpoint_flow_tests`), handed
//! to Carol's real node at a clock of the test's own, so every wait of 3 s is an injected
//! instant and not a real wait. One test lets bob's real sender write the checkpoints.

use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use ndn_foundation_types::Name;
use ndn_transport::{FaceId, SideKind};

use super::carrier_kit::LinkConfig;
use super::checkpoint_flow_tests::{Ck, HOLDER, HONEST, ck, ck_with, latest, path, verified};
use super::evidence::EvidenceKind;
use super::frame::Header;
use super::items::Items;
use super::rx::{Delivery, Dropped};
use super::sessions::EndReason;
use super::verbs::{EmitOptions, GetNotice, GetOptions, LiveEnd, Select};
use super::wire::ChannelMode;
use crate::log::Alert;
use crate::node::tests::space;
use crate::rt::Instant;

/// What an `Items` said, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Item(Name, Vec<u8>),
    Lagged(u64),
    Retracted { from: u64, to: u64 },
    Ended(EndReason),
}

fn item(letter: u8, payload: &[u8]) -> Seen {
    Seen::Item(path(letter), payload.to_vec())
}

/// Everything the `Items` hold now: items, then what they say besides.
fn drain(items: &mut Items) -> Vec<Seen> {
    let mut out = Vec::new();
    while let Some(Some(next)) = items.next().now_or_never() {
        out.push(match next {
            Ok(got) => Seen::Item(got.path, got.bytes.to_vec()),
            Err(GetNotice::Lagged { missed }) => Seen::Lagged(missed),
            Err(GetNotice::Retracted { from, to, .. }) => Seen::Retracted { from, to },
            Err(GetNotice::LiveEnded(LiveEnd::Ended { reason, .. })) => Seen::Ended(reason),
            Err(other) => panic!("a notice nothing here causes: {other:?}"),
        });
    }
    out
}

/// A second reader of Carol's space that trusts frames as they arrive.
fn prompt_reader(ck: &Ck) -> Items {
    ck.carol()
        .space(&space())
        .expect("carol is a member")
        .get(
            Select::Prefix(Name::root()),
            GetOptions {
                kept: false,
                ..latest()
            },
        )
        .expect("carol may read")
}

/// The pass the node's maintenance runs, at the test's clock `ms`.
fn sweep(ck: &Ck, ms: u64) {
    ck.carol().inner.chan.rx.sweep(&ck.carol().inner, ck.at(ms));
}

fn holding(ck: &Ck) -> bool {
    ck.carol()
        .inner
        .chan
        .rx
        .channel(ck.info.channel)
        .expect("carol holds the channel")
        .holding()
}

/// Frames Carol holds for a lane now.
fn held_frames(ck: &Ck) -> usize {
    ck.carol()
        .inner
        .chan
        .rx
        .channel(ck.info.channel)
        .expect("carol holds the channel")
        .deferred()
        .0
}

/// The text of an `Unverifiable` end; any other reason fails the test.
fn unverifiable(reason: &EndReason) -> &str {
    match reason {
        EndReason::Unverifiable { why } => why,
        other => panic!("the session should end as unverifiable, not {other:?}"),
    }
}

/// An end for lack of a checkpoint says why and what to do.
fn says_why_and_what_to_do(why: &str) {
    assert!(
        why.contains("waited 3 s for a checkpoint that verifies"),
        "it says what was waited for: {why}"
    );
    assert!(
        why.contains("ask the sender again"),
        "it says what to do: {why}"
    );
}

/// `Trust::Verified` never gives a frame that no verified checkpoint lists. A key holder's frame
/// at a sequence the sender used (a relay put it there) is dropped when the checkpoint comes, is
/// evidence against the face it came over, and a genuine frame is delivered after the checkpoint
/// that lists it verified and not before, however the frames and checkpoints interleave. A `Prompt`
/// reader of the same channel has the forgery at once and is told to take it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verified_delivery_never_delivers_an_unlisted_frame() {
    let mut ck = ck(ChannelMode::Reliable, verified(), LinkConfig::default()).await;
    ck.pause_tick();
    let mut prompt = prompt_reader(&ck);
    let s = ck.start();
    let a = ck.data(s, 0, b"genuine a");
    let forged = ck.data(s + 1, 1, b"forged b");
    let real_b = ck.data(s + 1, 1, b"the sender's b, which the relay replaced");
    let c = ck.data(s + 2, 2, b"genuine c");
    ck.deliver(&a, HONEST, ck.at(0)).await;
    ck.deliver(&forged, HOLDER, ck.at(1)).await;
    ck.deliver(&c, HONEST, ck.at(2)).await;

    assert_eq!(
        drain(&mut ck.items),
        [],
        "three frames are accepted and the Verified reader has none: no checkpoint lists them"
    );
    assert_eq!(
        drain(&mut prompt),
        [
            item(0, b"genuine a"),
            item(1, b"forged b"),
            item(2, b"genuine c")
        ],
        "the Prompt reader has them as they arrive, the forgery too"
    );
    assert!(ck.evidence().is_empty() && ck.bars().is_empty());

    // The sender's checkpoint lists the frames it sent: its own b is not the one Carol took.
    let first = ck.checkpoint(s + 3, s, s + 3, &[&a, &real_b, &c]);
    ck.checkpoint_in(&first, HONEST, 20).await;
    assert_eq!(
        drain(&mut ck.items),
        [
            item(0, b"genuine a"),
            Seen::Lagged(1),
            item(2, b"genuine c")
        ],
        "the listed frames, and in b's place a gap: the forgery never reached the reader"
    );
    assert_eq!(
        drain(&mut prompt),
        [Seen::Retracted {
            from: s + 1,
            to: s + 2
        }],
        "the Prompt reader is told to take back b; b carried its own name, which may have \
         changed how what followed was read, so the retraction runs to the highest sequence taken"
    );
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Mismatch);
    assert_eq!(evidence[0].seq0, s + 1);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(evidence[0].frame, forged, "the frame Carol accepted");
    assert_eq!(
        evidence[0].proof, first,
        "the checkpoint that contradicts it"
    );
    assert_eq!(
        ck.bars(),
        [HOLDER],
        "the link the forgery came over, not bob's"
    );
    let alerts = ck.alerts();
    assert!(
        matches!(
            &alerts[..],
            [Alert::ChannelForgery { seq, via, .. }] if *seq == s + 1 && *via == FaceId(HOLDER)
        ),
        "{alerts:?}"
    );
    assert_eq!(ck.stats().mismatches.get(), 1);

    // A genuine frame the checkpoint did not reach (it was sent after it was built) is accepted,
    // is no mismatch, and waits: delivered only when the checkpoint that lists it verified.
    let d = ck.data(s + 4, 3, b"late d");
    ck.deliver(&d, HONEST, ck.at(25)).await;
    assert_eq!(drain(&mut ck.items), [], "not covered yet: not delivered");
    assert_eq!(
        ck.stats().mismatches.get(),
        1,
        "a frame not yet covered is no mismatch"
    );
    let second = ck.checkpoint(s + 5, s + 3, s + 5, &[&d]);
    ck.checkpoint_in(&second, HONEST, 45).await;
    assert_eq!(drain(&mut ck.items), [item(3, b"late d")]);
    assert_eq!(ck.evidence().len(), 1, "no new evidence");
    assert_eq!(ck.bars(), [HOLDER]);
    assert!(ck.session_held());
}

/// The checkpoint that covers frames N..M never arrives. `Trust::Verified` does not wait for it
/// forever, and **never delivers the frames unverified**: as soon as a later checkpoint shows its
/// range passed them they are dropped, counted (`held_dropped`, `unchecked`) and told as a
/// `Lagged` (the frames and the lost checkpoint's own sequence); the frames the later checkpoint
/// lists are delivered. With no later checkpoint at all the held frames are dropped at the 3 s
/// bound, still counted and told, and the session ends as unverifiable (the receiver cannot tell
/// the sender's frames from a key holder's).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_checkpoint_does_not_stall_verified_forever() {
    let mut ck = ck(ChannelMode::Reliable, verified(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    // Frames s..s+2, whose checkpoint (at s+3) is lost on the way.
    for i in 0..3u8 {
        let frame = ck.data(s + u64::from(i), i, format!("early {i}").as_bytes());
        ck.deliver(&frame, HONEST, ck.at(u64::from(i))).await;
    }
    assert_eq!(drain(&mut ck.items), [], "held for a checkpoint");
    assert_eq!(ck.stats().held.get(), 3);

    // The next checkpoint begins where the lost one ended: it cannot list the early frames.
    let d = ck.data(s + 4, 3, b"after d");
    let e = ck.data(s + 5, 4, b"after e");
    ck.deliver(&d, HONEST, ck.at(25)).await;
    ck.deliver(&e, HONEST, ck.at(26)).await;
    let next = ck.checkpoint(s + 6, s + 3, s + 6, &[&d, &e]);
    ck.checkpoint_in(&next, HONEST, 45).await;
    assert_eq!(
        drain(&mut ck.items),
        [Seen::Lagged(4), item(3, b"after d"), item(4, b"after e")],
        "the three early frames and the lost checkpoint's sequence are told missed; the frames \
         the next checkpoint lists are delivered; the early ones never are"
    );
    let stats = ck.stats();
    assert_eq!(stats.held_dropped.get(), 3, "the early frames, counted");
    assert_eq!(
        stats.unchecked.get(),
        3,
        "no checkpoint can judge them any more"
    );
    assert_eq!(stats.checkpoints_verified.get(), 1);
    assert_eq!(stats.mismatches.get(), 0, "loss is not forgery");
    assert!(ck.evidence().is_empty() && ck.bars().is_empty() && ck.alerts().is_empty());
    assert_eq!(held_frames(&ck), 0);

    // Frames after that, whose checkpoint never comes either and nothing follows: held until 3 s
    // after they were accepted, no sooner.
    let f = ck.data(s + 7, 5, b"unlisted f");
    let g = ck.data(s + 8, 6, b"unlisted g");
    ck.deliver(&f, HONEST, ck.at(100)).await;
    ck.deliver(&g, HONEST, ck.at(110)).await;
    sweep(&ck, 3_100);
    assert_eq!(
        drain(&mut ck.items),
        [],
        "3 s after the first is not yet past 3 s after the second"
    );
    assert!(ck.session_held());
    assert_eq!(ck.stats().held_dropped.get(), 3);

    sweep(&ck, 3_111);
    let seen = drain(&mut ck.items);
    let [Seen::Lagged(2), Seen::Ended(reason)] = &seen[..] else {
        panic!("the two held frames told missed, then the end: {seen:?}");
    };
    says_why_and_what_to_do(unverifiable(reason));
    assert_eq!(ck.stats().held_dropped.get(), 5, "counted");
    assert_eq!(ck.stats().unverifiable.get(), 1);
    assert!(!ck.session_held());
}

/// A `Prompt` receiver does not take silence for trust: frames no verified checkpoint covers for
/// longer than `max(4 x period, 100 ms)` make it hold what follows (so a relay that drops the
/// sender's checkpoints cannot keep unverified frames flowing), one verified checkpoint releases
/// them (except any it contradicts), and 3 s without one ends the session as unverifiable with
/// the held frames told missed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silence_beyond_unchecked_max_holds_delivery_then_ends_the_session() {
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let frame = |ck: &Ck, i: u8| ck.data(s + u64::from(i), i, format!("frame {i}").as_bytes());
    let text = |i: u8| format!("frame {i}").into_bytes();

    // At the default 20 ms period the limit is max(4 x 20, 100) = 100 ms: up to and including it
    // frames are delivered as they come.
    let mut sent = Vec::new();
    for (i, ms) in [(0u8, 0u64), (1, 50), (2, 100)] {
        let f = frame(&ck, i);
        assert_eq!(
            ck.deliver(&f, HONEST, ck.at(ms)).await,
            Delivery::Delivered { messages: 1 }
        );
        assert_eq!(drain(&mut ck.items), [item(i, &text(i))]);
        sent.push(f);
    }
    assert!(
        !holding(&ck),
        "a frame exactly 100 ms old is not past the maximum"
    );

    // 1 ms later the oldest unchecked frame is past it: what follows is held, a forgery in it too.
    let f3 = frame(&ck, 3);
    assert_eq!(
        ck.deliver(&f3, HONEST, ck.at(101)).await,
        Delivery::Deferred
    );
    assert!(holding(&ck));
    let forged4 = ck.data(s + 4, 4, b"forged 4");
    let real4 = ck.data(s + 4, 4, b"the sender's 4");
    assert_eq!(
        ck.deliver(&forged4, HOLDER, ck.at(150)).await,
        Delivery::Deferred
    );
    let f5 = frame(&ck, 5);
    assert_eq!(
        ck.deliver(&f5, HONEST, ck.at(200)).await,
        Delivery::Deferred
    );
    // The relay drops every checkpoint; frames keep coming for nearly 3 s and none is delivered.
    let f6 = frame(&ck, 6);
    assert_eq!(
        ck.deliver(&f6, HONEST, ck.at(2_900)).await,
        Delivery::Deferred
    );
    sweep(&ck, 2_900);
    assert!(ck.session_held(), "the session ends only past 3 s");
    assert_eq!(drain(&mut ck.items), [], "nothing unverified flows");
    assert_eq!(ck.stats().held.get(), 4);
    sent.extend([f3, real4, f5, f6]);

    // One verified checkpoint lifts the hold: the held frames it lists are delivered in order, the
    // one it contradicts is not (it is evidence), and the reader is told what is missing.
    let sent: Vec<&Bytes> = sent.iter().collect();
    let cp = ck.checkpoint(s + 7, s, s + 7, &sent);
    ck.checkpoint_in(&cp, HONEST, 2_950).await;
    assert!(!holding(&ck));
    assert_eq!(
        drain(&mut ck.items),
        [
            item(3, &text(3)),
            Seen::Lagged(1),
            item(5, &text(5)),
            item(6, &text(6)),
            Seen::Retracted {
                from: s + 4,
                to: s + 6
            }
        ],
        "released in order; the forged frame never reached the reader"
    );
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Mismatch);
    assert_eq!(evidence[0].frame, forged4);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(ck.bars(), [HOLDER]);
    assert_eq!(ck.stats().held_dropped.get(), 0);

    // Delivery is prompt again, and the clock of silence starts over with the next frame.
    let f7 = frame(&ck, 8);
    ck.deliver(&f7, HONEST, ck.at(3_000)).await;
    assert_eq!(drain(&mut ck.items), [item(8, &text(8))]);
    let f8 = frame(&ck, 9);
    assert_eq!(
        ck.deliver(&f8, HONEST, ck.at(3_101)).await,
        Delivery::Deferred
    );
    // No checkpoint for 3 s: at 3 s the session still stands, 1 ms past it, it ends.
    sweep(&ck, 6_000);
    assert!(ck.session_held());
    assert_eq!(drain(&mut ck.items), []);
    sweep(&ck, 6_001);
    let seen = drain(&mut ck.items);
    let [Seen::Lagged(1), Seen::Ended(reason)] = &seen[..] else {
        panic!("the held frame told missed, then the end: {seen:?}");
    };
    says_why_and_what_to_do(unverifiable(reason));
    assert_eq!(
        ck.stats().held_dropped.get(),
        1,
        "the frame held at the end is counted"
    );
    assert_eq!(ck.stats().unverifiable.get(), 1);
    assert!(!ck.session_held());
}

/// A frame that comes after 3 s with no verified checkpoint does not just wait: the session ends
/// with it, it is not delivered, and the end says why and what to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_after_three_silent_seconds_ends_the_session_and_is_not_delivered() {
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let f0 = ck.data(s, 0, b"first");
    ck.deliver(&f0, HONEST, ck.at(0)).await;
    assert_eq!(drain(&mut ck.items), [item(0, b"first")]);
    // Exactly 3 s: held, not yet the end.
    let f1 = ck.data(s + 1, 1, b"at 3 s");
    assert_eq!(
        ck.deliver(&f1, HONEST, ck.at(3_000)).await,
        Delivery::Deferred
    );
    assert!(ck.session_held());
    let f2 = ck.data(s + 2, 2, b"past 3 s");
    let ended = ck.deliver(&f2, HONEST, ck.at(3_001)).await;
    let Delivery::Ended(reason) = &ended else {
        panic!("the frame that is past 3 s ends the session: {ended:?}");
    };
    says_why_and_what_to_do(unverifiable(reason));
    let seen = drain(&mut ck.items);
    let [Seen::Lagged(1), Seen::Ended(told)] = &seen[..] else {
        panic!("the held frame told missed, then the end, and no item: {seen:?}");
    };
    assert_eq!(told, reason);
    assert!(!ck.session_held());
    assert_eq!(ck.stats().unverifiable.get(), 1);
    assert_eq!(ck.stats().held_dropped.get(), 1);
}

/// A frame at a sequence already accepted costs a comparison, and a frame that differs from the
/// accepted one at most **three** AEAD attempts for the whole sequence (a key holder's second
/// frame at it is an event, so it is opened); after that more garbage at the sequence is a copy and
/// costs nothing. The accepted frame is delivered once whatever came after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_at_an_accepted_sequence_costs_three_aead_attempts_and_then_none() {
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let a = ck.data(s, 0, b"the frame");
    ck.deliver(&a, HONEST, ck.at(0)).await;
    assert_eq!(drain(&mut ck.items), [item(0, b"the frame")]);
    let before = ck.stats().aead_attempts.get();

    // The same octets again: a copy, no AEAD.
    assert_eq!(
        ck.deliver(&a, HOLDER, ck.at(1)).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    assert_eq!(ck.stats().aead_attempts.get(), before);

    // Ten frames that are not it (a tag octet flipped each time, so each differs from the others
    // too): three are opened and fail, the other seven are copies.
    for n in 1..=10u8 {
        let mut octets = a.to_vec();
        let last = octets.len() - 1;
        octets[last] ^= n;
        let garbage = Bytes::from(octets);
        let got = ck.deliver(&garbage, HOLDER, ck.at(2)).await;
        let want = if n <= 3 {
            Delivery::Dropped(Dropped::Unauthentic)
        } else {
            Delivery::Dropped(Dropped::Replayed)
        };
        assert_eq!(got, want, "garbage number {n}");
    }
    assert_eq!(
        ck.stats().aead_attempts.get() - before,
        3,
        "ten frames at one sequence, three attempts"
    );
    assert_eq!(ck.stats().unauthentic.get(), 3);
    assert_eq!(drain(&mut ck.items), [], "nothing more is delivered");
    assert!(ck.evidence().is_empty() && ck.bars().is_empty());
}

/// A channel whose sender sends no checkpoints (its path has no stream, so the session announces
/// period 0) cannot be verified: a `Verified` reader is told so once, with what to do, and is never
/// given a frame; a `Prompt` reader of the same channel is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_without_a_stream_cannot_be_verified() {
    let no_stream = LinkConfig {
        has_stream: false,
        ..LinkConfig::default()
    };
    let mut ck = ck(ChannelMode::Latest, verified(), no_stream).await;
    ck.pause_tick();
    let mut prompt = prompt_reader(&ck);
    assert_eq!(
        ck.info.checkpoint, None,
        "the session says it sends no checkpoints"
    );
    assert_eq!(ck.info.detection_window(Duration::from_millis(1)), None);
    let s = ck.start();
    let f0 = ck.data(s, 0, b"x");
    assert!(matches!(
        ck.deliver(&f0, HONEST, ck.at(0)).await,
        Delivery::Delivered { .. }
    ));
    assert_eq!(
        drain(&mut prompt),
        [item(0, b"x")],
        "the Prompt reader is unaffected"
    );
    let seen = drain(&mut ck.items);
    let [Seen::Ended(EndReason::Unverifiable { why })] = &seen[..] else {
        panic!("the Verified reader is told, and has no item: {seen:?}");
    };
    assert!(why.contains("sends no checkpoints"), "why: {why}");
    assert!(why.contains("Trust::Prompt"), "what to do: {why}");

    // Told once; and nothing is ever delivered to it, while the Prompt reader goes on.
    let f1 = ck.data(s + 1, 1, b"y");
    ck.deliver(&f1, HONEST, ck.at(10)).await;
    assert_eq!(drain(&mut ck.items), []);
    assert_eq!(drain(&mut prompt), [item(1, b"y")]);
    assert!(
        ck.session_held(),
        "the channel itself stands for the Prompt reader"
    );
    assert_eq!(ck.stats().checkpoints.get(), 0);
}

/// The period a sender is set to is what its sessions announce (`S_CKPT_MS`), within 1 ms to 2 s,
/// and what the receiver states as its detection window `W = P + d + 1 ms`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_announces_the_configured_period_held_to_one_millisecond_to_two_seconds() {
    for (asked, announced) in [
        (Duration::from_millis(50), 50u64),
        (Duration::ZERO, 1),
        (Duration::from_secs(10), 2_000),
    ] {
        let ck = ck_with(
            ChannelMode::Reliable,
            latest(),
            LinkConfig::default(),
            asked,
        )
        .await;
        let announced = Duration::from_millis(announced);
        assert_eq!(ck.info.checkpoint, Some(announced), "asked {asked:?}");
        let session = ck.carol().inner.chan.sessions.get(ck.info.channel).unwrap();
        assert_eq!(session.terms().ckpt_ms, announced.as_millis() as u64);
        assert_eq!(
            ck.info.detection_window(Duration::from_millis(1)),
            Some(announced + Duration::from_millis(2)),
            "W = P + d + epsilon"
        );
        let sender = ck
            .bob()
            .inner
            .chan
            .tx
            .get(&space(), ChannelMode::Reliable)
            .expect("bob has the channel he answered on");
        assert_eq!(
            sender.checkpoint_period(),
            Some(announced),
            "bob signs at it"
        );
    }
}

/// Everything bob's real sender wrote to the stream until a checkpoint covers every data frame.
async fn stream_until_covered(ck: &Ck) -> Vec<Bytes> {
    let mut frames: Vec<Bytes> = Vec::new();
    for _ in 0..200 {
        frames.extend(ck.link.take_stream());
        let mut data_end = 0;
        let mut covered = 0;
        for f in &frames {
            let header = Header::decode(f).expect("a frame bob wrote");
            match header.kind {
                SideKind::Checkpoint => covered = covered.max(ck.record_of(f).hi),
                _ => data_end = data_end.max(header.seq0 + header.sequences()),
            }
        }
        if data_end > 0 && covered >= data_end {
            return frames;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("bob's sender wrote no checkpoint that covers what he emitted in 5 s");
}

/// A real setup verifies: the key Carol verifies checkpoints under is bob's device key, found in
/// the certificate her validator vouches for, and the checkpoints bob's own sender writes (not
/// hand-made ones) verify and release the frames to a `Verified` reader. Were the key not found,
/// every checkpoint would count as unverifiable and nothing would ever be delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_real_setup_verifies_the_senders_own_checkpoints() {
    let mut ck = ck(ChannelMode::Reliable, verified(), LinkConfig::default()).await;
    ck.pause_tick();
    let bobs_key = ck.bob().inner.signer.public_key().expect("an Ed25519 key");
    assert_eq!(
        ck.public()[..],
        bobs_key[..],
        "the key found for the session is the one bob signs with"
    );
    let heap = ck.bob().space(&space()).expect("bob is a member");
    let words: [&'static [u8]; 3] = [b"one", b"two", b"three"];
    for (i, word) in words.iter().enumerate() {
        heap.emit(
            &path(i as u8),
            Bytes::from_static(word),
            EmitOptions::reliable(),
        )
        .await
        .unwrap();
    }
    let frames = stream_until_covered(&ck).await;
    // The kit took what the ask queued (bob's `HELLO`) off the stream: those sequences are
    // missing here, and a reader is told so.
    let first = frames
        .iter()
        .map(|f| Header::decode(f).unwrap().seq0)
        .min()
        .unwrap();
    let skipped = first - ck.start();
    let (checkpoints, rest): (Vec<&Bytes>, Vec<&Bytes>) = frames
        .iter()
        .partition(|f| Header::decode(f).unwrap().kind == SideKind::Checkpoint);
    assert!(!checkpoints.is_empty());
    for f in rest {
        ck.deliver(f, HONEST, Instant::now()).await;
    }
    assert_eq!(
        drain(&mut ck.items),
        [],
        "the frames are in, no checkpoint is: nothing is delivered to a Verified reader"
    );
    for f in checkpoints {
        assert_eq!(
            ck.deliver(f, HONEST, Instant::now()).await,
            Delivery::Checkpoint
        );
    }
    let mut want = if skipped > 0 {
        vec![Seen::Lagged(skipped)]
    } else {
        Vec::new()
    };
    want.extend([item(0, b"one"), item(1, b"two"), item(2, b"three")]);
    assert_eq!(
        drain(&mut ck.items),
        want,
        "bob's signed checkpoint lists them, so they are delivered, in order"
    );
    let stats = ck.stats();
    assert!(stats.checkpoints_verified.get() >= 1);
    assert_eq!(stats.unverifiable_checkpoints.get(), 0, "the key was found");
    assert_eq!(stats.bad_checkpoints.get(), 0);
    assert_eq!(stats.mismatches.get(), 0);
    assert!(ck.evidence().is_empty() && ck.bars().is_empty() && ck.alerts().is_empty());
    assert!(ck.session_held());
}

/// `Emitted::verified` says whether a signed checkpoint listed the frame before it was given: a
/// `Trust::Verified` reader is given only listed frames, so its items say `true`; a `Prompt`
/// reader of the same channel is given the same frame as it opens, before any checkpoint can
/// list it, and says `false` and goes on saying it once the checkpoint has come.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_emission_says_whether_a_checkpoint_listed_it_before_it_was_given() {
    use super::verbs::Kind;
    fn flags(items: &mut Items) -> Vec<bool> {
        let mut out = Vec::new();
        while let Some(Some(Ok(got))) = items.next().now_or_never() {
            let Kind::Emitted(emitted) = got.kind else {
                panic!("an emission, not {:?}", got.kind)
            };
            out.push(emitted.verified);
        }
        out
    }
    let mut ck = ck(ChannelMode::Reliable, verified(), LinkConfig::default()).await;
    ck.pause_tick();
    let mut prompt = prompt_reader(&ck);
    let s = ck.start();
    let a = ck.data(s, 0, b"genuine a");
    ck.deliver(&a, HONEST, ck.at(0)).await;
    assert_eq!(
        flags(&mut prompt),
        [false],
        "no checkpoint had listed the frame when the Prompt reader was given it"
    );
    let first = ck.checkpoint(s + 1, s, s + 1, &[&a]);
    ck.checkpoint_in(&first, HONEST, 20).await;
    assert_eq!(
        flags(&mut ck.items),
        [true],
        "the Verified reader is given the frame only once a checkpoint lists it"
    );
    let b = ck.data(s + 2, 1, b"genuine b");
    ck.deliver(&b, HONEST, ck.at(30)).await;
    assert_eq!(
        flags(&mut prompt),
        [false],
        "a Prompt item is never marked verified, the checkpoint came after it or not"
    );
}
