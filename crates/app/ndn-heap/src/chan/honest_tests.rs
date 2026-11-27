//! An honest sender is never accused (docs/specs/channel.md, Checkpoints, 15.4 and 15.5).
//!
//! A receiver treats a frame the checkpoint of its range does not list as a forgery: it retracts
//! what the frame delivered, and its face is barred. That is only sound if a checkpoint lists
//! **every frame the sender sent whose sequence lies in its range**. A frame the sender sent and
//! no checkpoint lists, a frame in flight when the checkpoint was written, is the sender's own
//! doing, and the receiver cannot tell it from a key holder's forgery.
//!
//! The case here runs the real sender over a link that lets the test act **while a frame is in
//! flight** (after the writer handed it over, before the link took it): the same name is emitted
//! again, which under `Latest` replaces the message the frame carries, and the period of a
//! checkpoint ends. The stream's own task writes the checkpoint; the test waits for it to be
//! on the stream before the frame goes on, so the order is the case's and no timing decides it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;

use super::carrier_kit::LinkConfig;
use super::checkpoint_flow_tests::{
    HONEST, ck_with, is_checkpoint, latest, path, settle, verified,
};
use super::rx::Delivery;
use super::verbs::{EmitOptions, GetNotice};
use super::wire::ChannelMode;
use crate::node::tests::space;
use crate::rt::Instant;

/// A frame whose message a newer emission of its name replaced while the frame was on its way
/// out, with a checkpoint written meanwhile: the checkpoint's range must not cover the frame
/// (it is not recorded yet), so the receiver, which gets the frame and then the checkpoint, has
/// nothing to contradict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_in_flight_whose_message_was_replaced_is_not_contradicted_by_a_checkpoint() {
    // A period of 2 s: the sender's own timer does not fire during the case.
    let mut ck = ck_with(
        ChannelMode::Latest,
        latest(),
        LinkConfig::default(),
        Duration::from_secs(2),
    )
    .await;
    ck.pause_tick();
    let tx = ck
        .bob()
        .inner
        .chan
        .tx
        .get(&space(), ChannelMode::Latest)
        .expect("bob's channel");
    // One frame sent and recorded, so that a checkpoint has something to list.
    ck.emit(1, b"warm").await;
    let warm = ck.link.take_datagrams();
    assert_eq!(warm.len(), 1, "one frame for the one message");
    ck.link.take_stream();

    let bob = ck.bob().space(&space()).expect("bob holds the space");
    let link = Arc::clone(&ck.link);
    let fired = Arc::new(AtomicBool::new(false));
    let before = link.stats().checkpoint_frames;
    ck.link.on_datagram(Some(Arc::new({
        let (link, fired) = (Arc::clone(&link), Arc::clone(&fired));
        move |_frame: &Bytes| {
            if fired.swap(true, Ordering::SeqCst) {
                return;
            }
            // The frame is on its way out: its message is replaced by a newer one of its name...
            bob.emit(
                &path(0),
                Bytes::from_static(b"second"),
                EmitOptions::latest(),
            )
            .now_or_never()
            .expect("a Latest emission never waits")
            .expect("bob emits");
            // ...and the period of a checkpoint ends: the stream's task writes it, now.
            tx.checkpoint_due(Instant::now());
            let started = std::time::Instant::now();
            while link.stats().checkpoint_frames == before {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "the checkpoint was never written"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    })));
    ck.emit(0, b"first").await;
    ck.link.on_datagram(None);
    settle().await;
    assert!(fired.load(Ordering::SeqCst), "the case ran");

    // What reached the receiver: the frames, then the checkpoint that was written while the
    // first of them was in flight.
    let datagrams = ck.link.take_datagrams();
    let checkpoint = ck
        .link
        .take_stream()
        .into_iter()
        .find(is_checkpoint)
        .expect("the checkpoint is on the stream");
    for frame in warm.iter().chain(&datagrams) {
        assert!(
            matches!(
                ck.deliver(frame, HONEST, Instant::now()).await,
                Delivery::Delivered { .. }
            ),
            "an honest frame is taken"
        );
    }
    assert_eq!(
        ck.deliver(&checkpoint, HONEST, Instant::now()).await,
        Delivery::Checkpoint
    );
    assert_eq!(
        ck.stats().mismatches.get(),
        0,
        "the sender sent every frame it was given: no checkpoint of its own contradicts one"
    );
    assert!(ck.evidence().is_empty(), "{:?}", ck.evidence());
    assert!(ck.bars().is_empty(), "an honest link was barred");
    let told = ck.events();
    assert!(
        told.iter()
            .all(|e| !matches!(e, Err(GetNotice::Retracted { .. }))),
        "nothing was retracted: {told:?}"
    );
    assert!(ck.session_held());
}

// -- No honest sender is ever accused ----------------------------------------------------------

/// A generator whose runs are the same on every machine: the cases are inputs, so a failure
/// names its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11
    }

    /// A number in `0..n`.
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// True in `percent` of a hundred.
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// What the hook of one round does when its first datagram is on its way out.
#[derive(Clone, Copy, Debug)]
enum Hook {
    /// Nothing.
    Nothing,
    /// Emit the names of the next few emissions again: each replaces a message waiting, or in
    /// the frame in flight.
    Replace,
    /// The period of a checkpoint ends and the stream's task writes it.
    Checkpoint,
    /// Both, replacement first.
    Both,
}

/// One run of the fuzz: a real sender whose emissions, checkpoints and carrier misbehave as `cfg`
/// and the rounds say, and a receiver that is handed what the link delivered in the order,
/// at the pace and with the losses the rounds choose. Nothing the sender sent may ever be taken
/// for a forgery.
async fn run(seed: u64, cfg: LinkConfig, opts: super::verbs::GetOptions, rounds: usize) {
    let mut rng = Rng(seed);
    let mut ck = ck_with(ChannelMode::Latest, opts, cfg, Duration::from_secs(2)).await;
    ck.pause_tick();
    let tx = ck
        .bob()
        .inner
        .chan
        .tx
        .get(&space(), ChannelMode::Latest)
        .expect("bob's channel");
    let bob = ck.bob().space(&space()).expect("bob holds the space");
    let mut backlog: std::collections::VecDeque<Bytes> = Default::default();
    let mut delayed: Option<Bytes> = None;
    let mut told = Vec::new();
    let mut sent = 0u64;
    let accused = |ck: &mut super::checkpoint_flow_tests::Ck, told: &mut Vec<_>, at: &str| {
        told.extend(ck.events());
        let s = ck.stats();
        let (m, c, b) = (
            s.mismatches.get(),
            s.conflicts.get(),
            s.bad_checkpoints.get(),
        );
        assert!(
            m + c + b == 0
                && ck.evidence().is_empty()
                && ck.bars().is_empty()
                && told.iter().all(|e| !matches!(
                    e,
                    Err(GetNotice::Retracted { .. } | GetNotice::LiveEnded(..))
                )),
            "seed {seed:#x}, {at}: an honest sender was accused: {m} mismatches, {c} conflicts, \
             {b} bad checkpoints, evidence {:?}, bars {:?}, told {told:?}",
            ck.evidence(),
            ck.bars()
        );
    };
    for round in 0..rounds {
        // What the carrier does this round: refuses everything (a busy link), or takes it.
        let busy = rng.chance(15);
        ck.link.set_full(busy);
        let before = ck.link.stats().checkpoint_frames;
        let hook = match rng.below(4) {
            0 => Hook::Nothing,
            1 => Hook::Replace,
            2 => Hook::Checkpoint,
            _ => Hook::Both,
        };
        let names: Vec<u8> = (0..1 + rng.below(4)).map(|_| rng.below(5) as u8).collect();
        let fired = Arc::new(AtomicBool::new(false));
        ck.link.on_datagram(Some(Arc::new({
            let (bob, tx, link, fired) = (
                bob.clone(),
                Arc::clone(&tx),
                Arc::clone(&ck.link),
                Arc::clone(&fired),
            );
            move |_frame: &Bytes| {
                if fired.swap(true, Ordering::SeqCst) {
                    return;
                }
                if matches!(hook, Hook::Replace | Hook::Both) {
                    for &i in &names {
                        let _ = bob
                            .emit(
                                &path(i),
                                Bytes::from_static(b"again"),
                                EmitOptions::latest(),
                            )
                            .now_or_never();
                    }
                }
                if matches!(hook, Hook::Checkpoint | Hook::Both) {
                    tx.checkpoint_due(Instant::now());
                    // The stream's task writes it on another thread; give it the chance to do
                    // so while the frame is in flight. What follows holds whether it did or not.
                    let started = std::time::Instant::now();
                    while link.stats().checkpoint_frames == before
                        && started.elapsed() < Duration::from_millis(20)
                    {
                        std::thread::sleep(Duration::from_micros(200));
                    }
                }
            }
        })));
        // A burst of emissions over a few names: each replaces the last of its name.
        for _ in 0..1 + rng.below(12) {
            let i = rng.below(5) as u8;
            let payload = sent.to_le_bytes();
            sent += 1;
            bob.emit(
                &path(i),
                Bytes::copy_from_slice(&payload),
                EmitOptions::latest(),
            )
            .await
            .expect("bob emits");
            if rng.chance(30) {
                tokio::task::yield_now().await;
            }
            if rng.chance(10) {
                tx.checkpoint_due(Instant::now());
            }
        }
        ck.link.on_datagram(None);
        ck.link.set_full(false);
        settle().await;

        // The receiver is handed what arrived: the datagrams as the link left them, appended to
        // what a slow receiver had not taken yet, and the stream in order, interleaved at random
        // (a checkpoint may overtake the frames it lists, or come after them).
        backlog.extend(ck.link.take_datagrams());
        let mut stream: std::collections::VecDeque<Bytes> = ck.link.take_stream().into();
        // A slow receiver takes a share of what waits and leaves the rest for a later round.
        let take = if rng.chance(30) {
            rng.below(backlog.len() as u64 + 1) as usize
        } else {
            backlog.len()
        };
        let mut datagrams: std::collections::VecDeque<Bytes> = backlog.drain(..take).collect();
        while !datagrams.is_empty() || !stream.is_empty() {
            let from_stream = !stream.is_empty() && (datagrams.is_empty() || rng.chance(40));
            let frame = if from_stream {
                stream.pop_front()
            } else {
                datagrams.pop_front()
            }
            .expect("a frame");
            if from_stream && is_checkpoint(&frame) {
                // A checkpoint may be lost, repeated or overtaken by the next.
                match rng.below(10) {
                    0 => continue,
                    1 => {
                        delayed = Some(frame);
                        continue;
                    }
                    2 => {
                        let _ = ck.deliver(&frame, HONEST, Instant::now()).await;
                    }
                    _ => {}
                }
            }
            let _ = ck.deliver(&frame, HONEST, Instant::now()).await;
            if from_stream
                && is_checkpoint(&frame)
                && let Some(old) = delayed.take()
            {
                let _ = ck.deliver(&old, HONEST, Instant::now()).await;
            }
        }
        accused(&mut ck, &mut told, &format!("round {round}"));
        assert!(
            ck.session_held(),
            "seed {seed:#x}, round {round}: the receiver let an honest session go"
        );
    }
    // Everything that is left reaches the receiver, and a last checkpoint covers it.
    ck.link.set_full(false);
    tx.checkpoint_due(Instant::now());
    settle().await;
    backlog.extend(ck.link.take_datagrams());
    let stream = ck.link.take_stream();
    for frame in backlog.drain(..).chain(stream) {
        let _ = ck.deliver(&frame, HONEST, Instant::now()).await;
    }
    accused(&mut ck, &mut told, "the end");
    assert!(
        ck.stats().checkpoints_verified.get() > 0,
        "seed {seed:#x}: no checkpoint was ever verified: the run judged nothing"
    );
}

/// Loss, duplication, reordering, a carrier that refuses, a receiver that is slow, checkpoints
/// that are lost, repeated and overtaken, and emissions that replace the messages of frames in
/// flight: no honest sender is accused (no mismatch, no conflict, no bad checkpoint, no
/// retraction, no bar, and its session is kept). Bounded: a few seeds of 40 rounds each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_sender_is_never_accused_under_loss_refusal_reorder_duplication_and_a_slow_receiver()
 {
    for (seed, loss, duplicate, reorder) in [
        (0x5eed_0001u64, 0, 0, 0),
        (0x5eed_0002, 200, 0, 0),
        (0x5eed_0003, 0, 150, 300),
        (0x5eed_0004, 200, 100, 300),
        (0x5eed_0005, 50, 50, 100),
    ] {
        run(
            seed,
            LinkConfig {
                seed,
                loss,
                duplicate,
                reorder,
                ..LinkConfig::default()
            },
            latest(),
            40,
        )
        .await;
    }
    // A reader that takes a frame only once a checkpoint lists it.
    run(0x5eed_0006, LinkConfig::default(), verified(), 40).await;
}
