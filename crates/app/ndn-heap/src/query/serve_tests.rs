//! The server of the signed path through real nodes over one forwarder (docs/specs/query.md): who
//! is answered, who is Nacked at what cost, what a sealed space shows a forwarder, what the
//! announce lists.
//!
//! The queries are built by hand (`rig`): the server is tested alone, and a test that needs a
//! crafted query (a stale clock, a forged key, a copy) makes it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::AppError;
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{CachePolicyType, NackReason};
use ndn_security::cert_name::key_name_of;
use ndn_transport::FaceId;
use tokio::sync::Semaphore;

use super::pair_context;
use super::rig::{
    answer_of, bare_ask, bare_query_at, eventually, hostile_query, hostile_query_at, in_force_of,
    interest_of, nacked, name_of, pair, plain_ask, public, rig, rig_started, rig_with, sealed,
    send, send_for, shared, signed_by, signed_query, signed_query_at, status_of,
};
use super::serve::PAIRS_MAX;
use super::{AppRefusal, Handler, Query, QueryId, QueryOutcome, Reply, ServeError, Serving, Via};
use crate::chan::answer::ASK_CLOCK_WINDOW_MS;
use crate::chan::wire::{Announce, ChannelMode};
use crate::error::NextStep;
use crate::error::Timestamp;
use crate::fold::Readers;
use crate::node::tests::{space, world, world_apart};
use crate::node::{Clock, Config, Node, NodeInner};
use crate::rt::Instant;
use crate::space::Heap;
use crate::space::{MembersChange, Share};
use crate::test_kit::n;
use crate::trust::InterestJudged;
use crate::wire::{AnswerBody, AskSeal, EpochId, Status, chan_prefix, sync_group_of};

/// A handler that answers the octets it was asked, and counts the queries that reached it.
fn echo(ran: &Arc<AtomicUsize>) -> impl Handler {
    let ran = Arc::clone(ran);
    move |q: Query| {
        ran.fetch_add(1, Ordering::SeqCst);
        let bytes = q.bytes.clone();
        async move { Reply::Answer(bytes) }
    }
}

/// A handler that holds every query until `gate` has a permit, counting the ones started.
fn held(started: &Arc<AtomicUsize>, gate: &Arc<Semaphore>) -> impl Handler {
    let (started, gate) = (Arc::clone(started), Arc::clone(gate));
    move |_q: Query| {
        started.fetch_add(1, Ordering::SeqCst);
        let gate = Arc::clone(&gate);
        async move {
            let permit = gate.acquire().await.unwrap();
            permit.forget();
            Reply::Answer(Bytes::from_static(b"released"))
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn signed(node: &Node) -> u64 {
    node.inner.signatures.load(Ordering::Relaxed)
}

/// What the server makes of `wire`, with no forwarder between: the Interest decoded and judged.
async fn outcome(inner: &Arc<NodeInner>, wire: &Bytes) -> QueryOutcome {
    inner.query_answer(&interest_of(wire), None).await
}

fn is_nack(outcome: &QueryOutcome, reason: NackReason) -> bool {
    matches!(outcome, QueryOutcome::Nack(r) if *r == reason)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// -- Who is answered --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listed_asker_gets_the_handlers_answer_signed_by_the_servers_device() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();

    let ask = plain_ask(bob, "/game/pickup", b"hello");
    let wire = signed_query(bob, alice, &ask);
    let signed_before = signed(alice);
    let data = send(bob, wire.clone())
        .await
        .expect("a listed asker is answered");

    assert_eq!(
        *data.name,
        *interest_of(&wire).name,
        "the Data is named as the Interest is"
    );
    assert_eq!(*data.name, name_of(alice, &wire));
    assert!(
        signed_by(bob, alice, &data).await,
        "the server's device signed it"
    );
    assert_eq!(
        data.sig_info()
            .and_then(|s| s.key_locator_name())
            .map(|k| (*k).clone()),
        Some(alice.writer().clone())
    );
    let answer = answer_of(&data);
    assert_eq!(answer.id, ask.id, "the id is echoed");
    assert_eq!(
        answer.body,
        AnswerBody::Plain(Status::Answered(Bytes::from_static(b"hello")))
    );
    assert_eq!(
        data.meta_info().and_then(|m| m.freshness_period),
        Some(Duration::ZERO)
    );
    assert_eq!(
        rig.taps[0].sent(&data.name),
        vec![Some(CachePolicyType::NoCache)],
        "sent once, NoCache"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(
        signed(alice) - signed_before,
        1,
        "one signature: the answer's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_query_is_nacked_and_costs_no_signature_verification() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/dave/pc"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob, dave) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let judge = &alice.inner.judge;
    let signed_before = signed(alice);

    // Dave's person is listed nowhere: a well-formed, validly signed query is Nacked, unjudged.
    let ask = plain_ask(dave, "/game/x", b"q");
    let r = send(dave, signed_query(dave, alice, &ask)).await;
    assert!(nacked(&r, NackReason::NoRoute));
    assert_eq!(judge.interest_walks(), 0, "no signature was checked");
    // A query over 8 KiB, and one that is no query, are Nacked before they are read.
    let big = hostile_query(dave, dave.writer(), alice, &vec![7u8; 9000]);
    assert!(nacked(&send(dave, big).await, NackReason::NoRoute));
    let junk = hostile_query(dave, dave.writer(), alice, b"not a query");
    assert!(nacked(&send(dave, junk).await, NackReason::NoRoute));
    assert_eq!(judge.interest_walks(), 0);
    assert_eq!(
        signed(alice),
        signed_before,
        "alice signed nothing for a stranger"
    );

    // A listed key named by a forger costs exactly one verification, and is Nacked too.
    let forged = hostile_query(
        dave,
        bob.writer(),
        alice,
        &plain_ask(bob, "/game/x", b"q").encode().unwrap(),
    );
    assert!(nacked(&send(dave, forged).await, NackReason::NoRoute));
    assert_eq!(
        judge.interest_walks(),
        1,
        "one verification, for the listed key it named"
    );
    assert_eq!(signed(alice), signed_before);
    assert_eq!(ran.load(Ordering::SeqCst), 0, "no handler ran");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readers_device_cannot_serve_and_a_reader_may_ask() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let share = Share {
        readers: Readers::Persons(vec![n("/bob"), n("/carol")]),
        writers: vec![n("/bob")],
    };
    shared(&rig, share, None).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let ran = Arc::new(AtomicUsize::new(0));

    // A reader's device never serves: ask the owner.
    let carols = carol.space(&space()).unwrap();
    let refused = carols.serve(n("/game"), echo(&ran)).unwrap_err();
    assert!(
        matches!(refused, ServeError::NotWriter { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);
    assert!(!refused.to_string().is_empty());

    // A writer's does; the reader, in the audience of the sealed space, asks it.
    let _serving = bob
        .space(&space())
        .unwrap()
        .serve(n("/game"), echo(&ran))
        .unwrap();
    eventually("carol and bob hold the same epoch", || {
        in_force_of(carol).is_some() && in_force_of(carol) == in_force_of(bob)
    })
    .await;
    let epoch = in_force_of(bob).unwrap();
    let keys = pair(carol, bob, &epoch);
    let (ask, sent) = keys.ask(carol, bob, "/game/look", b"around");
    let data = send(carol, signed_query(carol, bob, &ask))
        .await
        .expect("a reader in the audience may ask");
    assert_eq!(
        keys.open(carol, bob, &sent, &data),
        Some(Status::Answered(Bytes::from_static(b"around")))
    );

    // A query sent to the reader's device is Nacked: it is no writer, whatever it was told. It
    // is sealed to carol's own key, so that only the writer gate stands between it and a
    // (NotServed) answer.
    let to_carol_keys = pair(bob, carol, &epoch);
    let (ask, _) = to_carol_keys.ask(bob, carol, "/game/look", b"around");
    let to_carol = signed_query(bob, carol, &ask);
    assert!(nacked(&send(bob, to_carol).await, NackReason::NoRoute));
    assert_eq!(
        alice.inner.judge.interest_walks(),
        0,
        "alice was never asked"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handler_sees_the_askers_person_and_device_as_judged() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/bob/tablet"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, tablet) = (&rig.nodes[0], &rig.nodes[2]);
    let seen = Arc::new(Mutex::new(Vec::<Query>::new()));
    let log = Arc::clone(&seen);
    let _serving = heap
        .serve(n("/game"), move |q: Query| {
            log.lock().unwrap().push(q);
            async { Reply::Answer(Bytes::from_static(b"ok")) }
        })
        .unwrap();

    let ask = plain_ask(tablet, "/game/a/b", b"octets");
    send(tablet, signed_query(tablet, alice, &ask))
        .await
        .unwrap();

    let seen = seen.lock().unwrap();
    let [q] = seen.as_slice() else {
        panic!("the handler ran once, not {}", seen.len())
    };
    assert_eq!(q.asker.person, n("/bob"));
    assert_eq!(q.asker.device, n("/bob/tablet"));
    assert_eq!(q.id, QueryId(u64::from_be_bytes(ask.id)));
    assert_eq!(q.path, n("/game/a/b"));
    assert_eq!(q.bytes, Bytes::from_static(b"octets"));
    assert_eq!(q.via, Via::Signed);
    assert!(q.remaining() > Duration::ZERO && q.remaining() <= Duration::from_secs(3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_longest_prefix_handler_runs_and_a_path_no_prefix_serves_is_a_signed_notserved() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let (outer, inner) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let _a = heap.serve(n("/a"), echo(&outer)).unwrap();
    let _b = heap.serve(n("/a/b"), echo(&inner)).unwrap();
    let ask = |path: &str| plain_ask(bob, path, b"q");

    send(bob, signed_query(bob, alice, &ask("/a/b/c")))
        .await
        .unwrap();
    assert_eq!(
        (outer.load(Ordering::SeqCst), inner.load(Ordering::SeqCst)),
        (0, 1)
    );
    send(bob, signed_query(bob, alice, &ask("/a/x")))
        .await
        .unwrap();
    assert_eq!(
        (outer.load(Ordering::SeqCst), inner.load(Ordering::SeqCst)),
        (1, 1)
    );

    let signed_before = signed(alice);
    let data = send(bob, signed_query(bob, alice, &ask("/z")))
        .await
        .unwrap();
    assert_eq!(status_of(&data), Status::NotServed);
    assert!(
        signed_by(bob, alice, &data).await,
        "NotServed is a signed answer"
    );
    assert_eq!(signed(alice) - signed_before, 1);
    assert_eq!(
        (outer.load(Ordering::SeqCst), inner.load(Ordering::SeqCst)),
        (1, 1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_serving_stops_it() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let data = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"1")),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&data), Status::Answered(Bytes::from_static(b"1")));

    drop(serving);
    let data = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"2")),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&data), Status::NotServed);
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "the handler ran for the first query only"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_application_refusal_is_answered_with_its_code_and_text_and_cut_at_256() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    // The fields are public: a handler can build a refusal that is not cut, and the wire cuts it
    // at a character boundary all the same (two octets a character: 400 octets).
    let _serving = heap
        .serve(n("/game"), |q: Query| async move {
            match q.bytes.as_ref() {
                b"short" => Reply::refuse(7, "not yours"),
                _ => Reply::Refuse(AppRefusal {
                    code: 9,
                    text: "é".repeat(200),
                }),
            }
        })
        .unwrap();

    let short = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"short")),
    )
    .await
    .unwrap();
    assert_eq!(
        status_of(&short),
        Status::Refused {
            code: 7,
            text: "not yours".into()
        }
    );
    let long = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"long")),
    )
    .await
    .unwrap();
    assert_eq!(
        status_of(&long),
        Status::Refused {
            code: 9,
            text: "é".repeat(128)
        },
        "256 octets, on a character boundary"
    );
    assert!(signed_by(bob, alice, &long).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pass_is_silent() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ran);
    let _serving = heap
        .serve(n("/game"), move |_q: Query| {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Reply::Pass }
        })
        .unwrap();

    let wire = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"q"));
    let r = send_for(bob, wire, Duration::from_millis(1200)).await;
    assert!(
        matches!(r, Err(AppError::Timeout)),
        "nothing came back, not even a Nack: {r:?}"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(
        alice.inner.query.server.running(),
        0,
        "the slot was given back"
    );
}

// -- Replay, clock, restart ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_signed_query_is_a_duplicate_and_the_handler_ran_once() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();

    let wire = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"once"));
    assert!(matches!(
        outcome(&alice.inner, &wire).await,
        QueryOutcome::Data(_)
    ));
    assert!(is_nack(
        &outcome(&alice.inner, &wire).await,
        NackReason::Duplicate
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 1);

    // A copy costs the asker nothing. Her bucket is left one token (drained at a stamp an hour
    // ahead, so that no refill is counted: a copy that took a token would take that one), fifty
    // copies are Nacked, and a new query, signed before them, is still admitted.
    let server = &alice.inner.query.server;
    let stamp = Instant::now() + Duration::from_secs(3600);
    for _ in 0..127 {
        assert!(server.admit(&n("/bob"), stamp));
    }
    let fresh = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"again"));
    for _ in 0..50 {
        assert!(is_nack(
            &outcome(&alice.inner, &wire).await,
            NackReason::Duplicate
        ));
    }
    assert_eq!(
        server.rate_tokens(&n("/bob")),
        Some(1.0),
        "fifty copies took nothing of her bucket"
    );
    assert!(matches!(
        outcome(&alice.inner, &fresh).await,
        QueryOutcome::Data(_)
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_signed_up_to_the_floor_is_refused_and_one_after_it_is_answered() {
    let moved = Arc::new(AtomicU64::new(0));
    let rig = rig_with(
        world(&["/alice/laptop", "/bob/phone"]).await,
        2,
        |_, config| config.clock = moved_clock(&moved, 0),
    )
    .await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let floor = *alice.inner.query.replay_floor.get().unwrap();

    // In the quiet period a query made now, however fresh by the clock window, may be a copy a
    // restart's empty replay set would run: refused with a Nack, before any signature.
    advance(&moved, 10_000);
    let early = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"early"));
    assert!(nacked(&send(bob, early).await, NackReason::NoRoute));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    assert_eq!(alice.inner.judge.interest_walks(), 0);

    // The floor itself is inside the quiet period; the next millisecond is not.
    advance(&moved, ASK_CLOCK_WINDOW_MS);
    let at =
        |signed_at: u64| signed_query_at(bob, alice, &plain_ask(bob, "/game/x", b"q"), signed_at);
    assert!(
        alice.inner.now() > floor,
        "the quiet period is over by this clock"
    );
    assert!(nacked(&send(bob, at(floor)).await, NackReason::NoRoute));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    let data = send(bob, at(floor + 1))
        .await
        .expect("signed after the floor");
    assert_eq!(status_of(&data), Status::Answered(Bytes::from_static(b"q")));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_clock_window_holds() {
    let moved = Arc::new(AtomicU64::new(0));
    let rig = rig_with(
        world(&["/alice/laptop", "/bob/phone"]).await,
        2,
        |_, config| config.clock = moved_clock(&moved, 0),
    )
    .await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    // `/game` is served, `/x/..` is not: a query inside the window is a signed NotServed. The
    // quiet period and the window behind it are over: every offset shown is after the floor.
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    advance(&moved, 2 * ASK_CLOCK_WINDOW_MS + 2_000);
    let at = |offset: i64| {
        let wire = signed_query_at(
            bob,
            alice,
            &plain_ask(bob, "/x/y", b"q"),
            alice.inner.now().checked_add_signed(offset).unwrap(),
        );
        send(bob, wire)
    };
    assert!(
        nacked(&at(-121_000).await, NackReason::NoRoute),
        "121 s behind"
    );
    assert!(
        nacked(&at(121_000).await, NackReason::NoRoute),
        "121 s ahead"
    );
    assert_eq!(
        alice.inner.judge.interest_walks(),
        0,
        "refused by the clock before any signature was checked"
    );
    for offset in [-119_000, 119_000] {
        let data = at(offset).await.expect("inside the window");
        assert_eq!(status_of(&data), Status::NotServed);
    }
}

// -- Limits -----------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_person_inflight_and_rate_hold_across_her_devices() {
    let rig = rig_started(
        &[
            "/alice/laptop",
            "/bob/phone",
            "/bob/tablet",
            "/carol/pc",
            "/carol/tablet",
            "/erin/pc",
        ],
        1,
    )
    .await;
    let heap = public(&rig, &["/bob", "/carol", "/erin"]).await;
    let alice = &rig.nodes[0];
    let inner = &alice.inner;
    let dev = |i: usize| &rig.devs[i];

    // In flight: bob's two devices together may have 8 handlers running, not 5 each.
    let (started, gate) = (Arc::new(AtomicUsize::new(0)), Arc::new(Semaphore::new(0)));
    let serving = heap.serve(n("/game"), held(&started, &gate)).unwrap();
    let mut tasks = Vec::new();
    for i in 0..10 {
        let wire = bare_query_at(
            dev(1 + i % 2),
            alice,
            &bare_ask("/game/x", b"q"),
            alice.inner.now(),
        );
        let inner = Arc::clone(inner);
        tasks.push(tokio::spawn(async move { outcome(&inner, &wire).await }));
    }
    eventually("eight handlers run", || started.load(Ordering::SeqCst) == 8).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(started.load(Ordering::SeqCst), 8, "no ninth handler");
    let early: Vec<_> = tasks.iter().filter(|t| t.is_finished()).collect();
    assert_eq!(
        early.len(),
        2,
        "the other two were refused at once, with no wait"
    );
    // Another person is not held by bob's eight.
    let erin = bare_query_at(dev(5), alice, &bare_ask("/game/x", b"q"), alice.inner.now());
    let erins = tokio::spawn({
        let inner = Arc::clone(inner);
        async move { outcome(&inner, &erin).await }
    });
    eventually("erin's handler runs", || {
        started.load(Ordering::SeqCst) == 9
    })
    .await;
    gate.add_permits(11);
    let mut answered = 0;
    let mut congested = 0;
    for task in tasks {
        match task.await.unwrap() {
            QueryOutcome::Data(_) => answered += 1,
            other if is_nack(&other, NackReason::Congestion) => congested += 1,
            other => panic!("answered or Congestion, got {other:?}"),
        }
    }
    assert_eq!((answered, congested), (8, 2));
    assert!(matches!(erins.await.unwrap(), QueryOutcome::Data(_)));
    eventually("the slots are given back", || {
        alice.inner.query.server.running() == 0
    })
    .await;
    drop(serving);

    // Rate: carol's burst is 128 queries, however many devices she asks from; erin, who asked
    // once, is not held by it. Her bucket is drained through the server's own admission (the
    // bucket every judged query of her person passes), so no refill of the time a hundred
    // signatures take is counted.
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let server = &alice.inner.query.server;
    let stamp = Instant::now() + Duration::from_secs(3600);
    let drain = || {
        (0..200)
            .filter(|_| server.admit(&n("/carol"), stamp))
            .count()
    };
    assert_eq!(drain(), 128, "her burst");
    for device in [3, 4] {
        // (the refill of the milliseconds a query took is drained again: the bucket is hers)
        drain();
        let wire = bare_query_at(
            dev(device),
            alice,
            &bare_ask("/game/x", b"q"),
            alice.inner.now(),
        );
        assert!(
            is_nack(&outcome(inner, &wire).await, NackReason::Congestion),
            "her device {device} shares her bucket"
        );
    }
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    let erin = bare_query_at(dev(5), alice, &bare_ask("/game/x", b"q"), alice.inner.now());
    assert!(matches!(outcome(inner, &erin).await, QueryOutcome::Data(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_cap_is_busy_with_no_queue() {
    // Nine persons, eight handlers each at most: the server's 64 are the limit, not theirs.
    let persons: Vec<String> = (1..=9).map(|i| format!("/p{i}/d")).collect();
    let mut names = vec!["/alice/laptop"];
    names.extend(persons.iter().map(String::as_str));
    let rig = rig_started(&names, 1).await;
    let who: Vec<String> = (1..=9).map(|i| format!("/p{i}")).collect();
    let heap = public(&rig, &who.iter().map(String::as_str).collect::<Vec<_>>()).await;
    let alice = &rig.nodes[0];
    let (started, gate) = (Arc::new(AtomicUsize::new(0)), Arc::new(Semaphore::new(0)));
    let _serving = heap.serve(n("/game"), held(&started, &gate)).unwrap();

    let mut tasks = Vec::new();
    for person in 1..=9 {
        for _ in 0..8 {
            let wire = bare_query_at(
                &rig.devs[person],
                alice,
                &bare_ask("/game/x", b"q"),
                alice.inner.now(),
            );
            let inner = Arc::clone(&alice.inner);
            tasks.push(tokio::spawn(async move { outcome(&inner, &wire).await }));
        }
    }
    eventually("sixty-four handlers run", || {
        started.load(Ordering::SeqCst) == 64
    })
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(started.load(Ordering::SeqCst), 64, "no sixty-fifth handler");
    assert_eq!(alice.inner.query.server.running(), 64);
    let early = tasks.iter().filter(|t| t.is_finished()).count();
    assert_eq!(
        early, 8,
        "the 8 over the cap were Nacked at once, none waited"
    );
    gate.add_permits(72);
    let (mut answered, mut congested) = (0, 0);
    for task in tasks {
        match task.await.unwrap() {
            QueryOutcome::Data(_) => answered += 1,
            other if is_nack(&other, NackReason::Congestion) => congested += 1,
            other => panic!("answered or Congestion, got {other:?}"),
        }
    }
    assert_eq!((answered, congested), (64, 8));
    assert_eq!(
        started.load(Ordering::SeqCst),
        64,
        "a refused query never ran a handler"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handler_past_the_deadline_is_dropped_and_its_answer_not_sent() {
    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let dropped = Arc::new(AtomicUsize::new(0));
    let witness = Arc::clone(&dropped);
    let _serving = heap
        .serve(n("/game"), move |_q: Query| {
            let guard = Dropped(Arc::clone(&witness));
            async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(guard);
                Reply::Answer(Bytes::from_static(b"too late"))
            }
        })
        .unwrap();

    let mut ask = plain_ask(bob, "/game/x", b"q");
    ask.deadline_ms = 200;
    let wire = signed_query(bob, alice, &ask);
    let began = std::time::Instant::now();
    let out = outcome(&alice.inner, &wire).await;
    assert!(
        matches!(out, QueryOutcome::Silent),
        "nothing is sent: {out:?}"
    );
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "the handler was cut at the deadline, not run to its end: {:?}",
        began.elapsed()
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1, "its future was dropped");
    assert_eq!(alice.inner.query.server.running(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_over_4096_is_a_signed_toolarge_status() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let _serving = heap
        .serve(n("/game"), |q: Query| async move {
            let size = if q.bytes.as_ref() == b"fits" {
                4096
            } else {
                4097
            };
            Reply::Answer(Bytes::from(vec![5u8; size]))
        })
        .unwrap();

    let fits = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"fits")),
    )
    .await
    .unwrap();
    assert!(matches!(status_of(&fits), Status::Answered(b) if b.len() == 4096));
    let over = send(
        bob,
        signed_query(bob, alice, &plain_ask(bob, "/game/x", b"over")),
    )
    .await
    .unwrap();
    assert_eq!(status_of(&over), Status::TooLarge { max: 4096 });
    assert!(signed_by(bob, alice, &over).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_lookup_and_verification_budgets_are_shared_with_channel_asks() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/dave/pc"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob, dave) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    // Only a node that serves judges signed queries at all (and the rig's clocks have moved past
    // the quiet period that follows).
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let gates = &alice.inner.chan.gates;
    // Drained at a stamp an hour ahead, so that no refill of the milliseconds that follow is
    // counted (a bucket measures its refill from the last stamp it was given).
    let stamp = Instant::now() + Duration::from_secs(3600);

    // The verification budget of the face (burst 256) is the one a channel ask spends: a query
    // after it is Nacked Congestion, before its signature is looked at.
    while gates.verify(None, stamp) {}
    let wire = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"q"));
    assert!(is_nack(
        &outcome(&alice.inner, &wire).await,
        NackReason::Congestion
    ));
    assert_eq!(alice.inner.judge.interest_walks(), 0);
    // The lookup budget (burst 1,024) stands before the record is read: a stranger's query is
    // refused by it, not by its standing.
    while gates.lookup(None, stamp) {}
    let wire = signed_query(dave, alice, &plain_ask(dave, "/game/x", b"q"));
    assert!(is_nack(
        &outcome(&alice.inner, &wire).await,
        NackReason::Congestion
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_whose_chain_the_server_does_not_hold_is_nacked_notyet_and_carrying_it_answers() {
    let rig = rig_with(
        world_apart(&["/alice/laptop", "/bob/phone"]).await,
        2,
        |_, _| {},
    )
    .await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();

    // Alice holds none of bob's certificates and fetches nothing.
    let bare = bare_ask("/game/x", b"q");
    let wire = signed_query(bob, alice, &bare);
    assert!(nacked(&send(bob, wire).await, NackReason::NotYet));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    // The same query carrying the chain is judged and answered.
    let carried = plain_ask(bob, "/game/x", b"q");
    assert!(!carried.chain.is_empty());
    let data = send(bob, signed_query(bob, alice, &carried)).await.unwrap();
    assert!(matches!(status_of(&data), Status::Answered(_)));
}

// -- No answer is kept ------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_answer_is_stored_or_cached() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let held = |node: &Node| {
        node.inner
            .store
            .scan_under(&Name::root(), 0)
            .into_iter()
            .map(|(name, value)| (name, value.len()))
            .collect::<Vec<_>>()
    };
    let before = held(alice);

    // The same query three times, signed afresh each time (one name: its digest is the
    // parameters'): each reaches the handler, because nothing answered was cached anywhere,
    // and each Data went out NoCache.
    let ask = plain_ask(bob, "/game/x", b"same");
    let mut names = Vec::new();
    for _ in 0..3 {
        let wire = signed_query(bob, alice, &ask);
        let data = send(bob, wire).await.unwrap();
        assert_eq!(
            status_of(&data),
            Status::Answered(Bytes::from_static(b"same"))
        );
        names.push((*data.name).clone());
    }
    assert_eq!(ran.load(Ordering::SeqCst), 3, "the handler ran for each");
    for name in &names {
        assert_eq!(rig.taps[0].sent(name), vec![Some(CachePolicyType::NoCache)]);
    }
    assert_eq!(
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "the signature is in the parameters' digest: three names, three queries"
    );
    assert_eq!(held(alice), before, "the store holds nothing new");
    assert_eq!(
        heap.kept(&n("/game/x")).await.ok().flatten().map(|_| ()),
        None,
        "no answer is an entry"
    );
}

// -- Sealed spaces ----------------------------------------------------------------------------------

/// What a sealed space's server answers, and what it was asked, for the tests below.
struct Seen {
    asked: Arc<Mutex<Vec<(Name, Bytes)>>>,
}

fn secret_handler(seen: &Seen) -> impl Handler {
    let log = Arc::clone(&seen.asked);
    move |q: Query| {
        log.lock().unwrap().push((q.path.clone(), q.bytes.clone()));
        async { Reply::Answer(Bytes::from_static(b"the answer is 42")) }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_space_query_and_answer_are_ciphertext_on_the_wire() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let heap = super::rig::sealed(&rig, &["/bob"], &["/carol"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let seen = Seen {
        asked: Arc::new(Mutex::new(Vec::new())),
    };
    let _serving = heap.serve(n("/secret"), secret_handler(&seen)).unwrap();
    let server = &alice.inner.query.server;

    let epoch = in_force_of(alice).unwrap();
    let keys = pair(bob, alice, &epoch);
    let (ask, sent) = keys.ask(bob, alice, "/secret/place", b"top secret query");
    let wire = signed_query(bob, alice, &ask);
    for hidden in [&b"secret"[..], b"place", b"top secret query"] {
        assert!(
            !contains(&wire, hidden),
            "the query shows {hidden:?} to a forwarder"
        );
    }
    let data = send(bob, wire).await.unwrap();
    // (Not "42" alone: two octets show up by chance in about 1 run in 100 of a signed Data.)
    for hidden in [&b"the answer is 42"[..], b"answer"] {
        assert!(
            !contains(data.raw(), hidden),
            "the answer shows {hidden:?} to a forwarder"
        );
    }
    assert!(
        matches!(answer_of(&data).body, AnswerBody::Sealed { seq, .. } if seq == sent.seq),
        "the answer is sealed under the counter of the query it answers"
    );
    assert_eq!(
        keys.open(bob, alice, &sent, &data),
        Some(Status::Answered(Bytes::from_static(b"the answer is 42")))
    );
    assert!(
        signed_by(bob, alice, &data).await,
        "the Data is signed over the ciphertext"
    );
    assert_eq!(
        seen.asked.lock().unwrap().as_slice(),
        [(n("/secret/place"), Bytes::from_static(b"top secret query"))]
    );
    assert_eq!(server.agreements(), 1);

    // A second query of the pair opens under the same keys: no second agreement.
    let (ask, sent) = keys.ask(bob, alice, "/secret/place", b"again");
    let data = send(bob, signed_query(bob, alice, &ask)).await.unwrap();
    assert!(keys.open(bob, alice, &sent, &data).is_some());
    assert_eq!(
        (server.agreements(), server.pairs_held()),
        (1, 1),
        "the pair was derived once"
    );

    // An answer that is sealed for a NotServed path or a refusal is ciphertext too.
    let (ask, sent) = keys.ask(bob, alice, "/elsewhere", b"x");
    let data = send(bob, signed_query(bob, alice, &ask)).await.unwrap();
    assert!(matches!(answer_of(&data).body, AnswerBody::Sealed { .. }));
    assert_eq!(keys.open(bob, alice, &sent, &data), Some(Status::NotServed));

    // A re-key (an epoch change) drops the pair; a query under the new epoch derives a new one.
    heap.change(MembersChange {
        remove: vec![n("/carol")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    eventually("alice holds a new epoch", || {
        in_force_of(alice).is_some_and(|e| e != epoch)
    })
    .await;
    eventually("the pair of the old epoch is dropped", || {
        server.pairs_held() == 0
    })
    .await;
    let renewed = pair(bob, alice, &in_force_of(alice).unwrap());
    let (ask, sent) = renewed.ask(bob, alice, "/secret/place", b"after");
    let data = send(bob, signed_query(bob, alice, &ask)).await.unwrap();
    assert!(renewed.open(bob, alice, &sent, &data).is_some());
    assert_eq!((server.agreements(), server.pairs_held()), (2, 1));

    // The asker's removal drops it.
    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    eventually("the removed asker's pair is dropped", || {
        server.pairs_held() == 0
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_with_a_stale_epoch_is_nacked_notyet() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let heap = super::rig::sealed(&rig, &["/bob"], &["/carol"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let seen = Seen {
        asked: Arc::new(Mutex::new(Vec::new())),
    };
    let _serving = heap.serve(n("/secret"), secret_handler(&seen)).unwrap();
    let old = in_force_of(alice).unwrap();
    heap.change(MembersChange {
        remove: vec![n("/carol")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    eventually("alice holds a new epoch", || {
        in_force_of(alice).is_some_and(|e| e != old)
    })
    .await;

    // The asker is on the epoch the server has moved from.
    let stale = pair(bob, alice, &old);
    let (ask, _) = stale.ask(bob, alice, "/secret/x", b"q");
    assert!(nacked(
        &send(bob, signed_query(bob, alice, &ask)).await,
        NackReason::NotYet
    ));
    // And on one the server has never seen.
    let unseen = crate::wire::EpochId {
        creator: n("/alice/laptop"),
        seq: 9999,
    };
    let ahead = pair(bob, alice, &unseen);
    let (ask, _) = ahead.ask(bob, alice, "/secret/x", b"q");
    assert!(nacked(
        &send(bob, signed_query(bob, alice, &ask)).await,
        NackReason::NotYet
    ));
    assert!(seen.asked.lock().unwrap().is_empty());
    assert_eq!(
        alice.inner.query.server.agreements(),
        0,
        "no agreement for an epoch not in force"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_asker_not_in_the_audience_is_nacked() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    // Bob writes and reads nothing of the sealed space: listed, authenticated, not in the
    // audience. Carol reads it.
    let share = Share {
        readers: Readers::Persons(vec![n("/carol")]),
        writers: vec![n("/bob")],
    };
    let heap = shared(&rig, share, None).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let seen = Seen {
        asked: Arc::new(Mutex::new(Vec::new())),
    };
    let _serving = heap.serve(n("/secret"), secret_handler(&seen)).unwrap();
    let epoch = in_force_of(alice).unwrap();

    let outside = pair(bob, alice, &epoch);
    let (ask, _) = outside.ask(bob, alice, "/secret/x", b"q");
    assert!(nacked(
        &send(bob, signed_query(bob, alice, &ask)).await,
        NackReason::NoRoute
    ));
    assert!(seen.asked.lock().unwrap().is_empty());
    assert_eq!(
        alice.inner.query.server.agreements(),
        0,
        "no agreement for a person outside it"
    );

    eventually("carol holds the epoch", || {
        in_force_of(carol) == Some(epoch.clone())
    })
    .await;
    let inside = pair(carol, alice, &epoch);
    let (ask, sent) = inside.ask(carol, alice, "/secret/x", b"q");
    let data = send(carol, signed_query(carol, alice, &ask)).await.unwrap();
    assert!(inside.open(carol, alice, &sent, &data).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_query_in_a_sealed_space_and_a_sealed_one_in_a_public_space_are_nacked() {
    // Sealed: a plain query would show its path and octets to every forwarder.
    let rig_s = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let heap = super::rig::sealed(&rig_s, &["/bob"], &["/carol"]).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let (alice, bob) = (&rig_s.nodes[0], &rig_s.nodes[1]);
    let plain = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"q"));
    assert!(nacked(&send(bob, plain).await, NackReason::NoRoute));

    // Public: nothing is sealed there, and a sealed query has no meaning.
    let rig_p = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig_p, &["/bob"]).await;
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let (alice, bob) = (&rig_p.nodes[0], &rig_p.nodes[1]);
    let fake = crate::wire::EpochId {
        creator: alice.name().clone(),
        seq: 1,
    };
    let keys = pair(bob, alice, &fake);
    let (ask, _) = keys.ask(bob, alice, "/game/x", b"q");
    assert!(nacked(
        &send(bob, signed_query(bob, alice, &ask)).await,
        NackReason::NoRoute
    ));
    assert_eq!(alice.inner.query.server.agreements(), 0);
    assert_eq!(ran.load(Ordering::SeqCst), 0);
}

// -- The announce -----------------------------------------------------------------------------------

/// The announce of `sender` over the space's sync group, as a member's forwarder carries it.
fn announce_wire(sender: &str, modes: &[ChannelMode], serves: &[&str]) -> Bytes {
    let record = Announce {
        sender: n(sender),
        modes: modes.to_vec(),
        serves: serves.iter().map(|s| n(s)).collect(),
    }
    .encode();
    InterestBuilder::new(chan_prefix(&sync_group_of(&space()).unwrap()))
        .lifetime(Duration::from_secs(1))
        .hop_limit(8)
        .app_parameters(record.to_vec())
        .build()
}

fn hinted(node: &Node, path: &str) -> Vec<Name> {
    node.inner
        .query
        .hints
        .serving(&space(), &n(path), Instant::now())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_announce_lists_what_is_served_and_a_hearer_records_a_hint() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/dave/pc"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    assert!(
        alice.inner.chan.channels.modes(&space()).is_empty(),
        "alice has no channel: her announce has no mode"
    );

    // `serve` makes the node announce: the hearer, not listening for any channel, records the
    // hint all the same (a hint is not an ask).
    let _a = heap.serve(n("/game"), echo(&ran)).unwrap();
    let _b = heap.serve(n("/game/deep/er"), echo(&ran)).unwrap();
    eventually("bob heard what alice serves", || {
        !hinted(bob, "/game/x").is_empty()
    })
    .await;
    assert_eq!(hinted(bob, "/game/x"), vec![alice.name().clone()]);
    assert_eq!(hinted(bob, "/game/deep/er/est"), vec![alice.name().clone()]);
    assert!(
        hinted(bob, "/other").is_empty(),
        "no prefix of /other is served"
    );
    assert_eq!(
        bob.inner.chan.stats.announce_asks.get(),
        0,
        "no ask came of it"
    );

    // A stranger's announce records nothing: dave's person is no writer of the space.
    rig.syncs[0]
        .send(announce_wire(
            "/dave/pc",
            &[ChannelMode::Latest],
            &["/stranger"],
        ))
        .await
        .unwrap();
    eventually("bob counted the stranger", || {
        bob.inner.chan.stats.announce_strangers.get() >= 1
    })
    .await;
    assert!(hinted(bob, "/stranger/x").is_empty());

    // An announce with an empty `serves` (and a mode, which it must carry) takes no hint away:
    // it is unsigned, so anyone could send it in the name of the real server.
    let before = bob.inner.chan.stats.announces_heard.get();
    rig.syncs[0]
        .send(announce_wire("/alice/laptop", &[ChannelMode::Latest], &[]))
        .await
        .unwrap();
    eventually("bob heard it", || {
        bob.inner.chan.stats.announces_heard.get() > before
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hinted(bob, "/game/x"), vec![alice.name().clone()]);
}

/// Hand `node` the announce `wire` as its sync face would, without the forwarder.
fn hear(node: &Node, wire: Bytes) {
    let interest = ndn_packet::Interest::decode(wire).expect("an announce is an Interest");
    node.inner.chan_heard(&interest);
}

/// An announce is unsigned: anyone may name a device. So a hint only grows by what is said of a
/// device, and only its expiry takes it away (a spoofed announce of the real server with no
/// prefix, or with another one, must not make the asker lose it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsigned_announce_naming_a_server_cannot_take_its_hint_away() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let _heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    hear(
        bob,
        announce_wire("/alice/laptop", &[ChannelMode::Latest], &["/game"]),
    );
    assert_eq!(hinted(bob, "/game/x"), vec![alice.name().clone()]);
    // The same name with a mode and no prefix.
    hear(
        bob,
        announce_wire("/alice/laptop", &[ChannelMode::Latest], &[]),
    );
    assert_eq!(
        hinted(bob, "/game/x"),
        vec![alice.name().clone()],
        "an announce that lists nothing takes no hint away"
    );
    // The same name listing another prefix.
    hear(
        bob,
        announce_wire("/alice/laptop", &[ChannelMode::Latest], &["/other"]),
    );
    assert_eq!(
        hinted(bob, "/game/x"),
        vec![alice.name().clone()],
        "an announce that lists another prefix does not replace the first"
    );
}

/// Names that are no device (a stranger makes them up under a writer's namespace) must not push
/// the real server out of the targets of a query, whatever their number.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn spoofed_device_names_do_not_crowd_the_real_server_out_of_the_targets() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let _heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    hear(
        bob,
        announce_wire("/alice/laptop", &[ChannelMode::Latest], &["/game"]),
    );
    for i in 0..256 {
        hear(
            bob,
            announce_wire(
                &format!("/alice/fake{i}"),
                &[ChannelMode::Latest],
                &["/game"],
            ),
        );
    }
    let targets: Vec<Name> = hinted(bob, "/game/x").into_iter().take(16).collect();
    assert!(
        targets.contains(alice.name()),
        "the real server is among the 16 devices a query asks: {targets:?}"
    );
}

/// The announce is in the clear on the sync group. In a sealed space the prefixes a device
/// serves are not: the announce lists none, and a hearer takes no hint of one that does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_space_announce_names_no_served_prefix() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let heap = super::rig::sealed(&rig, &["/bob"], &["/carol"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/secret"), echo(&ran)).unwrap();
    assert!(
        !alice.inner.query_serves(&space()).is_empty(),
        "alice serves /secret"
    );
    if let Some((_, params)) = alice.inner.announce_record(&space()) {
        assert!(
            !contains(&params, b"secret"),
            "the announce of a sealed space shows the prefix served to the sync group"
        );
    }
    // A hearer takes no hint of a prefix in a sealed space, whoever announced it.
    hear(
        bob,
        announce_wire("/alice/laptop", &[ChannelMode::Latest], &["/secret"]),
    );
    assert!(
        hinted(bob, "/secret/x").is_empty(),
        "a sealed space's prefixes are no hint: ask Targets::Devices or Targets::Person"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_announce_is_sent_again_when_the_set_served_changes() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));

    let first = heap.serve(n("/a"), echo(&ran)).unwrap();
    eventually("bob hears /a", || !hinted(bob, "/a/x").is_empty()).await;
    assert!(hinted(bob, "/b/x").is_empty());
    let second = heap.serve(n("/b"), echo(&ran)).unwrap();
    eventually("bob hears /b", || !hinted(bob, "/b/x").is_empty()).await;
    assert_eq!(hinted(bob, "/a/x"), vec![alice.name().clone()]);
    // Dropping the first lists the rest in the next announce, which the drop sends. A hearer does
    // not take /a away on that word (an announce is unsigned, so one that did would let anyone
    // take a server's hint away): /a lapses after the hint's 90 s, and a query that reaches
    // the server meanwhile is answered NotServed.
    let before = bob.inner.chan.stats.announces_heard.get();
    drop(first);
    let (_, record) = alice.inner.announce_record(&space()).unwrap();
    assert_eq!(Announce::decode(record).unwrap().serves, vec![n("/b")]);
    eventually("bob heard the next announce", || {
        bob.inner.chan.stats.announces_heard.get() > before
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hinted(bob, "/a/x"), vec![alice.name().clone()]);
    let lapsed = Instant::now() + super::table::HINT_TTL + Duration::from_secs(1);
    assert!(
        bob.inner
            .query
            .hints
            .serving(&space(), &n("/a/x"), lapsed)
            .is_empty(),
        "/a lapses with its 90 s"
    );
    assert_eq!(hinted(bob, "/b/x"), vec![alice.name().clone()]);
    drop(second);
}

#[test]
fn the_announce_lists_at_most_16_names_and_512_octets_shortest_first() {
    use super::serve::announced_prefixes;
    // Twenty prefixes: sixteen are listed, the shortest ones.
    let many: Vec<Name> = (0..20).map(|i| n(&format!("/p{i:02}"))).collect();
    let listed = announced_prefixes(many.clone());
    assert_eq!(listed.len(), 16);
    assert_eq!(listed, many[..16].to_vec());
    // Long ones: the octets of the name values stand at 512 in all.
    let long: Vec<Name> = (0..8)
        .map(|i| n(&format!("/{}", format!("{i}").repeat(100))))
        .collect();
    let listed = announced_prefixes(long.clone());
    assert!(
        listed
            .iter()
            .map(crate::wire::name_value_len)
            .sum::<usize>()
            <= 512
    );
    assert_eq!(
        listed.len(),
        5,
        "five of 102 octets (510) fit in 512, the sixth does not"
    );
    // Shortest first, so the short ones are never crowded out by a long one.
    let mixed = vec![
        n(&format!("/{}", "x".repeat(200))),
        n("/a"),
        n(&format!("/{}", "y".repeat(250))),
    ];
    let listed = announced_prefixes(mixed);
    assert_eq!(listed[0], n("/a"));
}

#[test]
fn the_announce_is_due_every_30_s_while_something_is_served() {
    let server = super::serve::ServerState::default();
    let (a, b) = (n("/alice/32=data/a"), n("/alice/32=data/b"));
    let t0 = Instant::now();
    let serving = [a.clone(), b.clone()];
    assert_eq!(
        server.announce_due(&serving, t0),
        vec![a.clone(), b.clone()],
        "never announced"
    );
    server.announced(&a, t0);
    server.announced(&b, t0);
    let soon = t0 + Duration::from_secs(29);
    assert!(server.announce_due(&serving, soon).is_empty());
    server.announced(&a, soon);
    let later = t0 + Duration::from_secs(31);
    assert_eq!(
        server.announce_due(&serving, later),
        vec![b.clone()],
        "b's 30 s are up, a's are not"
    );
    // A space no longer served is forgotten, and is due at once when served again.
    assert!(server.announce_due(&[], later).is_empty());
    assert_eq!(
        server.announce_due(std::slice::from_ref(&a), later),
        vec![a]
    );
}

#[test]
fn the_answer_octets_of_a_person_are_a_budget_of_4_mib_a_second() {
    let server = super::serve::ServerState::default();
    let (bob, erin) = (n("/bob"), n("/erin"));
    let t0 = Instant::now();
    // Her burst is 4 MiB: an answer that overdraws it is sent, and the next handler is refused
    // until the budget has refilled (the answer octets of a person, not of a device).
    let slot = server.slot(&bob, t0).expect("a place");
    slot.charge(6 * 1024 * 1024, t0);
    drop(slot);
    assert!(server.slot(&bob, t0).is_none(), "2 MiB in debt");
    assert!(
        server.slot(&erin, t0).is_some(),
        "another person is not held by it"
    );
    assert!(
        server.slot(&bob, t0 + Duration::from_millis(400)).is_none(),
        "0.4 MiB in debt"
    );
    assert!(
        server.slot(&bob, t0 + Duration::from_millis(600)).is_some(),
        "4 MiB a second paid it"
    );
}

#[test]
fn the_replay_set_forgets_after_240_s_and_refuses_over_its_cap() {
    use super::serve::{REPLAY_KEPT, REPLAY_MAX, Replay, Replayed};
    assert_eq!(REPLAY_KEPT, Duration::from_secs(240));
    assert_eq!(REPLAY_MAX, 262_144);
    let key = n("/bob/phone/KEY/1");
    let t0 = Instant::now();
    let set = Replay::with_cap(4);
    assert_eq!(set.check(&key, b"n1", 5, t0), Replayed::Fresh);
    assert_eq!(
        set.check(&key, b"n1", 5, t0 + Duration::from_secs(239)),
        Replayed::Replay
    );
    // Another nonce, time or key is another query.
    assert_eq!(set.check(&key, b"n2", 5, t0), Replayed::Fresh);
    assert_eq!(set.check(&key, b"n1", 6, t0), Replayed::Fresh);
    assert_eq!(
        set.check(&n("/bob/tablet/KEY/1"), b"n1", 5, t0),
        Replayed::Fresh
    );
    // Full: a new query is refused (a set that dropped entries would let a copy run), and a
    // copy is still a copy.
    assert_eq!(set.check(&key, b"n3", 5, t0), Replayed::Full);
    assert_eq!(set.check(&key, b"n2", 5, t0), Replayed::Replay);
    // 240 s after its arrival a query is forgotten (a copy is acceptable only within 120 s of
    // the signed time, which was within 120 s of the arrival), and room is made.
    assert_eq!(set.check(&key, b"n3", 5, t0 + REPLAY_KEPT), Replayed::Fresh);
    assert_eq!(
        set.check(&key, b"n1", 5, t0 + REPLAY_KEPT),
        Replayed::Fresh,
        "forgotten"
    );
}

// -- The clock, before a signature --------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_query_with_a_forged_time_is_judged_by_the_window_before_a_signature() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    // Signed an hour ago, by bob's real key: refused by the clock, so no verification is spent.
    let hour = now() - 3_600_000;
    let wire = hostile_query_at(
        bob,
        bob.writer(),
        alice,
        &plain_ask(bob, "/game/x", b"q").encode().unwrap(),
        hour,
    );
    assert!(nacked(&send(bob, wire).await, NackReason::NoRoute));
    assert_eq!(alice.inner.judge.interest_walks(), 0);
}

// -- The replay floor ----------------------------------------------------------------------------

/// A clock a test moves: the system's, `skew_ms` ahead, and `moved` more.
fn moved_clock(moved: &Arc<AtomicU64>, skew_ms: u64) -> Clock {
    let wall = Config::new().clock;
    let moved = Arc::clone(moved);
    Arc::new(move || Timestamp(wall().0 + skew_ms + moved.load(Ordering::SeqCst)))
}

fn advance(moved: &Arc<AtomicU64>, ms: u64) {
    moved.fetch_add(ms, Ordering::SeqCst);
}

/// Serve `/game` at `heap` as soon as the record is held for writing (a restarted node reads it
/// from its store).
async fn serve_when_ready(heap: &Heap, ran: &Arc<AtomicUsize>) -> Serving {
    let mut serving = None;
    eventually("the restarted device may serve", || {
        serving = heap.serve(n("/game"), echo(ran)).ok();
        serving.is_some()
    })
    .await;
    serving.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_captured_query_cannot_run_again_after_a_restart_whatever_the_askers_clock() {
    // Alice serves; bob's clock is 100 s ahead of hers, inside the 120 s window. Both clocks are
    // the system's, moved by `moved`.
    let moved = Arc::new(AtomicU64::new(0));
    let mut rig = rig_with(
        world(&["/alice/laptop", "/bob/phone"]).await,
        2,
        |i, config| config.clock = moved_clock(&moved, if i == 1 { 100_000 } else { 0 }),
    )
    .await;
    let heap = public(&rig, &["/bob"]).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let serving = heap.serve(n("/game"), echo(&ran)).unwrap();

    // The quiet period over (alice's replay floor passed, by bob's clock too), bob asks and the
    // handler runs: an eavesdropper keeps the wire.
    advance(&moved, ASK_CLOCK_WINDOW_MS + 1_000);
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let captured = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"grant"));
    assert!(matches!(
        outcome(&alice.inner, &captured).await,
        QueryOutcome::Data(_)
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 1);

    // Alice restarts 5 s later and serves again 2 s after that: her replay set is empty, and the
    // captured query is still inside the window by her clock (93 s old) and was signed after the
    // moment she began serving by bob's clock.
    drop(serving);
    drop(heap);
    advance(&moved, 5_000);
    rig.restart(0, |config| config.clock = moved_clock(&moved, 0))
        .await;
    advance(&moved, 2_000);
    let heap = rig.nodes[0].space(&space()).expect("the space is restored");
    let _serving = serve_when_ready(&heap, &ran).await;
    let alice = &rig.nodes[0];
    let replayed = outcome(&alice.inner, &captured).await;
    assert!(
        is_nack(&replayed, NackReason::NoRoute),
        "the captured query must be refused after a restart, got {replayed:?}"
    );
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "the handler ran once, not twice"
    );
    assert_eq!(
        alice.inner.judge.interest_walks(),
        0,
        "refused by the floor before any signature was checked"
    );

    // It stays refused to the end of the window it was signed in; a query bob signs after the
    // floor is answered.
    advance(&moved, 30_000);
    assert!(is_nack(
        &outcome(&alice.inner, &captured).await,
        NackReason::NoRoute
    ));
    let bob = &rig.nodes[1];
    let fresh = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"fresh"));
    assert!(matches!(
        outcome(&alice.inner, &fresh).await,
        QueryOutcome::Data(_)
    ));
    assert_eq!(ran.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_query_before_the_first_serve_is_a_plain_nack_so_no_nonce_is_used_twice() {
    let mut rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let heap = sealed(&rig, &["/bob"], &[]).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let keys = pair(bob, alice, &in_force_of(alice).unwrap());
    let (ask, sent) = keys.ask(bob, alice, "/game/x", b"secret");
    let captured = signed_query(bob, alice, &ask);
    let data = match outcome(&alice.inner, &captured).await {
        QueryOutcome::Data(wire) => wire,
        other => panic!("answered before the restart: {other:?}"),
    };
    assert!(!data.is_empty() && sent.id == ask.id);

    // Alice restarts and serves nothing yet. The copy is inside its window and her replay set is
    // empty, but an answer would be sealed under the same key and counter as the first.
    drop(serving);
    drop(heap);
    rig.restart(0, |_| {}).await;
    let alice = &rig.nodes[0];
    let signed_before = signed(alice);
    let replayed = outcome(&alice.inner, &captured).await;
    assert!(
        is_nack(&replayed, NackReason::NoRoute),
        "a node that serves nothing yet answers no signed query, got {replayed:?}"
    );
    assert_eq!(signed(alice), signed_before, "nothing was sealed or signed");
    assert_eq!(alice.inner.judge.interest_walks(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_handler_is_reachable_while_the_floor_is_unset() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let ran = Arc::new(AtomicUsize::new(0));
    // The prefix is in the table and no `serve` has set the floor: the instant between the two
    // statements of a `serve` that registers before it arms the floor.
    let handler: Arc<dyn Handler> = Arc::new(echo(&ran));
    alice
        .inner
        .query
        .table
        .add(&space(), n("/game"), handler)
        .unwrap();
    assert!(alice.inner.query.replay_floor.get().is_none());
    let wire = signed_query(bob, alice, &plain_ask(bob, "/game/x", b"q"));
    let r = outcome(&alice.inner, &wire).await;
    assert!(is_nack(&r, NackReason::NoRoute), "{r:?}");
    assert_eq!(ran.load(Ordering::SeqCst), 0, "no handler ran");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_floor_is_set_before_the_prefix_is_reachable() {
    // `serve` arms the floor first: when the table holds the prefix, the floor stands, a clock
    // window past the moment `serve` began.
    let moved = Arc::new(AtomicU64::new(0));
    let rig = rig_with(
        world(&["/alice/laptop", "/bob/phone"]).await,
        2,
        |_, config| config.clock = moved_clock(&moved, 0),
    )
    .await;
    let heap = public(&rig, &["/bob"]).await;
    let alice = &rig.nodes[0];
    let before = alice.inner.now();
    let ran = Arc::new(AtomicUsize::new(0));
    let _serving = heap.serve(n("/game"), echo(&ran)).unwrap();
    let after = alice.inner.now();
    let floor = *alice
        .inner
        .query
        .replay_floor
        .get()
        .expect("the floor is set");
    assert!(
        (before + ASK_CLOCK_WINDOW_MS..=after + ASK_CLOCK_WINDOW_MS).contains(&floor),
        "{before} {floor} {after}"
    );
}

// -- The pair table, and what a copy or a forged chain costs -----------------------------------------

/// The pair of `device` of `person` in the test space, for an agreement made by the server of
/// `alice`: a real ephemeral key, as an asker derives it.
fn take_pair(alice: &Node, person: &str, device: usize) -> (Name, Name, AskSeal) {
    let asker = n(&format!("{person}/d{device}"));
    let epoch = EpochId {
        creator: n("/alice/laptop"),
        seq: 1,
    };
    let context = pair_context(&space(), &asker, alice.name(), &epoch);
    let (ephemeral, _) = ndn_security::pair_keys_to(&alice.recipient().public(), &context).unwrap();
    let key = n(&format!("{person}/d{device}/32=KEY/1"));
    (
        asker,
        key,
        AskSeal {
            ephemeral,
            epoch,
            seq: 0,
        },
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_pair_table_drops_the_idlest_pair_of_the_person_with_most_and_refuses_no_one() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    public(&rig, &["/bob"]).await;
    let alice = &rig.nodes[0];
    let server = &alice.inner.query.server;
    let space = space();
    // As judged by what the node holds now: the maintenance tick that judges the pairs again
    // leaves those judged by it alone (the made-up askers do not stand).
    let live = (
        alice.inner.judge.generation(),
        alice
            .inner
            .space_of(&space)
            .unwrap()
            .log
            .lock()
            .fold
            .version()
            .load(Ordering::SeqCst),
    );

    let take = |person: &str, i: usize| {
        let (device, key, seal) = take_pair(alice, person, i);
        server
            .pair(&alice.inner, &space, &device, &n(person), &key, &seal, live)
            .is_some()
    };

    // One person with many devices fills the table; her 1025th is let in, her idlest is dropped.
    for i in 0..=PAIRS_MAX {
        assert!(
            take("/many", i),
            "device {i} of one person is refused a pair"
        );
    }
    assert_eq!(server.pairs_held(), PAIRS_MAX, "the bound holds");
    assert!(
        !server.has_pair(&space, &n("/many/d0")),
        "her oldest pair was dropped for her newest"
    );

    // A device of someone else is let in, and the one that pays is the idlest of the person
    // who holds most. A pair used again is not the idlest.
    assert!(take("/many", 1));
    assert!(
        take("/other", 0),
        "a new person's first device is refused a pair because another person holds them all"
    );
    assert_eq!(server.pairs_held(), PAIRS_MAX);
    assert!(server.has_pair(&space, &n("/other/d0")));
    assert!(
        server.has_pair(&space, &n("/many/d1")),
        "used again: not the idlest"
    );
    assert!(
        !server.has_pair(&space, &n("/many/d2")),
        "the idlest of hers went"
    );
}

