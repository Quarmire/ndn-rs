//! The asker's half (docs/specs/query.md): what `get` refuses at creation, what the stream
//! yields and when it ends, how the servers are counted, and who is asked. The cases that need
//! a server are in the second half of this file; the first half runs on one node over a
//! forwarder that delivers nothing, so what was sent is the test's to count.

use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use ndn_foundation_types::Name;

use super::answers::{ANSWER_QUEUE_BYTES, ANSWER_QUEUE_ITEMS, AnswerSink};
use super::ask::{Outcome, PENDING_PER_SERVER, PENDING_TOTAL, Pending, drive};
use super::types::{
    ANSWER_MAX_DEFAULT, Answered, AppRefusal, Ask, DEADLINE_MAX, QueryError, QueryId, QueryPath,
    Targets, Via,
};
use crate::chan::items::Items;
use crate::chan::verbs::{GetNotice, GetOptions, Got, Kind, Live, Select};
use crate::error::HeapError;
use crate::fold::Readers;
use crate::node::Node;
use crate::node::tests::{Dev, boot, cfg, solo, space};
use crate::rt::Instant;
use crate::space::{Heap, PutOptions, Share};
use crate::test_kit::n;
use crate::wire::query_prefix;

// -- What the cases read with ----------------------------------------------------------------------

fn everything() -> Select {
    Select::Prefix(Name::root())
}

/// A stream of a query alone.
fn query_only(ask: Ask) -> GetOptions {
    GetOptions {
        kept: false,
        live: Live::Off,
        ask: Some(ask),
        ..GetOptions::default()
    }
}

/// The answer item of `server` for the query `id`: `text` as the octets.
fn answer_of(server: &str, id: u64, text: &str) -> Got {
    Got {
        path: n("/q"),
        bytes: Bytes::copy_from_slice(text.as_bytes()),
        by: n("/bob"),
        writer: n(server),
        kind: Kind::Answered(Answered {
            query: QueryId(id),
            via: Via::Signed,
            refusal: None,
            proof: None,
        }),
    }
}

fn refusal_of(server: &str, id: u64) -> Got {
    let mut got = answer_of(server, id, "");
    if let Kind::Answered(a) = &mut got.kind {
        a.refusal = Some(AppRefusal::new(7, "no"));
    }
    got
}

/// What is queued in `sink` now, in order, without waiting.
fn drain(sink: &AnswerSink) -> Vec<Result<Got, GetNotice>> {
    let waker = futures::task::noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut out = Vec::new();
    while let Poll::Ready(Some(next)) = sink.poll_next(&mut cx) {
        out.push(next);
    }
    out
}

/// Everything the stream holds now, without waiting.
fn read(items: &mut Items) -> Vec<Result<Got, GetNotice>> {
    let mut out = Vec::new();
    while let Some(Some(next)) = items.next().now_or_never() {
        out.push(next);
    }
    out
}

/// A label for an item: `kept`, `answer` or the answer's text; for a notice its name.
fn label(next: &Result<Got, GetNotice>) -> String {
    match next {
        Ok(got) => match &got.kind {
            Kind::Kept(_) => format!("kept:{}", got.path),
            Kind::Answered(_) => format!("answer:{}", String::from_utf8_lossy(&got.bytes)),
            Kind::Emitted(_) => "emitted".into(),
        },
        Err(GetNotice::Lagged { missed }) => format!("lagged:{missed}"),
        Err(GetNotice::QueryFailed { .. }) => "failed".into(),
        Err(GetNotice::AnswersDone { .. }) => "done".into(),
        Err(other) => format!("{other:?}"),
    }
}

async fn keep(heap: &Heap, path: &str, value: &str) {
    heap.put(
        &n(path),
        Bytes::copy_from_slice(value.as_bytes()),
        PutOptions::default(),
    )
    .await
    .expect("a writer keeps a value");
}

/// One node, owner of `/alice/32=data/notes`, that lists `/bob` as a writer; the forwarder under it
/// delivers nothing and counts what the node sent. The world holds the certificates of the
/// devices the cases name (`/bob/phone`, `/bob/phone0` to `/bob/phone9`, `/bob/d00` to `/bob/d19`
/// and `/carol/phone`), so the node can say whose they are, and starts none of them.
async fn solo_heap() -> (Dev, Node, Heap) {
    let mut names: Vec<String> = vec![
        "/alice/laptop".into(),
        "/bob/phone".into(),
        "/bob/tablet".into(),
        "/carol/phone".into(),
    ];
    names.extend((0..10).map(|i| format!("/bob/phone{i}")));
    names.extend((0..20).map(|i| format!("/bob/d{i:02}")));
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let dev = crate::node::tests::world(&names).await.remove(0);
    let (node, _) = boot(&dev, cfg()).await;
    let share = Share {
        readers: Readers::Anyone,
        writers: vec![n("/bob")],
    };
    let heap = node.create(&space(), share).await.unwrap();
    (dev, node, heap)
}

fn ask_to(devices: &[&str], deadline: Duration) -> Ask {
    let mut ask = Ask::new(Bytes::from_static(b"q"));
    ask.targets = Targets::Devices(devices.iter().map(|d| n(d)).collect());
    ask.deadline = deadline;
    ask
}

fn bad_request(heap: &Heap, ask: Ask) -> String {
    match heap.get(Select::Path(n("/q")), query_only(ask)) {
        Err(HeapError::BadRequest { why }) => why,
        Err(other) => panic!("BadRequest, not {other:?}"),
        Ok(_) => panic!("a bad request was taken"),
    }
}

// -- Creation -------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_with_ask_refuses_each_bad_request_with_its_reason() {
    let (_dev, node, heap) = solo_heap().await;
    let base = || ask_to(&["/bob/phone"], Duration::from_secs(1));

    let mut over = base();
    over.query = Bytes::from(vec![0u8; 2049]);
    let why = bad_request(&heap, over);
    assert!(why.contains("2049") && why.contains("2048"), "{why}");
    assert!(why.contains("put the data"), "says what to do: {why}");

    for deadline in [Duration::ZERO, DEADLINE_MAX + Duration::from_millis(1)] {
        let mut ask = base();
        ask.deadline = deadline;
        let why = bad_request(&heap, ask);
        assert!(why.contains("deadline") && why.contains("10s"), "{why}");
    }
    let mut ask = base();
    ask.deadline = DEADLINE_MAX;
    heap.get(Select::Path(n("/q")), query_only(ask))
        .expect("ten seconds is the longest deadline, and is allowed");

    let seventeen: Vec<String> = (0..17).map(|i| format!("/bob/phone{i}")).collect();
    let refs: Vec<&str> = seventeen.iter().map(String::as_str).collect();
    let why = bad_request(&heap, ask_to(&refs, Duration::from_secs(1)));
    assert!(why.contains("17") && why.contains("16"), "{why}");
    heap.get(
        Select::Path(n("/q")),
        query_only(ask_to(&refs[..16], Duration::from_secs(1))),
    )
    .expect("sixteen devices are the most, and are allowed");

    for max in [0, ANSWER_MAX_DEFAULT + 1] {
        let mut ask = base();
        ask.answer_max = max;
        let why = bad_request(&heap, ask);
        assert!(why.contains("answer_max") && why.contains("4096"), "{why}");
    }

    let mut ask = base();
    ask.via = QueryPath::Channel;
    let why = bad_request(&heap, ask);
    assert!(
        why.contains("not built") && why.contains("QueryPath::Signed"),
        "says it is not built and what to ask instead: {why}"
    );
    for via in [QueryPath::Auto, QueryPath::Signed] {
        let mut ask = base();
        ask.via = via;
        heap.get(Select::Path(n("/q")), query_only(ask))
            .expect("the signed path is built");
    }

    let why = bad_request(
        &heap,
        ask_to(&["/bob/phone/32=query"], Duration::from_secs(1)),
    );
    assert!(
        why.contains("no device name"),
        "a keyword is no device name: {why}"
    );
    let why = bad_request(&heap, ask_to(&["/localhost/x/y"], Duration::from_secs(1)));
    assert!(why.contains("no device name"), "{why}");
    let own = node.name().to_string();
    let why = bad_request(&heap, ask_to(&[&own], Duration::from_secs(1)));
    assert!(why.contains("does not ask itself"), "{why}");

    let why = bad_request(&heap, ask_to(&[], Duration::from_secs(1)));
    assert!(why.contains("names no device"), "{why}");

    let long = format!("/{}", "x".repeat(256));
    let refused = heap.get(Select::Path(n(&long)), query_only(base()));
    assert!(
        matches!(&refused, Err(HeapError::BadRequest { why }) if why.contains("limit of 255")),
        "a path over 255 octets: {refused:?}"
    );

    // Nothing asked and nothing kept is still refused, as it always was.
    let nothing = GetOptions {
        kept: false,
        live: Live::Off,
        ..GetOptions::default()
    };
    let refused = heap.get(everything(), nothing);
    assert!(
        matches!(&refused, Err(HeapError::BadRequest { why }) if why.contains("Live::Off")),
        "{refused:?}"
    );
    // A query alone is allowed.
    heap.get(everything(), query_only(base()))
        .expect("a query-only stream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_follower_and_an_unlisted_device_may_not_ask() {
    // A follower.
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let _follower = node.follow(&space()).await.unwrap();
    let held = node.inner.space_of(&space()).expect("the carrier holds it");
    assert!(held.follower);
    let heap = Heap::new(held, std::sync::Arc::clone(&node.inner));
    let refused = heap
        .get(
            Select::Path(n("/q")),
            query_only(ask_to(&["/bob/phone"], Duration::from_secs(1))),
        )
        .expect_err("a follower takes no part in queries");
    assert!(
        matches!(&refused, HeapError::NotAllowed { why, .. } if why.contains("member")),
        "{refused:?}"
    );

    // A device of a person the space does not list.
    let rig = super::rig::rig(&["/alice/laptop", "/dave/phone"]).await;
    let owner = super::rig::public(&rig, &["/bob"]).await;
    let _ = owner;
    let dave = &rig.nodes[1];
    let heap = dave.open(&space()).await.unwrap();
    let mut refused = None;
    for _ in 0..200 {
        match heap.get(
            Select::Path(n("/q")),
            query_only(ask_to(&["/alice/laptop"], Duration::from_secs(1))),
        ) {
            Err(HeapError::NotReady { .. }) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            other => {
                refused = Some(other);
                break;
            }
        }
    }
    let refused = refused.expect("the record arrives");
    assert!(
        matches!(&refused, Err(HeapError::NotAllowed { why, .. }) if why.contains("neither a writer nor a reader")),
        "an unlisted person's device is no member: {:?}",
        refused.as_ref().map(|_| "an Items")
    );
}

// -- Counting -------------------------------------------------------------------------------------

/// A deterministic stream of numbers: the cases draw outcomes from it.
struct Draw(u64);

impl Draw {
    fn next(&mut self, below: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % below
    }
}

#[derive(Clone, Copy, Debug)]
enum Fate {
    Answers,
    Refuses,
    Fails,
    Silent,
    Never,
    TooLate,
    Soon,
}

#[tokio::test(start_paused = true)]
async fn asked_is_always_answered_plus_refused_plus_failed_plus_silent() {
    let mut draw = Draw(0x9E37_79B9_7F4A_7C15);
    for round in 0..300 {
        let count = 1 + draw.next(16) as usize;
        let servers: Vec<Name> = (0..count).map(|i| n(&format!("/bob/d{i}"))).collect();
        let fates: Vec<Fate> = (0..count)
            .map(|_| match draw.next(7) {
                0 => Fate::Answers,
                1 => Fate::Refuses,
                2 => Fate::Fails,
                3 => Fate::Silent,
                4 => Fate::Never,
                5 => Fate::TooLate,
                _ => Fate::Soon,
            })
            .collect();
        let not_asked = draw.next(5) as u32;
        let sink = AnswerSink::default();
        let deadline = Instant::now() + Duration::from_secs(1);
        let table: std::collections::HashMap<Name, Fate> =
            servers.iter().cloned().zip(fates.iter().copied()).collect();
        drive(&sink, servers.clone(), not_asked, deadline, |server| {
            let fate = table[&server];
            async move {
                let text = server.to_string();
                match fate {
                    Fate::Answers => Outcome::Answered(answer_of(&text, 1, "yes")),
                    Fate::Refuses => Outcome::Refused(refusal_of(&text, 1)),
                    Fate::Fails => Outcome::Failed(QueryError::Busy),
                    Fate::Silent => Outcome::Silent,
                    Fate::Never => std::future::pending().await,
                    Fate::TooLate => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        Outcome::Answered(answer_of(&text, 1, "late"))
                    }
                    Fate::Soon => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        Outcome::Answered(answer_of(&text, 1, "soon"))
                    }
                }
            }
        })
        .await;

        let told = drain(&sink);
        let (done, rest) = told.split_last().expect("a notice at least");
        let Err(GetNotice::AnswersDone {
            asked,
            answered,
            refused,
            failed,
            silent,
            not_asked: counted_not_asked,
        }) = done
        else {
            panic!("round {round}: AnswersDone is told last, not {done:?}");
        };
        assert_eq!(
            *asked as usize, count,
            "round {round}: every server is asked once"
        );
        assert_eq!(
            asked,
            &(answered + refused + failed + silent),
            "round {round}: {fates:?}"
        );
        assert_eq!(*counted_not_asked, not_asked);
        let count_of = |f: fn(&Fate) -> bool| fates.iter().filter(|x| f(x)).count() as u32;
        assert_eq!(
            *answered,
            count_of(|f| matches!(f, Fate::Answers | Fate::Soon)),
            "round {round}"
        );
        assert_eq!(*refused, count_of(|f| matches!(f, Fate::Refuses)));
        assert_eq!(*failed, count_of(|f| matches!(f, Fate::Fails)));
        assert_eq!(
            *silent,
            count_of(|f| matches!(f, Fate::Silent | Fate::Never | Fate::TooLate)),
            "round {round}: a server that did not resolve by the deadline is silent"
        );
        // What was told: one item per answered or refused server, one notice per failure, and
        // nothing from a late server.
        let items = rest.iter().filter(|r| r.is_ok()).count() as u32;
        let notices = rest.len() as u32 - items;
        assert_eq!(items, answered + refused, "round {round}");
        assert_eq!(notices, *failed, "round {round}");
        let mut writers: Vec<_> = rest
            .iter()
            .filter_map(|r| r.as_ref().ok().map(|g| g.writer.clone()))
            .collect();
        writers.sort();
        writers.dedup();
        assert_eq!(
            writers.len() as u32,
            items,
            "round {round}: at most one answer per server"
        );
        assert!(
            rest.iter()
                .filter_map(|r| r.as_ref().ok())
                .all(|g| g.bytes.as_ref() != b"late"),
            "round {round}: a late answer is dropped"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn the_deadline_ends_the_run_and_a_late_answer_is_never_told() {
    let sink = AnswerSink::default();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(300);
    drive(&sink, vec![n("/bob/slow")], 0, deadline, |_| async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        Outcome::Answered(answer_of("/bob/slow", 1, "late"))
    })
    .await;
    assert_eq!(
        started.elapsed(),
        Duration::from_millis(300),
        "the run ended at the deadline, not when the handler did"
    );
    let told: Vec<String> = drain(&sink).iter().map(label).collect();
    assert_eq!(told, ["done"]);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(drain(&sink).is_empty(), "nothing arrives after done");
}

// -- The pending set ------------------------------------------------------------------------------

#[test]
fn the_pending_set_holds_sixteen_per_server_and_sixty_four_in_all_and_releases() {
    let mut pending = Pending::default();
    let one = n("/bob/one");
    for _ in 0..PENDING_PER_SERVER {
        assert!(pending.acquire(&one, PENDING_TOTAL, PENDING_PER_SERVER));
    }
    assert!(
        !pending.acquire(&one, PENDING_TOTAL, PENDING_PER_SERVER),
        "the seventeenth to one server"
    );
    for s in 1..4 {
        let server = n(&format!("/bob/s{s}"));
        for _ in 0..PENDING_PER_SERVER {
            assert!(pending.acquire(&server, PENDING_TOTAL, PENDING_PER_SERVER));
        }
    }
    assert_eq!(pending.total(), PENDING_TOTAL);
    assert!(
        !pending.acquire(&n("/bob/other"), PENDING_TOTAL, PENDING_PER_SERVER),
        "the sixty-fifth in all"
    );
    pending.release(&one);
    assert!(pending.acquire(&n("/bob/other"), PENDING_TOTAL, PENDING_PER_SERVER));
    assert!(
        !pending.acquire(&one, PENDING_TOTAL, PENDING_PER_SERVER),
        "the total is full again"
    );
    for _ in 0..PENDING_TOTAL {
        pending.release(&one);
        pending.release(&n("/bob/s1"));
        pending.release(&n("/bob/s2"));
        pending.release(&n("/bob/s3"));
        pending.release(&n("/bob/other"));
    }
    assert_eq!(pending.total(), 0, "released slots never go below zero");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outstanding_limits_hold() {
    let (_dev, node, heap) = solo_heap().await;
    let long = Duration::from_secs(8);
    let get_to = |device: String| {
        heap.get(Select::Path(n("/q")), query_only(ask_to(&[&device], long)))
            .unwrap()
    };
    let refused_at_once = |mut items: Items| async move {
        let told = tokio::time::timeout(Duration::from_secs(2), async {
            let mut told = Vec::new();
            while let Some(next) = items.next().await {
                told.push(next);
            }
            told
        })
        .await
        .expect("a refused query is told at once, not at its deadline");
        assert!(
            matches!(
                &told[..],
                [
                    Err(GetNotice::QueryFailed {
                        why: QueryError::TooManyOutstanding,
                        ..
                    }),
                    Err(GetNotice::AnswersDone {
                        asked: 1,
                        failed: 1,
                        ..
                    })
                ]
            ),
            "{told:?}"
        );
    };
    // Sixteen to one server: the seventeenth is refused while the node has room for more.
    let mut held: Vec<Items> = (0..PENDING_PER_SERVER)
        .map(|_| get_to("/bob/phone0".into()))
        .collect();
    super::rig::eventually("sixteen are outstanding", || {
        node.inner.query_pending() == PENDING_PER_SERVER
    })
    .await;
    refused_at_once(get_to("/bob/phone0".into())).await;
    // Another server is still welcome; sixteen to each of four is sixty-four in all.
    for server in 1..4 {
        for _ in 0..PENDING_PER_SERVER {
            held.push(get_to(format!("/bob/phone{server}")));
        }
    }
    super::rig::eventually("the sixty-four are outstanding", || {
        node.inner.query_pending() == PENDING_TOTAL
    })
    .await;
    // The sixty-fifth, to a server none of them is for, is refused for the node's total.
    refused_at_once(get_to("/bob/phone9".into())).await;

    held.truncate(held.len() - 1);
    super::rig::eventually("a dropped Items releases its slot", || {
        node.inner.query_pending() == PENDING_TOTAL - 1
    })
    .await;
    drop(held);
    super::rig::eventually("every slot is released", || node.inner.query_pending() == 0).await;
}

// -- The stream -----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_during_the_listing_come_after_it() {
    let (_dev, _node, heap) = solo_heap().await;
    keep(&heap, "/a", "1").await;
    keep(&heap, "/b", "2").await;
    let sink = std::sync::Arc::new(AnswerSink::default());
    sink.push(answer_of("/bob/x", 1, "first"));
    let opts = GetOptions {
        live: Live::Off,
        ..GetOptions::default()
    };
    let mut items = heap
        .items(everything(), opts, Some(std::sync::Arc::clone(&sink)))
        .unwrap();
    // One item of the listing is read; more answers arrive meanwhile.
    let first = items.next().await.unwrap();
    assert_eq!(label(&first), "kept:/a");
    sink.push(answer_of("/bob/y", 1, "second"));
    let told: Vec<String> = read(&mut items).iter().map(label).collect();
    assert_eq!(
        told,
        ["kept:/b", "answer:first", "answer:second"],
        "the listing first, whatever the answers hold"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_alternate_fairly_with_kept_after_the_listing() {
    let (_dev, _node, heap) = solo_heap().await;
    keep(&heap, "/listed", "0").await;
    let sink = std::sync::Arc::new(AnswerSink::default());
    let opts = GetOptions {
        live: Live::Off,
        ..GetOptions::default()
    };
    let mut items = heap
        .items(everything(), opts, Some(std::sync::Arc::clone(&sink)))
        .unwrap();
    items.caught_up().await;
    for i in 0..4 {
        keep(&heap, &format!("/k{i}"), "v").await;
        sink.push(answer_of("/bob/x", 1, &format!("a{i}")));
    }
    // The kept changes arrive through the register's feed: queued beside the answers before
    // anything is read, so both sources have something at every turn.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let told: Vec<String> = read(&mut items).iter().map(label).collect();
    assert_eq!(
        told.len(),
        9,
        "the listing's one item, then four of each: {told:?}"
    );
    let kinds: Vec<bool> = told.iter().map(|l| l.starts_with("kept")).collect();
    assert!(
        kinds.windows(2).all(|w| w[0] != w[1]),
        "the two sources take turns, neither starves the other: {told:?}"
    );
    let answers: Vec<&String> = told.iter().filter(|l| l.starts_with("answer")).collect();
    assert_eq!(
        answers,
        ["answer:a0", "answer:a1", "answer:a2", "answer:a3"],
        "within the answers: arrival order"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_query_only_stream_ends_after_answersdone() {
    let (_dev, _node, heap) = solo_heap().await;
    let sink = std::sync::Arc::new(AnswerSink::default());
    let opts = GetOptions {
        kept: false,
        live: Live::Off,
        ..GetOptions::default()
    };
    let mut items = heap
        .items(everything(), opts, Some(std::sync::Arc::clone(&sink)))
        .unwrap();
    sink.push(answer_of("/bob/x", 1, "one"));
    sink.notice(GetNotice::QueryFailed {
        server: n("/bob/y"),
        why: QueryError::Busy,
    });
    sink.notice(GetNotice::AnswersDone {
        asked: 2,
        answered: 1,
        refused: 0,
        failed: 1,
        silent: 0,
        not_asked: 0,
    });
    // Nothing is accepted after it.
    sink.push(answer_of("/bob/z", 1, "after"));
    let mut told = Vec::new();
    while let Some(next) = tokio::time::timeout(Duration::from_secs(2), items.next())
        .await
        .expect("a query-only stream ends")
    {
        told.push(label(&next));
    }
    assert_eq!(told, ["answer:one", "failed", "done"]);
    assert!(
        items.next().await.is_none(),
        "it stays ended: None again and again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_with_kept_goes_on_after_answersdone() {
    let (_dev, _node, heap) = solo_heap().await;
    keep(&heap, "/a", "1").await;
    let sink = std::sync::Arc::new(AnswerSink::default());
    let opts = GetOptions {
        live: Live::Off,
        ..GetOptions::default()
    };
    let mut items = heap
        .items(everything(), opts, Some(std::sync::Arc::clone(&sink)))
        .unwrap();
    sink.notice(GetNotice::AnswersDone {
        asked: 0,
        answered: 0,
        refused: 0,
        failed: 0,
        silent: 0,
        not_asked: 0,
    });
    items.caught_up().await;
    let first: Vec<String> = [items.next().await.unwrap(), items.next().await.unwrap()]
        .iter()
        .map(label)
        .collect();
    assert_eq!(first, ["kept:/a", "done"]);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), items.next())
            .await
            .is_err(),
        "the stream goes on: kept changes are still to come"
    );
    keep(&heap, "/b", "2").await;
    let next = tokio::time::timeout(Duration::from_secs(2), items.next())
        .await
        .expect("a kept change arrives after AnswersDone")
        .unwrap();
    assert_eq!(label(&next), "kept:/b");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_reader_loses_the_oldest_answers_and_is_told_lagged() {
    let sink = AnswerSink::default();
    for i in 0..(ANSWER_QUEUE_ITEMS + 6) {
        sink.push(answer_of("/bob/x", 1, &format!("a{i}")));
    }
    assert_eq!(sink.queued().0, ANSWER_QUEUE_ITEMS, "the bound holds");
    sink.notice(GetNotice::AnswersDone {
        asked: 1,
        answered: 70,
        refused: 0,
        failed: 0,
        silent: 0,
        not_asked: 0,
    });
    let told: Vec<String> = drain(&sink).iter().map(label).collect();
    assert_eq!(told.len(), ANSWER_QUEUE_ITEMS + 2, "{told:?}");
    assert_eq!(
        told[0], "lagged:6",
        "the oldest six were dropped, in their place"
    );
    assert_eq!(told[1], "answer:a6", "what stays is the newest, in order");
    assert_eq!(
        told[ANSWER_QUEUE_ITEMS],
        format!("answer:a{}", ANSWER_QUEUE_ITEMS + 5)
    );
    assert_eq!(
        told[ANSWER_QUEUE_ITEMS + 1],
        "done",
        "a notice is never dropped"
    );

    // The octets bound: answers of 300 KiB are three at most in 1 MiB.
    let sink = AnswerSink::default();
    let big = |tag: &str| {
        let mut got = answer_of("/bob/x", 1, tag);
        got.bytes = Bytes::from(vec![7u8; 300 * 1024]);
        got
    };
    for i in 0..5 {
        sink.push(big(&format!("{i}")));
    }
    let (items, bytes) = sink.queued();
    assert_eq!(items, 3);
    assert!(bytes <= ANSWER_QUEUE_BYTES, "{bytes}");
    let told: Vec<String> = drain(&sink)
        .iter()
        .map(|r| match r {
            Ok(g) => format!("answer:{}", g.bytes.len()),
            Err(other) => label(&Err(other.clone())),
        })
        .collect();
    assert_eq!(told[0], "lagged:2");
    assert_eq!(told.len(), 4);
}

// -- Through `get`: what one node does with nobody to answer --------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_writer_that_never_answers_is_silent_at_the_deadline() {
    let (_dev, node, heap) = solo_heap().await;
    let signed = || {
        node.inner
            .signatures
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = signed();
    let mut items = heap
        .get(
            Select::Path(n("/q")),
            query_only(ask_to(&["/bob/phone"], Duration::from_millis(300))),
        )
        .unwrap();
    let started = std::time::Instant::now();
    let next = tokio::time::timeout(Duration::from_secs(3), items.next())
        .await
        .expect("told at the deadline")
        .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "{:?}",
        started.elapsed()
    );
    assert!(
        matches!(
            next,
            Err(GetNotice::AnswersDone {
                asked: 1,
                silent: 1,
                answered: 0,
                refused: 0,
                failed: 0,
                not_asked: 0
            })
        ),
        "{next:?}"
    );
    assert!(items.next().await.is_none(), "a query alone ends");
    assert_eq!(signed(), before + 1, "one signed query, to the one server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_named_non_writer_is_not_asked() {
    let (_dev, node, heap) = solo_heap().await;
    let signed = || {
        node.inner
            .signatures
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = signed();
    // `/carol` is no person the space lists; `/bob/phone` is a writer's device.
    let mut items = heap
        .get(
            Select::Path(n("/q")),
            query_only(ask_to(
                &["/carol/phone", "/bob/phone"],
                Duration::from_millis(300),
            )),
        )
        .unwrap();
    let mut told = Vec::new();
    while let Some(next) = tokio::time::timeout(Duration::from_secs(3), items.next())
        .await
        .expect("told")
    {
        told.push(next);
    }
    assert_eq!(told.len(), 2, "{told:?}");
    match &told[0] {
        Err(GetNotice::QueryFailed {
            server,
            why: why @ QueryError::NotWriter { .. },
        }) => {
            assert_eq!(*server, n("/carol/phone"));
            assert_eq!(why.next(), crate::error::NextStep::FixRequest);
            assert!(why.to_string().contains("no writer"), "{why}");
        }
        other => panic!("a named non-writer is a QueryFailed{{NotWriter}}: {other:?}"),
    }
    assert!(
        matches!(
            told[1],
            Err(GetNotice::AnswersDone {
                asked: 2,
                failed: 1,
                silent: 1,
                answered: 0,
                refused: 0,
                ..
            })
        ),
        "{:?}",
        told[1]
    );
    assert_eq!(signed(), before + 1, "only the writer's device was asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_items_cancels_the_pending_query() {
    let (_dev, node, heap) = solo_heap().await;
    let items = heap
        .get(
            Select::Path(n("/q")),
            query_only(ask_to(&["/bob/phone"], Duration::from_secs(8))),
        )
        .unwrap();
    super::rig::eventually("the query is outstanding", || {
        node.inner.query_pending() == 1
    })
    .await;
    drop(items);
    let dropped = std::time::Instant::now();
    while node.inner.query_pending() != 0 {
        assert!(
            dropped.elapsed() < Duration::from_secs(2),
            "the pending slot is released at once, not at the query's deadline (8 s)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_serving_uses_the_announce_hint_and_none_known_is_noserver() {
    let (_dev, node, heap) = solo_heap().await;
    let mut serving = Ask::new(Bytes::from_static(b"q"));
    serving.deadline = Duration::from_millis(400);
    let read_all = |mut items: Items| async move {
        let mut told = Vec::new();
        while let Some(next) = tokio::time::timeout(Duration::from_secs(5), items.next())
            .await
            .expect("told")
        {
            told.push(next);
        }
        told
    };

    // None known: the query waits for an announce until the deadline, then says so.
    let started = std::time::Instant::now();
    let told = read_all(
        heap.get(
            Select::Path(n("/world/pickup/1")),
            query_only(serving.clone()),
        )
        .unwrap(),
    )
    .await;
    assert!(started.elapsed() >= Duration::from_millis(350), "it waited");
    match &told[..] {
        [
            Err(GetNotice::QueryFailed {
                server,
                why: QueryError::NoServer { path },
            }),
            Err(GetNotice::AnswersDone {
                asked: 0,
                answered: 0,
                refused: 0,
                failed: 0,
                silent: 0,
                not_asked: 0,
            }),
        ] => {
            assert_eq!(*server, space(), "the failure names the space");
            assert_eq!(*path, n("/world/pickup/1"));
        }
        other => panic!("{other:?}"),
    }

    // A hint that arrives while it waits is taken at once.
    let hints = &node.inner.query.hints;
    let items = heap
        .get(
            Select::Path(n("/world/pickup/1")),
            query_only({
                let mut ask = serving.clone();
                ask.deadline = Duration::from_secs(3);
                ask
            }),
        )
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let signed = || {
        node.inner
            .signatures
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = signed();
    // `/carol/phone` serves it by its announce, but is no writer: not asked and counted nowhere.
    let record = |device: &str, person: &str, serves: &str| {
        hints.record(
            &space(),
            &n(device),
            &n(person),
            false,
            &[n(serves)],
            Instant::now(),
        );
    };
    record("/carol/phone", "/carol", "/world");
    record("/bob/phone", "/bob", "/world");
    record("/bob/tablet", "/bob", "/other");
    let started = std::time::Instant::now();
    let told = read_all(items).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline ends it"
    );
    assert!(
        matches!(
            told.last(),
            Some(Err(GetNotice::AnswersDone {
                asked: 1,
                silent: 1,
                not_asked: 0,
                ..
            }))
        ),
        "the hinted writer for this path is the one asked; a non-writer and a device that \
         serves another prefix are not: {told:?}"
    );
    assert_eq!(signed(), before + 1);

    // More than sixteen (the record vouches for them): the sixteen heard last are asked, the
    // rest counted.
    for i in 0..20 {
        hints.record(
            &space(),
            &n(&format!("/bob/d{i:02}")),
            &n("/bob"),
            true,
            &[n("/many")],
            Instant::now(),
        );
    }
    let told = read_all(
        heap.get(Select::Path(n("/many/x")), query_only(serving.clone()))
            .unwrap(),
    )
    .await;
    assert!(
        matches!(
            told.last(),
            Some(Err(GetNotice::AnswersDone {
                asked: 16,
                silent: 16,
                not_asked: 4,
                ..
            }))
        ),
        "{told:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_interest_signs_a_query_and_refuses_anything_else_under_query() {
    let (_dev, node, _heap) = solo_heap().await;
    let ask = super::rig::plain_ask(&node, "/q", b"hello")
        .encode()
        .unwrap();
    let wire = node
        .sign_interest(&query_prefix(&n("/bob/phone")), &ask)
        .expect("a query for a device is signed");
    let interest = ndn_packet::Interest::decode(wire).unwrap();
    let (device, digest) = crate::wire::parse_query_name(&interest.name).expect("a query name");
    assert_eq!(device, n("/bob/phone"));
    assert_ne!(digest, [0u8; 32]);
    assert!(interest.selectors().must_be_fresh);
    assert_eq!(
        interest.lifetime(),
        Some(Duration::from_millis(3000)),
        "the lifetime is the query's own deadline"
    );
    assert!(interest.sig_info().is_some(), "it is signed");
    assert_eq!(
        interest.app_parameters().map(|p| p.to_vec()),
        Some(ask.to_vec())
    );

    let signed = || {
        node.inner
            .signatures
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = signed();
    // Anything under `32=query` that is no query, a channel's ask included.
    let chan_ask = crate::chan::wire::ChanAsk {
        space: space(),
        prefix: Name::root(),
        mode: crate::chan::wire::ChannelMode::Latest,
        recipient: node.inner.recipient().public(),
        carriers: vec![crate::chan::wire::carrier::DATAGRAM],
        lifetime: 3600,
        epoch: None,
        since: None,
        new: true,
        chain: vec![],
    }
    .encode()
    .unwrap();
    for params in [
        b"not a query".as_slice(),
        &[],
        &[7u8; 9000],
        chan_ask.as_ref(),
    ] {
        let refused = node.sign_interest(&query_prefix(&n("/bob/phone")), params);
        assert!(
            matches!(refused, Err(HeapError::BadRequest { .. })),
            "{} octets that are no query: {refused:?}",
            params.len()
        );
    }
    for device in ["/localhost/ndn/x", "/localhop/ndn/x", "/localhost"] {
        let refused = node.sign_interest(&query_prefix(&n(device)), &ask);
        assert!(
            matches!(refused, Err(HeapError::BadRequest { .. })),
            "{device} is reserved: {refused:?}"
        );
    }
    // A query is no ask of a channel and the other way round; other names are refused.
    let refused = node.sign_interest(&crate::wire::chan_prefix(&n("/bob/phone")), &ask);
    assert!(
        matches!(refused, Err(HeapError::BadRequest { .. })),
        "{refused:?}"
    );
    for name in [
        "/bob/phone/32=other",
        "/bob/phone",
        "/bob/phone/32=query/extra",
    ] {
        let refused = node.sign_interest(&n(name), &ask);
        assert!(
            matches!(refused, Err(HeapError::BadRequest { .. })),
            "{name}: {refused:?}"
        );
    }
    assert_eq!(signed(), before, "nothing was signed for a refusal");
}

// -- Through a server -----------------------------------------------------------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::rig;
use super::types::{ProofError, ProvenAnswer};
use super::types::{Query, Reply};
use crate::wire::{AnswerBody, QueryAnswer, QueryAsk, QueryProof, Status};
use ndn_packet::encode::DataBuilder;

fn heap_of(node: &Node) -> Heap {
    node.space(&space()).expect("the space is open here")
}

/// Read a query-only stream to its end.
async fn asked(heap: &Heap, path: &str, ask: Ask) -> Vec<Result<Got, GetNotice>> {
    let mut items = heap
        .get(Select::Path(n(path)), query_only(ask))
        .expect("a query is taken");
    let mut told = Vec::new();
    while let Some(next) = tokio::time::timeout(Duration::from_secs(20), items.next())
        .await
        .expect("the query ends")
    {
        told.push(next);
    }
    told
}

fn to(ask: Ask, devices: &[&str]) -> Ask {
    Ask {
        targets: Targets::Devices(devices.iter().map(|d| n(d)).collect()),
        ..ask
    }
}

fn done(asked: u32, answered: u32, refused: u32, failed: u32, silent: u32) -> GetNotice {
    GetNotice::AnswersDone {
        asked,
        answered,
        refused,
        failed,
        silent,
        not_asked: 0,
    }
}

/// A handler that answers `prefix:` and the query, and counts how often it ran.
fn echo(prefix: &'static str, runs: &Arc<AtomicUsize>) -> impl super::types::Handler {
    let runs = Arc::clone(runs);
    move |q: Query| {
        let runs = Arc::clone(&runs);
        async move {
            runs.fetch_add(1, Ordering::SeqCst);
            let mut out = prefix.as_bytes().to_vec();
            out.extend_from_slice(&q.bytes);
            Reply::Answer(Bytes::from(out))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_listed_asker_gets_the_handlers_answer_signed_by_the_servers_device() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob"]).await;
    let bob_heap = heap_of(&rig.nodes[1]);
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let _serving = {
        let seen = Arc::clone(&seen);
        alice_heap
            .serve(n("/world"), move |q: Query| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.lock()
                        .push((q.id, q.path.clone(), q.asker.clone(), q.via));
                    Reply::Answer(Bytes::from(format!("pong:{}", q.bytes.len())))
                }
            })
            .unwrap()
    };
    let mut ask = to(Ask::new(Bytes::from_static(b"ping")), &["/alice/laptop"]);
    ask.deadline = Duration::from_secs(5);
    let told = asked(&bob_heap, "/world/pickup/1", ask).await;
    let [Ok(got), Err(finished)] = &told[..] else {
        panic!("one answer and its end: {told:?}");
    };
    assert_eq!(got.path, n("/world/pickup/1"), "the asked name");
    assert_eq!(got.bytes.as_ref(), b"pong:4");
    assert_eq!(got.writer, n("/alice/laptop"), "the server's device");
    assert_eq!(got.by, n("/alice"), "its person, as the asker judged it");
    let Kind::Answered(answered) = &got.kind else {
        panic!("an answer: {got:?}");
    };
    assert_eq!(answered.via, Via::Signed);
    assert!(answered.refusal.is_none() && answered.proof.is_none());
    assert_eq!(*finished, done(1, 1, 0, 0, 0));
    let seen = seen.lock();
    assert_eq!(seen.len(), 1, "the handler ran once");
    assert_eq!(seen[0].0, answered.query, "the id the asker made");
    assert_eq!(seen[0].1, n("/world/pickup/1"));
    assert_eq!(seen[0].2.person, n("/bob"));
    assert_eq!(seen[0].2.device, n("/bob/phone"));
    assert_eq!(seen[0].3, Via::Signed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_may_ask() {
    let rig = rig::rig(&["/alice/laptop", "/carol/phone"]).await;
    let alice_heap = rig::sealed(&rig, &["/alice"], &["/carol"]).await;
    let carol_heap = heap_of(&rig.nodes[1]);
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/world"), echo("echo:", &runs)).unwrap();
    let mut ask = to(Ask::new(Bytes::from_static(b"hi")), &["/alice/laptop"]);
    ask.deadline = Duration::from_secs(5);
    let told = asked(&carol_heap, "/world/x", ask).await;
    let [Ok(got), Err(finished)] = &told[..] else {
        panic!("one answer and its end: {told:?}");
    };
    assert_eq!(got.bytes.as_ref(), b"echo:hi");
    assert_eq!(got.writer, n("/alice/laptop"));
    assert_eq!(*finished, done(1, 1, 0, 0, 0));
    // A reader's device never serves.
    assert!(
        carol_heap.serve(n("/world"), echo("x", &runs)).is_err(),
        "a reader asks, a writer's device serves"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_servers_answer_and_done_counts_add_up() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/bob/tablet", "/carol/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob_phone, bob_tablet, carol) = (
        heap_of(&rig.nodes[1]),
        heap_of(&rig.nodes[2]),
        heap_of(&rig.nodes[3]),
    );
    let runs = Arc::new(AtomicUsize::new(0));
    let _a = alice_heap.serve(n("/w"), echo("alice:", &runs)).unwrap();
    let _p = bob_phone
        .serve(n("/w"), |_q: Query| async {
            Reply::refuse(7, "closed today")
        })
        .unwrap();
    let _t = bob_tablet
        .serve(n("/w"), |_q: Query| async { Reply::Pass })
        .unwrap();
    let mut ask = to(
        Ask::new(Bytes::from_static(b"?")),
        &["/alice/laptop", "/bob/phone", "/bob/tablet"],
    );
    ask.deadline = Duration::from_millis(1500);
    let told = asked(&carol, "/w/x", ask).await;
    let items: Vec<&Got> = told.iter().filter_map(|t| t.as_ref().ok()).collect();
    assert_eq!(items.len(), 2, "{told:?}");
    let alice = items
        .iter()
        .find(|g| g.writer == n("/alice/laptop"))
        .unwrap();
    assert_eq!(alice.bytes.as_ref(), b"alice:?");
    let phone = items.iter().find(|g| g.writer == n("/bob/phone")).unwrap();
    assert!(phone.bytes.is_empty());
    let Kind::Answered(a) = &phone.kind else {
        panic!()
    };
    assert_eq!(a.refusal, Some(AppRefusal::new(7, "closed today")));
    assert_eq!(
        told.last().unwrap().as_ref().unwrap_err(),
        &done(3, 1, 1, 0, 1),
        "answered, refused, and the Pass counted silent at the deadline: {told:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pass_is_counted_silent_and_a_refusal_is_refused_not_failed() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let _pass = alice_heap
        .serve(n("/pass"), |_q: Query| async { Reply::Pass })
        .unwrap();
    let _no = alice_heap
        .serve(n("/no"), |_q: Query| async {
            Reply::refuse(403, "not for you")
        })
        .unwrap();
    let mut ask = to(Ask::new(Bytes::new()), &["/alice/laptop"]);
    ask.deadline = Duration::from_millis(600);
    let started = std::time::Instant::now();
    let told = asked(&bob, "/pass/x", ask.clone()).await;
    assert_eq!(told, [Err(done(1, 0, 0, 0, 1))], "Pass: nothing is told");
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "silence is counted at the deadline: {:?}",
        started.elapsed()
    );
    let started = std::time::Instant::now();
    let told = asked(&bob, "/no/x", ask).await;
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a refusal is an answer: it resolves the server at once"
    );
    let [Ok(got), Err(finished)] = &told[..] else {
        panic!("{told:?}");
    };
    assert!(got.bytes.is_empty());
    let Kind::Answered(a) = &got.kind else {
        panic!()
    };
    assert_eq!(a.refusal, Some(AppRefusal::new(403, "not for you")));
    assert_eq!(*finished, done(1, 0, 1, 0, 0), "refused, not failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_answer_is_dropped_and_the_deadline_ends_the_query() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let _slow = alice_heap
        .serve(n("/slow"), |_q: Query| async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Reply::Answer(Bytes::from_static(b"late"))
        })
        .unwrap();
    let mut ask = to(Ask::new(Bytes::new()), &["/alice/laptop"]);
    ask.deadline = Duration::from_millis(500);
    // Kept on, so the stream outlives AnswersDone and a late answer would have somewhere to go.
    let opts = GetOptions {
        live: Live::Off,
        ask: Some(ask),
        ..GetOptions::default()
    };
    let mut items = bob.get(Select::Path(n("/slow/x")), opts).unwrap();
    let started = std::time::Instant::now();
    let finished = loop {
        let next = tokio::time::timeout(Duration::from_secs(5), items.next())
            .await
            .expect("told at the deadline")
            .unwrap();
        if let Err(GetNotice::AnswersDone { .. }) = next {
            break next;
        }
    };
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(finished, Err(done(1, 0, 0, 0, 1)), "counted silent");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        read(&mut items).is_empty(),
        "the handler finished, and its answer was not told"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_over_answer_max_fails_answertoolarge() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let _big = alice_heap
        .serve(n("/big"), |_q: Query| async {
            Reply::Answer(Bytes::from(vec![9u8; 3000]))
        })
        .unwrap();
    let mut ask = to(Ask::new(Bytes::new()), &["/alice/laptop"]);
    ask.deadline = Duration::from_secs(5);
    ask.answer_max = 100;
    let told = asked(&bob, "/big/x", ask.clone()).await;
    match &told[..] {
        [
            Err(GetNotice::QueryFailed {
                server,
                why:
                    why @ QueryError::AnswerTooLarge {
                        size: 3000,
                        max: 100,
                    },
            }),
            Err(finished),
        ] => {
            assert_eq!(*server, n("/alice/laptop"));
            assert_eq!(why.next(), crate::error::NextStep::FixRequest);
            assert_eq!(*finished, done(1, 0, 0, 1, 0));
        }
        other => panic!("{other:?}"),
    }
    ask.answer_max = 4096;
    let told = asked(&bob, "/big/x", ask).await;
    assert!(
        matches!(&told[0], Ok(got) if got.bytes.len() == 3000),
        "{told:?}"
    );
}

/// The proof of the answer `heap` is told by `device` to the query `query` of `path`: the proof,
/// the query id and the answer octets.
async fn proof_of(
    heap: &Heap,
    device: &str,
    path: &str,
    query: &'static [u8],
) -> (Bytes, QueryId, Bytes) {
    let mut ask = to(Ask::new(Bytes::from_static(query)), &[device]);
    ask.deadline = Duration::from_secs(5);
    ask.proof = true;
    let told = asked(heap, path, ask).await;
    let Ok(Got {
        kind: Kind::Answered(answered),
        bytes,
        ..
    }) = &told[0]
    else {
        panic!("{told:?}");
    };
    (
        answered.proof.clone().expect("the proof is kept"),
        answered.query,
        bytes.clone(),
    )
}

/// The two packets a proof holds.
fn parts(proof: &Bytes) -> QueryProof {
    QueryProof::decode(proof.clone()).expect("a proof is a QUERY_PROOF bundle")
}

fn bundle(interest: Bytes, answer: Bytes) -> Bytes {
    QueryProof { interest, answer }
        .encode()
        .expect("a bundle of two packets")
}

/// Whether `hay` holds `needle`.
fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The Data `signer` signs as the answer `Answered(text)` to the query `wire` (made for the
/// device `to`), with `signer`'s certificates: what a device that was never asked, or is no
/// writer, writes by hand.
fn answered_by(
    signer: &Node,
    to: &Node,
    wire: &Bytes,
    ask: &QueryAsk,
    text: &'static [u8],
) -> Bytes {
    let content = QueryAnswer {
        id: ask.id,
        body: AnswerBody::Plain(Status::Answered(Bytes::from_static(text))),
        certs: signer.inner.signer_chain(),
    }
    .encode()
    .unwrap();
    let builder = DataBuilder::new(rig::name_of(to, wire), &content).freshness(Duration::ZERO);
    crate::seal::sign(builder, &*signer.inner.signer).expect("the device signs")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_third_party_verifies_the_proof_from_the_record_alone_and_learns_what_and_when() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("a:", &runs)).unwrap();
    let mut plain = to(Ask::new(Bytes::from_static(b"x")), &["/alice/laptop"]);
    plain.deadline = Duration::from_secs(5);
    let without = asked(&bob, "/w/1", plain).await;
    assert!(matches!(&without[0], Ok(Got { kind: Kind::Answered(a), .. }) if a.proof.is_none()));

    let before = rig.nodes[1].inner.now();
    let (proof, query, answer) = proof_of(&bob, "/alice/laptop", "/w/2", b"where is it").await;
    let after = rig.nodes[1].inner.now();
    assert_eq!(answer.as_ref(), b"a:where is it");

    // Carol never took part in the exchange: she holds the record and the proof, nothing else.
    let seen = carol
        .verify_answer_proof(&proof)
        .await
        .expect("a member that never took part verifies the proof");
    assert_eq!(seen.space, space());
    assert_eq!(seen.query, query);
    assert_eq!(seen.asker, n("/bob"));
    assert_eq!(seen.asker_device, n("/bob/phone"));
    assert_eq!(seen.server_person, n("/alice"));
    assert_eq!(seen.server, n("/alice/laptop"));
    assert_eq!(seen.path, Some(n("/w/2")), "what was asked");
    assert_eq!(
        seen.query_bytes.as_deref(),
        Some(b"where is it".as_slice()),
        "the octets asked"
    );
    assert!(
        (before..=after).contains(&seen.signed_at.0),
        "when: the asker's SignatureTime {} lies in {before}..={after}",
        seen.signed_at.0
    );
    assert_eq!(seen.answer, ProvenAnswer::Answered(answer));

    // The bundle is the question and its answer: one Interest and the Data named as it.
    let held = parts(&proof);
    let interest = ndn_packet::Interest::decode(held.interest).expect("an Interest");
    let data = ndn_packet::Data::decode(held.answer).expect("a Data");
    assert_eq!(*data.name, *interest.name);
    assert_eq!(rig::answer_of(&data).id, query.0.to_be_bytes());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_with_a_changed_answer_or_a_changed_question_is_refused() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("a:", &runs)).unwrap();
    let (proof, ..) = proof_of(&bob, "/alice/laptop", "/w/2", b"where is it").await;
    assert!(carol.verify_answer_proof(&proof).await.is_ok(), "control");
    let held = parts(&proof);

    // The answer's octets changed, the length kept: the server's signature does not verify.
    let mut raw = held.answer.to_vec();
    let at = raw
        .windows(3)
        .position(|w| w == b"a:w")
        .expect("the answer octets are in the Data");
    raw[at + 2] = b'W';
    let err = carol
        .verify_answer_proof(&bundle(held.interest.clone(), Bytes::from(raw)))
        .await
        .expect_err("a changed answer is refused");
    assert!(matches!(err, ProofError::Answer { .. }), "{err}");

    // The query's octets changed: the Interest no longer hashes to the digest in its name.
    let mut raw = held.interest.to_vec();
    let at = raw
        .windows(11)
        .position(|w| w == b"where is it")
        .expect("the query octets are in the Interest");
    raw[at] = b'W';
    let err = carol
        .verify_answer_proof(&bundle(Bytes::from(raw), held.answer.clone()))
        .await
        .expect_err("a changed question is refused");
    assert!(matches!(err, ProofError::Question { .. }), "{err}");

    // Bytes that are no proof.
    let err = carol
        .verify_answer_proof(&held.answer)
        .await
        .expect_err("a bare Data is no proof");
    assert!(matches!(err, ProofError::Malformed { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_whose_question_was_swapped_for_another_is_refused() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("a:", &runs)).unwrap();
    let (first, ..) = proof_of(&bob, "/alice/laptop", "/w/1", b"first").await;
    let (second, ..) = proof_of(&bob, "/alice/laptop", "/w/2", b"second").await;
    for proof in [&first, &second] {
        assert!(carol.verify_answer_proof(proof).await.is_ok(), "control");
    }
    let (a, b) = (parts(&first), parts(&second));
    // Each packet is genuine, signed by the right key: but the answer to one is no answer to the
    // other (its name is the digest of the question it answers).
    for swapped in [
        bundle(b.interest.clone(), a.answer.clone()),
        bundle(a.interest.clone(), b.answer.clone()),
    ] {
        let err = carol
            .verify_answer_proof(&swapped)
            .await
            .expect_err("a swapped question is refused");
        assert!(matches!(err, ProofError::Unrelated { .. }), "{err}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_signed_by_a_non_writer_or_asked_by_a_non_member_is_refused() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone", "/dave/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (alice, bob, carol, dave) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2], &rig.nodes[3]);

    // Control: bob's query to carol's device (a writer's), answered and signed by carol.
    let ask = rig::plain_ask(bob, "/w/1", b"x");
    let wire = rig::signed_query(bob, carol, &ask);
    let data = answered_by(carol, carol, &wire, &ask, b"yes");
    let seen = alice_heap
        .verify_answer_proof(&bundle(wire, data))
        .await
        .expect("a writer's answer to a member's query verifies");
    assert_eq!(seen.server, n("/carol/phone"));
    assert_eq!(
        seen.answer,
        ProvenAnswer::Answered(Bytes::from_static(b"yes"))
    );

    // Dave's device is no writer: what it signs is no word of the space's writers.
    let wire = rig::signed_query(bob, dave, &ask);
    let data = answered_by(dave, dave, &wire, &ask, b"yes");
    let err = alice_heap
        .verify_answer_proof(&bundle(wire, data))
        .await
        .expect_err("a non-writer's answer is refused");
    assert!(matches!(err, ProofError::ServerNotWriter { .. }), "{err}");

    // The right device name, another device's key: it does not verify as the server's.
    let wire = rig::signed_query(bob, alice, &ask);
    let data = answered_by(carol, alice, &wire, &ask, b"yes");
    let err = alice_heap
        .verify_answer_proof(&bundle(wire, data))
        .await
        .expect_err("another device's signature is refused");
    assert!(matches!(err, ProofError::Answer { .. }), "{err}");

    // A query of a person the record does not list: no member asked it.
    let ask = rig::plain_ask(dave, "/w/1", b"x");
    let wire = rig::signed_query(dave, carol, &ask);
    let data = answered_by(carol, carol, &wire, &ask, b"yes");
    let err = alice_heap
        .verify_answer_proof(&bundle(wire, data))
        .await
        .expect_err("a stranger's query is refused");
    assert!(matches!(err, ProofError::AskerNotListed { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proof_of_a_sealed_answer_is_signed_ciphertext_and_the_verifier_says_so() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    let alice_heap = rig::sealed(&rig, &["/alice"], &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("s:", &runs)).unwrap();
    let before = rig.nodes[1].inner.now();
    let (proof, query, answer) =
        proof_of(&bob, "/alice/laptop", "/w/hidden-path", b"secret query").await;
    let after = rig.nodes[1].inner.now();
    assert_eq!(answer.as_ref(), b"s:secret query");
    for secret in [b"secret query".as_slice(), b"hidden-path", b"s:secret"] {
        assert!(
            !holds(&proof, secret),
            "the proof of a sealed space shows {:?} in the clear",
            String::from_utf8_lossy(secret)
        );
    }
    let seen = carol
        .verify_answer_proof(&proof)
        .await
        .expect("a reader that never took part verifies the signed ciphertext");
    assert_eq!(seen.query, query);
    assert_eq!(seen.server, n("/alice/laptop"));
    assert_eq!(seen.asker_device, n("/bob/phone"));
    assert_eq!(seen.path, None, "the path is ciphertext");
    assert_eq!(seen.query_bytes, None, "the octets are ciphertext");
    assert!((before..=after).contains(&seen.signed_at.0));
    assert!(
        matches!(&seen.answer, ProvenAnswer::Sealed { ciphertext } if !ciphertext.is_empty()),
        "{:?}",
        seen.answer
    );
    // Changed ciphertext does not verify.
    let held = parts(&proof);
    let mut raw = held.answer.to_vec();
    let last = raw.len() - 100;
    raw[last] ^= 1;
    let err = carol
        .verify_answer_proof(&bundle(held.interest, Bytes::from(raw)))
        .await
        .expect_err("a changed ciphertext is refused");
    assert!(matches!(err, ProofError::Answer { .. }), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_answer_is_ever_an_entry() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::public(&rig, &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("a:", &runs)).unwrap();
    let mut ask = to(Ask::new(Bytes::from_static(b"x")), &["/alice/laptop"]);
    ask.deadline = Duration::from_secs(5);
    let first = asked(&bob, "/w/1", ask.clone()).await;
    assert!(
        matches!(&first[0], Ok(got) if got.bytes.as_ref() == b"a:x"),
        "{first:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    // Nowhere in the register, at the asker or at the server.
    for heap in [&bob, &alice_heap] {
        assert!(heap.kept(&n("/w/1")).await.unwrap().is_none());
        assert!(heap.kept(&n("/w")).await.unwrap().is_none());
    }
    // A `get` with no ask lists nothing of it, and a later `get` is not told it again.
    let mut items = bob
        .get(
            everything(),
            GetOptions {
                live: Live::Off,
                ..GetOptions::default()
            },
        )
        .unwrap();
    items.caught_up().await;
    assert!(
        read(&mut items).iter().all(|r| !matches!(
            r,
            Ok(Got {
                kind: Kind::Answered(_),
                ..
            })
        )),
        "an answer is not an entry and is never replayed"
    );
    // A second `get` with ask runs the handler again.
    let second = asked(&bob, "/w/1", ask).await;
    assert!(
        matches!(&second[0], Ok(got) if got.bytes.as_ref() == b"a:x"),
        "{second:?}"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "no memo: the handler ran for each query"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_space_query_end_to_end_one_agreement_for_two_queries() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let alice_heap = rig::sealed(&rig, &["/alice"], &["/bob"]).await;
    let bob_node = &rig.nodes[1];
    let bob = heap_of(bob_node);
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = alice_heap.serve(n("/w"), echo("s:", &runs)).unwrap();
    let mut ask = to(Ask::new(Bytes::from_static(b"secret")), &["/alice/laptop"]);
    ask.deadline = Duration::from_secs(5);
    for round in 0..2 {
        let told = asked(&bob, "/w/x", ask.clone()).await;
        let [Ok(got), Err(finished)] = &told[..] else {
            panic!("round {round}: {told:?}");
        };
        assert_eq!(got.bytes.as_ref(), b"s:secret");
        assert_eq!(got.writer, n("/alice/laptop"));
        assert_eq!(got.by, n("/alice"));
        assert_eq!(*finished, done(1, 1, 0, 0, 0));
    }
    assert_eq!(runs.load(Ordering::SeqCst), 2);
    assert_eq!(
        bob_node.inner.query_key_counts(),
        (1, 1),
        "one seal key and one pair for the two queries"
    );
    assert_eq!(
        bob_node.inner.query_agreements(),
        1,
        "one X25519 agreement for the two queries"
    );
    // The served space refuses a prefix it does not serve, sealed too: NotServed is told as
    // the failure it is.
    let told = asked(&bob, "/nothing/here", ask).await;
    assert!(
        matches!(
            &told[0],
            Err(GetNotice::QueryFailed {
                why: QueryError::NotServed { .. },
                ..
            })
        ),
        "{told:?}"
    );
    assert_eq!(
        bob_node.inner.query_agreements(),
        1,
        "still the one agreement"
    );
}

/// A sealed space's announces name no prefix, so `Targets::Serving` has nothing to go by: it is
/// refused at once with what to do, not left to wait out the deadline for a hint that cannot come.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_serving_in_a_sealed_space_is_refused_with_what_to_do() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    let _alice_heap = rig::sealed(&rig, &["/alice"], &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let refused = bob.get(
        Select::Path(n("/w/x")),
        query_only(Ask::new(Bytes::from_static(b"q"))),
    );
    assert!(
        matches!(&refused, Err(HeapError::BadRequest { why })
            if why.contains("Targets::Devices") && why.contains("sealed")),
        "{:?}",
        refused.as_ref().map(|_| "an Items")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn targets_person_and_devices() {
    let rig = rig::rig(&[
        "/alice/laptop",
        "/bob/phone",
        "/bob/tablet",
        "/carol/phone",
        "/dave/phone",
    ])
    .await;
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let alice_node = &rig.nodes[0];
    // The record knows the devices that put.
    keep(&heap_of(&rig.nodes[1]), "/p", "1").await;
    keep(&heap_of(&rig.nodes[2]), "/t", "1").await;
    rig::eventually("alice's record holds both of bob's devices", || {
        let held = alice_node.inner.space_of(&space()).unwrap();
        held.log.lock().devices_of(&n("/bob")).len() == 2
    })
    .await;
    let held = alice_node.inner.space_of(&space()).unwrap();
    let targets = |t: Targets| {
        let mut ask = Ask::new(Bytes::new());
        ask.targets = t;
        ask.deadline = Duration::from_millis(200);
        let run = alice_node
            .inner
            .query_prepare(&held, &Select::Path(n("/w")), ask)
            .unwrap();
        let node = Arc::clone(&alice_node.inner);
        async move {
            let found = node.query_targets(&run).await;
            (found.servers, found.not_asked)
        }
    };
    assert_eq!(
        targets(Targets::Person(n("/bob"))).await,
        (vec![n("/bob/phone"), n("/bob/tablet")], 0),
        "the known devices of a writer"
    );
    assert_eq!(
        targets(Targets::Devices(vec![n("/bob/tablet"), n("/carol/phone")])).await,
        (vec![n("/bob/tablet"), n("/carol/phone")], 0),
        "exactly those, in the order named"
    );
    assert_eq!(
        targets(Targets::Devices(vec![n("/bob/tablet"), n("/bob/tablet")])).await,
        (vec![n("/bob/tablet")], 0),
        "a device named twice is asked once"
    );
    assert_eq!(
        targets(Targets::Person(n("/alice"))).await.0,
        Vec::<Name>::new(),
        "this device is never its own server"
    );
    // A device of a person the space does not list announces that it serves: it is no writer.
    alice_node.inner.query.hints.record(
        &space(),
        &n("/dave/phone"),
        &n("/dave"),
        false,
        &[n("/z")],
        Instant::now(),
    );
    assert_eq!(
        targets(Targets::Person(n("/dave"))).await.0,
        Vec::<Name>::new(),
        "a person the space does not list has no writer device, announced or not"
    );
    // An announce of a device of the person that the record holds nothing of.
    alice_node.inner.query.hints.record(
        &space(),
        &n("/carol/phone"),
        &n("/carol"),
        false,
        &[n("/z")],
        Instant::now(),
    );
    assert_eq!(
        targets(Targets::Person(n("/carol"))).await.0,
        vec![n("/carol/phone")]
    );
    let _ = alice_heap;
}

// -- The answer as the asker judges it ------------------------------------------------------------

/// The Data `signer` answers the query named `name` with: `answer`, signed by its device key.
fn crafted(signer: &Node, name: &Name, answer: &QueryAnswer) -> ndn_packet::Data {
    let builder =
        ndn_packet::encode::DataBuilder::new(name.clone(), &answer.encode().expect("an answer"));
    let wire = crate::seal::sign(builder, &*signer.inner.signer).expect("a signed Data");
    ndn_packet::Data::decode(wire).expect("a Data")
}

/// Judge `data` as `asker` would the answer of `server` to its query, through the real judge.
async fn judged(
    asker: &Node,
    server: &Node,
    data: ndn_packet::Data,
    id: Option<[u8; 8]>,
) -> Result<super::ask::Outcome, super::ask::Stop> {
    let held = asker.inner.space_of(&space()).unwrap();
    let mut ask = Ask::new(Bytes::new());
    ask.targets = Targets::Devices(vec![server.name().clone()]);
    let mut run = asker
        .inner
        .query_prepare(&held, &Select::Path(n("/w")), ask)
        .unwrap();
    if let Some(id) = id {
        run.set_id(QueryId(u64::from_be_bytes(id)));
    }
    let name = (*data.name).clone();
    asker
        .inner
        .query_take_answer(&run, server.name(), &name, &Bytes::new(), data, None)
        .await
}

fn plain(id: [u8; 8], status: Status) -> QueryAnswer {
    QueryAnswer {
        id,
        body: AnswerBody::Plain(status),
        certs: Vec::new(),
    }
}

fn failure(r: Result<super::ask::Outcome, super::ask::Stop>) -> QueryError {
    match r {
        Err(super::ask::Stop::Failed(why)) => why,
        Err(super::ask::Stop::Silent) => panic!("silent, not a failure"),
        Ok(_) => panic!("an answer was taken"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_answer_signed_by_a_non_writer_is_badanswer() {
    let rig = rig::rig(&["/alice/laptop", "/carol/phone", "/bob/phone"]).await;
    // Carol reads; only Alice and Bob write.
    rig::sealed(&rig, &["/alice", "/bob"], &["/carol"]).await;
    let (alice, carol, bob) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let name = crate::wire::query_ask_name(carol.name(), &[3u8; 32]);
    let id = [5u8; 8];
    // A writer's signature on a well-formed answer would do; a reader's does not. (Sealed space:
    // the standing of the signer is judged before the body is read.)
    let from_reader = crafted(
        carol,
        &name,
        &plain(id, Status::Answered(Bytes::from_static(b"x"))),
    );
    let why = failure(judged(bob, carol, from_reader, Some(id)).await);
    match &why {
        QueryError::BadAnswer { why: text } => {
            assert!(text.contains("no writer"), "says why: {text}");
        }
        other => panic!("BadAnswer, not {other:?}"),
    }
    assert_eq!(why.next(), crate::error::NextStep::RetryLater);
    // The same answer signed by a writer is taken (the caller says whether a body is sealed; the
    // signer is judged first and alone here).
    let name = crate::wire::query_ask_name(alice.name(), &[3u8; 32]);
    let from_writer = crafted(
        alice,
        &name,
        &plain(id, Status::Answered(Bytes::from_static(b"x"))),
    );
    assert!(
        matches!(
            judged(bob, alice, from_writer, Some(id)).await,
            Ok(super::ask::Outcome::Answered(_))
        ),
        "a writer's signature on the same answer passes the signer's judgement"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mismatched_query_id_is_badanswer() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    rig::public(&rig, &["/bob"]).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let name = crate::wire::query_ask_name(alice.name(), &[3u8; 32]);
    let ok = plain([5u8; 8], Status::Answered(Bytes::from_static(b"x")));
    let data = crafted(alice, &name, &ok);
    // The id asked for is [5; 8]: taken.
    let again = ndn_packet::Data::decode(data.raw().clone()).unwrap();
    let taken = judged(bob, alice, again, Some([5u8; 8])).await;
    assert!(
        matches!(&taken, Ok(super::ask::Outcome::Answered(got)) if got.bytes.as_ref() == b"x"),
        "a correct answer is taken"
    );
    // Another id: the same Data is the answer to another query.
    match failure(judged(bob, alice, data, Some([6u8; 8])).await) {
        QueryError::BadAnswer { why } => assert!(why.contains("another query"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A Data named otherwise is no answer to this query.
    let other_name = crate::wire::query_ask_name(alice.name(), &[4u8; 32]);
    let held = bob.inner.space_of(&space()).unwrap();
    let mut ask = Ask::new(Bytes::new());
    ask.targets = Targets::Devices(vec![alice.name().clone()]);
    let run = bob
        .inner
        .query_prepare(&held, &Select::Path(n("/w")), ask)
        .unwrap();
    let data = crafted(alice, &other_name, &ok);
    let r = bob
        .inner
        .query_take_answer(&run, alice.name(), &name, &Bytes::new(), data, None)
        .await;
    match failure(r) {
        QueryError::BadAnswer { why } => assert!(why.contains("is named"), "{why}"),
        other => panic!("{other:?}"),
    }
}

// -- The keys of a sealed space -------------------------------------------------------------------

#[test]
fn the_pair_cache_derives_once_per_epoch_and_drops_what_moved_and_is_bounded() {
    use super::ask::{KEYS_MAX, Keys};
    use crate::wire::EpochId;
    let (space, asker, server) = (n("/alice/32=data/w"), n("/bob/phone"), n("/alice/laptop"));
    let epoch = |seq| EpochId {
        creator: n("/alice/laptop"),
        seq,
    };
    let public = ndn_security::RecipientKey::generate().public();
    let mut keys = Keys::default();
    let pair = |keys: &mut Keys, e: u64, pk: [u8; 32], at: (u64, u64)| {
        keys.pair(&space, &asker, &server, &epoch(e), pk, at)
            .unwrap()
    };

    let first = pair(&mut keys, 1, public, (1, 1));
    let second = pair(&mut keys, 1, public, (1, 1));
    assert_eq!(
        (first.seq, second.seq),
        (0, 1),
        "a counter that never repeats"
    );
    assert_eq!(
        first.ephemeral, second.ephemeral,
        "one agreement serves both"
    );
    assert_eq!(keys.agreements, 1);

    let next_epoch = pair(&mut keys, 2, public, (1, 1));
    assert_eq!(next_epoch.seq, 0);
    assert_ne!(
        next_epoch.ephemeral, first.ephemeral,
        "a new epoch, a new agreement"
    );
    assert_eq!(keys.agreements, 2);
    assert_eq!(keys.counts().1, 1, "the old epoch's keys are gone");

    let after_generation = pair(&mut keys, 2, public, (2, 1));
    assert_ne!(
        after_generation.ephemeral, next_epoch.ephemeral,
        "the trust generation moved"
    );
    let after_fold = pair(&mut keys, 2, public, (2, 2));
    assert_ne!(
        after_fold.ephemeral, after_generation.ephemeral,
        "the members fold moved"
    );
    let other_key = pair(
        &mut keys,
        2,
        ndn_security::RecipientKey::generate().public(),
        (2, 2),
    );
    assert_ne!(
        other_key.ephemeral, after_fold.ephemeral,
        "the server's key changed"
    );
    assert_eq!(keys.agreements, 5);

    // The server's key is held until the trust generation moves.
    keys.put_seal(&server, public, 7);
    assert_eq!(keys.seal_public(&server, 7), Some(public));
    assert_eq!(
        keys.seal_public(&server, 8),
        None,
        "judged under another generation"
    );
    assert_eq!(keys.seal_public(&server, 7), None, "and dropped by it");
    keys.put_seal(&server, public, 7);
    keys.forget(&server);
    assert_eq!(
        keys.counts(),
        (0, 0),
        "a server that is no writer is forgotten"
    );

    // Bounded: the most recently used of KEYS_MAX stay.
    for i in 0..(KEYS_MAX + 6) {
        let other = n(&format!("/alice/d{i}"));
        keys.put_seal(&other, public, 1);
        keys.pair(&space, &asker, &other, &epoch(1), public, (1, 1))
            .unwrap();
    }
    assert_eq!(keys.counts(), (KEYS_MAX, KEYS_MAX));
    assert_eq!(
        keys.seal_public(&n("/alice/d0"), 1),
        None,
        "the oldest went"
    );
    assert!(
        keys.seal_public(&n(&format!("/alice/d{}", KEYS_MAX + 5)), 1)
            .is_some()
    );
}
