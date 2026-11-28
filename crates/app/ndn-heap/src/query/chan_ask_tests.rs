//! The asker's channel path (docs/specs/query.md, the channel path): which path a query takes,
//! the setup it needs, what it seals and sends, how an answer is judged, and what it keeps.
//!
//! Most cases run the asker alone against answers built by hand: the node of the asker holds the
//! pair a real setup gave it (`ask_channel_in(.., Ask)`), its `QUERY` frames are held back from
//! the forwarder ([`Tap::swallow_queries`]) and the test seals the answers under the pair's `Ka`
//! as a server would. The cases that name a server's handler run on a real server.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::SideClass;

use super::rig::{self, Rig, Tap, eventually};
use super::types::{
    ANSWER_MAX_CHANNEL, ANSWER_MAX_DEFAULT, Answered, Ask, CHANNEL_QUERY_MAX, Handler, Query,
    QueryError, QueryPath, Reply, Targets, Via,
};
use crate::chan::error::ChanError;
use crate::chan::pair::ASK_IDLE;
use crate::chan::qframe::{AnswerHeader, ChanStatus, QUERY_OVERHEAD, QueryHeader, QueryPlain};
use crate::chan::verbs::{GetNotice, GetOptions, Got, Kind, Live, Select};
use crate::chan::wire::ChannelMode;
use crate::error::HeapError;
use crate::node::Node;
use crate::node::tests::space;
use crate::rt::Instant;
use crate::space::Heap;
use crate::test_kit::n;

// -- The world and what the cases read with -----------------------------------------------------

/// Two nodes on one forwarder, both with the forwarder attached: alice owns the space and is the
/// server, bob (a writer of the public space, a reader of the sealed one) asks.
struct Duo {
    rig: Rig,
    alice: Heap,
    bob: Heap,
}

impl Duo {
    fn alice_node(&self) -> &Node {
        &self.rig.nodes[0]
    }

    fn bob_node(&self) -> &Node {
        &self.rig.nodes[1]
    }

    /// What bob sent into the forwarder.
    fn tap(&self) -> &Arc<Tap> {
        &self.rig.taps[1]
    }
}

fn heap_of(node: &Node) -> Heap {
    node.space(&space()).expect("the space is open here")
}

async fn duo(sealed: bool) -> Duo {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    for node in &rig.nodes {
        node.attach_forwarder()
            .expect("the engine's face carries channel frames");
    }
    let alice = if sealed {
        rig::sealed(&rig, &["/alice"], &["/bob"]).await
    } else {
        rig::public(&rig, &["/bob"]).await
    };
    let bob = heap_of(&rig.nodes[1]);
    Duo { rig, alice, bob }
}

fn alice() -> Name {
    n("/alice/laptop")
}

fn query_only(ask: Ask) -> GetOptions {
    GetOptions {
        kept: false,
        live: Live::Off,
        ask: Some(ask),
        ..GetOptions::default()
    }
}

/// A query of `q` to `devices` over `via`, which lives 5 s.
fn ask(via: QueryPath, devices: &[&str], q: &[u8]) -> Ask {
    let mut ask = Ask::new(Bytes::copy_from_slice(q));
    ask.targets = Targets::Devices(devices.iter().map(|d| n(d)).collect());
    ask.via = via;
    ask.deadline = Duration::from_secs(5);
    ask
}

type Told = Vec<Result<Got, GetNotice>>;

/// Read a query-only stream to its end.
async fn asked(heap: &Heap, path: &str, ask: Ask) -> Told {
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

fn bad_request(heap: &Heap, ask: Ask) -> String {
    match heap.get(Select::Path(n("/world/x")), query_only(ask)) {
        Err(HeapError::BadRequest { why }) => why,
        Err(other) => panic!("BadRequest, not {other:?}"),
        Ok(_) => panic!("a bad request was taken"),
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

/// The one answer a stream told and the notice that ended it.
fn one_answer(told: &Told) -> (&Got, &Answered) {
    let [Ok(got), Err(GetNotice::AnswersDone { .. })] = &told[..] else {
        panic!("one answer and its end: {told:?}");
    };
    let Kind::Answered(answered) = &got.kind else {
        panic!("an answer item: {got:?}");
    };
    (got, answered)
}

/// The notice a stream ended with.
fn ended(told: &Told) -> &GetNotice {
    match told.last() {
        Some(Err(end @ GetNotice::AnswersDone { .. })) => end,
        other => panic!("the stream ends with AnswersDone: {other:?}"),
    }
}

/// The one failure a stream told, and that it ended with one failed server.
fn one_failure(told: &Told) -> &QueryError {
    let [Err(GetNotice::QueryFailed { why, .. }), Err(end)] = &told[..] else {
        panic!("one failure and its end: {told:?}");
    };
    assert_eq!(*end, done(1, 0, 0, 1, 0), "the end counts it failed");
    why
}

fn echo(prefix: &'static str, runs: &Arc<AtomicUsize>) -> impl Handler {
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

/// bob asks `server` for an `Ask` session over the space and holds it with its pair.
async fn warm(duo: &Duo, server: &Name) {
    duo.bob_node()
        .ask_channel_in(&space(), server, ChannelMode::Ask)
        .await
        .expect("the server gives an Ask session");
}

fn held(node: &Node, server: &Name) -> Option<u64> {
    node.inner
        .chan
        .sessions
        .find(&space(), server, ChannelMode::Ask)
        .map(|s| s.id())
}

// -- Answers built by hand ----------------------------------------------------------------------

/// What `asker` holds as the pair of the channel `route`, as a server would answer under it.
fn answer_frame(asker: &Node, query: &Bytes, status: &ChanStatus) -> Bytes {
    let (head, _) = QueryHeader::parse(query).expect("a QUERY frame");
    let pair = asker
        .inner
        .chan
        .ask_pairs
        .get(head.route)
        .expect("the asker holds the pair of the route");
    answer_under(&pair, &head, status)
}

fn answer_under(
    pair: &crate::chan::pair::AskPair,
    head: &QueryHeader,
    status: &ChanStatus,
) -> Bytes {
    let header = AnswerHeader {
        class: SideClass::Datagram,
        route: head.route,
        token: head.token,
        epoch: head.epoch,
    }
    .encode();
    let sealed = pair
        .ciphers()
        .seal_answer(head.epoch, head.qseq, &header, &status.encode());
    let mut frame = header.to_vec();
    frame.extend_from_slice(&sealed);
    Bytes::from(frame)
}

/// The `QUERY` frame the `seen`-th to be sent by the asker's node, waited for.
async fn query_after(tap: &Tap, seen: usize) -> Bytes {
    eventually("the asker sent a QUERY frame", || {
        tap.queries().len() > seen
    })
    .await;
    tap.queries()[seen].clone()
}

/// bob's `ask` for `path`, with its `QUERY` frames held back and answered by hand with `status`.
async fn by_hand(duo: &Duo, path: &str, ask: Ask, status: ChanStatus) -> Told {
    duo.tap().swallow_queries(true);
    let seen = duo.tap().queries().len();
    let reading = asked(&duo.bob, path, ask);
    let answering = async {
        let query = query_after(duo.tap(), seen).await;
        duo.bob_node()
            .inner
            .query_answer_frame(answer_frame(duo.bob_node(), &query, &status));
    };
    let (told, ()) = tokio::join!(reading, answering);
    told
}

fn answered(text: &str) -> ChanStatus {
    ChanStatus::Answered(Bytes::copy_from_slice(text.as_bytes()))
}

// -- The path a query takes ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_uses_a_warm_session_and_else_signed_and_via_says_which() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("sig:", &runs)).unwrap();
    // No session held: signed.
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Auto, &["/alice/laptop"], b"1"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"sig:1");
    assert_eq!(
        answered_by.via,
        Via::Signed,
        "no session held: the signed path"
    );
    assert!(duo.tap().queries().is_empty(), "no QUERY frame was sent");
    // A warm session with its pair: the channel, with no signature of the asker's.
    warm(&duo, &alice()).await;
    let signed = duo.bob_node().signatures();
    let told = by_hand(
        &duo,
        "/world/a",
        ask(QueryPath::Auto, &["/alice/laptop"], b"2"),
        answered("hand:2"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"hand:2");
    assert_eq!(answered_by.via, Via::Sealed, "a warm session: the channel");
    assert_eq!(got.author.writer, alice(), "the server's device");
    assert_eq!(got.author.by, n("/alice"), "its person, as judged now");
    assert_eq!(
        duo.bob_node().signatures(),
        signed,
        "the channel query signed nothing"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "only the signed query ran the handler"
    );
    // The session let go: signed again.
    let id = held(duo.bob_node(), &alice()).expect("held");
    let session = duo.bob_node().inner.chan.sessions.get(id).unwrap();
    duo.bob_node().inner.chan_let_go(&session);
    duo.bob_node().inner.chan.ask_pairs.remove(id);
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Auto, &["/alice/laptop"], b"3"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"sig:3");
    assert_eq!(answered_by.via, Via::Signed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_never_creates_a_session() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("sig:", &runs)).unwrap();
    for i in 0..3 {
        let told = asked(
            &duo.bob,
            "/world/a",
            ask(
                QueryPath::Auto,
                &["/alice/laptop"],
                format!("{i}").as_bytes(),
            ),
        )
        .await;
        let (_, answered_by) = one_answer(&told);
        assert_eq!(answered_by.via, Via::Signed);
    }
    assert!(
        held(duo.bob_node(), &alice()).is_none(),
        "no session was made"
    );
    assert_eq!(
        duo.bob_node().inner.chan.ask_pairs.count(),
        0,
        "no pair was made"
    );
    assert_eq!(
        duo.bob_node().inner.chan.stats.asked.get(),
        0,
        "no ask was signed"
    );
    assert!(duo.tap().queries().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_with_a_refused_setup_never_falls_back_to_signed() {
    // carol's device is in the world and a writer of the space, but not started: nothing answers
    // the ask of its channel.
    let rig = rig::rig_started(&["/alice/laptop", "/bob/phone", "/carol/phone"], 2).await;
    for node in &rig.nodes {
        node.attach_forwarder().unwrap();
    }
    let _alice = rig::public(&rig, &["/bob", "/carol"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let signed = rig.nodes[1].signatures();
    let mut query = ask(QueryPath::Channel, &["/carol/phone"], b"q");
    query.deadline = Duration::from_secs(10);
    let told = asked(&bob, "/world/x", query).await;
    let [Err(GetNotice::QueryFailed { why, .. }), Err(end)] = &told[..] else {
        panic!("one failure and its end: {told:?}");
    };
    let QueryError::NoSession { why: setup } = why else {
        panic!("the setup's refusal, not {why:?}");
    };
    assert!(
        matches!(
            setup,
            ChanError::NotAnswered { .. } | ChanError::Unreachable { .. }
        ),
        "the setup's reason: {setup:?}"
    );
    assert_eq!(why.next(), setup.next(), "its next step is the setup's");
    assert_eq!(*end, done(1, 0, 0, 1, 0));
    assert_eq!(
        rig.nodes[1].signatures(),
        signed + 1,
        "the one signature is the channel's ask: no signed query was made"
    );
    assert!(rig.taps[1].queries().is_empty(), "no QUERY frame was sent");
    assert!(held(&rig.nodes[1], &n("/carol/phone")).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_creates_the_session_with_one_signed_ask() {
    let duo = duo(false).await;
    let signed = duo.bob_node().signatures();
    let told = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
        answered("a"),
    )
    .await;
    let (_, answered_by) = one_answer(&told);
    assert_eq!(answered_by.via, Via::Sealed);
    assert_eq!(
        duo.bob_node().signatures(),
        signed + 1,
        "one signature: the ask of the channel"
    );
    assert!(held(duo.bob_node(), &alice()).is_some());
    assert_eq!(duo.bob_node().inner.chan.ask_pairs.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_second_query_in_a_session_costs_no_signature() {
    let duo = duo(false).await;
    let first = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"one"),
        answered("1"),
    )
    .await;
    one_answer(&first);
    let (bob_signed, alice_signed) = (duo.bob_node().signatures(), duo.alice_node().signatures());
    let asks = duo.alice_node().inner.chan.stats.asks.get();
    let second = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"two"),
        answered("2"),
    )
    .await;
    one_answer(&second);
    assert_eq!(
        duo.bob_node().signatures(),
        bob_signed,
        "the asker signed nothing"
    );
    assert_eq!(
        duo.alice_node().signatures(),
        alice_signed,
        "the server signed nothing"
    );
    assert_eq!(
        duo.alice_node().inner.chan.stats.asks.get(),
        asks,
        "the server judged no ask: no signature of the asker's was verified"
    );
    // One pair, one counter taken once each, a token of its own for every query.
    let sent = duo.tap().queries();
    assert_eq!(sent.len(), 2);
    let heads: Vec<_> = sent
        .iter()
        .map(|f| QueryHeader::parse(f).unwrap().0)
        .collect();
    assert_eq!(heads[0].pair, heads[1].pair, "one pair");
    assert_eq!(
        (heads[0].qseq, heads[1].qseq),
        (0, 1),
        "the counter rises from 0"
    );
    assert_ne!(heads[0].token, heads[1].token);
    assert_eq!(heads[0].route, heads[1].route);
    // Nothing survives an answer.
    assert_eq!(duo.bob_node().inner.query.ask.chan.pending(), 0);
    assert_eq!(
        duo.bob_node().inner.chan.ask_pairs.count(),
        1,
        "the pair is the one thing kept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ask_session_survives_items_drop_and_is_released_after_60_s_idle() {
    let duo = duo(false).await;
    one_answer(
        &by_hand(
            &duo,
            "/world/x",
            ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
            answered("a"),
        )
        .await,
    );
    // The `Items` of the query is gone: the session stays.
    let node = &duo.bob_node().inner;
    assert!(
        held(duo.bob_node(), &alice()).is_some(),
        "survives the Items"
    );
    node.chan_tick(Instant::now() + Duration::from_secs(30))
        .await;
    assert!(
        held(duo.bob_node(), &alice()).is_some(),
        "30 s idle: still held"
    );
    assert_eq!(node.chan.ask_pairs.count(), 1);
    // A minute with no query: let go, with its pair, and the route given up.
    let unsubs = node.chan.route.unsubs.get();
    node.chan_tick(Instant::now() + ASK_IDLE + Duration::from_secs(1))
        .await;
    assert!(
        held(duo.bob_node(), &alice()).is_none(),
        "released after the idle minute"
    );
    assert_eq!(node.chan.ask_pairs.count(), 0, "the pair went with it");
    assert!(
        node.chan.route.unsubs.get() > unsubs,
        "the Unsub went upstream"
    );
}

// -- What a frame says and holds ----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_public_space_channel_query_is_sealed_to_the_pair() {
    let duo = duo(false).await;
    let told = by_hand(
        &duo,
        "/world/pickup/7",
        ask(QueryPath::Channel, &["/alice/laptop"], b"the secret words"),
        answered("ok"),
    )
    .await;
    one_answer(&told);
    let frame = duo.tap().queries().remove(0);
    assert!(
        duo.tap()
            .side_sent()
            .iter()
            .any(|(sent, class)| *sent == frame && *class == SideClass::Datagram),
        "a QUERY goes as a datagram"
    );
    let (head, body) = QueryHeader::parse(&frame).unwrap();
    assert!(
        !frame.windows(16).any(|w| w == b"the secret words")
            && !frame.windows(6).any(|w| w == b"pickup"),
        "the path and the octets are not in the clear, in a public space too"
    );
    assert_eq!(head.qseq, 0);
    assert!(
        (1..=100).contains(&head.ttl_ticks),
        "the ttl is the deadline in 100 ms"
    );
    let expected = {
        let plain = QueryPlain {
            id: 0,
            deadline_ms: 5000,
            path: n("/world/pickup/7"),
            bytes: Bytes::from_static(b"the secret words"),
        };
        plain.encode().unwrap().len()
    };
    assert_eq!(
        frame.len(),
        QUERY_OVERHEAD + expected,
        "the frame is the header, the plaintext and the tag"
    );
    let pair = duo.bob_node().inner.chan.ask_pairs.get(head.route).unwrap();
    assert_eq!(pair.id(), head.pair);
    assert_eq!(head.epoch, pair.epoch());
    // Opens under Kq with the 36 header octets as additional data, and under nothing else.
    let plain = pair
        .ciphers()
        .open_query(head.epoch, head.qseq, &frame[..36], body)
        .expect("opens under Kq with the header as additional data");
    let plain = QueryPlain::decode(&plain).unwrap();
    assert_eq!(plain.path, n("/world/pickup/7"));
    assert_eq!(plain.bytes.as_ref(), b"the secret words");
    assert!((1..=5000).contains(&plain.deadline_ms));
    assert!(
        pair.ciphers()
            .open_answer(head.epoch, head.qseq, &frame[..36], body)
            .is_none(),
        "not under Ka"
    );
    let mut other = frame.to_vec();
    other[20] ^= 1; // a header octet the seal covers (the token)
    assert!(
        pair.ciphers()
            .open_query(head.epoch, head.qseq, &other[..36], body)
            .is_none(),
        "a changed header octet fails the seal"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_space_channel_query_round_trips() {
    let duo = duo(true).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("echo:", &runs)).unwrap();
    // By hand first: the asker alone.
    let told = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"hi"),
        answered("hand"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"hand");
    assert_eq!(answered_by.via, Via::Sealed);
    assert_eq!(got.author.by, n("/alice"));
    // Then through the real server over the forwarder.
    duo.tap().swallow_queries(false);
    let told = asked(
        &duo.bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"hi"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"echo:hi");
    assert_eq!(answered_by.via, Via::Sealed);
    assert_eq!(got.author.writer, alice());
    assert_eq!(runs.load(Ordering::SeqCst), 1, "the handler ran once");
}

// -- Judging an answer --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_for_a_token_not_pending_is_dropped() {
    let duo = duo(false).await;
    let told = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
        answered("a"),
    )
    .await;
    one_answer(&told);
    let state = &duo.bob_node().inner.query.ask.chan;
    let query = duo.tap().queries().remove(0);
    let valid = answer_frame(duo.bob_node(), &query, &answered("late"));
    let before = state.stats.unmatched.get();
    // The answer of a query that is done, a token never asked, and a frame that is no ANSWER.
    duo.bob_node().inner.query_answer_frame(valid);
    let (mut head, _) = QueryHeader::parse(&query).unwrap();
    head.token ^= 1;
    let pair = duo.bob_node().inner.chan.ask_pairs.get(head.route).unwrap();
    duo.bob_node()
        .inner
        .query_answer_frame(answer_under(&pair, &head, &answered("x")));
    assert_eq!(state.stats.unmatched.get(), before + 2, "both counted");
    duo.bob_node()
        .inner
        .query_answer_frame(Bytes::from_static(&[0, 0x26, 1, 2]));
    assert_eq!(state.stats.bad_frame.get(), 1, "a cut frame is counted");
    assert_eq!(state.pending(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_answer_for_a_token_is_dropped() {
    let duo = duo(false).await;
    duo.tap().swallow_queries(true);
    let reading = asked(
        &duo.bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
    );
    let answering = async {
        let query = query_after(duo.tap(), 0).await;
        let node = &duo.bob_node().inner;
        node.query_answer_frame(answer_frame(duo.bob_node(), &query, &answered("first")));
        node.query_answer_frame(answer_frame(duo.bob_node(), &query, &answered("second")));
        node.query_answer_frame(answer_frame(duo.bob_node(), &query, &ChanStatus::NotServed));
    };
    let (told, ()) = tokio::join!(reading, answering);
    let (got, _) = one_answer(&told);
    assert_eq!(
        got.bytes.as_ref(),
        b"first",
        "the first answer is the outcome"
    );
    assert_eq!(ended(&told), &done(1, 1, 0, 0, 0));
    assert_eq!(
        duo.bob_node().inner.query.ask.chan.stats.unmatched.get(),
        2,
        "the other two were dropped and counted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_fails_the_aead_is_a_bad_answer_and_one_outcome() {
    let duo = duo(false).await;
    duo.tap().swallow_queries(true);
    let reading = asked(
        &duo.bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
    );
    let answering = async {
        let query = query_after(duo.tap(), 0).await;
        let node = &duo.bob_node().inner;
        let mut forged = answer_frame(duo.bob_node(), &query, &answered("forged")).to_vec();
        let last = forged.len() - 1;
        forged[last] ^= 1; // the tag
        node.query_answer_frame(Bytes::from(forged));
        // The true answer comes too late: the query has its one outcome.
        node.query_answer_frame(answer_frame(duo.bob_node(), &query, &answered("true")));
    };
    let (told, ()) = tokio::join!(reading, answering);
    let QueryError::BadAnswer { why } = one_failure(&told) else {
        panic!("BadAnswer: {told:?}");
    };
    assert!(why.contains("open"), "says it did not open: {why}");
    let stats = &duo.bob_node().inner.query.ask.chan.stats;
    assert_eq!(stats.bad_answers.get(), 1);
    assert_eq!(
        stats.unmatched.get(),
        1,
        "the later answer found nothing waiting"
    );
    assert_eq!(duo.bob_node().inner.query.ask.chan.pending(), 0);
    // Every octet of the header is covered by the seal: a changed epoch octet is no answer either.
    duo.tap().swallow_queries(true);
    let reading = asked(
        &duo.bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
    );
    let answering = async {
        let query = query_after(duo.tap(), 1).await;
        let mut forged = answer_frame(duo.bob_node(), &query, &answered("forged")).to_vec();
        forged[18] ^= 1; // the epoch octet
        duo.bob_node().inner.query_answer_frame(Bytes::from(forged));
    };
    let (told, ()) = tokio::join!(reading, answering);
    assert!(matches!(one_failure(&told), QueryError::BadAnswer { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_silent_queries_let_the_session_go_and_the_next_asks_again() {
    let duo = duo(false).await;
    duo.tap().swallow_queries(true);
    let mut quick = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    quick.deadline = Duration::from_millis(400);
    // The first query makes the session; nothing answers it, nor the next two.
    for i in 0..3 {
        let told = asked(&duo.bob, "/world/x", quick.clone()).await;
        assert!(
            matches!(&told[..], [Err(end)] if *end == done(1, 0, 0, 0, 1)),
            "query {i} is silent: {told:?}"
        );
        if i < 2 {
            assert!(
                held(duo.bob_node(), &alice()).is_some(),
                "{} silent: still held",
                i + 1
            );
        }
    }
    assert!(
        held(duo.bob_node(), &alice()).is_none(),
        "three in a row: the session is let go"
    );
    assert_eq!(
        duo.bob_node().inner.chan.ask_pairs.count(),
        0,
        "with its pair"
    );
    assert_eq!(duo.bob_node().inner.query.ask.chan.stats.silent.get(), 3);
    let queries = duo.tap().queries();
    assert_eq!(queries.len(), 3);
    let first = QueryHeader::parse(&queries[0]).unwrap().0;
    let seqs: Vec<u64> = queries
        .iter()
        .map(|f| QueryHeader::parse(f).unwrap().0.qseq)
        .collect();
    assert_eq!(seqs, [0, 1, 2], "each number was taken once");
    // The fourth asks again: a new session, a new pair, a counter from 0, and it is answered.
    let told = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
        answered("again"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"again");
    assert_eq!(answered_by.via, Via::Sealed);
    let fourth = QueryHeader::parse(&duo.tap().queries()[3]).unwrap().0;
    assert_ne!(fourth.pair, first.pair, "a new pair");
    assert_eq!(fourth.qseq, 0, "a counter of its own");
    assert!(held(duo.bob_node(), &alice()).is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_in_time_clears_the_silence() {
    let duo = duo(false).await;
    duo.tap().swallow_queries(true);
    let mut quick = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    quick.deadline = Duration::from_millis(400);
    asked(&duo.bob, "/world/x", quick.clone()).await;
    asked(&duo.bob, "/world/x", quick.clone()).await;
    // Two silent, then one answered: the run of silence is broken.
    one_answer(
        &by_hand(
            &duo,
            "/world/x",
            ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
            answered("a"),
        )
        .await,
    );
    asked(&duo.bob, "/world/x", quick.clone()).await;
    asked(&duo.bob, "/world/x", quick).await;
    assert!(
        held(duo.bob_node(), &alice()).is_some(),
        "two silent after an answer: still held"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_items_cancels_the_pending_entries() {
    let duo = duo(false).await;
    duo.tap().swallow_queries(true);
    let state = &duo.bob_node().inner.query.ask.chan;
    let items = duo
        .bob
        .get(
            Select::Path(n("/world/x")),
            query_only(ask(QueryPath::Channel, &["/alice/laptop"], b"q")),
        )
        .unwrap();
    query_after(duo.tap(), 0).await;
    assert_eq!(state.pending(), 1, "the query waits for its answer");
    drop(items);
    eventually("the pending entry is removed", || state.pending() == 0).await;
    // The answer that comes after is dropped, and a cancelled query is no silence of the server.
    let query = duo.tap().queries().remove(0);
    let before = state.stats.unmatched.get();
    duo.bob_node().inner.query_answer_frame(answer_frame(
        duo.bob_node(),
        &query,
        &answered("late"),
    ));
    assert_eq!(state.stats.unmatched.get(), before + 1);
    assert_eq!(state.stats.silent.get(), 0, "cancelling is not silence");
    assert_eq!(
        duo.bob_node().inner.query.ask.pending.lock().total(),
        0,
        "the slot of the pending set is released too"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_with_no_forwarder_says_so_and_auto_goes_signed() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone"]).await;
    rig.nodes[0].attach_forwarder().unwrap(); // the server side only
    let owner = rig::public(&rig, &["/bob"]).await;
    let bob = heap_of(&rig.nodes[1]);
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = owner.serve(n("/world"), echo("sig:", &runs)).unwrap();
    let told = asked(
        &bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
    )
    .await;
    let QueryError::NotReady { why } = one_failure(&told) else {
        panic!("NotReady: {told:?}");
    };
    assert!(why.contains("attach_forwarder"), "says what to do: {why}");
    assert!(rig.taps[1].queries().is_empty());
    // With a session held (no forwarder is needed to be given one), Auto still goes signed.
    rig.nodes[1]
        .ask_channel_in(&space(), &alice(), ChannelMode::Ask)
        .await
        .expect("a session is given");
    let told = asked(
        &bob,
        "/world/x",
        ask(QueryPath::Auto, &["/alice/laptop"], b"2"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"sig:2");
    assert_eq!(answered_by.via, Via::Signed, "no forwarder: no channel");
}

// -- Limits and what the path refuses -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_over_1024_octets_is_refused_on_channel_and_goes_signed_on_auto() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("sig:", &runs)).unwrap();
    let big = vec![7u8; CHANNEL_QUERY_MAX + 1];
    let why = bad_request(&duo.bob, ask(QueryPath::Channel, &["/alice/laptop"], &big));
    assert!(
        why.contains("1024") && why.contains("Channel"),
        "says the limit and the path: {why}"
    );
    // 1,024 octets of query and a long path do not fit one frame of 1,150 octets.
    let at_limit = vec![7u8; CHANNEL_QUERY_MAX];
    let long = format!("/world/{}", "p".repeat(200));
    let why = match duo.bob.get(
        Select::Path(n(&long)),
        query_only(ask(QueryPath::Channel, &["/alice/laptop"], &at_limit)),
    ) {
        Err(HeapError::BadRequest { why }) => why,
        other => panic!("BadRequest, not {:?}", other.map(|_| ())),
    };
    assert!(
        why.contains("1150") || why.contains("1,150"),
        "says the frame limit: {why}"
    );
    // Auto with a warm session goes signed for it: the channel would refuse.
    warm(&duo, &alice()).await;
    let told = asked(
        &duo.bob,
        "/world/x",
        ask(QueryPath::Auto, &["/alice/laptop"], &big),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(
        answered_by.via,
        Via::Signed,
        "the query does not fit a channel frame"
    );
    assert_eq!(got.bytes.len(), 4 + big.len());
    assert!(duo.tap().queries().is_empty(), "no QUERY frame was made");
    // A query of 1,024 octets is taken on Channel.
    let told = by_hand(
        &duo,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], &at_limit),
        answered("fits"),
    )
    .await;
    assert_eq!(one_answer(&told).1.via, Via::Sealed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channel_with_proof_is_refused_and_auto_with_proof_goes_signed() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("sig:", &runs)).unwrap();
    let mut with_proof = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    with_proof.proof = true;
    let why = bad_request(&duo.bob, with_proof.clone());
    assert!(
        why.contains("proof") && why.contains("Signed"),
        "says what to ask instead: {why}"
    );
    warm(&duo, &alice()).await;
    with_proof.via = QueryPath::Auto;
    let told = asked(&duo.bob, "/world/x", with_proof).await;
    let (_, answered_by) = one_answer(&told);
    assert_eq!(answered_by.via, Via::Signed, "only the signed path proves");
    assert!(answered_by.proof.is_some());
    assert!(duo.tap().queries().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limits_of_answer_max_follow_the_path() {
    let duo = duo(false).await;
    let over = |via, max| {
        let mut a = ask(via, &["/alice/laptop"], b"q");
        a.answer_max = max;
        a
    };
    let why = bad_request(&duo.bob, over(QueryPath::Signed, ANSWER_MAX_DEFAULT + 1));
    assert!(why.contains("answer_max") && why.contains("4096"), "{why}");
    for via in [QueryPath::Channel, QueryPath::Auto] {
        let why = bad_request(&duo.bob, over(via, ANSWER_MAX_CHANNEL + 1));
        assert!(
            why.contains("answer_max") && why.contains("65536"),
            "{via:?}: {why}"
        );
        assert!(
            duo.bob
                .get(
                    Select::Path(n("/world/x")),
                    query_only(over(via, ANSWER_MAX_CHANNEL))
                )
                .is_ok(),
            "{via:?}: 65,536 is taken"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_over_answer_max_is_answer_too_large() {
    let duo = duo(false).await;
    let mut small = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    small.answer_max = 10;
    let told = by_hand(&duo, "/world/x", small.clone(), answered("eleven bytes")).await;
    assert_eq!(
        *one_failure(&told),
        QueryError::AnswerTooLarge { size: 12, max: 10 }
    );
    let told = by_hand(&duo, "/world/x", small, answered("ten bytes!")).await;
    assert_eq!(
        one_answer(&told).0.bytes.len(),
        10,
        "at the limit it is told"
    );
}

// -- Outcomes ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_status_is_the_outcome_the_signed_path_gives() {
    let duo = duo(false).await;
    let channel = || ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    let told = by_hand(
        &duo,
        "/world/x",
        channel(),
        ChanStatus::refused(7, "not for you"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert!(got.bytes.is_empty());
    let refusal = answered_by.refusal.as_ref().expect("a refusal");
    assert_eq!((refusal.code, refusal.text.as_str()), (7, "not for you"));
    assert_eq!(
        ended(&told),
        &done(1, 0, 1, 0, 0),
        "counted refused, not failed"
    );
    let told = by_hand(
        &duo,
        "/world/x",
        channel(),
        ChanStatus::Busy { retry_ms: 500 },
    )
    .await;
    assert_eq!(*one_failure(&told), QueryError::Busy);
    let told = by_hand(&duo, "/world/x", channel(), ChanStatus::NotServed).await;
    assert_eq!(
        *one_failure(&told),
        QueryError::NotServed {
            path: n("/world/x")
        }
    );
    let told = by_hand(
        &duo,
        "/world/x",
        channel(),
        ChanStatus::TooLarge { max: 99 },
    )
    .await;
    assert!(matches!(
        one_failure(&told),
        QueryError::TooLarge { max: 99, .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn asked_equals_answered_refused_failed_silent_on_the_channel_path() {
    let names = [
        "/alice/laptop",
        "/bob/phone",
        "/carol/phone",
        "/erin/phone",
        "/frank/phone",
    ];
    let rig = rig::rig(&names).await;
    for node in &rig.nodes {
        node.attach_forwarder().unwrap();
    }
    let _alice = rig::public(&rig, &["/bob", "/carol", "/erin", "/frank"]).await;
    let bob = heap_of(&rig.nodes[1]);
    rig.taps[1].swallow_queries(true);
    let servers = [
        "/alice/laptop",
        "/carol/phone",
        "/erin/phone",
        "/frank/phone",
    ];
    let mut query = ask(QueryPath::Channel, &servers, b"q");
    query.deadline = Duration::from_millis(2500);
    let reading = asked(&bob, "/world/x", query);
    let answering = async {
        // One QUERY for each server: the route says which.
        eventually("four QUERY frames", || rig.taps[1].queries().len() == 4).await;
        let asker = &rig.nodes[1];
        for frame in rig.taps[1].queries() {
            let (head, _) = QueryHeader::parse(&frame).unwrap();
            let server = asker
                .inner
                .chan
                .sessions
                .get(head.route)
                .unwrap()
                .sender()
                .clone();
            let status = match server.to_string().as_str() {
                "/alice/laptop" => Some(answered("yes")),
                "/carol/phone" => Some(ChanStatus::refused(3, "no")),
                "/erin/phone" => Some(ChanStatus::Busy { retry_ms: 1 }),
                _ => None, // frank is silent
            };
            if let Some(status) = status {
                asker
                    .inner
                    .query_answer_frame(answer_frame(asker, &frame, &status));
            }
        }
    };
    let (told, ()) = tokio::join!(reading, answering);
    assert_eq!(
        told.len(),
        4,
        "one answer, one refusal, one failure and the end: {told:?}"
    );
    let end = told.last().unwrap();
    assert_eq!(*end, Err(done(4, 1, 1, 1, 1)));
    let GetNotice::AnswersDone {
        asked,
        answered,
        refused,
        failed,
        silent,
        ..
    } = end.as_ref().unwrap_err().clone()
    else {
        unreachable!()
    };
    assert_eq!(asked, answered + refused + failed + silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_servers_answer_with_different_pairs_and_tokens() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    for node in &rig.nodes {
        node.attach_forwarder().unwrap();
    }
    let _alice = rig::public(&rig, &["/bob", "/carol"]).await;
    let bob = heap_of(&rig.nodes[1]);
    rig.taps[1].swallow_queries(true);
    let reading = asked(
        &bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop", "/carol/phone"], b"q"),
    );
    let answering = async {
        eventually("two QUERY frames", || rig.taps[1].queries().len() == 2).await;
        let queries = rig.taps[1].queries();
        let heads: Vec<_> = queries
            .iter()
            .map(|f| QueryHeader::parse(f).unwrap().0)
            .collect();
        assert_ne!(heads[0].pair, heads[1].pair, "two servers, two pairs");
        assert_ne!(heads[0].route, heads[1].route, "two channels");
        assert_ne!(heads[0].token, heads[1].token, "a token for each");
        assert_eq!(
            (heads[0].qseq, heads[1].qseq),
            (0, 0),
            "a counter for each pair"
        );
        let asker = &rig.nodes[1];
        // An answer sealed under the other server's pair, for this token, does not open.
        let (first, second) = (&heads[0], &heads[1]);
        let other_pair = asker.inner.chan.ask_pairs.get(second.route).unwrap();
        asker
            .inner
            .query_answer_frame(answer_under(&other_pair, first, &answered("crossed")));
        for (frame, head) in queries.iter().zip(&heads) {
            if head.route == second.route {
                asker
                    .inner
                    .query_answer_frame(answer_frame(asker, frame, &answered("two")));
            }
        }
    };
    let (told, ()) = tokio::join!(reading, answering);
    // One answer, one failure (the crossed one did not open), nothing else.
    let answers: Vec<&Got> = told.iter().filter_map(|t| t.as_ref().ok()).collect();
    assert_eq!(answers.len(), 1, "{told:?}");
    assert_eq!(answers[0].bytes.as_ref(), b"two");
    assert!(
        told.iter().any(|t| matches!(
            t,
            Err(GetNotice::QueryFailed {
                why: QueryError::BadAnswer { .. },
                ..
            })
        )),
        "the crossed answer is a bad answer: {told:?}"
    );
}

// -- On a real server --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_warm_session_carries_many_queries_to_a_real_server_with_no_signature() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("echo:", &runs)).unwrap();
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Channel, &["/alice/laptop"], b"0"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(
        (got.bytes.as_ref(), answered_by.via),
        (&b"echo:0"[..], Via::Sealed)
    );
    let (bob_signed, alice_signed) = (duo.bob_node().signatures(), duo.alice_node().signatures());
    let asks = duo.alice_node().inner.chan.stats.asks.get();
    for i in 1..=5 {
        let q = format!("{i}");
        let told = asked(
            &duo.bob,
            "/world/a",
            ask(QueryPath::Auto, &["/alice/laptop"], q.as_bytes()),
        )
        .await;
        let (got, answered_by) = one_answer(&told);
        assert_eq!(got.bytes.as_ref(), format!("echo:{i}").as_bytes());
        assert_eq!(answered_by.via, Via::Sealed, "Auto uses the warm session");
        assert_eq!(got.author.writer, alice());
        assert_eq!(got.author.by, n("/alice"));
    }
    assert_eq!(
        runs.load(Ordering::SeqCst),
        6,
        "the handler ran once for each query"
    );
    assert_eq!(
        duo.bob_node().signatures(),
        bob_signed,
        "no query was signed"
    );
    assert_eq!(duo.alice_node().signatures(), alice_signed);
    assert_eq!(
        duo.alice_node().inner.chan.stats.asks.get(),
        asks,
        "no ask was judged"
    );
    // Nothing survives an answer, at the asker.
    assert_eq!(duo.bob_node().inner.query.ask.chan.pending(), 0);
    assert_eq!(duo.bob_node().inner.query.ask.pending.lock().total(), 0);
    // One counter taken once each: six queries, the numbers 0 to 5.
    let seqs: Vec<u64> = duo
        .tap()
        .queries()
        .iter()
        .map(|f| QueryHeader::parse(f).unwrap().0.qseq)
        .collect();
    assert_eq!(seqs, [0, 1, 2, 3, 4, 5]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_server_is_found_out_by_silence_and_the_fourth_query_works() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("echo:", &runs)).unwrap();
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Channel, &["/alice/laptop"], b"0"),
    )
    .await;
    one_answer(&told);
    let first = QueryHeader::parse(&duo.tap().queries()[0]).unwrap().0;
    // The server forgets every pair, as a restart does.
    duo.alice_node().inner.chan.pairs.drop_all();
    let mut quick = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    quick.deadline = Duration::from_millis(600);
    for i in 0..3 {
        let told = asked(&duo.bob, "/world/a", quick.clone()).await;
        assert!(
            matches!(&told[..], [Err(end)] if *end == done(1, 0, 0, 0, 1)),
            "query {i} is silent: {told:?}"
        );
    }
    assert!(
        held(duo.bob_node(), &alice()).is_none(),
        "the session is let go"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "no handler ran for a forgotten pair"
    );
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Channel, &["/alice/laptop"], b"4"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(got.bytes.as_ref(), b"echo:4");
    assert_eq!(answered_by.via, Via::Sealed);
    let last = QueryHeader::parse(&duo.tap().queries()[4]).unwrap().0;
    assert_ne!(last.pair, first.pair, "a new pair");
    assert_eq!(last.qseq, 0, "a counter from 0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_real_servers_answer_one_query_each_over_their_own_pairs() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    for node in &rig.nodes {
        node.attach_forwarder().unwrap();
    }
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let runs = Arc::new(AtomicUsize::new(0));
    let _a = alice_heap
        .serve(n("/world"), echo("alice:", &runs))
        .unwrap();
    let _c = carol.serve(n("/world"), echo("carol:", &runs)).unwrap();
    let told = asked(
        &bob,
        "/world/x",
        ask(
            QueryPath::Channel,
            &["/alice/laptop", "/carol/phone"],
            b"hi",
        ),
    )
    .await;
    let mut texts: Vec<String> = told
        .iter()
        .filter_map(|t| t.as_ref().ok())
        .map(|g| String::from_utf8_lossy(&g.bytes).into_owned())
        .collect();
    texts.sort();
    assert_eq!(texts, ["alice:hi", "carol:hi"]);
    assert_eq!(ended(&told), &done(2, 2, 0, 0, 0));
    let queries = rig.taps[1].queries();
    let heads: Vec<_> = queries
        .iter()
        .map(|f| QueryHeader::parse(f).unwrap().0)
        .collect();
    assert_eq!(heads.len(), 2);
    assert_ne!(heads[0].pair, heads[1].pair, "two servers, two pairs");
    assert_ne!(heads[0].token, heads[1].token);
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_not_served_path_and_a_pass_on_a_real_server() {
    let duo = duo(false).await;
    let _serving = duo
        .alice
        .serve(n("/world"), |q: Query| async move {
            match q.bytes.as_ref() {
                b"refuse" => Reply::refuse(9, "not today"),
                b"pass" => Reply::Pass,
                _ => Reply::Answer(Bytes::from_static(b"ok")),
            }
        })
        .unwrap();
    let mut quick = ask(QueryPath::Channel, &["/alice/laptop"], b"refuse");
    quick.deadline = Duration::from_secs(2);
    let told = asked(&duo.bob, "/world/x", quick.clone()).await;
    let (_, answered_by) = one_answer(&told);
    assert_eq!(answered_by.refusal.as_ref().map(|r| r.code), Some(9));
    assert_eq!(ended(&told), &done(1, 0, 1, 0, 0));
    let told = asked(
        &duo.bob,
        "/elsewhere/x",
        Ask {
            query: Bytes::from_static(b"ok"),
            ..quick.clone()
        },
    )
    .await;
    assert!(matches!(one_failure(&told), QueryError::NotServed { .. }));
    quick.query = Bytes::from_static(b"pass");
    quick.deadline = Duration::from_millis(500);
    let told = asked(&duo.bob, "/world/x", quick).await;
    assert!(
        matches!(&told[..], [Err(end)] if *end == done(1, 0, 0, 0, 1)),
        "a pass sends nothing: {told:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handler_is_given_the_query_id_of_the_get_on_the_channel_path() {
    let rig = rig::rig(&["/alice/laptop", "/bob/phone", "/carol/phone"]).await;
    for node in &rig.nodes {
        node.attach_forwarder().unwrap();
    }
    let alice_heap = rig::public(&rig, &["/bob", "/carol"]).await;
    let (bob, carol) = (heap_of(&rig.nodes[1]), heap_of(&rig.nodes[2]));
    let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let recorder = |seen: &Arc<parking_lot::Mutex<Vec<(super::types::QueryId, Via)>>>| {
        let seen = Arc::clone(seen);
        move |q: Query| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock().push((q.id, q.via));
                Reply::Answer(Bytes::from_static(b"ok"))
            }
        }
    };
    let _a = alice_heap.serve(n("/world"), recorder(&seen)).unwrap();
    let _c = carol.serve(n("/world"), recorder(&seen)).unwrap();
    let told = asked(
        &bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop", "/carol/phone"], b"q"),
    )
    .await;
    let ids: Vec<_> = told
        .iter()
        .filter_map(|t| t.as_ref().ok())
        .map(|got| match &got.kind {
            Kind::Answered(a) => a.query,
            other => panic!("an answer: {other:?}"),
        })
        .collect();
    assert_eq!(ids.len(), 2, "both servers answered: {told:?}");
    assert_eq!(ids[0], ids[1], "one id for every server of one get");
    let heard = seen.lock().clone();
    assert_eq!(heard.len(), 2, "each handler ran once");
    for (id, via) in &heard {
        assert_eq!(*id, ids[0], "the handler is given the id of the get");
        assert_eq!(*via, Via::Sealed);
    }
    // A second get is a new query with its own id.
    let told = asked(
        &bob,
        "/world/x",
        ask(QueryPath::Channel, &["/alice/laptop"], b"q"),
    )
    .await;
    let (_, again) = one_answer(&told);
    assert_ne!(again.query, ids[0]);
    assert_eq!(seen.lock().last().map(|(id, _)| *id), Some(again.query));
}

// -- Gate review ------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_dropped_frames_do_not_silently_move_auto_to_the_signed_path() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("echo:", &runs)).unwrap();
    warm(&duo, &alice()).await;
    let first = held(duo.bob_node(), &alice()).expect("held");
    let first_pair = duo.bob_node().inner.chan.ask_pairs.get(first).unwrap().id();

    // A relay drops three queries of the pair: the asker lets the session go.
    duo.tap().swallow_queries(true);
    let mut quick = ask(QueryPath::Auto, &["/alice/laptop"], b"q");
    quick.deadline = Duration::from_millis(400);
    for i in 0..3 {
        let told = asked(&duo.bob, "/world/a", quick.clone()).await;
        assert!(
            matches!(&told[..], [Err(end)] if *end == done(1, 0, 0, 0, 1)),
            "query {i} is silent: {told:?}"
        );
    }
    assert!(
        held(duo.bob_node(), &alice()).is_none(),
        "three in a row: the session is let go"
    );
    assert_eq!(duo.tap().queries().len(), 3);

    // The next `Auto` query is not sent in the clear because of that: it asks once more for a
    // session, inside its deadline, and goes sealed.
    duo.tap().swallow_queries(false);
    let asked_before = duo.bob_node().inner.chan.stats.asked.get();
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Auto, &["/alice/laptop"], b"4"),
    )
    .await;
    let (got, answered_by) = one_answer(&told);
    assert_eq!(
        answered_by.via,
        Via::Sealed,
        "after a silence release `Auto` went to the signed path (a public space's query in the \
         clear) without trying the channel again"
    );
    assert_eq!(got.bytes.as_ref(), b"echo:4");
    assert_eq!(
        duo.bob_node().inner.chan.stats.asked.get(),
        asked_before + 1,
        "one setup"
    );
    let now = held(duo.bob_node(), &alice()).expect("a session is held again");
    let new_pair = duo.bob_node().inner.chan.ask_pairs.get(now).unwrap().id();
    assert_ne!(new_pair, first_pair, "a new pair, from a new setup");

    // The setup was owed once: with the session let go for being idle, `Auto` is signed again.
    let session = duo.bob_node().inner.chan.sessions.get(now).unwrap();
    duo.bob_node().inner.chan_let_go(&session);
    duo.bob_node().inner.chan.ask_pairs.remove(now);
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Auto, &["/alice/laptop"], b"5"),
    )
    .await;
    assert_eq!(one_answer(&told).1.via, Via::Signed);
    assert!(held(duo.bob_node(), &alice()).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_sent_before_an_answer_are_no_evidence_that_the_server_forgot_the_pair() {
    let duo = duo(false).await;
    warm(&duo, &alice()).await;
    // Four queries are in flight on the pair; the server answers the last (the others hit a limit
    // or a `Pass`, or a relay lost them): the pair is plainly held.
    duo.tap().swallow_queries(true);
    let mut slow = ask(QueryPath::Channel, &["/alice/laptop"], b"q");
    slow.deadline = Duration::from_millis(700);
    let reading = async {
        tokio::join!(
            asked(&duo.bob, "/world/x", slow.clone()),
            asked(&duo.bob, "/world/x", slow.clone()),
            asked(&duo.bob, "/world/x", slow.clone()),
            asked(&duo.bob, "/world/x", slow.clone()),
        )
    };
    let answering = async {
        let last = query_after(duo.tap(), 3).await;
        duo.bob_node().inner.query_answer_frame(answer_frame(
            duo.bob_node(),
            &last,
            &answered("the last"),
        ));
    };
    let ((a, b, c, d), ()) = tokio::join!(reading, answering);
    let told = [a, b, c, d];
    let silent = told
        .iter()
        .filter(|t| matches!(&t[..], [Err(end)] if *end == done(1, 0, 0, 0, 1)))
        .count();
    let answered_ones = told
        .iter()
        .filter(|t| matches!(&t[..], [Ok(_), Err(end)] if *end == done(1, 1, 0, 0, 0)))
        .count();
    assert_eq!((silent, answered_ones), (3, 1), "{told:?}");
    assert!(
        held(duo.bob_node(), &alice()).is_some(),
        "three silent queries sent before an answer did not release a pair the server answered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_suspected_server_is_no_server_at_the_askers_next_channel_query() {
    let duo = duo(false).await;
    let runs = Arc::new(AtomicUsize::new(0));
    let _serving = duo.alice.serve(n("/world"), echo("echo:", &runs)).unwrap();
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Channel, &["/alice/laptop"], b"1"),
    )
    .await;
    one_answer(&told);

    // Bob's node marks the server's key suspected: whatever the channel brings under that session
    // is not the server's, as the signed path would say.
    duo.bob_node()
        .suspect(duo.alice_node().writer(), crate::error::Timestamp(1))
        .unwrap();
    let told = asked(
        &duo.bob,
        "/world/a",
        ask(QueryPath::Channel, &["/alice/laptop"], b"2"),
    )
    .await;
    assert!(
        told.iter().all(|t| t.is_err()),
        "a suspected server answered: {told:?}"
    );
    assert!(
        matches!(
            one_failure(&told),
            QueryError::BadAnswer { .. } | QueryError::NoSession { .. }
        ),
        "{told:?}"
    );
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "a query was sent to a server this node marks suspected, and its handler ran"
    );
}
