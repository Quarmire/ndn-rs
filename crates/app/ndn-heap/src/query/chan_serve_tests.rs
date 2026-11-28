//! The server's half of the channel path through real nodes (docs/specs/query.md, the channel
//! path): a `QUERY` frame is judged cheapest first, answered once under the pair's key or dropped
//! with a counter, and nothing a handler answers is kept.
//!
//! The asker is a real node that made a real `Ask` session (`chan_ask`), so the pair the server
//! holds is the one its own session answer made; the queries are built by hand from the asker's
//! half of that pair and handed to `query_frame` as the forwarder's app face would, and every
//! frame the server sends is read from a [`Link`] attached as its carrier.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::FaceId;
use ndn_transport::{SideClass, SideKind};
use tokio::sync::Semaphore;

use super::rig::{Rig, eventually, public, rig, sealed};
use super::serve::{HANDLERS_MAX, PERSON_BURST, PERSON_INFLIGHT};
use super::{Handler, Query, QueryId, Reply, Serving, Via};
use crate::chan::aead::{Aead, FrameCipher};
use crate::chan::carrier_kit::{Link, LinkConfig};
use crate::chan::frame::Header;
use crate::chan::pair::{AskPair, PairOwner, PairStats, ServerPair, nonce};
use crate::chan::qframe::{
    ANSWER_HEADER_LEN, ANSWER_OVERHEAD, AnswerHeader, ChanStatus, QUERY_HEADER_LEN, QueryHeader,
    QueryPlain,
};
use crate::chan::wire::ChannelMode;
use crate::node::Node;
use crate::node::tests::space;
use crate::rt::Instant;
use crate::space::{Heap, MembersChange};
use crate::test_kit::n;

// -- Handlers ----------------------------------------------------------------------------------

/// What the handlers saw.
#[derive(Default)]
struct Seen {
    queries: Mutex<Vec<Query>>,
}

impl Seen {
    fn count(&self) -> usize {
        self.queries.lock().unwrap().len()
    }
}

/// Answers the octets it was asked, and keeps the query.
fn echo(seen: &Arc<Seen>) -> impl Handler {
    let seen = Arc::clone(seen);
    move |q: Query| {
        let bytes = q.bytes.clone();
        seen.queries.lock().unwrap().push(q);
        async move { Reply::Answer(bytes) }
    }
}

/// Holds every query until `gate` has a permit, counting the ones started.
fn held(started: &Arc<AtomicUsize>, gate: &Arc<Semaphore>) -> impl Handler {
    let (started, gate) = (Arc::clone(started), Arc::clone(gate));
    move |_q: Query| {
        started.fetch_add(1, Ordering::SeqCst);
        let gate = Arc::clone(&gate);
        async move {
            gate.acquire().await.unwrap().forget();
            Reply::Answer(Bytes::from_static(b"released"))
        }
    }
}

/// Answers by what the query's octets say: `pass`, `refuse`, `late` (a second after the asker's
/// deadline) or a run of `len` octets (`big:N`).
fn by_word(ran: &Arc<AtomicUsize>) -> impl Handler {
    let ran = Arc::clone(ran);
    move |q: Query| {
        ran.fetch_add(1, Ordering::SeqCst);
        let word = String::from_utf8_lossy(&q.bytes).to_string();
        async move {
            if word == "pass" {
                Reply::Pass
            } else if word == "refuse" {
                Reply::refuse(7, "no, and here is why")
            } else if word == "late" {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Reply::Answer(Bytes::from_static(b"too late"))
            } else if let Some(len) = word.strip_prefix("big:") {
                Reply::Answer(Bytes::from(vec![0x5a; len.parse().unwrap()]))
            } else {
                Reply::Answer(Bytes::from(word))
            }
        }
    }
}

// -- The bed -----------------------------------------------------------------------------------

/// Alice (the owner, the server, a carrier that is a [`Link`] this test reads), bob and carol
/// (askers, writers of the space).
struct Bed {
    rig: Rig,
    heap: Heap,
    link: Arc<Link>,
    _serving: Serving,
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Public,
    /// Bob writes, carol reads.
    Sealed,
}

impl Bed {
    async fn new(kind: Kind, link: LinkConfig, handler: impl Handler) -> Bed {
        let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
        let heap = match kind {
            Kind::Public => public(&rig, &["/bob", "/carol"]).await,
            Kind::Sealed => sealed(&rig, &["/bob"], &["/carol"]).await,
        };
        let link = Link::new(link);
        rig.nodes[0].attach_carrier(link.clone());
        let serving = heap.serve(n("/game"), handler).unwrap();
        Bed {
            rig,
            heap,
            link,
            _serving: serving,
        }
    }

    fn alice(&self) -> &Node {
        &self.rig.nodes[0]
    }
    fn bob(&self) -> &Node {
        &self.rig.nodes[1]
    }
    fn carol(&self) -> &Node {
        &self.rig.nodes[2]
    }
    fn stats(&self) -> &PairStats {
        &self.alice().inner.chan.pairs.stats
    }

    /// `from`'s `Ask` session with alice, and the pair it holds for it.
    async fn pair(&self, from: &Node) -> Arc<AskPair> {
        let session = from
            .inner
            .chan_ask(&space(), self.alice().name(), ChannelMode::Ask)
            .await
            .expect("the ask is answered");
        from.inner
            .chan
            .ask_pairs
            .get(session.id())
            .expect("the asker holds a pair")
    }

    /// Hand `frame` to alice as her forwarder does.
    fn send(&self, frame: Bytes) {
        self.alice().inner.query_frame(frame, FaceId(0));
    }

    /// The answers alice sent so far: (frame, on the stream).
    fn sent(&self) -> Vec<(Bytes, bool)> {
        let mut out: Vec<(Bytes, bool)> = self
            .link
            .take_datagrams()
            .into_iter()
            .map(|f| (f, false))
            .collect();
        out.extend(self.link.take_stream().into_iter().map(|f| (f, true)));
        out.into_iter().filter(|(f, _)| f[1] & 0x0f == 6).collect()
    }

    /// Exactly `want` answers within 10 s (no more, after a moment more).
    async fn answers(&self, want: usize) -> Vec<(Bytes, bool)> {
        let mut got = Vec::new();
        for _ in 0..200 {
            got.extend(self.sent());
            if got.len() >= want {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        got.extend(self.sent());
        assert_eq!(got.len(), want, "the answers alice sent");
        got
    }

    async fn silence(&self) {
        self.answers(0).await;
    }
}

/// How many frames of every kind of drop the server counted.
fn dropped(s: &PairStats) -> u64 {
    [
        &s.malformed,
        &s.unknown_pair,
        &s.replayed,
        &s.rejudged_out,
        &s.bad_seal,
        &s.bad_plain,
    ]
    .iter()
    .map(|c| c.get())
    .sum()
}

// -- Frames by hand ----------------------------------------------------------------------------

fn plain(path: &str, bytes: &[u8]) -> QueryPlain {
    QueryPlain {
        id: 0x1d,
        deadline_ms: 3000,
        path: n(path),
        bytes: Bytes::copy_from_slice(bytes),
    }
}

fn header(pair: &AskPair, token: u64, qseq: u64) -> QueryHeader {
    QueryHeader {
        route: pair.channel,
        token,
        ttl_ticks: 30,
        pair: pair.id(),
        qseq,
        epoch: pair.epoch(),
    }
}

fn join(header: &QueryHeader, sealed: &[u8]) -> Bytes {
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(sealed);
    Bytes::from(frame)
}

/// A genuine `QUERY` of `pair`: sealed under `Kq`, the header as the additional data.
fn query(pair: &AskPair, qseq: u64, token: u64, plain: &QueryPlain) -> Bytes {
    let head = header(pair, token, qseq);
    let sealed = pair.ciphers().seal_query(
        head.epoch,
        qseq,
        &head.encode(),
        &plain.encode().expect("a query"),
    );
    join(&head, &sealed)
}

/// The simplest genuine query: `/game/x` asking `bytes`.
fn ask(pair: &AskPair, qseq: u64, bytes: &[u8]) -> Bytes {
    query(pair, qseq, 1_000 + qseq, &plain("/game/x", bytes))
}

/// The token of [`ask`]'s query `qseq`.
fn token(qseq: u64) -> u64 {
    1_000 + qseq
}

/// What an answer says, opened as the asker does under `Ka` with the query's counter.
fn open(pair: &AskPair, frame: &Bytes, qseq: u64) -> Option<(AnswerHeader, ChanStatus)> {
    let (head, sealed) = AnswerHeader::parse(frame).ok()?;
    let plain =
        pair.ciphers()
            .open_answer(head.epoch, qseq, &frame[..ANSWER_HEADER_LEN], sealed)?;
    Some((head, ChanStatus::decode(&plain).ok()?))
}

fn answered(bytes: &[u8]) -> ChanStatus {
    ChanStatus::Answered(Bytes::copy_from_slice(bytes))
}

fn seal_under(cipher: &FrameCipher, epoch: u8, qseq: u64, aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    let tag = cipher.seal_detached(nonce(epoch, qseq), aad, &mut buf);
    buf.extend_from_slice(&tag);
    buf
}

fn in_game(from: &Node, device: &Node) -> bool {
    from.inner.chan.pairs.has(&space(), device.name())
}

/// The fold version of `node`'s copy of the space.
fn fold_version(node: &Node) -> u64 {
    node.inner
        .space_of(&space())
        .unwrap()
        .log
        .lock()
        .fold
        .version()
        .load(Ordering::SeqCst)
}

/// `node`'s keyring adopts version 2 of `person`'s trust context, which revokes `key`.
fn revoke_at(node: &Node, person: &Name, key: &Name) {
    let validator = &node.inner.judge.validator;
    let held = validator
        .keyring()
        .contexts()
        .into_iter()
        .find(|c| c.namespace() == person)
        .expect("the namespace's context");
    let next = ndn_security::SignedTrustContext::hierarchical(person.clone())
        .with_version(2)
        .with_revocation(key.clone());
    for anchor in held.anchors().iter() {
        next.add_anchor(anchor.value().clone());
    }
    validator
        .keyring()
        .adopt_update(Arc::new(next))
        .expect("adopted");
}

// -- What a query costs before it is opened -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_from_an_unknown_pair_id_costs_no_aead() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();

    // A pair id the server never made, however well the rest is sealed.
    let mut head = header(&pair, 1, 0);
    head.pair = [0x77; 8];
    let sealed = pair.ciphers().seal_query(
        head.epoch,
        0,
        &head.encode(),
        &plain("/game/x", b"q").encode().unwrap(),
    );
    let (opens, drops) = (s.opens.get(), s.unknown_pair.get());
    bed.send(join(&head, &sealed));
    assert_eq!(
        s.opens.get(),
        opens,
        "no AEAD is tried for a pair id nobody holds"
    );
    assert_eq!(s.unknown_pair.get(), drops + 1);
    bed.silence().await;
    assert_eq!(seen.count(), 0);

    // The pair's own id, on another route: the same.
    let mut head = header(&pair, 2, 0);
    head.route ^= 1;
    let sealed = pair.ciphers().seal_query(
        head.epoch,
        0,
        &head.encode(),
        &plain("/game/x", b"q").encode().unwrap(),
    );
    bed.send(join(&head, &sealed));
    assert_eq!(
        s.opens.get(),
        opens,
        "nor for a route that is not the pair's channel"
    );
    assert_eq!(s.unknown_pair.get(), drops + 2);

    // A genuine one is opened (one AEAD) and answered.
    bed.send(ask(&pair, 0, b"real"));
    let got = bed.answers(1).await;
    assert_eq!(s.opens.get(), opens + 1);
    assert_eq!(open(&pair, &got[0].0, 0).unwrap().1, answered(b"real"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flipped_octet_in_any_header_field_or_body_fails_the_aead() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();
    let genuine = ask(&pair, 0, b"hello");

    let mut cases: Vec<usize> = (0..QUERY_HEADER_LEN).collect();
    // The first and the middle octet of the sealed body, and the last octet of its tag.
    cases.extend([QUERY_HEADER_LEN, QUERY_HEADER_LEN + 3, genuine.len() - 1]);
    for at in cases {
        let mut forged = genuine.to_vec();
        forged[at] ^= 0x01;
        let (drops, opens, bad) = (dropped(s), s.opens.get(), s.bad_seal.get());
        bed.send(Bytes::from(forged));
        assert_eq!(
            dropped(s),
            drops + 1,
            "octet {at}: the frame is dropped and counted once"
        );
        let reaches_the_aead = (10..=18).contains(&at) || at == 34 || at >= QUERY_HEADER_LEN;
        if reaches_the_aead {
            assert_eq!(
                s.bad_seal.get(),
                bad + 1,
                "octet {at}: the tag does not verify"
            );
            assert_eq!(s.opens.get(), opens + 1, "octet {at}: one AEAD");
        }
        if at <= 9 || (19..=26).contains(&at) || at == 35 {
            assert_eq!(s.opens.get(), opens, "octet {at}: judged before any AEAD");
        }
    }
    bed.silence().await;
    assert_eq!(seen.count(), 0, "no forged frame reached the handler");

    // None of it burnt the counter: the genuine frame is answered.
    bed.send(genuine);
    let got = bed.answers(1).await;
    assert_eq!(open(&pair, &got[0].0, 0).unwrap().1, answered(b"hello"));
    assert_eq!(seen.count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_sealed_under_the_channel_key_is_not_accepted() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let session = bed
        .bob()
        .inner
        .chan_ask(&space(), bed.alice().name(), ChannelMode::Ask)
        .await
        .unwrap();
    let pair = bed.bob().inner.chan.ask_pairs.get(session.id()).unwrap();
    let s = bed.stats();

    // The key every asker of the channel holds (the one data frames are sealed under), carol's as
    // much as bob's: a query sealed under it proves "a holder of the key", never which asker.
    let (frame_key, _) = session
        .frame_key_epoch(pair.epoch(), Instant::now())
        .expect("the session holds its key");
    let channel_cipher = FrameCipher::from_key_octets(frame_key.expose(), Aead::Aes256Gcm);
    let head = header(&pair, 9, 0);
    let body = plain("/game/x", b"as a channel member").encode().unwrap();
    let sealed = seal_under(&channel_cipher, head.epoch, 0, &head.encode(), &body);
    let (opens, bad) = (s.opens.get(), s.bad_seal.get());
    bed.send(join(&head, &sealed));
    assert_eq!(
        (s.opens.get(), s.bad_seal.get()),
        (opens + 1, bad + 1),
        "tried once under Kq and refused"
    );

    // And a query sealed under Ka (the server's own direction) is no query either.
    let sealed = pair
        .ciphers()
        .seal_answer(head.epoch, 0, &head.encode(), &body);
    bed.send(join(&head, &sealed));
    assert_eq!(s.bad_seal.get(), bad + 2, "Ka opens no query");

    bed.silence().await;
    assert_eq!(seen.count(), 0);
    // The counter 0 is not burnt by either: the genuine query is answered.
    bed.send(ask(&pair, 0, b"mine"));
    assert_eq!(
        open(&pair, &bed.answers(1).await[0].0, 0).unwrap().1,
        answered(b"mine")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_qseq_is_dropped_and_marked_only_after_the_aead() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();

    // A forged frame with a genuine qseq does not burn it.
    let genuine = ask(&pair, 5, b"five");
    let mut forged = genuine.to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 0x80;
    bed.send(Bytes::from(forged));
    assert_eq!(s.bad_seal.get(), 1);
    assert_eq!(s.replayed.get(), 0, "the forgery marked nothing");
    bed.silence().await;

    // The genuine frame runs the handler once and is answered once.
    bed.send(genuine.clone());
    let got = bed.answers(1).await;
    assert_eq!(open(&pair, &got[0].0, 5).unwrap().1, answered(b"five"));
    assert_eq!(seen.count(), 1);

    // A copy of it, and a copy that changed only what is not sealed (the token is in the
    // additional data, so that one fails the AEAD instead): neither runs it again.
    let opens = s.opens.get();
    bed.send(genuine.clone());
    assert_eq!(s.replayed.get(), 1, "the copy is dropped before the AEAD");
    assert_eq!(s.opens.get(), opens);
    bed.send(genuine);
    assert_eq!(s.replayed.get(), 2);
    bed.silence().await;
    assert_eq!(seen.count(), 1, "the handler ran once");

    // A lower counter that was never used is still fresh: counters need not arrive in order.
    bed.send(ask(&pair, 3, b"three"));
    assert_eq!(
        open(&pair, &bed.answers(1).await[0].0, 3).unwrap().1,
        answered(b"three")
    );
    assert_eq!(seen.count(), 2);
}

// -- The asker stands, or the pair is gone ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_asker_is_dropped_at_the_generation_move_before_open() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    // The maintenance pass would drop the pair on its own; the server's per-query check is
    // what this case is about.
    bed.alice()
        .inner
        .chan
        .tick_paused
        .store(true, Ordering::SeqCst);
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();
    bed.send(ask(&pair, 0, b"while a member"));
    assert_eq!(
        open(&pair, &bed.answers(1).await[0].0, 0).unwrap().1,
        answered(b"while a member")
    );

    let before = fold_version(bed.alice());
    bed.heap
        .change(MembersChange {
            remove: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("alice's fold moved", || fold_version(bed.alice()) != before).await;
    assert!(
        in_game(bed.alice(), bed.bob()),
        "nothing dropped the pair yet"
    );

    let (opens, ran) = (s.opens.get(), seen.count());
    bed.send(ask(&pair, 1, b"after the removal"));
    assert_eq!(
        s.opens.get(),
        opens,
        "the generation moved: judged before any AEAD"
    );
    assert_eq!(s.rejudged_out.get(), 1);
    assert!(!in_game(bed.alice(), bed.bob()), "and the pair is gone");
    bed.silence().await;
    assert_eq!(seen.count(), ran, "no handler ran");

    // Her next query finds no pair at all.
    bed.send(ask(&pair, 2, b"again"));
    assert_eq!(s.unknown_pair.get(), 1);
    assert_eq!(s.opens.get(), opens);
    bed.silence().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removal_revocation_and_a_sealed_space_audience_move_drop_the_pair_at_once() {
    // A public space: a person's removal, and a key's revocation with no change of members.
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let (bob, carol) = (bed.pair(bed.bob()).await, bed.pair(bed.carol()).await);
    let alice = bed.alice();
    assert!(in_game(alice, bed.bob()) && in_game(alice, bed.carol()));

    bed.heap
        .change(MembersChange {
            remove: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("bob's pair is dropped by the removal", || {
        !in_game(alice, bed.bob())
    })
    .await;
    assert!(in_game(alice, bed.carol()), "carol still stands");
    bed.send(ask(&bob, 0, b"bob"));
    bed.silence().await;

    revoke_at(alice, &n("/carol"), bed.carol().writer());
    eventually("carol's pair is dropped by the revocation", || {
        !in_game(alice, bed.carol())
    })
    .await;
    bed.send(ask(&carol, 0, b"carol"));
    bed.silence().await;
    assert_eq!(seen.count(), 0, "neither ran a handler");
    drop(bed);

    // A sealed space: removing a reader moves the audience (a new epoch); she is out of it.
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Sealed, LinkConfig::default(), echo(&seen)).await;
    let (bob, carol) = (bed.pair(bed.bob()).await, bed.pair(bed.carol()).await);
    bed.send(ask(&carol, 0, b"as a reader"));
    assert_eq!(
        open(&carol, &bed.answers(1).await[0].0, 0).unwrap().1,
        answered(b"as a reader")
    );
    bed.heap
        .change(MembersChange {
            remove: vec![n("/carol")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol's pair is dropped by the audience move", || {
        !in_game(bed.alice(), bed.carol())
    })
    .await;
    bed.send(ask(&carol, 1, b"after"));
    bed.silence().await;
    assert_eq!(seen.count(), 1);
    // Bob, who writes, is untouched by her removal.
    bed.send(ask(&bob, 0, b"bob"));
    assert_eq!(
        open(&bob, &bed.answers(1).await[0].0, 0).unwrap().1,
        answered(b"bob")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_standing_members_pair_survives_another_members_removal() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Sealed, LinkConfig::default(), echo(&seen)).await;
    let bob = bed.pair(bed.bob()).await;
    bed.pair(bed.carol()).await;
    let before = bed.alice().inner.chan.pairs.count();
    assert_eq!(before, 2);
    let (bob_id, epoch) = (bob.id(), bob.key_epoch);

    // Removing carol writes a new epoch and re-keys what is re-keyed: nothing bob holds is, so
    // dropping his pair would only silence him.
    bed.heap
        .change(MembersChange {
            remove: vec![n("/carol")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol is dropped", || !in_game(bed.alice(), bed.carol())).await;
    assert!(in_game(bed.alice(), bed.bob()), "bob's pair stands");
    assert_eq!(bed.alice().inner.chan.pairs.count(), 1);

    // Bob's next query opens under the pair he holds and is answered; its keys are the same.
    bed.send(ask(&bob, 0, b"still here"));
    let got = bed.answers(1).await;
    let (head, status) = open(&bob, &got[0].0, 0).expect("opens under his pair");
    assert_eq!(status, answered(b"still here"));
    assert_eq!(
        (bob.id(), bob.key_epoch, head.epoch),
        (bob_id, epoch, epoch as u8)
    );
    assert_eq!(bed.stats().rejudged_out.get(), 0);
}

// -- One answer per query ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_answer_is_never_made_for_one_qseq_busy_included() {
    let (started, gate) = (Arc::new(AtomicUsize::new(0)), Arc::new(Semaphore::new(0)));
    let bed = Bed::new(Kind::Public, LinkConfig::default(), held(&started, &gate)).await;
    let pair = bed.pair(bed.bob()).await;
    let alice = bed.alice().inner.clone();

    // 100 copies of one frame, at once: the handler is started once.
    let frame = ask(&pair, 0, b"once");
    let barrier = Arc::new(tokio::sync::Barrier::new(100));
    let tasks: Vec<_> = (0..100)
        .map(|_| {
            let (alice, frame, barrier) = (alice.clone(), frame.clone(), Arc::clone(&barrier));
            tokio::spawn(async move {
                barrier.wait().await;
                alice.query_frame(frame, FaceId(0));
            })
        })
        .collect();
    for task in tasks {
        task.await.unwrap();
    }
    eventually("the handler started", || {
        started.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(
        bed.stats().replayed.get(),
        99,
        "the other copies were dropped"
    );

    // Fill the person's places; the ninth query is answered Busy, and a copy of it is not
    // answered again.
    for qseq in 1..PERSON_INFLIGHT as u64 {
        bed.send(ask(&pair, qseq, b"x"));
    }
    eventually("eight handlers run", || {
        started.load(Ordering::SeqCst) == PERSON_INFLIGHT
    })
    .await;
    let busy = ask(&pair, 20, b"busy");
    bed.send(busy.clone());
    let first = bed.answers(1).await;
    assert!(matches!(
        open(&pair, &first[0].0, 20).unwrap().1,
        ChanStatus::Busy { .. }
    ));
    bed.send(busy);
    bed.send(ask(&pair, 20, b"busy"));
    bed.silence().await;

    // A NotServed path: one sealed answer, and a copy of it none.
    let nowhere = query(&pair, 30, token(30), &plain("/nowhere", b"?"));
    gate.add_permits(PERSON_INFLIGHT);
    let mut every: Vec<(u64, Bytes)> = bed
        .answers(PERSON_INFLIGHT)
        .await
        .into_iter()
        .map(|(f, _)| (AnswerHeader::parse(&f).unwrap().0.token, f))
        .collect();
    bed.send(nowhere.clone());
    bed.send(nowhere);
    let got = bed.answers(1).await;
    assert_eq!(open(&pair, &got[0].0, 30).unwrap().1, ChanStatus::NotServed);
    every.extend(
        got.into_iter()
            .map(|(f, _)| (AnswerHeader::parse(&f).unwrap().0.token, f)),
    );
    every.extend(
        first
            .into_iter()
            .map(|(f, _)| (AnswerHeader::parse(&f).unwrap().0.token, f)),
    );

    // Nonce uniqueness: no two answers share a token, so none share (pair, qseq).
    let tokens: HashSet<u64> = every.iter().map(|(t, _)| *t).collect();
    assert_eq!(tokens.len(), every.len(), "one answer for each counter");
    assert_eq!(every.len(), PERSON_INFLIGHT + 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_servers_and_a_rekey_never_reuse_a_nonce() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let heap = public(&rig, &["/bob", "/carol"]).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let (seen_a, seen_b) = (Arc::new(Seen::default()), Arc::new(Seen::default()));
    let _a = heap.serve(n("/game"), echo(&seen_a)).unwrap();
    let _b = bob
        .space(&space())
        .unwrap()
        .serve(n("/game"), echo(&seen_b))
        .unwrap();
    let (link_a, link_b) = (
        Link::new(LinkConfig::default()),
        Link::new(LinkConfig::default()),
    );
    alice.attach_carrier(link_a.clone());
    bob.attach_carrier(link_b.clone());

    // Every (server, pair, nonce) an answer was sealed under, and the ciphertexts.
    let mut used: HashSet<(usize, [u8; 8], [u8; crate::chan::aead::NONCE_LEN])> = HashSet::new();
    let mut sealed_bodies: Vec<Vec<u8>> = Vec::new();
    let mut run = |server: usize, link: &Link, pair: &AskPair, from: u64, count: u64| {
        let node = &rig.nodes[server];
        for qseq in from..from + count {
            node.inner
                .query_frame(ask(pair, qseq, b"same octets"), FaceId(0));
        }
        let mut frames = Vec::new();
        for _ in 0..100 {
            frames.extend(link.take_datagrams());
            if frames.len() as u64 >= count {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(frames.len() as u64, count, "an answer for each query");
        for frame in frames {
            let (head, _) = AnswerHeader::parse(&frame).unwrap();
            let qseq = head.token - 1_000;
            assert!(open(pair, &frame, qseq).is_some());
            assert!(
                used.insert((server, pair.id(), nonce(head.epoch, qseq))),
                "server {server} pair {:?} nonce of qseq {qseq} used twice",
                pair.id()
            );
            sealed_bodies.push(frame[ANSWER_HEADER_LEN..].to_vec());
        }
    };

    // Carol asks both servers: two pairs, two counters, both from 0.
    let session_a = carol
        .inner
        .chan_ask(&space(), alice.name(), ChannelMode::Ask)
        .await
        .unwrap();
    let session_b = carol
        .inner
        .chan_ask(&space(), bob.name(), ChannelMode::Ask)
        .await
        .unwrap();
    let pair_a = carol.inner.chan.ask_pairs.get(session_a.id()).unwrap();
    let pair_b = carol.inner.chan.ask_pairs.get(session_b.id()).unwrap();
    assert_ne!(pair_a.id(), pair_b.id());
    run(0, &link_a, &pair_a, 0, 3);
    run(1, &link_b, &pair_b, 0, 3);

    // A renewal (the same channel, a new session answer): a new pair, a counter from 0 again.
    carol
        .inner
        .chan_ask(&space(), alice.name(), ChannelMode::Ask)
        .await
        .unwrap();
    let renewed = carol.inner.chan.ask_pairs.get(session_a.id()).unwrap();
    assert_ne!(
        renewed.id(),
        pair_a.id(),
        "a renewal gives new keys, never the old"
    );
    run(0, &link_a, &renewed, 0, 3);
    // The retired pair still opens in its grace; its counters 0..3 are used, 3 is not.
    run(0, &link_a, &pair_a, 3, 1);

    // An eviction, and a restart (the server forgets every pair): the old pair opens nothing, and
    // the asker's next ask gives a pair no earlier one is.
    alice.inner.chan.pairs.drop_all();
    let unknown = alice.inner.chan.pairs.stats.unknown_pair.get();
    alice
        .inner
        .query_frame(ask(&renewed, 3, b"to nobody"), FaceId(0));
    assert_eq!(alice.inner.chan.pairs.stats.unknown_pair.get(), unknown + 1);
    assert!(link_a.take_datagrams().is_empty());
    carol
        .inner
        .chan_ask(&space(), alice.name(), ChannelMode::Ask)
        .await
        .unwrap();
    let again = carol.inner.chan.ask_pairs.get(session_a.id()).unwrap();
    assert!(![pair_a.id(), renewed.id()].contains(&again.id()));
    run(0, &link_a, &again, 0, 3);

    // The same octets sealed at the same counter 0 under four different keys are four different
    // ciphertexts: no key repeated.
    let firsts: Vec<&Vec<u8>> = sealed_bodies.iter().step_by(1).collect();
    let distinct: HashSet<&Vec<u8>> = firsts.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        firsts.len(),
        "no two answers share a ciphertext"
    );
    assert_eq!(seen_a.count() + seen_b.count(), sealed_bodies.len());
}

// -- The answer ---------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handler_sees_the_askers_query_id_not_the_token() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;

    // The id is inside the seal (the same to every server of one `get`); the token is the
    // relay's, random per query per server: the handler is told the first.
    let id = 0xabcd_ef01_2345_6789;
    let token = 0xfeed;
    let mut sealed = plain("/game/x", b"who am i");
    sealed.id = id;
    bed.send(query(&pair, 0, token, &sealed));
    bed.answers(1).await;
    assert_eq!(seen.queries.lock().unwrap()[0].id, QueryId(id));
    assert_ne!(QueryId(id), QueryId(token));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_goes_to_the_one_asker_and_the_handler_runs_once() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let (bob, carol) = (bed.pair(bed.bob()).await, bed.pair(bed.carol()).await);
    let s = bed.stats();

    bed.send(query(&bob, 0, 0xfeed, &plain("/game/pickup/key", b"hello")));
    let got = bed.answers(1).await;
    let (frame, on_stream) = &got[0];
    assert!(!on_stream, "a small answer is a datagram");
    let (head, status) = open(&bob, frame, 0).expect("bob opens it");
    assert_eq!(status, answered(b"hello"));
    assert_eq!(
        (head.class, head.route, head.token, head.epoch),
        (SideClass::Datagram, bob.channel, 0xfeed, bob.epoch()),
        "addressed by route and token, sealed at the pair's epoch"
    );
    assert!(
        open(&carol, frame, 0).is_none(),
        "no other asker's pair opens it"
    );
    assert_eq!(frame.len(), ANSWER_OVERHEAD + status.encode().len());

    // What the handler was given.
    let queries = seen.queries.lock().unwrap();
    assert_eq!(queries.len(), 1, "the handler ran once");
    let q = &queries[0];
    assert_eq!(q.path, n("/game/pickup/key"));
    assert_eq!(q.bytes, Bytes::from_static(b"hello"));
    assert_eq!(q.via, Via::Sealed);
    assert_eq!(q.asker.person, n("/bob"));
    assert_eq!(q.asker.device, bed.bob().name().clone());
    assert!(q.remaining() <= Duration::from_secs(3));
    drop(queries);
    assert_eq!((s.handlers.get(), s.answers.get()), (1, 1));
    assert_eq!(
        bed.alice().inner.query.server.running(),
        0,
        "the place is given back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handler_limits_per_person_and_in_all_answer_busy_once_a_second_per_pair() {
    let (started, gate) = (Arc::new(AtomicUsize::new(0)), Arc::new(Semaphore::new(0)));
    let bed = Bed::new(Kind::Public, LinkConfig::default(), held(&started, &gate)).await;
    let (bob, carol) = (bed.pair(bed.bob()).await, bed.pair(bed.carol()).await);
    let s = bed.stats();

    // Bob's eight places.
    for qseq in 0..PERSON_INFLIGHT as u64 {
        bed.send(ask(&bob, qseq, b"x"));
    }
    eventually("eight handlers run", || {
        started.load(Ordering::SeqCst) == PERSON_INFLIGHT
    })
    .await;
    bed.silence().await;

    // The ninth is Busy, sealed under Ka with its own counter; the tenth, the same second, is
    // dropped and counted: a refusal is limited too.
    bed.send(ask(&bob, 8, b"ninth"));
    let got = bed.answers(1).await;
    let (_, status) = open(&bob, &got[0].0, 8).expect("a sealed Busy");
    let ChanStatus::Busy { retry_ms } = status else {
        panic!("Busy, not {status:?}");
    };
    assert!(retry_ms > 0);
    bed.send(ask(&bob, 9, b"tenth"));
    bed.silence().await;
    assert_eq!((s.busy.get(), s.busy_dropped.get()), (1, 1));
    assert_eq!(started.load(Ordering::SeqCst), PERSON_INFLIGHT);

    // A second on, the pair is told again.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    bed.send(ask(&bob, 10, b"eleventh"));
    let got = bed.answers(1).await;
    assert!(matches!(
        open(&bob, &got[0].0, 10).unwrap().1,
        ChanStatus::Busy { .. }
    ));
    assert_eq!(s.busy.get(), 2);

    // Another person has places of her own: the limit is per person.
    bed.send(ask(&carol, 0, b"carol"));
    eventually("carol's handler runs", || {
        started.load(Ordering::SeqCst) == PERSON_INFLIGHT + 1
    })
    .await;
    gate.add_permits(PERSON_INFLIGHT + 1);
    let released = bed.answers(PERSON_INFLIGHT + 1).await;
    assert_eq!(released.len(), PERSON_INFLIGHT + 1);
    assert_eq!(bed.alice().inner.query.server.running(), 0);

    // In all: 64 places on the node, whoever asks.
    let server = &bed.alice().inner.query.server;
    let now = Instant::now();
    let mut places = Vec::new();
    for person in 0..HANDLERS_MAX / PERSON_INFLIGHT + 1 {
        let person = n(&format!("/person{person}"));
        while let Some(slot) = server.slot(&person, now) {
            places.push(slot);
        }
    }
    assert_eq!(
        places.len(),
        HANDLERS_MAX,
        "the node runs at most 64 handlers"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_rate_per_person_is_256_a_second() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let server = &bed.alice().inner.query.server;
    let (bob, carol) = (n("/bob"), n("/carol"));
    let t0 = Instant::now();

    // A burst of 256, then none; a second later, 256 again (a bucket of its own, refilled).
    let admitted = |at: Instant, person: &Name| {
        (0..400)
            .filter(|_| server.admit_channel(person, at))
            .count()
    };
    assert_eq!(admitted(t0, &bob), 256);
    assert_eq!(admitted(t0, &bob), 0);
    assert_eq!(admitted(t0 + Duration::from_secs(1), &bob), 256);
    assert_eq!(
        admitted(t0 + Duration::from_millis(1_500), &bob),
        128,
        "256 a second: half a second is half the burst"
    );
    // Per person: carol's bucket is full while bob's is empty.
    assert_eq!(admitted(t0, &carol), 256);

    // The signed path's bucket (64 a second, a burst of 128) is another: spending one does not
    // spend the other.
    let dave = n("/dave");
    assert_eq!(admitted(t0, &dave), 256);
    let signed = (0..400).filter(|_| server.admit(&dave, t0)).count();
    assert_eq!(
        signed, PERSON_BURST as usize,
        "the signed bucket was untouched"
    );
    assert_eq!(admitted(t0, &dave), 0, "and the channel bucket stays spent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_served_and_too_large_are_sealed_statuses() {
    let ran = Arc::new(AtomicUsize::new(0));
    let bed = Bed::new(Kind::Public, LinkConfig::default(), by_word(&ran)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();

    // A path no prefix serves: a sealed NotServed, and no handler.
    bed.send(query(&pair, 0, 100, &plain("/elsewhere/x", b"?")));
    let got = bed.answers(1).await;
    assert_eq!(open(&pair, &got[0].0, 0).unwrap().1, ChanStatus::NotServed);
    assert_eq!((s.not_served.get(), ran.load(Ordering::SeqCst)), (1, 0));

    // The handler's refusal is the application's word: a sealed Refused.
    bed.send(ask(&pair, 1, b"refuse"));
    let got = bed.answers(1).await;
    assert_eq!(
        open(&pair, &got[0].0, 1).unwrap().1,
        ChanStatus::Refused {
            code: 7,
            text: "no, and here is why".into()
        }
    );

    // An answer over what the channel path carries (65,536 octets) is TooLarge{65,536}, though
    // it would fit a stream frame; one of exactly 65,536 goes on the stream.
    bed.send(ask(&pair, 2, b"big:65537"));
    let got = bed.answers(1).await;
    assert_eq!(
        open(&pair, &got[0].0, 2).unwrap().1,
        ChanStatus::TooLarge { max: 65_536 }
    );
    assert!(!got[0].1, "the refusal is small: a datagram");
    bed.send(ask(&pair, 3, b"big:65536"));
    let got = bed.answers(1).await;
    assert!(got[0].1, "the largest answer is on the stream");
    assert!(matches!(
        open(&pair, &got[0].0, 3).unwrap().1,
        ChanStatus::Answered(b) if b.len() == 65_536
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pass_and_a_late_handler_send_nothing() {
    let ran = Arc::new(AtomicUsize::new(0));
    let bed = Bed::new(Kind::Public, LinkConfig::default(), by_word(&ran)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();

    bed.send(ask(&pair, 0, b"pass"));
    eventually("the handler passed", || s.silent.get() == 1).await;
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    bed.silence().await;

    // A handler that is still working at the asker's deadline: its answer is never sent.
    let late = query(
        &pair,
        1,
        101,
        &QueryPlain {
            id: 0x1d,
            deadline_ms: 300,
            path: n("/game/x"),
            bytes: Bytes::from_static(b"late"),
        },
    );
    bed.send(late);
    eventually("the handler ran", || ran.load(Ordering::SeqCst) == 2).await;
    tokio::time::sleep(Duration::from_millis(2_300)).await;
    assert_eq!(s.silent.get(), 2, "past the deadline: counted silent");
    assert_eq!(bed.sent().len(), 0, "nothing was sent");
    assert_eq!(s.answers.get(), 0);
    assert_eq!(
        bed.alice().inner.query.server.running(),
        0,
        "the place was given back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_state_survives_an_answer() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;
    let alice = &bed.alice().inner;
    let server = &alice.query.server;
    let held = || {
        (
            alice.chan.pairs.count(),
            server.running(),
            alice.chan.tx.all().len(),
            alice
                .chan
                .channels
                .receiver_count(&space(), ChannelMode::Ask),
            alice.query.table.prefixes(&space()).len(),
        )
    };
    let before = held();

    // Answered, refused-by-path and replayed queries: afterwards the server holds what it held.
    let mut answers = 0;
    for batch in 0..10u64 {
        // Five at a time: the person has eight places, and a burst past them is answered Busy.
        let mut sent = 5;
        for qseq in batch * 5..batch * 5 + 5 {
            bed.send(ask(&pair, qseq, b"answer me"));
        }
        if batch < 5 {
            bed.send(query(
                &pair,
                1_000 + batch,
                5_000 + batch,
                &plain("/elsewhere", b"?"),
            ));
            sent += 1;
        }
        answers += bed.answers(sent).await.len();
    }
    assert_eq!(answers, 55);
    assert_eq!(
        held(),
        before,
        "pairs, places, channels, receivers, prefixes: all as before"
    );
    assert_eq!(server.running(), 0);

    // No answer is kept to give again: a copy of an answered query gets nothing, and the pair
    // holds a window of counters, never answers.
    bed.send(ask(&pair, 7, b"answer me"));
    bed.silence().await;
    assert_eq!(seen.count(), 50);
    // The asker's person has all her places back.
    let now = Instant::now();
    let slots: Vec<_> = std::iter::from_fn(|| server.slot(&n("/bob"), now))
        .take(PERSON_INFLIGHT + 1)
        .collect();
    assert_eq!(slots.len(), PERSON_INFLIGHT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_or_answer_frame_given_to_deliver_frame_is_dropped_as_a_kind_and_reaches_no_query_layer()
 {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let pair = bed.pair(bed.bob()).await;
    let (alice, bob) = (bed.alice(), bed.bob());

    // A real ANSWER: the server's own to a genuine query (counter 1).
    bed.send(ask(&pair, 1, b"first"));
    let answer = bed.answers(1).await.remove(0).0;
    assert_eq!(answer[1] & 0x0f, 6);
    assert_eq!(seen.count(), 1);
    // A real QUERY, valid header and sealed body, that nothing has been given yet (counter 5).
    let frame = ask(&pair, 5, b"through the query layer");
    assert_eq!(frame[1] & 0x0f, 5);

    let asked = || {
        let s = &bob.inner.query.ask.chan.stats;
        [
            s.sent.get(),
            s.unmatched.get(),
            s.bad_frame.get(),
            s.bad_answers.get(),
            s.answers.get(),
            s.silent.get(),
            s.congested.get(),
        ]
    };
    let (queries, asked_before, ran) = (bed.stats().queries.get(), asked(), seen.count());
    let server_pair = || {
        alice
            .inner
            .chan
            .pairs
            .get(&pair.id(), pair.channel, Instant::now())
            .expect("the server holds the pair")
    };

    // The public host path (`deliver_frame`) takes channel frames of a data layout only: a QUERY
    // or an ANSWER is a kind it refuses, on the server's node and on the asker's.
    for node in [alice, bob] {
        for frame in [frame.clone(), answer.clone()] {
            let delivery = node.deliver_frame(frame, 0).await;
            assert_eq!(
                delivery,
                crate::Delivery::Dropped(crate::Dropped::Kind),
                "refused as a kind, not read as a frame of the data layout"
            );
        }
    }
    assert_eq!(
        bed.stats().queries.get(),
        queries,
        "the query layer never saw a frame"
    );
    assert_eq!(asked(), asked_before, "nor did the asker's");
    assert!(server_pair().fresh(5), "no counter was marked");
    bed.silence().await;
    assert_eq!(seen.count(), ran, "no handler ran");

    // The forwarder's app-face path hands the same frame to the query layer: answered once.
    // (`chan_side_frame` is private; it calls `query_frame`, as here.)
    bed.send(frame);
    let got = bed.answers(1).await;
    assert_eq!(
        open(&pair, &got[0].0, 5).unwrap().1,
        answered(b"through the query layer")
    );
    assert_eq!(bed.stats().queries.get(), queries + 1);
    assert!(!server_pair().fresh(5), "now it is marked");
    assert_eq!(seen.count(), ran + 1, "the handler ran once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_channel_carries_no_emission_and_emit_refuses_it() {
    let seen = Arc::new(Seen::default());
    let bed = Bed::new(Kind::Public, LinkConfig::default(), echo(&seen)).await;
    let session = bed
        .bob()
        .inner
        .chan_ask(&space(), bed.alice().name(), ChannelMode::Ask)
        .await
        .unwrap();
    let pair = bed.bob().inner.chan.ask_pairs.get(session.id()).unwrap();
    bed.send(ask(&pair, 0, b"q"));
    bed.answers(1).await;

    // The server made no sender of it: nothing to emit into, and nothing sent but the answer.
    let alice = &bed.alice().inner;
    assert!(alice.chan.tx.all().is_empty());
    assert!(alice.chan.tx.get(&space(), ChannelMode::Ask).is_none());
    assert!(!ChannelMode::Ask.needs_stream());

    // A frame of a data layout that names the session id is dropped before any key is tried.
    let header = Header::new(
        SideClass::Datagram,
        SideKind::Data,
        session.id(),
        pair.epoch(),
        0,
        1,
    )
    .unwrap();
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&[0u8; 40]);
    let rx = &bed.bob().inner.chan.stats.rx;
    let kind = rx.kind.get();
    let delivery = bed
        .bob()
        .inner
        .chan_deliver(Bytes::from(frame), 0, Instant::now())
        .await;
    assert!(matches!(
        delivery,
        crate::chan::rx::Delivery::Dropped(crate::chan::rx::Dropped::Kind)
    ));
    assert_eq!(rx.kind.get(), kind + 1);
}

// -- What an answer may be sent on ------------------------------------------------------------------------

/// A pair the server holds that this test made: the asker's half, for a path whose owner offers no
/// stream (the real asker always offers one).
fn made_pair(bed: &Bed, stream: bool) -> Arc<AskPair> {
    let alice = bed.alice();
    let held = alice.inner.space_of(&space()).unwrap();
    let fold = held.log.lock().fold.version();
    let judged_at = (alice.inner.judge.generation(), fold.load(Ordering::SeqCst));
    let (_, keys) = ndn_security::pair_keys_to(&alice.inner.recipient().public(), b"a test pair")
        .expect("a pair");
    let channel = 0x1234_5678;
    let owner = PairOwner {
        space: space(),
        channel,
        key_epoch: 0,
        device: bed.bob().name().clone(),
        person: n("/bob"),
        key: bed.bob().writer().clone(),
        stream,
    };
    let lease = Instant::now() + Duration::from_secs(600);
    let pair = ServerPair::new(&keys, Aead::Aes256Gcm, owner, judged_at, fold, lease);
    alice
        .inner
        .chan
        .pairs
        .install(pair, Instant::now())
        .unwrap();
    Arc::new(AskPair::new(
        &keys,
        Aead::Aes256Gcm,
        channel,
        0,
        Instant::now(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_less_hop_limits_the_answer_to_a_datagram() {
    let ran = Arc::new(AtomicUsize::new(0));
    let link = LinkConfig {
        has_stream: false,
        ..LinkConfig::default()
    };
    let bed = Bed::new(Kind::Public, link, by_word(&ran)).await;
    let pair = bed.pair(bed.bob()).await;

    // 1,400 octets a datagram: a frame is 35 octets over the status (1 + a 2-octet length + the
    // answer), so 1,362 octets of answer is the most.
    bed.send(ask(&pair, 0, b"big:1362"));
    let got = bed.answers(1).await;
    assert_eq!(got[0].0.len(), 1_400);
    assert!(matches!(
        open(&pair, &got[0].0, 0).unwrap().1,
        ChanStatus::Answered(b) if b.len() == 1_362
    ));
    bed.send(ask(&pair, 1, b"big:1363"));
    let got = bed.answers(1).await;
    assert_eq!(
        open(&pair, &got[0].0, 1).unwrap().1,
        ChanStatus::TooLarge { max: 1_362 },
        "no stream on this carrier: told what does fit"
    );
    assert!(!got[0].1);
    assert_eq!(bed.link.queued_stream_bytes(), 0);
    drop(bed);

    // The carrier has a stream and the pair's owner path has none (a hop that carries
    // datagrams only): the same.
    let bed = Bed::new(Kind::Public, LinkConfig::default(), by_word(&ran)).await;
    let pair = made_pair(&bed, false);
    bed.send(ask(&pair, 0, b"big:5000"));
    let got = bed.answers(1).await;
    assert!(!got[0].1);
    assert_eq!(
        open(&pair, &got[0].0, 0).unwrap().1,
        ChanStatus::TooLarge { max: 1_362 }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_answer_goes_on_the_stream_class() {
    let ran = Arc::new(AtomicUsize::new(0));
    let bed = Bed::new(Kind::Public, LinkConfig::default(), by_word(&ran)).await;
    let pair = bed.pair(bed.bob()).await;
    let s = bed.stats();
    assert!(
        bed.alice()
            .inner
            .chan
            .pairs
            .get(&pair.id(), pair.channel, Instant::now())
            .unwrap()
            .owner
            .stream,
        "the asker's path offers a stream"
    );

    bed.send(ask(&pair, 0, b"big:5000"));
    let got = bed.answers(1).await;
    let (frame, on_stream) = &got[0];
    assert!(
        on_stream,
        "5,000 octets do not fit a datagram: the stream class"
    );
    let (head, status) = open(&pair, frame, 0).expect("opens under Ka, the class in the header");
    assert_eq!(head.class, SideClass::Stream);
    assert_eq!(frame[1], 0x36);
    assert!(matches!(status, ChanStatus::Answered(b) if b.len() == 5_000));
    assert_eq!((s.answers.get(), s.not_sent.get()), (1, 0));

    // A small one still goes as a datagram, and the stream class is bound into the seal: the
    // same frame told it is a datagram does not open.
    bed.send(ask(&pair, 1, b"small"));
    let got = bed.answers(1).await;
    assert!(!got[0].1);
    assert_eq!(got[0].0[1], 0x26);
    let mut forged = got[0].0.to_vec();
    forged[1] = 0x36;
    assert!(open(&pair, &Bytes::from(forged), 1).is_none());
}
