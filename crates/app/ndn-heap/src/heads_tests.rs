//! Every head of a path and the merge put (docs/specs/heap.md §10.3–§10.4, channel.md §17):
//! `GetOptions::heads`, `Heap::kept_all` and `Heap::put_merged`.
//!
//! A concurrent head is an entry of another device that names nothing at the path, so the cases
//! forge such entries (one per device) and hand them to the node as a fetch would. The heads
//! are ranked by the signed-region digest, so a case that needs a head to win or lose orders its
//! forged ids by digest instead of hoping.

use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use ndn_foundation_types::Name;
use ndn_packet::Data;

use crate::chan::items::Items;
use crate::chan::verbs::{GetNotice, GetOptions, Got, Heads, Kept, Kind, Live, Select};
use crate::error::{HeapError, NextStep, Refusal};
use crate::log::Outcome;
use crate::node::Node;
use crate::node::tests::{Dev, boot, bytes, cfg, deliver, public, space, world};
use crate::register::EntryId;
use crate::space::{Heap, PutOptions};
use crate::surface_tests::{forge, put_body, take};
use crate::test_kit::n;
use crate::wire::{Body, Entry, EntryRef, Payload, Prev, PutBody, log_name};
use crate::{Config, Merged};

// -- What the cases are made of ----------------------------------------------------------------

/// A node that owns a public space, and devices of the owner's person that write into it by
/// forged entries: `devs[0]` is the node's own device, `devs[k]` the k-th forging device.
struct Fork {
    devs: Vec<Dev>,
    node: Node,
    heap: Heap,
    /// The seq each forging device last used and the digest of its entry.
    last: Vec<(u64, Option<[u8; 32]>)>,
}

async fn fork(forgers: usize, config: Config) -> Fork {
    let names: Vec<String> = std::iter::once("/alice/laptop".to_owned())
        .chain((1..=forgers).map(|k| format!("/alice/d{k:02}")))
        .collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let devs = world(&refs).await;
    let (node, _) = boot(&devs[0], config).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let last = vec![(0, None); devs.len()];
    Fork {
        devs,
        node,
        heap,
        last,
    }
}

impl Fork {
    /// Forge forging device `k`'s next entry: `value` at `path`, superseding `after`.
    fn forged(
        &mut self,
        k: usize,
        path: &str,
        value: &str,
        after: &[&EntryId],
    ) -> (EntryId, Bytes) {
        let (seq, digest) = self.last[k];
        let prev = digest.map(|digest| Prev { digest, seq: None });
        let after: Vec<EntryRef> = after.iter().map(|id| (*id).clone()).collect();
        let (id, packet) = forge(&self.devs[k], seq + 1, prev, after, put_body(path, value));
        self.last[k] = (seq + 1, Some(id.digest));
        (id, packet)
    }

    /// Forge forging device `k`'s next entry at `path` so that its digest ranks under `bound`.
    fn forged_under(&mut self, k: usize, path: &str, bound: &[u8; 32]) -> (EntryId, Bytes) {
        for i in 0..64 {
            let (seq, digest) = self.last[k];
            let prev = digest.map(|digest| Prev { digest, seq: None });
            let body = put_body(path, &format!("v{i}"));
            let (id, packet) = forge(&self.devs[k], seq + 1, prev, vec![], body);
            if id.digest < *bound {
                self.last[k] = (seq + 1, Some(id.digest));
                return (id, packet);
            }
        }
        panic!("64 values and none ranks under the bound");
    }
    async fn apply(&self, packet: Bytes) {
        assert_eq!(take(&self.node, packet).await, Outcome::Applied);
    }

    /// Forge and apply at once.
    async fn head(&mut self, k: usize, path: &str, value: &str, after: &[&EntryId]) -> EntryId {
        let (id, packet) = self.forged(k, path, value, after);
        self.apply(packet).await;
        id
    }

    async fn heads_at(&self, path: &str) -> Vec<EntryId> {
        let heads = self.heap.kept_all(&n(path)).await.unwrap();
        heads.into_iter().map(|item| item.id).collect()
    }

    fn own_seq(&self) -> u64 {
        self.heap.inner.log.lock().next_seq()
    }
}

/// Highest rank first: the winner, then the others (digest, then device, then seq).
fn ranked(mut ids: Vec<EntryId>) -> Vec<EntryId> {
    ids.sort_by(|a, b| (&b.digest, &b.device, b.seq).cmp(&(&a.digest, &a.device, a.seq)));
    ids
}

fn everything() -> Select {
    Select::Prefix(Name::root())
}

/// Every head, kept values only (a follower may read these).
fn all() -> GetOptions {
    GetOptions {
        heads: Heads::All,
        live: Live::Off,
        ..GetOptions::default()
    }
}

/// The winner of each path, kept values only.
fn winner() -> GetOptions {
    GetOptions {
        live: Live::Off,
        ..GetOptions::default()
    }
}

/// Everything the stream holds now, without waiting.
fn drain(items: &mut Items) -> Vec<Result<Got, GetNotice>> {
    let mut out = Vec::new();
    while let Some(Some(next)) = items.next().now_or_never() {
        out.push(next);
    }
    out
}

fn kept(got: &Got) -> &Kept {
    match &got.kind {
        Kind::Kept(kept) => kept,
        other => panic!("a kept value was expected, got {other:?}"),
    }
}

fn told(got: &Result<Got, GetNotice>) -> &Got {
    got.as_ref()
        .unwrap_or_else(|notice| panic!("an item was expected, got {notice:?}"))
}

fn text(got: &Got) -> String {
    String::from_utf8_lossy(&got.bytes).into_owned()
}

// -- `get` with every head ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_heads_lists_every_concurrent_head_winner_first() {
    let mut f = fork(3, cfg()).await;
    let mut ids = Vec::new();
    for (k, value) in [(1, "one"), (2, "two"), (3, "three")] {
        ids.push(f.head(k, "/p", value, &[]).await);
    }
    let alone = f.head(1, "/q", "alone", &[]).await;
    let order = ranked(ids);

    assert_eq!(f.heads_at("/p").await, order, "kept_all: winner first");
    assert_eq!(f.heap.kept(&n("/p")).await.unwrap().unwrap().id, order[0]);

    let mut items = f.heap.get(everything(), all()).unwrap();
    let got = drain(&mut items);
    assert_eq!(got.len(), 4, "{got:?}");
    let paths: Vec<String> = got.iter().map(|g| told(g).path.to_string()).collect();
    assert_eq!(
        paths,
        ["/p", "/p", "/p", "/q"],
        "path order, every head of /p"
    );
    let listed: Vec<EntryId> = got.iter().map(|g| kept(told(g)).id.clone()).collect();
    assert_eq!(listed[..3], order[..], "rank order");
    assert_eq!(listed[3], alone);
    let winners: Vec<bool> = got.iter().map(|g| kept(told(g)).winner).collect();
    assert_eq!(
        winners,
        [true, false, false, true],
        "only the winner says so"
    );
    assert!(
        got.iter()
            .all(|g| kept(told(g)).supersedes.is_empty() && !kept(told(g)).removed),
        "a listing supersedes nothing"
    );

    // The same space in `Winner` mode lists one value per path.
    let mut one = f.heap.get(everything(), winner()).unwrap();
    let got = drain(&mut one);
    let listed: Vec<EntryId> = got.iter().map(|g| kept(told(g)).id.clone()).collect();
    assert_eq!(listed, [order[0].clone(), alone]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn winner_mode_is_unchanged_byte_for_byte() {
    let mut f = fork(3, cfg()).await;
    let (a, pa) = f.forged(1, "/p", "a", &[]);
    let (b, pb) = f.forged(2, "/p", "b", &[]);
    let (lo, hi) = if a.digest < b.digest {
        (pa, pb)
    } else {
        (pb, pa)
    };
    let (lo_id, hi_id) = if a.digest < b.digest {
        (&a, &b)
    } else {
        (&b, &a)
    };
    f.apply(lo).await;

    let mut items = f.heap.get(everything(), winner()).unwrap();
    let got = drain(&mut items);
    assert_eq!(got.len(), 1);
    let first = told(&got[0]);
    assert_eq!(
        (
            first.path.clone(),
            first.bytes.clone(),
            first.by.clone(),
            first.writer.clone()
        ),
        (
            n("/p"),
            bytes(if lo_id == &a { "a" } else { "b" }),
            n("/alice"),
            lo_id.device.clone()
        )
    );
    let mut expected = Kept::new(lo_id.clone());
    expected.winner = true;
    assert_eq!(
        kept(first),
        &expected,
        "`winner` is always true and nothing is superseded"
    );

    // A head that outranks it wins: one item that says nothing about the old one.
    f.apply(hi).await;
    let got = drain(&mut items);
    assert_eq!(got.len(), 1, "{got:?}");
    let won = told(&got[0]);
    assert_eq!(kept(won).id, *hi_id);
    assert!(kept(won).winner && kept(won).supersedes.is_empty() && !kept(won).removed);

    // A head under the winner is told nothing; no head notice exists in this mode.
    let c = f.head(3, "/p", "c", &[]).await;
    let ranked_now = f.heads_at("/p").await;
    let got = drain(&mut items);
    if ranked_now[0] == c {
        assert_eq!(got.len(), 1, "the new winner is told as it always was");
    } else {
        assert!(got.is_empty(), "a non-winning head is not told: {got:?}");
    }
    assert!(
        got.iter().all(|g| !matches!(
            g,
            Err(GetNotice::HeadsEnded { .. } | GetNotice::HeadsCapped { .. })
        )),
        "no head notice in `Winner` mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_winning_head_arriving_is_told_in_all_mode_and_not_in_winner_mode() {
    let mut small = cfg();
    small.watch_queue = 1;
    let mut f = fork(5, small).await;
    let (a, pa) = f.forged(1, "/p", "a", &[]);
    let (b, pb) = f.forged(2, "/p", "b", &[]);
    let ((high, high_packet), (low, low_packet)) = if a.digest > b.digest {
        ((a, pa), (b, pb))
    } else {
        ((b, pb), (a, pa))
    };
    // The higher-ranked head is applied first, then both feeds are opened.
    f.apply(high_packet).await;
    let mut every = f.heap.get(everything(), all()).unwrap();
    let mut one = f.heap.get(everything(), winner()).unwrap();
    assert_eq!(drain(&mut every).len(), 1);
    assert_eq!(drain(&mut one).len(), 1);

    f.apply(low_packet).await;
    let got = drain(&mut every);
    assert_eq!(got.len(), 1, "{got:?}");
    let told_low = told(&got[0]);
    assert_eq!(kept(told_low).id, low);
    assert!(!kept(told_low).winner && kept(told_low).supersedes.is_empty());
    assert!(drain(&mut one).is_empty(), "`Winner` mode is told nothing");

    // Only the feed that asked for heads pays for them: more heads, all ranked under the
    // winner, overflow a queue of one for the `All` feed and never for the other.
    for k in 3..=5 {
        let (_, packet) = f.forged_under(k, "/p", &high.digest);
        f.apply(packet).await;
    }
    assert_eq!(
        f.heap.inner.overflowed(),
        1,
        "the `All` feed alone queued the heads"
    );
    let again = drain(&mut every);
    assert!(
        !again.is_empty() && again.iter().all(Result::is_ok),
        "a feed that overflowed reads the heads again and loses none: {again:?}"
    );
    assert!(drain(&mut one).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supersedes_is_stream_relative_across_a_chain() {
    // A queue of one that an unrelated change fills: the chain M, M2 is dropped from it and
    // the stream reads the heads again, so it never saw M.
    let mut small = cfg();
    small.watch_queue = 1;
    let mut f = fork(3, small).await;
    let a = f.head(1, "/p", "a", &[]).await;
    let mut items = f.heap.get(everything(), all()).unwrap();
    let got = drain(&mut items);
    assert_eq!(got.len(), 1);
    assert_eq!(kept(told(&got[0])).id, a);

    f.heap
        .put(&n("/other"), bytes("fill"), PutOptions::default())
        .await
        .unwrap();
    let m = f.head(2, "/p", "m", &[&a]).await;
    let m2 = f.head(3, "/p", "m2", &[&m]).await;
    assert_eq!(
        f.heads_at("/p").await,
        std::slice::from_ref(&m2),
        "the register holds only M2"
    );

    let got = drain(&mut items);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(told(&got[0]).path, n("/other"));
    let last = told(&got[1]);
    assert_eq!(text(last), "m2");
    let k = kept(last);
    assert_eq!(k.id, m2);
    assert!(k.winner);
    assert_eq!(
        k.supersedes,
        [a],
        "it lists what this stream had told, A, and not M it never saw"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_ending_without_a_successor_is_headsended() {
    let mut f = fork(3, cfg()).await;
    let a = f.head(1, "/p", "a", &[]).await;
    // E names A and is held back; E2 names E and arrives first, so it is a head beside A.
    let (e, e_packet) = f.forged(2, "/p", "e", &[&a]);
    let e2 = f.head(3, "/p", "e2", &[&e]).await;
    let mut items = f.heap.get(everything(), all()).unwrap();
    let got = drain(&mut items);
    let listed: Vec<EntryId> = got.iter().map(|g| kept(told(g)).id.clone()).collect();
    assert_eq!(listed, ranked(vec![a.clone(), e2.clone()]));

    // E arrives: it is already superseded by E2, and it supersedes A. A ends, and nothing
    // takes its place.
    f.apply(e_packet).await;
    let got = drain(&mut items);
    assert_eq!(
        got.len(),
        1,
        "no item: the only head left, E2, was told already: {got:?}"
    );
    assert_eq!(
        got[0],
        Err(GetNotice::HeadsEnded {
            path: n("/p"),
            ids: vec![a]
        })
    );
    assert_eq!(f.heads_at("/p").await, [e2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawn_head_with_nothing_to_restore_is_withdrawn_and_headsended() {
    let mut f = fork(1, cfg()).await;
    let x = f.head(1, "/p", "x", &[]).await;
    let mut items = f.heap.get(everything(), all()).unwrap();
    assert_eq!(drain(&mut items).len(), 1);
    withdraw(&f, &x);
    let got = drain(&mut items);
    assert_eq!(
        got,
        vec![
            Err(GetNotice::Withdrawn {
                id: x.clone(),
                why: Refusal::NotMember
            }),
            Err(GetNotice::HeadsEnded {
                path: n("/p"),
                ids: vec![x]
            }),
        ]
    );
}

fn withdraw(f: &Fork, id: &EntryId) {
    let mut log = f.heap.inner.log.lock();
    let fx = log.withdraw(&id.device, id.seq, Refusal::NotMember);
    f.heap.inner.route(&f.node.inner, &log, fx, false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawn_head_returns_as_an_item() {
    let mut f = fork(2, cfg()).await;
    let a = f.head(1, "/p", "a", &[]).await;
    let b = f.head(2, "/p", "b", &[&a]).await;
    let mut items = f.heap.get(everything(), all()).unwrap();
    let got = drain(&mut items);
    assert_eq!(got.len(), 1);
    assert_eq!(
        kept(told(&got[0])).id,
        b,
        "A is superseded: only B is a head"
    );

    withdraw(&f, &b);
    let got = drain(&mut items);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(
        got[0],
        Err(GetNotice::Withdrawn {
            id: b.clone(),
            why: Refusal::NotMember
        })
    );
    let back = told(&got[1]);
    assert_eq!(
        text(back),
        "a",
        "A returns, and this stream no longer holds it"
    );
    assert_eq!(kept(back).id, a);
    assert_eq!(
        kept(back).supersedes,
        [b],
        "and it retires the head that was withdrawn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_all_stream_tells_at_most_64_heads_per_path() {
    let mut f = fork(1, cfg()).await;
    // 66 concurrent heads of one device: each names nothing.
    for i in 0..66 {
        f.head(1, "/p", &format!("v{i}"), &[]).await;
    }
    assert_eq!(
        f.heads_at("/p").await.len(),
        66,
        "kept_all reads every head"
    );
    let top: Vec<EntryId> = f.heads_at("/p").await.into_iter().take(64).collect();

    let mut items = f.heap.get(everything(), all()).unwrap();
    let got = drain(&mut items);
    assert_eq!(
        got.len(),
        65,
        "64 heads and the notice that says there are more"
    );
    let listed: Vec<EntryId> = got[..64].iter().map(|g| kept(told(g)).id.clone()).collect();
    assert_eq!(listed, top, "the 64 of highest rank");
    assert_eq!(
        got[64],
        Err(GetNotice::HeadsCapped {
            path: n("/p"),
            hidden: 2
        })
    );

    // A head more: the gap grows, and is said again.
    f.head(1, "/p", "v66", &[]).await;
    let got = drain(&mut items);
    assert_eq!(
        got.last().unwrap(),
        &Err(GetNotice::HeadsCapped {
            path: n("/p"),
            hidden: 3
        }),
        "{got:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_all_reader_catches_up_and_loses_no_head() {
    let mut small = cfg();
    small.watch_queue = 2;
    let mut f = fork(2, small).await;
    let mut items = f.heap.get(everything(), all()).unwrap();
    assert!(drain(&mut items).is_empty());
    for i in 0..6 {
        let path = format!("/s{i}");
        f.head(1, &path, "one", &[]).await;
        f.head(2, &path, "two", &[]).await;
    }
    assert!(f.heap.inner.overflowed() > 0, "the queue of two overflowed");

    let got = drain(&mut items);
    assert!(
        got.iter().all(Result::is_ok),
        "never told it lagged: {got:?}"
    );
    let mut seen: Vec<(String, EntryId)> = got
        .iter()
        .map(|g| (told(g).path.to_string(), kept(told(g)).id.clone()))
        .collect();
    let mut want = Vec::new();
    for i in 0..6 {
        let path = format!("/s{i}");
        for id in f.heads_at(&path).await {
            want.push((path.clone(), id));
        }
    }
    seen.sort();
    want.sort();
    assert_eq!(seen, want, "every head of every path, once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follower_may_read_heads_with_live_off() {
    let dev = crate::node::tests::solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let _follower = node.follow(&space()).await.unwrap();
    let held = node.inner.space_of(&space()).expect("the carrier holds it");
    let heap = Heap::new(held, std::sync::Arc::clone(&node.inner));
    let mut items = heap
        .get(everything(), all())
        .expect("a follower reads every head with no emissions");
    tokio::time::timeout(Duration::from_secs(1), items.caught_up())
        .await
        .expect("caught up");
    let live = heap
        .get(
            everything(),
            GetOptions {
                heads: Heads::All,
                ..GetOptions::default()
            },
        )
        .expect_err("a follower takes no part in channels, whatever it reads");
    assert!(matches!(live, HeapError::NotAllowed { .. }), "{live:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_space_head_held_closed_is_not_told() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice
        .create(&space(), crate::node::tests::private(&["/bob"]))
        .await
        .unwrap();
    heap.put(&n("/secret"), bytes("for bob"), PutOptions::default())
        .await
        .unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let kept = theirs
        .kept(&n("/secret"))
        .await
        .expect_err("the entry is held closed");
    let listed = theirs
        .get(everything(), all())
        .expect_err("a listing that cannot show the closed entry's path is not whole");
    assert!(matches!(listed, HeapError::NotReady { .. }), "{listed:?}");
    assert_eq!(
        listed.to_string(),
        kept.to_string(),
        "the reason `kept` gives"
    );
    let heads = theirs
        .kept_all(&n("/secret"))
        .await
        .expect_err("and the point read of every head");
    assert_eq!(heads.to_string(), kept.to_string());
}

// -- The merge put -----------------------------------------------------------------------------

/// What an entry superseded, read from the store under its name.
fn after_of(f: &Fork, id: &EntryId) -> Vec<EntryRef> {
    let dev = f.devs.iter().find(|d| d.name == id.device).unwrap();
    let wire = dev
        .store
        .get(&log_name(&id.device, &space(), id.seq))
        .unwrap();
    let data = Data::decode(wire).unwrap();
    Entry::decode(data.content().unwrap()).unwrap().after
}

/// Heads A and B read, C arrives, the merge of A and B is put.
async fn hazard() -> (Fork, [EntryId; 3]) {
    let mut f = fork(3, cfg()).await;
    let a = f.head(1, "/p", "a", &[]).await;
    let b = f.head(2, "/p", "b", &[]).await;
    let read = f.heads_at("/p").await;
    assert_eq!(read.len(), 2, "the library read A and B");
    let c = f.head(3, "/p", "c", &[]).await;
    (f, [a, b, c])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_merged_names_exactly_the_given_heads() {
    let (f, [a, b, c]) = hazard().await;
    let merged = f
        .heap
        .put_merged(
            &n("/p"),
            bytes("ab"),
            &[a.clone(), b.clone()],
            PutOptions::default(),
        )
        .await
        .unwrap();
    let mut named = after_of(&f, &merged.id);
    named.sort();
    let mut want = vec![a.clone(), b.clone()];
    want.sort();
    assert_eq!(named, want, "it names the heads merged, no others");
    assert_eq!(
        merged,
        Merged {
            id: merged.id.clone(),
            open: vec![c.clone()]
        },
        "C arrived between the read and the put: it stays a head, and `open` says so"
    );
    let now = f.heads_at("/p").await;
    assert_eq!(ranked(vec![merged.id.clone(), c.clone()]), now);

    // The plain put names every head it holds at signing time: C is superseded unmerged, the
    // silent lost edit that `put_merged` closes.
    let (plain, [_, _, c2]) = hazard().await;
    let id = plain
        .heap
        .put(&n("/p"), bytes("ab"), PutOptions::default())
        .await
        .unwrap();
    assert_eq!(plain.heads_at("/p").await, std::slice::from_ref(&id));
    assert!(
        after_of(&plain, &id).contains(&c2),
        "the plain put superseded C without having merged it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_merged_refuses_an_id_at_another_path_an_unknown_id_and_nine_ids() {
    let mut f = fork(9, cfg()).await;
    let mut ids = Vec::new();
    for k in 1..=9 {
        ids.push(f.head(k, "/p", &format!("v{k}"), &[]).await);
    }
    let elsewhere = f.head(1, "/other", "o", &[]).await;
    let before = f.own_seq();

    let refused = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &ids, PutOptions::default())
        .await
        .expect_err("nine ids are more than an entry can name");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
    let why = refused.to_string();
    assert!(
        why.contains('9') && why.contains('8') && why.contains("rounds"),
        "it says how many, the most, and what to do: {why}"
    );

    let refused = f
        .heap
        .put_merged(
            &n("/p"),
            bytes("m"),
            std::slice::from_ref(&elsewhere),
            PutOptions::default(),
        )
        .await
        .expect_err("an entry of another path is not merged here");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
    assert!(
        refused.to_string().contains("/other"),
        "it names the path: {refused}"
    );

    let unknown = EntryRef {
        device: f.devs[1].name.clone(),
        seq: 77,
        digest: [9; 32],
    };
    let refused = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &[unknown], PutOptions::default())
        .await
        .expect_err("an entry not applied here");
    assert!(matches!(refused, HeapError::NotReady { .. }), "{refused:?}");
    assert_eq!(refused.next(), NextStep::RetryLater);
    assert_eq!(f.own_seq(), before, "a refusal signs nothing");

    // Eight is the most.
    let merged = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &ids[..8], PutOptions::default())
        .await
        .expect("eight ids");
    assert_eq!(merged.open, [ids[8].clone()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_already_superseded_id_is_accepted_and_hides_nothing_else() {
    let mut f = fork(3, cfg()).await;
    let a = f.head(1, "/p", "a", &[]).await;
    let b = f.head(2, "/p", "b", &[&a]).await;
    let c = f.head(3, "/p", "c", &[]).await;
    assert_eq!(f.heads_at("/p").await, ranked(vec![b.clone(), c.clone()]));

    let merged = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &[a], PutOptions::default())
        .await
        .expect("A is applied at the path; that it is superseded is no refusal");
    assert_eq!(
        ranked(merged.open.clone()),
        ranked(vec![b.clone(), c.clone()]),
        "whatever superseded A stays a head, concurrent with the new entry"
    );
    assert_eq!(f.heads_at("/p").await, ranked(vec![merged.id, b, c]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twelve_heads_merge_in_two_rounds() {
    let mut f = fork(12, cfg()).await;
    for k in 1..=12 {
        f.head(k, "/p", &format!("v{k}"), &[]).await;
    }
    let heads = f.heads_at("/p").await;
    assert_eq!(heads.len(), 12);

    let first = f
        .heap
        .put_merged(&n("/p"), bytes("r1"), &heads[..8], PutOptions::default())
        .await
        .unwrap();
    assert_eq!(first.open.len(), 4, "12 - 8 heads remain beside the merge");
    assert_eq!(f.heads_at("/p").await.len(), 5, "the merge and the four");

    let mut round_two = first.open.clone();
    round_two.push(first.id.clone());
    let second = f
        .heap
        .put_merged(&n("/p"), bytes("r2"), &round_two, PutOptions::default())
        .await
        .unwrap();
    assert!(second.open.is_empty(), "this put left a single head");
    assert_eq!(f.heads_at("/p").await, [second.id]);
}

/// The merging library's contract (heap.md §10.4): merge deterministically; put only if some
/// head's bytes differ from the merge. Returns how many puts it made.
async fn converge(heap: &Heap, path: &Name) -> usize {
    let mut puts = 0;
    loop {
        let heads = heap.kept_all(path).await.unwrap();
        let mut parts: Vec<String> = heads
            .iter()
            .flat_map(|h| {
                String::from_utf8_lossy(&h.bytes)
                    .split('+')
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        parts.sort();
        parts.dedup();
        let merge = Bytes::from(parts.join("+"));
        if heads.iter().all(|h| h.bytes == merge) {
            return puts;
        }
        let ids: Vec<EntryId> = heads.into_iter().map(|h| h.id).collect();
        heap.put_merged(path, merge, &ids, PutOptions::default())
            .await
            .unwrap();
        puts += 1;
        assert!(puts <= 4, "a library that follows the contract stops");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_replicas_merging_the_same_heads_converge_without_looping() {
    let devs = world(&["/alice/laptop", "/alice/phone", "/alice/d01", "/alice/d02"]).await;
    let (laptop, _) = boot(&devs[0], cfg()).await;
    let on_laptop = laptop.create(&space(), public()).await.unwrap();
    let (phone, _) = boot(&devs[1], cfg()).await;
    let on_phone = phone.open(&space()).await.unwrap();
    deliver(&devs[0], &phone).await;

    let (_, pa) = forge(&devs[2], 1, None, vec![], put_body("/p", "A"));
    let (_, pb) = forge(&devs[3], 1, None, vec![], put_body("/p", "B"));
    for node in [&laptop, &phone] {
        assert_eq!(take(node, pa.clone()).await, Outcome::Applied);
        assert_eq!(take(node, pb.clone()).await, Outcome::Applied);
    }
    assert_eq!(converge(&on_laptop, &n("/p")).await, 1);
    assert_eq!(converge(&on_phone, &n("/p")).await, 1);

    // Each now hears of the other's merge: two heads of equal bytes. Neither puts again.
    deliver(&devs[0], &phone).await;
    deliver(&devs[1], &laptop).await;
    assert_eq!(on_laptop.kept_all(&n("/p")).await.unwrap().len(), 2);
    assert_eq!(on_phone.kept_all(&n("/p")).await.unwrap().len(), 2);
    assert_eq!(converge(&on_laptop, &n("/p")).await, 0);
    assert_eq!(converge(&on_phone, &n("/p")).await, 0);
    let (l, p) = (
        on_laptop.kept(&n("/p")).await.unwrap().unwrap(),
        on_phone.kept(&n("/p")).await.unwrap().unwrap(),
    );
    assert_eq!(
        (l.id, l.bytes),
        (p.id, bytes("A+B")),
        "the winner is the same on both"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_merged_refuses_a_superseded_id_of_another_path_and_a_non_write() {
    let mut f = fork(2, cfg()).await;
    f.head(1, "/p", "p", &[]).await;
    // `/q`'s first entry is superseded: it is applied at another path and no head.
    let q1 = f.head(1, "/q", "q1", &[]).await;
    let q2 = f.head(2, "/q", "q2", &[&q1]).await;
    assert_eq!(f.heads_at("/q").await, [q2], "q1 is no head any more");
    // The space's creation is an applied Members entry: it writes no path.
    let creation_name = log_name(&f.devs[0].name, &space(), 1);
    let creation = EntryRef {
        device: f.devs[0].name.clone(),
        seq: 1,
        digest: crate::wire::signed_digest(&f.devs[0].store.get(&creation_name).unwrap()),
    };
    let before = f.own_seq();

    let refused = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &[q1], PutOptions::default())
        .await
        .expect_err("an applied entry of another path is refused whether or not it is a head");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
    assert!(
        refused.to_string().contains("/q"),
        "it names the path: {refused}"
    );

    let refused = f
        .heap
        .put_merged(&n("/p"), bytes("m"), &[creation], PutOptions::default())
        .await
        .expect_err("a Members entry is no write at any path");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
    assert_eq!(f.own_seq(), before, "a refusal signs nothing");
}

impl Fork {
    /// Forge forging device `k`'s next entry: a blob at `path` (its pieces are nowhere), its
    /// digest ranking under `bound` when there is one.
    fn forged_blob(&mut self, k: usize, path: &str, bound: Option<&[u8; 32]>) -> (EntryId, Bytes) {
        for i in 0..16_384u32 {
            let (seq, digest) = self.last[k];
            let prev = digest.map(|digest| Prev { digest, seq: None });
            let mut root = [0u8; 32];
            root[..4].copy_from_slice(&i.to_be_bytes());
            let payload = Payload::Blob {
                size: 1 << 20,
                root,
            };
            let body = Body::Put(PutBody {
                path: n(path),
                payload,
            });
            let (id, packet) = forge(&self.devs[k], seq + 1, prev, vec![], body);
            if bound.is_none_or(|bound| id.digest < *bound) {
                self.last[k] = (seq + 1, Some(id.digest));
                return (id, packet);
            }
        }
        panic!("16384 blobs and none ranks under the bound");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_head_beyond_the_64_told_is_not_fetched() {
    let mut f = fork(1, cfg()).await;
    let _every = f.heap.get(everything(), all()).unwrap();
    let mut lowest = [0xff; 32];
    for _ in 0..crate::HEADS_MAX {
        let (id, packet) = f.forged_blob(1, "/p", None);
        lowest = lowest.min(id.digest);
        f.apply(packet).await;
    }
    assert_eq!(
        f.heap.inner.unassembled().len(),
        crate::HEADS_MAX,
        "the 64 heads a feed tells are fetched"
    );
    // Three more heads that all rank under those 64: nobody is told them.
    for _ in 0..3 {
        let (id, packet) = f.forged_blob(1, "/p", Some(&lowest));
        lowest = lowest.min(id.digest);
        f.apply(packet).await;
    }
    let held = f.heap.inner.log.lock().register.heads_of(&n("/p")).len();
    assert_eq!(held, crate::HEADS_MAX + 3);
    let owed = f.heap.inner.unassembled().len();
    assert_eq!(
        owed,
        crate::HEADS_MAX,
        "{owed} values are fetched: a head the feed will not tell is not fetched for it"
    );

    // `kept_all` reads every head, also past the 64: it says the pieces are not here yet, and
    // makes them wanted, so that reading again finds them once fetched.
    let refused = f.heap.kept_all(&n("/p")).await.unwrap_err();
    assert!(
        matches!(refused, HeapError::Unavailable { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::RetryLater);
    let owed = f.heap.inner.unassembled().len();
    assert_eq!(
        owed,
        crate::HEADS_MAX + 3,
        "{owed} values are fetched after a read of every head"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_all_feed_reads_ahead_no_more_than_its_byte_budget() {
    let mut config = cfg();
    config.heads_read = 250;
    let mut f = fork(1, config).await;
    for i in 0..6 {
        f.head(1, "/p", &format!("{i}{}", "x".repeat(99)), &[])
            .await;
    }
    let order = f.heads_at("/p").await;
    let heap = &f.heap;
    let mut feed = heap
        .inner
        .kept_feed(&heap.node, everything(), Heads::All)
        .unwrap();
    let mut told = Vec::new();
    while let Some(got) = feed.listing_next() {
        let ahead = feed.read_ahead();
        assert!(
            ahead <= 250,
            "{ahead} octets of values read ahead with a budget of 250"
        );
        told.push(kept(&got).id.clone());
    }
    assert_eq!(
        told, order,
        "every head, in rank order, whatever the budget"
    );
}
