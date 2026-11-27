//! Stage 6: `Heap::get` is one stream of the kept values of a space and its live emissions
//! (docs/specs/channel.md, The verbs: put, emit, get). The order, the duplicate rules, what a slow
//! reader keeps and loses, who `by` is and who is refused are the ones that section states.
//!
//! The kept cases run on one node (it is the writer and the reader of its own register); the cases
//! that need a sender and a receiver run on three nodes over a [`Link`] the test pumps by hand, so
//! what reached the receiver, and when, is the test's to say.

use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::FutureExt;
use ndn_foundation_types::Name;

use super::carrier_kit::LinkConfig;
use super::items::Items;
use super::rx_tests::{Wire, eventually, rig_tuned, shared};
use super::verbs::{Congestion, EmitOptions, GetNotice, GetOptions, Got, Kept, Kind, Live, Select};
use super::wire::ChannelMode;
use crate::error::{HeapError, Refusal};
use crate::log::Frontier;
use crate::node::Node;
use crate::node::tests::{Dev, boot, cfg, public, solo, space, world};
use crate::register::EntryId;
use crate::space::{Heap, MembersChange, PutOptions};
use crate::test_kit::n;

// -- What the cases read with ----------------------------------------------------------------------

fn everything() -> Select {
    Select::Prefix(Name::root())
}

/// Kept values only, as a follower may read them.
fn kept_only() -> GetOptions {
    GetOptions {
        live: Live::Off,
        ..GetOptions::default()
    }
}

/// Emissions only.
fn emitted_only() -> GetOptions {
    GetOptions {
        kept: false,
        ..GetOptions::default()
    }
}

/// An item as the cases compare it: path, value as text, and what kind it is.
type Seen = (String, String, &'static str);

fn seen(got: &Got) -> Seen {
    let kind = match &got.kind {
        Kind::Kept(kept) if kept.removed => "removed",
        Kind::Kept(_) => "kept",
        Kind::Emitted(_) => "emitted",
    };
    (
        got.path.to_string(),
        String::from_utf8_lossy(&got.bytes).into_owned(),
        kind,
    )
}

fn item(path: &str, value: &str, kind: &'static str) -> Result<Seen, GetNotice> {
    Ok((path.to_owned(), value.to_owned(), kind))
}

/// Everything the stream holds now, without waiting: items and notices, in the order given.
fn drain(items: &mut Items) -> Vec<Result<Got, GetNotice>> {
    let mut out = Vec::new();
    while let Some(Some(next)) = items.next().now_or_never() {
        out.push(next);
    }
    out
}

fn views(items: &mut Items) -> Vec<Result<Seen, GetNotice>> {
    drain(items)
        .into_iter()
        .map(|next| next.map(|got| seen(&got)))
        .collect()
}

/// Keep `value` at `path`. A writer whose space is sealed waits for the key of its epoch (the
/// refusal says to retry later): that wait is the caller's, so it is here.
async fn keep(heap: &Heap, path: &str, value: &str) -> EntryId {
    let started = Instant::now();
    loop {
        match heap
            .put(
                &n(path),
                Bytes::copy_from_slice(value.as_bytes()),
                PutOptions::default(),
            )
            .await
        {
            Ok(id) => return id,
            Err(HeapError::NotReady { .. }) if started.elapsed() < Duration::from_secs(20) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(refused) => panic!("a writer keeps a value: {refused:?}"),
        }
    }
}

// -- One node ------------------------------------------------------------------------------------

/// One device that created a public space and watches it with a queue of `queue` changes.
async fn solo_heap(queue: usize) -> (Dev, Node, Heap) {
    let dev = solo().await;
    let mut config = cfg();
    config.watch_queue = queue;
    let (node, _) = boot(&dev, config).await;
    let heap = node.create(&space(), public()).await.unwrap();
    (dev, node, heap)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_gives_the_current_kept_values_in_path_order_and_caught_up_resolves_after_them() {
    let (dev, _node, heap) = solo_heap(4096).await;
    keep(&heap, "/a", "old").await;
    let b = keep(&heap, "/b", "two").await;
    let a = keep(&heap, "/a", "one").await;
    let kept_of = |path: &str, bytes: &str, id: &EntryId| {
        Ok(Got {
            path: n(path),
            bytes: Bytes::copy_from_slice(bytes.as_bytes()),
            by: n("/alice"),
            writer: dev.name.clone(),
            kind: Kind::Kept(Kept {
                id: id.clone(),
                as_of: None,
                removed: false,
            }),
        })
    };

    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    assert_eq!(
        drain(&mut items),
        vec![kept_of("/a", "one", &a), kept_of("/b", "two", &b)],
        "the current value of each path, in path order, the superseded one never"
    );
    tokio::time::timeout(Duration::from_secs(1), items.caught_up())
        .await
        .expect("caught_up resolves once the listing was yielded");
    assert!(drain(&mut items).is_empty(), "and nothing is repeated");

    // Asked for before the listing was read, it resolves too and the listing still comes first.
    let mut early = heap.get(everything(), kept_only()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), early.caught_up())
        .await
        .expect("caught_up resolves without the listing having been read");
    assert_eq!(
        drain(&mut early),
        vec![kept_of("/a", "one", &a), kept_of("/b", "two", &b)]
    );

    // With nothing kept to deliver, there is nothing to catch up on.
    let mut live = heap.get(everything(), emitted_only()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), live.caught_up())
        .await
        .expect("an emissions-only stream is caught up at once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_select_gives_that_path_and_a_prefix_what_is_below_it_and_changes_are_filtered_too()
{
    let (_dev, _node, heap) = solo_heap(4096).await;
    keep(&heap, "/a", "a").await;
    keep(&heap, "/a/b", "ab").await;
    keep(&heap, "/c", "c").await;
    let mut one = heap
        .get(Select::Path(n("/a")), GetOptions::default())
        .unwrap();
    let mut below = heap
        .get(Select::Prefix(n("/a")), GetOptions::default())
        .unwrap();
    assert_eq!(views(&mut one), vec![item("/a", "a", "kept")]);
    assert_eq!(
        views(&mut below),
        vec![item("/a", "a", "kept"), item("/a/b", "ab", "kept")]
    );
    keep(&heap, "/c", "c2").await;
    keep(&heap, "/a/b", "ab2").await;
    assert!(views(&mut one).is_empty(), "/a did not change");
    assert_eq!(views(&mut below), vec![item("/a/b", "ab2", "kept")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kept_changes_follow_the_listing_in_apply_order() {
    let (_dev, _node, heap) = solo_heap(4096).await;
    keep(&heap, "/a", "1").await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    keep(&heap, "/a", "2").await;
    keep(&heap, "/b", "x").await;
    keep(&heap, "/a", "3").await;
    assert_eq!(
        views(&mut items),
        vec![
            item("/a", "1", "kept"),
            item("/a", "2", "kept"),
            item("/b", "x", "kept"),
            item("/a", "3", "kept"),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_is_delivered_as_kept_with_removed_set() {
    let (_dev, _node, heap) = solo_heap(4096).await;
    keep(&heap, "/a", "here").await;
    keep(&heap, "/keep", "k").await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    assert_eq!(views(&mut items).len(), 2);

    let gone = keep(&heap, "/a", "").await;
    let got = drain(&mut items);
    assert_eq!(got.len(), 1, "{got:?}");
    let got = got.into_iter().next().unwrap().unwrap();
    assert_eq!(got.path, n("/a"));
    assert!(got.bytes.is_empty(), "a removal carries no bytes");
    assert_eq!(
        got.kind,
        Kind::Kept(Kept {
            id: gone,
            as_of: None,
            removed: true
        })
    );
}

/// What a slow reader is owed when its queue of `watch_queue` changes overflowed: no loss is
/// shown, every path's current value is read again from the store, and what it was given before
/// is not given twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_reader_loses_no_path_and_is_given_the_latest_value_never_an_older_after_a_newer() {
    let (_dev, _node, heap) = solo_heap(4).await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    // `watch` has the same queue: what it does with this is the premise of the case.
    let mut watched = heap.watch(&Frontier::everything()).await.unwrap();

    keep(&heap, "/x", "1").await;
    for i in 0..6 {
        keep(&heap, &format!("/s/{i}"), &format!("v{i}")).await;
    }
    keep(&heap, "/x", "2").await;
    keep(&heap, "/x", "3").await;

    let mut lagged = false;
    while let Some(Some(change)) = watched.next().now_or_never() {
        lagged |= matches!(change, Ok(crate::log::Change::Lagged { .. }));
    }
    assert!(lagged, "the queue of 4 overflowed for `watch`");

    assert_eq!(
        views(&mut items),
        vec![
            // what the queue held: the first four changes
            item("/x", "1", "kept"),
            item("/s/0", "v0", "kept"),
            item("/s/1", "v1", "kept"),
            item("/s/2", "v2", "kept"),
            // the current value of every path the queue did not hold, from the store, in path order
            item("/s/3", "v3", "kept"),
            item("/s/4", "v4", "kept"),
            item("/s/5", "v5", "kept"),
            item("/x", "3", "kept"),
        ],
        "no notice of a loss, every path's current value, /x never 2 and never 1 after 3"
    );

    // And the stream goes on as it was.
    keep(&heap, "/after", "ok").await;
    assert_eq!(views(&mut items), vec![item("/after", "ok", "kept")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removal_the_queue_dropped_is_still_told() {
    let (_dev, _node, heap) = solo_heap(4).await;
    keep(&heap, "/gone", "here").await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    assert_eq!(views(&mut items), vec![item("/gone", "here", "kept")]);

    for i in 0..6 {
        keep(&heap, &format!("/f/{i}"), "v").await;
    }
    let removal = keep(&heap, "/gone", "").await;

    let got = drain(&mut items);
    let told: Vec<(String, bool)> = got
        .iter()
        .map(|next| match next {
            Ok(got) => (
                got.path.to_string(),
                matches!(&got.kind, Kind::Kept(Kept { removed: true, .. })),
            ),
            Err(notice) => panic!("a lost queue is not shown: {notice:?}"),
        })
        .collect();
    let expect: Vec<(String, bool)> = ["/f/0", "/f/1", "/f/2", "/f/3", "/f/4", "/f/5", "/gone"]
        .iter()
        .map(|p| (p.to_string(), *p == "/gone"))
        .collect();
    assert_eq!(told, expect, "every path once, the removal among them");
    let Some(Ok(last)) = got.last() else {
        unreachable!()
    };
    assert!(last.bytes.is_empty());
    assert!(
        matches!(&last.kind, Kind::Kept(k) if k.removed && k.id == removal),
        "{last:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_refused_after_it_was_delivered_is_told_withdrawn_and_what_it_superseded_returns()
{
    let (dev, node, heap) = solo_heap(4096).await;
    let first = keep(&heap, "/a", "v1").await;
    let second = keep(&heap, "/a", "v2").await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    assert_eq!(views(&mut items), vec![item("/a", "v2", "kept")]);

    {
        let mut log = heap.inner.log.lock();
        let fx = log.withdraw(&dev.name, second.seq, Refusal::NotMember);
        heap.inner.route(&node.inner, &log, fx, false);
    }
    let got = drain(&mut items);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(
        got[0],
        Err(GetNotice::Withdrawn {
            id: second,
            why: Refusal::NotMember
        })
    );
    let back = got[1].as_ref().unwrap();
    assert_eq!(seen(back), ("/a".to_owned(), "v1".to_owned(), "kept"));
    assert!(matches!(&back.kind, Kind::Kept(k) if k.id == first));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn asking_for_nothing_is_refused_with_why_and_kept_only_is_allowed() {
    let (_dev, _node, heap) = solo_heap(4096).await;
    let nothing = GetOptions {
        kept: false,
        live: Live::Off,
        ..GetOptions::default()
    };
    let refused = heap.get(everything(), nothing).expect_err("nothing wanted");
    match &refused {
        HeapError::BadRequest { why } => assert!(
            why.contains("kept: false") && why.contains("Live::Off"),
            "the refusal says what was asked and what to do: {why}"
        ),
        other => panic!("BadRequest, not {other:?}"),
    }
    heap.get(everything(), kept_only())
        .expect("kept values with no emissions is a read");
    heap.get(everything(), emitted_only())
        .expect("emissions with no kept values is a stream of what channels deliver");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follower_is_refused_live_and_may_read_kept_values_with_live_off() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let _follower = node.follow(&space()).await.unwrap();
    let held = node.inner.space_of(&space()).expect("the carrier holds it");
    assert!(held.follower);
    let heap = Heap::new(held, std::sync::Arc::clone(&node.inner));

    let refused = heap
        .get(everything(), GetOptions::default())
        .expect_err("a follower takes no part in channels");
    assert!(
        matches!(refused, HeapError::NotAllowed { .. }),
        "{refused:?}"
    );
    let mut items = heap
        .get(everything(), kept_only())
        .expect("a follower reads kept values");
    tokio::time::timeout(Duration::from_secs(1), items.caught_up())
        .await
        .expect("caught up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_items_closes_both_feeds() {
    let (_dev, node, heap) = solo_heap(4096).await;
    let items = heap.get(everything(), GetOptions::default()).unwrap();
    assert!(
        node.inner.chan.rx.wanted(&space(), ChannelMode::Latest),
        "the emission sink is installed at creation"
    );
    assert_eq!(heap.inner.watching(), 1, "the kept watcher too");
    drop(items);
    assert!(
        !node.inner.chan.rx.wanted(&space(), ChannelMode::Latest),
        "the sink is gone"
    );
    assert_eq!(heap.inner.watching(), 0, "and the watcher");

    // A stream of kept values alone installs no sink; of emissions alone, no watcher.
    let kept = heap.get(everything(), kept_only()).unwrap();
    assert!(!node.inner.chan.rx.wanted(&space(), ChannelMode::Latest));
    assert_eq!(heap.inner.watching(), 1);
    drop(kept);
    let live = heap.get(everything(), emitted_only()).unwrap();
    assert!(node.inner.chan.rx.wanted(&space(), ChannelMode::Latest));
    assert_eq!(heap.inner.watching(), 0);
    drop(live);
}

// -- Three nodes -----------------------------------------------------------------------------------

/// Alice owns the space, Bob writes (his phone sends), Carol reads.
async fn three(link: LinkConfig, queue: usize) -> Wire {
    let rig = rig_tuned(
        world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await,
        |config| config.watch_queue = queue,
    )
    .await;
    shared(&rig).await;
    let link = super::carrier_kit::Link::new(link);
    rig.nodes[1].attach_carrier(link.clone());
    Wire { rig, link }
}

fn carol_heap(w: &Wire) -> Heap {
    w.carol().space(&space()).unwrap()
}

fn carol_get(w: &Wire, opts: GetOptions) -> Items {
    carol_heap(w).get(everything(), opts).unwrap()
}

/// Carol holds `path` with `value` (the entry came by sync).
async fn holds(w: &Wire, path: &str, value: &str) {
    let heap = carol_heap(w);
    let started = Instant::now();
    loop {
        let held = heap.kept(&n(path)).await;
        if matches!(&held, Ok(Some(item)) if item.bytes == value.as_bytes()) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "carol never held {path} = {value}: {held:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Hand Carol what the link holds until `watcher` (an emissions-only `Items` of hers, which takes
/// the same messages as any other) has been given a message whose bytes begin with `last`: every
/// `Items` of Carol's then holds what the watcher was given. Returns what the watcher was given.
async fn pump_until(w: &Wire, watcher: &mut Items, last: &str) -> Vec<Got> {
    let started = Instant::now();
    let mut got = Vec::new();
    loop {
        w.pump(|_| {}).await;
        got.extend(drain(watcher).into_iter().flatten());
        if got.iter().any(|g| g.bytes.starts_with(last.as_bytes())) {
            return got;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{last} never reached carol: {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_gets_the_kept_values_before_the_emissions_queued_before_its_first_poll() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    keep(&bob, "/b", "kept-b").await;
    keep(&bob, "/a", "kept-a").await;
    holds(&w, "/a", "kept-a").await;
    holds(&w, "/b", "kept-b").await;

    let mut items = carol_get(&w, GetOptions::default());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;
    bob.emit(
        &n("/a"),
        Bytes::from_static(b"live-a"),
        EmitOptions::latest(),
    )
    .await
    .unwrap();
    // The emission is queued in `items` now; nothing of `items` was polled.
    pump_until(&w, &mut watcher, "live-a").await;

    assert_eq!(
        views(&mut items),
        vec![
            item("/a", "kept-a", "kept"),
            item("/b", "kept-b", "kept"),
            item("/a", "live-a", "emitted"),
        ],
        "the kept listing in path order first, then what was emitted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_put_and_an_emit_on_one_path_are_each_delivered_once_tagged_never_merged() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    let mut items = carol_get(&w, GetOptions::default());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;

    keep(&bob, "/p", "same").await;
    bob.emit(&n("/p"), Bytes::from_static(b"same"), EmitOptions::latest())
        .await
        .unwrap();
    holds(&w, "/p", "same").await;
    pump_until(&w, &mut watcher, "same").await;

    let mut got: Vec<Seen> = Vec::new();
    for _ in 0..3 {
        // More pumping and more polling add nothing: each is delivered once.
        w.pump(|_| {}).await;
        got.extend(
            drain(&mut items)
                .into_iter()
                .map(|next| seen(&next.expect("no notice"))),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    got.sort();
    assert_eq!(
        got,
        vec![
            ("/p".to_owned(), "same".to_owned(), "emitted"),
            ("/p".to_owned(), "same".to_owned(), "kept"),
        ],
        "one Kept and one Emitted: an emission is never the current value and a put never hides it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn by_is_the_authenticated_person_and_writer_the_device_for_both_kinds() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    let mut items = carol_get(&w, GetOptions::default());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;
    let id = keep(&bob, "/w", "kept").await;
    bob.emit(&n("/w"), Bytes::from_static(b"live"), EmitOptions::latest())
        .await
        .unwrap();
    holds(&w, "/w", "kept").await;
    pump_until(&w, &mut watcher, "live").await;

    let got: Vec<Got> = drain(&mut items)
        .into_iter()
        .map(|next| next.expect("no notice"))
        .collect();
    assert_eq!(got.len(), 2, "{got:?}");
    for one in &got {
        assert_eq!(one.by, n("/bob"), "the writer's person: {one:?}");
        assert_eq!(one.writer, n("/bob/phone"), "the writer's device: {one:?}");
    }
    let kept = got
        .iter()
        .find_map(|g| match &g.kind {
            Kind::Kept(k) => Some(k),
            Kind::Emitted(_) => None,
        })
        .expect("a kept item");
    assert_eq!(kept.id, id);
    let read = carol_heap(&w).kept(&n("/w")).await.unwrap().unwrap();
    assert_eq!((&read.by, &read.writer), (&n("/bob"), &n("/bob/phone")));
}

/// A writer who has put nothing is heard from his first emission (channel.md §9): the receiver
/// holds no entry of his device, so it cannot vouch for it by the record, and the announce he
/// pushes is taken as a hint all the same. His person is a writer the record lists; the ask the
/// hint makes is signed, and his answer carries his certificates, so what he says of himself is
/// judged by the space's trust and not believed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_who_never_put_is_heard_from_his_first_emission() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    let device = n("/bob/phone");
    let vouched = |w: &Wire| carol_heap(w).inner.log.lock().vouches(&device);
    assert!(
        !vouched(&w),
        "the case needs a receiver that holds no entry of bob's device: he has put nothing"
    );
    // Carol only waits: she asks nobody by name; the announce is what tells her.
    let mut watcher = carol_get(&w, emitted_only());
    let started = Instant::now();
    let mut got = Vec::new();
    while got.is_empty() {
        bob.emit(
            &n("/cursor"),
            Bytes::from_static(b"here"),
            EmitOptions::latest(),
        )
        .await
        .unwrap();
        w.pump(|_| {}).await;
        got.extend(drain(&mut watcher).into_iter().flatten());
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "bob's emissions never reached carol, who holds no entry of his device: the announce \
             of a writer who has not put was not acted on"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(&got[0].bytes[..], b"here");
    assert_eq!((&got[0].by, &got[0].writer), (&n("/bob"), &device));
    assert!(
        matches!(got[0].kind, Kind::Emitted(_)),
        "an emission, not a kept value: {:?}",
        got[0]
    );
    assert!(
        !vouched(&w),
        "carol still holds no entry of his device: he was heard without a put"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_member_gets_nothing_neither_kept_values_nor_a_session() {
    let w = three(LinkConfig::default(), 4096).await;
    keep(&w.bob(), "/secret", "s").await;
    holds(&w, "/secret", "s").await;
    let owner = w.rig.nodes[0].space(&space()).unwrap();
    owner
        .change(MembersChange {
            remove: vec![n("/carol")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol holds the removal", || {
        !w.carol()
            .inner
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .is_reader(&n("/carol"))
    })
    .await;

    let refused = carol_heap(&w)
        .get(everything(), GetOptions::default())
        .expect_err("a person the space no longer lists reads nothing of it");
    assert!(matches!(refused, HeapError::Sealed { .. }), "{refused:?}");
    let refused = carol_heap(&w)
        .get(everything(), kept_only())
        .expect_err("not with emissions off either");
    assert!(matches!(refused, HeapError::Sealed { .. }), "{refused:?}");
    assert!(
        w.carol()
            .ask_channel_in(&space(), w.rig.nodes[1].name(), ChannelMode::Latest)
            .await
            .is_err(),
        "and no sender gives her a session"
    );
}

/// A kept feed that is open when its reader is removed gives no further value, whether or not its
/// queue overflowed: what it had queued before the removal reached this node is not told, and the
/// feed ends saying why (a removed member gets no kept value, §17.7).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_kept_feed_ends_when_its_reader_is_removed_though_its_queue_never_overflowed() {
    let w = three(LinkConfig::default(), 4096).await;
    let mut items = carol_get(&w, kept_only());
    assert_eq!(drain(&mut items), vec![], "an empty space has no listing");
    keep(&w.bob(), "/before", "v").await;
    holds(&w, "/before", "v").await;
    let owner = w.rig.nodes[0].space(&space()).unwrap();
    owner
        .change(MembersChange {
            remove: vec![n("/carol")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    eventually("carol holds the removal", || {
        !w.carol()
            .inner
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .is_reader(&n("/carol"))
    })
    .await;

    let got = drain(&mut items);
    assert!(
        got.iter().all(Result::is_err),
        "a removed reader was given a kept value: {got:?}"
    );
    let [Err(GetNotice::KeptEnded { why })] = &got[..] else {
        panic!("the feed says it ended, once: {got:?}")
    };
    assert!(
        why.contains("reader") && why.contains("owner"),
        "it says why and what to do: {why}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn latest_emissions_coalesce_per_name_and_lag_past_the_bound_while_kept_items_are_unaffected()
{
    let w = three(
        LinkConfig {
            datagram_capacity: 100_000,
            ..LinkConfig::default()
        },
        4096,
    )
    .await;
    let bob = w.bob();
    keep(&bob, "/k", "kept").await;
    holds(&w, "/k", "kept").await;
    let mut items = carol_get(&w, GetOptions::default());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;

    // Five values of one name, none read: the newest is what is left, and that is no loss.
    for i in 1..=5 {
        bob.emit(&n("/n"), Bytes::from(i.to_string()), EmitOptions::latest())
            .await
            .unwrap();
    }
    pump_until(&w, &mut watcher, "5").await;
    assert_eq!(
        views(&mut items),
        vec![item("/k", "kept", "kept"), item("/n", "5", "emitted")],
        "the kept value as always, one value of /n, the newest, and no notice"
    );

    // Many names past the queue's byte bound: the oldest are evicted and counted, and the newest
    // name is there.
    let total = 1500;
    for i in 0..total {
        let mut value = format!("{i:04}").into_bytes();
        value.resize(1000, b'.');
        bob.emit(
            &n(&format!("/m/{i}")),
            Bytes::from(value),
            EmitOptions::latest(),
        )
        .await
        .unwrap();
    }
    pump_until(&w, &mut watcher, &format!("{:04}", total - 1)).await;
    let (mut delivered, mut missed) = (Vec::new(), 0u64);
    for next in drain(&mut items) {
        match next {
            Ok(got) => {
                assert!(matches!(got.kind, Kind::Emitted(_)), "{got:?}");
                delivered.push(got.path.to_string());
            }
            Err(GetNotice::Lagged { missed: m }) => missed += m,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert!(
        missed > 0,
        "past 1 MiB the oldest names are evicted and counted"
    );
    assert!(
        delivered.contains(&format!("/m/{}", total - 1)),
        "the newest is kept"
    );
    let mut unique = delivered.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), delivered.len(), "no name twice");
    assert!(
        (delivered.len() as u64) < total,
        "1 MiB holds fewer than {total} messages of 1 KB: {} delivered",
        delivered.len()
    );
}

/// The host's read loop never waits: `deliver_frame` takes every frame it is handed. On one worker
/// with the consumer of `Items` (a host's runtime, a slow core) a loop that is never interrupted
/// runs ahead of the consumer, until the queue's 1 MiB bound evicts messages that were opened,
/// checked and queued for nothing. `deliver_frame` lets the consumer run once in a while.
#[tokio::test(flavor = "current_thread")]
async fn a_tight_read_loop_lets_the_consumer_run_so_a_burst_that_fits_in_turn_loses_nothing() {
    let w = three(
        LinkConfig {
            datagram_max: 9_000,
            datagram_capacity: 100_000,
            ..LinkConfig::default()
        },
        4096,
    )
    .await;
    let bob = w.bob();
    let items = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;
    let (delivered, missed) = (
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
    );
    let consumer = {
        let (delivered, missed) = (delivered.clone(), missed.clone());
        let mut items = items;
        tokio::spawn(async move {
            while let Some(next) = items.next().await {
                match next {
                    Ok(_) => delivered.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                    Err(GetNotice::Lagged { missed: m }) => {
                        missed.fetch_add(m, std::sync::atomic::Ordering::Relaxed)
                    }
                    Err(other) => panic!("{other:?}"),
                };
            }
        })
    };
    // 1,600 messages of 1 KB on distinct names (1.7 MB, over the queue's 1 MiB bound), emitted in
    // rounds the sender's own queue holds, each round let out to the link before the next.
    let total = 1_600u64;
    for i in 0..total {
        let mut value = format!("{i:04}").into_bytes();
        value.resize(1000, b'.');
        bob.emit(
            &n(&format!("/m/{i}")),
            Bytes::from(value),
            EmitOptions::latest(),
        )
        .await
        .unwrap();
        if i % 200 == 199 {
            for _ in 0..200 {
                tokio::task::yield_now().await;
            }
        }
    }
    // The frames are handed over in one loop, which the consumer shares the thread with.
    let (mut frames, mut carried) = (0, 0u64);
    while let Some(frame) = w.link.pop_datagram() {
        match w.carol().deliver_frame(frame, 1).await {
            super::rx::Delivery::Delivered { messages } => carried += messages as u64,
            other => panic!("{other:?}"),
        }
        frames += 1;
    }
    assert!(frames > 100, "the burst is many frames: {frames}");
    assert!(
        carried > 1_000,
        "the burst is over the queue's bound: {carried}"
    );
    let started = Instant::now();
    while delivered.load(std::sync::atomic::Ordering::Relaxed)
        + missed.load(std::sync::atomic::Ordering::Relaxed)
        < carried
    {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{carried} carried, {} delivered, {} missed",
            delivered.load(std::sync::atomic::Ordering::Relaxed),
            missed.load(std::sync::atomic::Ordering::Relaxed)
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    consumer.abort();
    assert_eq!(
        missed.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "no message was evicted: the consumer ran between the frames of the burst"
    );
    assert_eq!(
        delivered.load(std::sync::atomic::Ordering::Relaxed),
        carried
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_with_drop_discards_the_oldest_and_says_lagged_while_kept_items_are_unaffected() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    keep(&bob, "/k", "kept").await;
    holds(&w, "/k", "kept").await;
    let dropping = GetOptions {
        congestion: Congestion::Drop,
        ..GetOptions::default()
    };
    let mut items = carol_get(&w, dropping);
    // The watcher drops too, so it is drained as it goes and never stalls the stream.
    let mut watcher = carol_get(
        &w,
        GetOptions {
            kept: false,
            ..dropping
        },
    );
    w.join(ChannelMode::Reliable).await;
    let emitted = 6u8;
    for i in 0..emitted {
        let mut bytes = vec![b'0' + i];
        bytes.resize(400 * 1024, 0);
        bob.emit(&n("/big"), Bytes::from(bytes), EmitOptions::reliable())
            .await
            .unwrap();
        pump_until(&w, &mut watcher, &((b'0' + i) as char).to_string()).await;
    }

    let (mut kept, mut emitted_seen, mut missed) = (Vec::new(), Vec::new(), 0u64);
    for next in drain(&mut items) {
        match next {
            Ok(got) => match got.kind {
                Kind::Kept(_) => kept.push(seen(&got)),
                Kind::Emitted(_) => emitted_seen.push(got.bytes[0]),
            },
            Err(GetNotice::Lagged { missed: m }) => missed += m,
            Err(other) => panic!("{other:?}"),
        }
    }
    assert_eq!(
        kept,
        vec![("/k".to_owned(), "kept".to_owned(), "kept")],
        "the kept value is delivered whatever the emissions did to their queue"
    );
    assert!(
        missed >= 1,
        "1 MiB of queue, 2.4 MiB sent: {emitted_seen:?}"
    );
    assert_eq!(
        emitted_seen.last().copied(),
        Some(b'0' + emitted - 1),
        "the newest is kept"
    );
    assert!(
        emitted_seen.windows(2).all(|p| p[0] < p[1]),
        "in the channel's order: {emitted_seen:?}"
    );
    assert_eq!(
        emitted_seen.len() as u64 + missed,
        u64::from(emitted),
        "every message was delivered or counted: {emitted_seen:?}, missed {missed}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reliable_with_block_stalls_the_stream_loses_nothing_and_kept_items_still_come() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    keep(&bob, "/k", "kept").await;
    holds(&w, "/k", "kept").await;
    let mut items = carol_get(&w, GetOptions::default());
    w.join(ChannelMode::Reliable).await;
    let emitted = 5u8;
    let kept_later = keep(&bob, "/later", "kept-later");

    let consumer = async {
        let (mut kept, mut values) = (Vec::new(), Vec::new());
        let started = Instant::now();
        while kept.len() < 2 || values.len() < usize::from(emitted) {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "kept {kept:?}, emitted {values:?}"
            );
            match tokio::time::timeout(Duration::from_millis(200), items.next()).await {
                Ok(Some(Ok(got))) => match got.kind {
                    Kind::Kept(_) => kept.push(seen(&got)),
                    Kind::Emitted(_) => values.push(got.bytes[0]),
                },
                Ok(Some(Err(notice))) => panic!("Block loses nothing: {notice:?}"),
                Ok(None) => panic!("the stream ended"),
                Err(_) => {}
            }
        }
        (kept, values)
    };
    let feed = async {
        let emitter = async {
            kept_later.await;
            for i in 0..emitted {
                let mut bytes = vec![b'0' + i];
                bytes.resize(400 * 1024, 0);
                bob.emit(&n("/big"), Bytes::from(bytes), EmitOptions::reliable())
                    .await
                    .unwrap();
            }
        };
        let pumper = async {
            loop {
                w.pump(|_| {}).await;
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        };
        tokio::join!(emitter, pumper)
    };
    let (kept, values) = tokio::select! {
        got = consumer => got,
        _ = feed => unreachable!("the pump does not end"),
    };
    assert_eq!(
        kept,
        vec![
            ("/k".to_owned(), "kept".to_owned(), "kept"),
            ("/later".to_owned(), "kept-later".to_owned(), "kept"),
        ]
    );
    assert_eq!(values, (0..emitted).map(|i| b'0' + i).collect::<Vec<_>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn next_batch_hands_over_the_listing_then_the_kept_changes_without_waiting() {
    let (_dev, _node, heap) = solo_heap(4096).await;
    keep(&heap, "/b", "2").await;
    keep(&heap, "/a", "1").await;
    let mut items = heap.get(everything(), GetOptions::default()).unwrap();
    keep(&heap, "/c", "3").await;
    let mut buf = Vec::new();
    assert_eq!(items.next_batch(&mut buf), 3);
    assert_eq!(
        buf.iter().map(seen).collect::<Vec<_>>(),
        vec![
            ("/a".to_owned(), "1".to_owned(), "kept"),
            ("/b".to_owned(), "2".to_owned(), "kept"),
            ("/c".to_owned(), "3".to_owned(), "kept"),
        ],
        "the listing in path order, then the change"
    );
    assert_eq!(
        items.next_batch(&mut buf),
        0,
        "nothing queued: it never waits"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kept_changes_and_emissions_are_taken_in_turn_so_neither_starves_the_other() {
    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    let mut items = carol_get(&w, GetOptions::default());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;
    for i in 0..40 {
        keep(&bob, &format!("/k/{i:02}"), "v").await;
    }
    for i in 0..3 {
        bob.emit(
            &n(&format!("/e/{i}")),
            Bytes::from_static(b"live"),
            EmitOptions::latest(),
        )
        .await
        .unwrap();
    }
    for i in 0..40 {
        holds(&w, &format!("/k/{i:02}"), "v").await;
    }
    let mut emitted = 0;
    let started = Instant::now();
    while emitted < 3 {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{emitted} of 3"
        );
        w.pump(|_| {}).await;
        emitted += drain(&mut watcher).len();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let got: Vec<Seen> = drain(&mut items)
        .into_iter()
        .map(|next| seen(&next.expect("no notice")))
        .collect();
    assert_eq!(got.len(), 43, "{got:?}");
    assert!(
        got[..2].iter().any(|(_, _, kind)| *kind == "emitted")
            && got[..2].iter().any(|(_, _, kind)| *kind == "kept"),
        "the first two polls took one of each: {:?}",
        &got[..2]
    );
    let mut kept: Vec<&String> = got
        .iter()
        .filter(|(_, _, kind)| *kind == "kept")
        .map(|(path, _, _)| path)
        .collect();
    kept.sort();
    kept.dedup();
    assert_eq!(kept.len(), 40, "each kept path once: {got:?}");
}

/// A poll that finds nothing registers the consumer's waker and a message that then arrives wakes
/// it; a poll that finds a message ready returns it and does not wake the waker it is given.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_items_poll_registers_its_waker_only_when_nothing_is_ready_and_is_woken_by_the_next_message()
 {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    use futures::Stream;

    struct Counting(AtomicUsize);
    impl Wake for Counting {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let w = three(LinkConfig::default(), 4096).await;
    let bob = w.bob();
    let mut items = carol_get(&w, emitted_only());
    let mut watcher = carol_get(&w, emitted_only());
    w.join(ChannelMode::Latest).await;
    // Frames that came with the join (HELLO, checkpoints) are not messages: drain what is there.
    w.pump(|_| {}).await;
    drain(&mut items);

    let first = Arc::new(Counting(AtomicUsize::new(0)));
    let first_waker = Waker::from(Arc::clone(&first));
    let mut cx = Context::from_waker(&first_waker);
    assert!(
        matches!(Pin::new(&mut items).poll_next(&mut cx), Poll::Pending),
        "nothing is ready"
    );
    assert_eq!(first.0.load(Ordering::SeqCst), 0);

    bob.emit(&n("/w"), Bytes::from_static(b"one"), EmitOptions::latest())
        .await
        .unwrap();
    pump_until(&w, &mut watcher, "one").await;
    assert_eq!(
        first.0.load(Ordering::SeqCst),
        1,
        "the message woke the waker the empty poll registered"
    );

    // A message is ready now: polled with another waker it is returned, and that is not woken.
    let second = Arc::new(Counting(AtomicUsize::new(0)));
    let second_waker = Waker::from(Arc::clone(&second));
    let mut cx2 = Context::from_waker(&second_waker);
    match Pin::new(&mut items).poll_next(&mut cx2) {
        Poll::Ready(Some(Ok(got))) => assert_eq!(&got.bytes[..], b"one"),
        other => panic!("the queued message is given: {other:?}"),
    }
    assert_eq!(second.0.load(Ordering::SeqCst), 0);
}
