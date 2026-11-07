//! The merge machinery against what the slice 6 review found: parents
//! bound to the packets they name (a checkpoint covers only what its writer
//! applied), a version applied only under the rule it was made for, a past
//! that is the same on every device, `/merge/yrs` updates bounded by their
//! past, a rule's apply never refusing for the state it meets, pieces
//! served by the devices that applied them, and large operations kept out
//! of memory.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::merge_tests::{
    Made, Notes, RULE, at, body_in, c, checkpoint, device, device_on, edit, give, id, key, made_in,
    n, notes, options, rules, state, tip, version,
};
use super::*;
use crate::layer::Share;
use ndn_sync::MemoryStore;

/// The same rule as [`RULE`], under its next name.
const V2: &str = "/test/merge/notes/v=2";

fn both_rules() -> MergeRules {
    rules().with(Arc::new(Notes { function: n(V2) }))
}

fn share_under(rule: &str, writers: &[&str]) -> Share {
    Share {
        rule: Rule::Merge { function: n(rule) },
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: Vec::new(),
    }
}

/// The notes of collection `c` in `dev`'s state.
async fn notes_of(dev: &Device, c: &Name) -> Vec<String> {
    match dev.get(c).await.unwrap().got {
        Got::State(s) => notes(&s),
        other => panic!("not a state: {other:?}"),
    }
}

#[tokio::test]
async fn a_state_another_writer_made_never_refuses_a_version_nor_withdraws_its_group() {
    let trip = |x: &str| n(&format!("/alice/32=data/trip/{x}"));
    let (plan, budget) = (trip("plan"), trip("budget"));
    let dev = super::merge_tests::device_under(rules(), &plan, RULE).await;
    dev.share(&budget, share_under(RULE, &["/alice", "/bob", "/carol"]))
        .await
        .unwrap();
    let grouped = |c: &Name, seq: u64, op: Bytes| {
        let mut body = body_in(c, RULE, &[], op);
        body.group = Some(Group { id: 10, count: 2 });
        made_in(c, "/bob/laptop", seq, Record::Version(body))
    };
    // Carol notes "a" first; Bob's group claims "a" in the plan and adds
    // "b" to the budget. His claim meets a state Carol made: it does not
    // count, and refuses nothing of his.
    let carol = made_in(
        &plan,
        "/carol/laptop",
        5,
        Record::Version(body_in(&plan, RULE, &[], edit(None, "a"))),
    );
    let claim = grouped(&plan, 10, Bytes::from_static(b"Xa"));
    let other = grouped(&budget, 11, edit(None, "b"));
    for m in [&carol, &claim, &other] {
        give(&dev, m);
    }
    assert!(
        notes_of(&dev, &budget).await.contains(&"b".to_owned()),
        "the group's other member counts"
    );
    let st = dev.inner.st.lock();
    assert!(
        !st.refused.contains_key(&claim.name),
        "{:?}",
        st.refused.get(&claim.name)
    );
    assert!(st.colls[&plan].not_counted.contains_key(&claim.id()));
    drop(st);
    dev.shutdown();
}

/// Carol's edits `from..=to`, each made over the one before `prev`.
fn carols(prev: &Made, from: u64, to: u64) -> Vec<Made> {
    let mut out: Vec<Made> = Vec::new();
    for s in from..=to {
        let parent = tip(out.last().unwrap_or(prev));
        out.push(version(
            "/carol/laptop",
            s,
            &[parent],
            edit(None, &format!("c{s}")),
        ));
    }
    out
}

#[tokio::test]
async fn a_checkpoint_naming_a_parent_its_writer_never_saw_covers_nothing() {
    let dev = device(rules()).await;
    let c5 = version("/carol/laptop", 5, &[], edit(None, "c5"));
    // Bob signs a checkpoint over Carol's seq 12 while she is at 5: the
    // packet it names does not exist yet, so he cannot know its digest.
    let cp = version(
        "/bob/laptop",
        10,
        &[(id("/carol/laptop", 12), [0xab; 32])],
        checkpoint(&["bob"]),
    );
    give(&dev, &c5);
    give(&dev, &cp);
    for m in carols(&c5, 6, 12) {
        give(&dev, &m);
    }
    let s = state(&dev).await;
    for seq in 5..=12 {
        assert!(
            notes(&s).contains(&format!("c{seq}")),
            "Carol's edit {seq} survives: {:?}",
            notes(&s)
        );
    }
    assert!(!s.at.contains(&cp.id()), "the checkpoint is not applied");
    let why = dev.inner.st.lock().refused.get(&cp.name).cloned();
    assert!(
        matches!(&why, Some(Refusal::Parent { parent, .. }) if *parent == id("/carol/laptop", 12)),
        "{why:?}"
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_checkpoint_naming_its_readers_own_future_never_erases_its_edits() {
    let dev = device(rules()).await;
    let first = dev.put_op(&c(), edit(None, "a1"), options()).await.unwrap();
    let ahead = VersionId {
        writer: first.writer.clone(),
        seq: Seq(first.seq.0 + 4),
    };
    let cp = version(
        "/bob/laptop",
        10,
        &[(ahead, [0xcd; 32])],
        checkpoint(&["bob"]),
    );
    give(&dev, &cp);
    for i in 2..=5 {
        dev.put_op(&c(), edit(None, &format!("a{i}")), options())
            .await
            .unwrap();
    }
    // Whatever arrives next runs what waits.
    give(&dev, &version("/carol/laptop", 1, &[], edit(None, "c1")));
    let s = state(&dev).await;
    for i in 1..=5 {
        assert!(
            notes(&s).contains(&format!("a{i}")),
            "the writer's own edit {i} survives: {:?}",
            notes(&s)
        );
    }
    assert!(!s.at.contains(&cp.id()));
    dev.shutdown();
}

#[tokio::test]
async fn a_checkpoint_over_a_parent_that_never_applies_is_refused() {
    let dev = device(rules()).await;
    let c5 = version("/carol/laptop", 5, &[], edit(None, "c5"));
    give(&dev, &c5);
    // Carol is removed; the owner held nothing of hers past 5.
    dev.share(&c(), share_under(RULE, &["/alice", "/bob"]))
        .await
        .unwrap();
    // Bob names her seq 9, which no reader applies, to stand for 6..9.
    let cp = version(
        "/bob/laptop",
        10,
        &[(id("/carol/laptop", 9), [0xee; 32])],
        checkpoint(&["bob"]),
    );
    give(&dev, &cp);
    let s = state(&dev).await;
    assert!(!s.at.contains(&cp.id()));
    assert!(notes(&s).contains(&"c5".to_owned()));
    let why = dev.inner.st.lock().refused.get(&cp.name).cloned();
    assert!(matches!(why, Some(Refusal::Parent { .. })), "{why:?}");
    dev.shutdown();
}

#[tokio::test]
async fn a_version_made_under_another_rule_is_never_applied_under_the_one_in_force() {
    let dev = device(both_rules()).await;
    let b10 = version("/bob/laptop", 10, &[], edit(None, "before"));
    give(&dev, &b10);
    // The owner moves the collection to the rule's next version; Bob, not
    // having heard, writes one more operation for the first.
    dev.share(&c(), share_under(V2, &["/alice", "/bob", "/carol"]))
        .await
        .unwrap();
    let stale = version("/bob/laptop", 11, &[tip(&b10)], edit(None, "stale"));
    let fresh = made_in(
        &c(),
        "/bob/laptop",
        12,
        Record::Version(body_in(&c(), V2, &[tip(&stale)], edit(None, "fresh"))),
    );
    give(&dev, &stale);
    give(&dev, &fresh);
    let s = state(&dev).await;
    assert!(!notes(&s).contains(&"stale".to_owned()), "{:?}", notes(&s));
    assert!(notes(&s).contains(&"fresh".to_owned()), "{:?}", notes(&s));
    let why = dev.inner.st.lock().refused.get(&stale.name).cloned();
    match why {
        Some(r @ Refusal::OtherRule { .. }) => {
            assert_eq!(
                DataError::Refused {
                    id: stale.id(),
                    why: r
                }
                .next(),
                crate::error::NextStep::None
            );
        }
        other => panic!("not refused for its rule: {other:?}"),
    }
    dev.shutdown();
}

#[tokio::test]
async fn a_basis_that_never_applies_is_judged_alike_whether_held_or_not() {
    let x = version("/carol/laptop", 5, &[], edit(None, "x"));
    let w = version("/bob/laptop", 10, &[tip(&x)], edit(Some(x.digest()), "w"));
    let early = device(rules()).await;
    let late = device(rules()).await;
    for d in [&early, &late] {
        d.share(&c(), share_under(RULE, &["/alice", "/bob"]))
            .await
            .unwrap();
    }
    // One reader holds Carol's version, refused; the other never fetched it.
    give(&early, &x);
    for d in [&early, &late] {
        give(d, &w);
    }
    let verdict = |d: &Device| d.inner.st.lock().refused.get(&w.name).cloned();
    assert_eq!(verdict(&early), verdict(&late));
    assert_eq!(notes(&state(&early).await), notes(&state(&late).await));
    early.shutdown();
    late.shutdown();
}

/// A Yjs update `writer` makes in a document holding `seen`, by `edit`.
fn yjs(
    writer: &Writer,
    seen: &[&Bytes],
    edit: impl FnOnce(&yrs::MapRef, &mut yrs::TransactionMut),
) -> Bytes {
    use yrs::Transact;
    use yrs::updates::decoder::Decode;
    let doc = yrs::Doc::with_client_id(crate::merge::yrs_client(writer));
    let map = doc.get_or_insert_map("fields");
    for u in seen {
        doc.transact_mut()
            .apply_update(yrs::Update::decode_v1(u).unwrap())
            .unwrap();
    }
    let mut txn = doc.transact_mut();
    edit(&map, &mut txn);
    Bytes::from(txn.encode_update_v1())
}

#[tokio::test]
async fn a_yjs_update_reaching_outside_its_past_is_refused() {
    use yrs::Map;
    let doc = n("/alice/32=data/doc");
    let dev = device_on(
        MergeRules::standard(),
        &doc,
        "/merge/yrs",
        Arc::new(MemoryStore::new()),
    )
    .await;
    let (carol, bob) = (
        Writer::new(key("/carol/laptop")),
        Writer::new(key("/bob/laptop")),
    );
    let yrs_version = |device: &str, seq: u64, parents: &[(VersionId, [u8; 32])], op: Bytes| {
        made_in(
            &doc,
            device,
            seq,
            Record::Version(body_in(&doc, "/merge/yrs", parents, op)),
        )
    };
    let field = |dev: &Device| {
        let st = dev.inner.st.lock();
        st.colls[&doc]
            .state
            .as_ref()
            .unwrap()
            .value()
            .fields()
            .unwrap()
            .get("a")
            .cloned()
    };
    let u1 = yjs(&carol, &[], |m, t| {
        m.insert(t, "a", yrs::Any::Buffer(Arc::from(b"carol".as_slice())));
    });
    let c5 = yrs_version("/carol/laptop", 5, &[], u1.clone());
    give(&dev, &c5);
    assert_eq!(field(&dev).as_deref(), Some(b"carol".as_slice()));
    // Bob saw Carol's field outside the layer and, over nothing, deletes it
    // and writes after it.
    let delete = yrs_version(
        "/bob/laptop",
        10,
        &[],
        yjs(&bob, &[&u1], |m, t| {
            m.remove(t, "a");
        }),
    );
    let after = yrs_version(
        "/bob/laptop",
        11,
        &[],
        yjs(&bob, &[&u1], |m, t| {
            m.insert(t, "a", yrs::Any::Buffer(Arc::from(b"bob".as_slice())));
        }),
    );
    give(&dev, &delete);
    give(&dev, &after);
    assert_eq!(
        field(&dev).as_deref(),
        Some(b"carol".as_slice()),
        "nothing outside an update's past is touched"
    );
    for m in [&delete, &after] {
        let why = dev.inner.st.lock().refused.get(&m.name).cloned();
        assert!(matches!(why, Some(Refusal::Rule { .. })), "{why:?}");
    }
    // Made over Carol's version, the same delete applies.
    let over = yrs_version(
        "/bob/laptop",
        12,
        &[tip(&c5)],
        yjs(&bob, &[&u1], |m, t| {
            m.remove(t, "a");
        }),
    );
    give(&dev, &over);
    assert!(!dev.inner.st.lock().refused.contains_key(&over.name));
    assert_eq!(field(&dev), None);
    dev.shutdown();
}

#[tokio::test]
async fn a_device_serves_the_pieces_of_a_version_it_applied() {
    let dev = device(rules()).await;
    let big = "p".repeat(3 * wire::INLINE_MAX);
    let (large, pieces) = super::merge_tests::in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    give(&dev, &large);
    for p in &pieces {
        dev.inner.store.insert(p.name.clone(), p.wire.clone());
    }
    dev.inner.st.lock().pieces_arrived(&c(), &large.name);
    assert!(at(&dev).contains(&large.id()));
    // A reader whose versions are built over it asks this device for them.
    for p in &pieces {
        assert_eq!(
            dev.inner.packet_for(&p.name, false).as_ref(),
            Some(&p.wire),
            "{} served",
            p.name
        );
    }
    dev.shutdown();
}

#[tokio::test]
async fn a_reader_asks_the_pieces_of_a_version_of_the_devices_that_built_over_it() {
    let dev = device(rules()).await;
    let big = "p".repeat(3 * wire::INLINE_MAX);
    let (large, _) = super::merge_tests::in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    let over = version("/carol/phone", 3, &[tip(&large)], edit(None, "over"));
    give(&dev, &large);
    give(&dev, &over);
    let sources = dev.inner.st.lock().appliers(&c(), &large.name);
    assert_eq!(sources, vec![n("/carol/phone")]);
    dev.shutdown();
}

/// A store counting the presence checks of names under `watched`.
struct Counting {
    inner: MemoryStore,
    watched: Name,
    checks: AtomicUsize,
}

impl DataStore for Counting {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn contains(&self, name: &Name) -> bool {
        if name.has_prefix(&self.watched) && *name != self.watched {
            self.checks.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.contains(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.inner.remove(name);
    }
}

#[tokio::test]
async fn a_large_operation_is_neither_kept_in_memory_nor_looked_for_on_every_arrival() {
    let big = "p".repeat(3 * wire::INLINE_MAX);
    let (large, pieces) = super::merge_tests::in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    let store = Arc::new(Counting {
        inner: MemoryStore::new(),
        watched: large.name.clone(),
        checks: AtomicUsize::new(0),
    });
    let dev = device_on(
        rules(),
        &c(),
        RULE,
        Arc::clone(&store) as Arc<dyn DataStore>,
    )
    .await;
    give(&dev, &large);
    let looked = store.checks.load(Ordering::SeqCst);
    // Arrivals that change nothing about its pieces do not look for them
    // again.
    let c1 = version("/carol/laptop", 1, &[], edit(None, "c1"));
    give(&dev, &c1);
    for m in carols(&c1, 2, 20) {
        give(&dev, &m);
    }
    assert_eq!(store.checks.load(Ordering::SeqCst), looked);
    for p in pieces {
        store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &large.name);
    let s = state(&dev).await;
    assert!(notes(&s).contains(&big));
    // Applied, its operation is not kept in memory; it is read again from
    // the pieces when the state is computed anew.
    assert!(
        dev.inner.st.lock().colls[&c()].versions[&large.id()]
            .op
            .is_empty()
    );
    let named = state_name(&c(), &[large.id()].into_iter().collect());
    match dev.get(&named).await.unwrap().got {
        Got::State(s) => assert_eq!(notes(&s), vec![big]),
        other => panic!("not a state: {other:?}"),
    }
    dev.shutdown();
}
