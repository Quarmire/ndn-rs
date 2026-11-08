//! A merge collection's state built lazily from its newest checkpoint after
//! a restart (spec §5.2, case l1), and an incomplete group's members held in
//! the store rather than in memory (spec §5.5).

use std::sync::atomic::AtomicUsize;

use super::group_tests::{self, give};
use super::*;
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

const RULE: &str = "/test/merge/counted/v=1";

/// How often the rule started a state and applied an operation.
#[derive(Default)]
struct Calls {
    starts: AtomicUsize,
    applies: AtomicUsize,
}

impl Calls {
    fn starts(&self) -> usize {
        self.starts.load(Ordering::SeqCst)
    }

    fn applies(&self) -> usize {
        self.applies.load(Ordering::SeqCst)
    }
}

/// Notes that count (`E`), notes held back (`N`, never counted), a
/// checkpoint (`C`) whose notes replace those of its past, keeping those
/// concurrent to it, and one (`D`) the rule does not count until a release
/// (`R`, a note that counts) is applied; every start and apply counted in
/// `calls`.
struct Counted {
    function: Name,
    calls: Arc<Calls>,
}

impl MergeRule for Counted {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _collection: &Name, _local: &Writer) -> Box<dyn MergeState> {
        self.calls.starts.fetch_add(1, Ordering::SeqCst);
        Box::new(CountedState {
            calls: Arc::clone(&self.calls),
            notes: Vec::new(),
            held: Vec::new(),
            unreleased: BTreeSet::new(),
            released: false,
            changed: Vec::new(),
        })
    }
}

struct CountedState {
    calls: Arc<Calls>,
    notes: Vec<(VersionId, String)>,
    held: Vec<(VersionId, String)>,
    /// The `D` checkpoints applied while no release was.
    unreleased: BTreeSet<VersionId>,
    released: bool,
    changed: Vec<(VersionId, Counting)>,
}

fn text(op: &Op<'_>) -> Result<String, MergeError> {
    String::from_utf8(op.bytes[1..].to_vec()).map_err(|_| MergeError("not text".into()))
}

impl MergeState for CountedState {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        match op.bytes.first() {
            Some(b'E' | b'N' | b'R') => Ok(OpKind::Edit),
            Some(b'C' | b'D') => Ok(OpKind::Checkpoint),
            _ => Err(MergeError("not an operation of this rule".into())),
        }
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        self.calls.applies.fetch_add(1, Ordering::SeqCst);
        match op.bytes.first() {
            Some(b'E') => self.notes.push((op.id.clone(), text(op)?)),
            Some(b'N') => {
                self.held.push((op.id.clone(), text(op)?));
                return Ok(Counting::NotCounted("held back".into()));
            }
            Some(b'R') => {
                self.notes.push((op.id.clone(), text(op)?));
                self.released = true;
                for id in std::mem::take(&mut self.unreleased) {
                    self.changed.push((id, Counting::Counted));
                }
            }
            Some(k @ (b'C' | b'D')) => {
                self.notes.retain(|(id, _)| !op.past.contains(id));
                self.held.retain(|(id, _)| !op.past.contains(id));
                for t in text(op)?.split('\n').filter(|t| !t.is_empty()) {
                    self.notes.push((op.id.clone(), t.to_owned()));
                }
                if *k == b'D' && !self.released {
                    self.unreleased.insert(op.id.clone());
                    return Ok(Counting::NotCounted(
                        "a checkpoint held back until a release".into(),
                    ));
                }
            }
            _ => return Err(MergeError("not an operation of this rule".into())),
        }
        Ok(Counting::Counted)
    }

    fn counting_changed(&mut self) -> Vec<(VersionId, Counting)> {
        std::mem::take(&mut self.changed)
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        let notes: BTreeSet<&str> = self
            .notes
            .iter()
            .filter(|(id, _)| !excluded.contains(id) && !self.unreleased.contains(id))
            .map(|(_, t)| t.as_str())
            .collect();
        Value::Rule(Bytes::from(
            notes.into_iter().collect::<Vec<_>>().join("\n"),
        ))
    }
}

fn op(kind: u8, text: &str) -> Bytes {
    Bytes::from([&[kind][..], text.as_bytes()].concat())
}

fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// `/alice/laptop` with `keys`, keeping its data in `store`, knowing the
/// counted rule (its calls in `calls`).
async fn start(
    keys: &Arc<SecurityManager>,
    store: &Arc<dyn DataStore>,
    calls: &Arc<Calls>,
) -> Device {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob"] {
        assert!(validator.adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns)))));
    }
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    let rule = Counted {
        function: n(RULE),
        calls: Arc::clone(calls),
    };
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n("/alice/laptop"),
        Arc::clone(keys),
        validator,
        Arc::clone(store),
        Config {
            rules: MergeRules::standard().with(Arc::new(rule)),
            first_look: Duration::from_millis(20),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// The state `get` answers for merge collection `c`.
async fn state(dev: &Device, c: &Name) -> State {
    match dev.get(c).await.unwrap().got {
        Got::State(s) => s,
        other => panic!("not a state: {other:?}"),
    }
}

/// What a state shows: its frontier, value and versions not counted.
fn shown(s: &State) -> (Frontier, Value, Vec<(VersionId, String)>) {
    (s.at.clone(), s.value.clone(), s.not_counted.clone())
}

#[tokio::test]
async fn after_a_restart_a_merge_state_is_built_on_first_need_from_its_newest_checkpoint() {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n("/alice/laptop/KEY/1")).unwrap();
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let calls = Arc::new(Calls::default());
    let f = n("/alice/32=data/notes");
    let (a, b, c) = (
        f.clone().append("a"),
        f.clone().append("b"),
        f.clone().append("c"),
    );
    let dev = start(&keys, &store, &calls).await;
    dev.share_folder(
        &f,
        Share {
            rule: Rule::Merge { function: n(RULE) },
            writers: vec![n("/alice")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    // Before its checkpoint, `a` holds a note held back; after it, another.
    for o in [
        op(b'E', "one"),
        op(b'N', "held"),
        op(b'E', "two"),
        op(b'C', "one\ntwo"),
        op(b'E', "three"),
        op(b'N', "later"),
    ] {
        dev.put_op(&a, o, options()).await.unwrap();
    }
    for x in [&b, &c] {
        dev.put_op(x, op(b'E', "other"), options()).await.unwrap();
    }
    let before = shown(&state(&dev, &a).await);
    assert_eq!(
        before.1,
        Value::Rule(Bytes::from_static(b"one\nthree\ntwo")),
        "the checkpoint's notes and the note after it"
    );
    assert_eq!(
        before.2.len(),
        1,
        "only the note held back after the checkpoint is not counted: the one before it is covered"
    );
    dev.shutdown();
    drop(dev);

    let calls = Arc::new(Calls::default());
    let dev = start(&keys, &store, &calls).await;
    assert_eq!(
        calls.starts(),
        0,
        "no merge state is built at start: every collection is only indexed"
    );
    for x in [&a, &b, &c] {
        assert!(dev.inner.st.lock().colls[x].state.is_none());
    }
    let after = shown(&state(&dev, &a).await);
    assert_eq!(
        after, before,
        "the state built lazily is the state before the restart"
    );
    assert_eq!(calls.starts(), 1, "one state built: the one read");
    assert_eq!(
        calls.applies(),
        3,
        "built from its newest checkpoint: the checkpoint and the two versions after it applied"
    );
    for x in [&b, &c] {
        let st = dev.inner.st.lock();
        let coll = &st.colls[x];
        assert!(
            coll.state.is_none() && coll.dormant.is_some() && coll.versions.is_empty(),
            "a collection nobody touched costs its index only"
        );
    }
    // Written into, a collection is built first, and the write goes on top.
    dev.put_op(&b, op(b'E', "more"), options()).await.unwrap();
    assert_eq!(calls.starts(), 2);
    assert_eq!(
        state(&dev, &b).await.value,
        Value::Rule(Bytes::from_static(b"more\nother"))
    );
    assert!(dev.inner.st.lock().colls[&c].dormant.is_some());
    dev.shutdown();
}

/// The ids `s` lists not counted.
fn not_counted(s: &State) -> BTreeSet<VersionId> {
    s.not_counted.iter().map(|(id, _)| id.clone()).collect()
}

/// A version a checkpoint covers counts as the checkpoints covering it
/// count, and follows them (spec §5.2, round-2 review M1): covered only by
/// one the rule does not count, it is not counted — and out of the value,
/// whether it was applied before or never —, the same after a restart's
/// lazy build; once the rule counts the checkpoint, it counts.
#[tokio::test]
async fn a_version_a_checkpoint_covers_counts_as_that_checkpoint_counts() {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n("/alice/laptop/KEY/1")).unwrap();
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let calls = Arc::new(Calls::default());
    let f = n("/alice/32=data/notes");
    let a = f.clone().append("a");
    let dev = start(&keys, &store, &calls).await;
    dev.share_folder(
        &f,
        Share {
            rule: Rule::Merge { function: n(RULE) },
            writers: vec![n("/alice")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    let mut changes = dev.watch(&a, &Frontier::new()).await.unwrap();
    let one = dev.put_op(&a, op(b'E', "one"), options()).await.unwrap();
    let held = dev.put_op(&a, op(b'N', "held"), options()).await.unwrap();
    let cp = dev.put_op(&a, op(b'D', "kept"), options()).await.unwrap();
    let s = state(&dev, &a).await;
    assert_eq!(
        not_counted(&s),
        BTreeSet::from([one.clone(), held.clone(), cp.clone()]),
        "a version covered only by a checkpoint the rule does not count is not counted: {:?}",
        s.not_counted
    );
    assert_eq!(
        s.value,
        Value::Rule(Bytes::new()),
        "what a checkpoint not counted covers is out of the value, as the state says"
    );
    let told = group_tests::drain(&mut changes).await;
    assert!(
        !told
            .iter()
            .any(|c| matches!(c, Change::Counted { id, .. } if *id == held || *id == one)),
        "no covered version is told counted while its checkpoint does not count: {told:?}"
    );
    let before = shown(&s);
    dev.shutdown();
    drop(dev);

    let dev = start(&keys, &store, &calls).await;
    assert_eq!(
        shown(&state(&dev, &a).await),
        before,
        "the state built lazily from the newest checkpoint is the state before the restart"
    );
    let mut changes = dev.watch(&a, &Frontier::new()).await.unwrap();
    let _ = group_tests::drain(&mut changes).await;
    // The rule now counts the checkpoint: what it covers counts with it.
    dev.put_op(&a, op(b'R', "go"), options()).await.unwrap();
    let s = state(&dev, &a).await;
    assert!(
        s.not_counted.is_empty(),
        "the checkpoint counts, and what it covers with it: {:?}",
        s.not_counted
    );
    assert_eq!(s.value, Value::Rule(Bytes::from_static(b"go\nkept")));
    let told = group_tests::drain(&mut changes).await;
    for id in [&one, &held, &cp] {
        assert!(
            told.iter()
                .any(|c| matches!(c, Change::Counted { id: x, .. } if x == id)),
            "{id:?} is told counted as its checkpoint's counting changes: {told:?}"
        );
    }
    let after = shown(&s);
    dev.shutdown();
    drop(dev);
    let dev = start(&keys, &store, &calls).await;
    assert_eq!(shown(&state(&dev, &a).await), after);
    dev.shutdown();
}

#[tokio::test]
async fn a_folder_watch_builds_only_the_collections_holding_versions_past_its_frontier() {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n("/alice/laptop/KEY/1")).unwrap();
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let calls = Arc::new(Calls::default());
    let f = n("/alice/32=data/notes");
    let (a, b) = (f.clone().append("a"), f.clone().append("b"));
    let dev = start(&keys, &store, &calls).await;
    dev.share_folder(
        &f,
        Share {
            rule: Rule::Merge { function: n(RULE) },
            writers: vec![n("/alice")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    dev.put_op(&a, op(b'E', "a1"), options()).await.unwrap();
    let seen = state(&dev, &a).await.at;
    let later = dev.put_op(&b, op(b'E', "b1"), options()).await.unwrap();
    dev.shutdown();
    drop(dev);

    let calls = Arc::new(Calls::default());
    let dev = start(&keys, &store, &calls).await;
    let mut changes = dev.watch(&f, &seen).await.unwrap();
    let got = group_tests::drain(&mut changes).await;
    assert!(
        got.iter()
            .any(|ch| matches!(ch, Change::Version(v) if v.id == later)),
        "what lies past the frontier is listed: {got:?}"
    );
    assert!(
        !got.iter()
            .any(|ch| matches!(ch, Change::Version(v) if v.collection == a)),
        "nothing inside it: {got:?}"
    );
    let st = dev.inner.st.lock();
    assert!(
        st.colls[&a].dormant.is_some(),
        "a holds nothing past it: not built"
    );
    assert!(
        st.colls[&b].state.is_some(),
        "b holds a version past it: built"
    );
    drop(st);
    dev.shutdown();
}

/// A version of Bob's in `c` at `seq`, of `group`.
fn bobs(c: &Name, seq: u64, group: Group) -> group_tests::Made {
    group_tests::version("/bob/phone", c, seq, &[], Some(group))
}

#[tokio::test]
async fn an_incomplete_groups_members_wait_in_the_store_not_in_memory() {
    let dev = group_tests::device().await;
    let cs: Vec<Name> = (0..3)
        .map(|i| n(&format!("/alice/32=data/trip/day{i}")))
        .collect();
    for c in &cs {
        dev.share(c, group_tests::log_share()).await.unwrap();
    }
    let group = Group { id: 5, count: 3 };
    let members: Vec<_> = cs
        .iter()
        .enumerate()
        .map(|(i, c)| bobs(c, 5 + i as u64, group))
        .collect();
    for m in &members[..2] {
        give(&dev, m);
    }
    {
        let st = dev.inner.st.lock();
        for (c, m) in cs.iter().zip(&members[..2]) {
            let coll = &st.colls[c];
            let id = group_tests::id("/bob/phone", parse_log_name(&m.name).unwrap().seq);
            assert!(
                coll.parked.contains_key(&id) && !coll.versions.contains_key(&id),
                "a member of an incomplete group is not in memory"
            );
            assert!(
                st.store.get(&parked_name(&m.name)).is_some(),
                "it is in the store"
            );
            assert!(
                coll.not_counted_list()
                    .iter()
                    .any(|(x, why)| *x == id && why.contains("group incomplete")),
                "and listed not counted, with why"
            );
        }
    }
    give(&dev, &members[2]);
    let st = dev.inner.st.lock();
    for (c, m) in cs.iter().zip(&members) {
        let id = group_tests::id("/bob/phone", parse_log_name(&m.name).unwrap().seq);
        let coll = &st.colls[c];
        assert!(coll.parked.is_empty(), "complete, nothing stays parked");
        assert!(
            coll.at().contains(&id),
            "every member counts once the group is complete"
        );
        assert!(st.store.get(&parked_name(&m.name)).is_none());
    }
    drop(st);
    dev.shutdown();
}

#[tokio::test]
async fn a_parked_member_and_its_equivocation_outlive_a_restart() {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n("/alice/laptop/KEY/1")).unwrap();
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let calls = Arc::new(Calls::default());
    let (plan, budget, list) = (
        n("/alice/32=data/trip/plan"),
        n("/alice/32=data/trip/budget"),
        n("/alice/32=data/home/list"),
    );
    let dev = start(&keys, &store, &calls).await;
    for c in [&plan, &budget, &list] {
        dev.share(c, group_tests::log_share()).await.unwrap();
    }
    let group = Group { id: 5, count: 2 };
    let (a, b) = (bobs(&plan, 5, group), bobs(&budget, 6, group));
    // Bob's second entry at seq 5, in another folder: equivocation.
    let twin = group_tests::version("/bob/phone", &list, 5, &[], None);
    give(&dev, &a);
    give(&dev, &twin);
    let five = group_tests::id("/bob/phone", 5);
    assert!(dev.inner.st.lock().colls[&plan].parked.contains_key(&five));
    dev.shutdown();
    drop(dev);

    // Nothing reaches the restarted device but the group's other member.
    let dev = start(&keys, &store, &calls).await;
    give(&dev, &b);
    assert!(
        group_tests::counts(&dev, &plan, &five)
            && group_tests::counts(&dev, &budget, &group_tests::id("/bob/phone", 6)),
        "the member parked before the restart is still held: its group completes without it \
         being fetched again"
    );
    let mut changes = dev.watch(&list, &Frontier::new()).await.unwrap();
    let seen = group_tests::drain(&mut changes).await;
    // Which of the two was seen first depends on the order they were read
    // back in; both are reported.
    let pair = BTreeSet::from([a.name.clone(), twin.name.clone()]);
    assert!(
        seen.iter().any(|c| matches!(
            c,
            Change::Equivocation { collection, first, second }
                if *collection == list
                    && BTreeSet::from([first.name().clone(), second.name().clone()]) == pair
        )),
        "the equivocation is still reported after the restart: {seen:?}"
    );
    dev.shutdown();
}
