//! Merge rules by name, app-built operations, `NotCounted`, checkpoints and
//! operations in pieces, against crafted packets and an in-test rule shaped
//! like ndf's (a basis named by digest, and edits).

use super::*;
use crate::error::NextStep;
use futures::StreamExt;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A forwarder that never delivers anything: the test hands the device the
/// packets it would have fetched.
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

pub(super) fn n(s: &str) -> Name {
    s.parse().unwrap()
}

pub(super) const RULE: &str = "/test/merge/notes/v=1";

pub(super) fn c() -> Name {
    n("/alice/32=data/notes")
}

/// Notes: an edit (`E`) names its basis by digest (all zero: none) and adds
/// a note; a checkpoint (`C`) replaces the notes of its past by its own,
/// keeping those of versions concurrent to it; a held note (`W`) is not
/// counted until its pair (`P`) applies; a follow-up (`B`) is checked
/// against the notes applied: its first line must be one.
pub(super) struct Notes {
    pub(super) function: Name,
}

impl MergeRule for Notes {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(NotesState::default())
    }
}

#[derive(Default)]
struct NotesState {
    /// Each note in the value, with the version that wrote it.
    notes: Vec<(VersionId, String)>,
    held: BTreeMap<String, VersionId>,
    paired: BTreeSet<String>,
    counted: Vec<VersionId>,
}

fn text(op: &Op<'_>, from: usize) -> Result<String, MergeError> {
    op.bytes
        .get(from..)
        .and_then(|b| String::from_utf8(b.to_vec()).ok())
        .ok_or_else(|| MergeError("not text".into()))
}

impl MergeState for NotesState {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        match op.bytes.first() {
            Some(b'E') => {
                let basis: [u8; 32] = op
                    .bytes
                    .get(1..33)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| MergeError("an edit names its basis".into()))?;
                if basis != [0; 32] && op.past.by_digest(&basis).is_none() {
                    return Err(MergeError("its basis is outside its past".into()));
                }
                Ok(OpKind::Edit)
            }
            Some(b'C') => Ok(OpKind::Checkpoint),
            Some(b'W' | b'P' | b'X') => Ok(OpKind::Edit),
            Some(b'B') => {
                let t = text(op, 1)?;
                let basis = t.lines().next().unwrap_or_default();
                match self.notes.iter().any(|(_, n)| n == basis) {
                    true => Ok(OpKind::Edit),
                    false => Err(MergeError(format!("{basis} is not applied"))),
                }
            }
            _ => Err(MergeError("not an operation of this rule".into())),
        }
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        match op.bytes.first() {
            Some(b'E') => {
                self.notes.push((op.id.clone(), text(op, 33)?));
            }
            Some(b'C') => {
                // The state of its past is the checkpoint's; what was
                // applied concurrent to it stays.
                self.notes.retain(|(id, _)| !op.past.contains(id));
                for t in text(op, 1)?.split('\n').filter(|t| !t.is_empty()) {
                    self.notes.push((op.id.clone(), t.to_owned()));
                }
            }
            Some(b'W') => {
                let t = text(op, 1)?;
                if !self.paired.contains(&t) {
                    self.held.insert(t, op.id.clone());
                    return Ok(Counting::NotCounted("waits for its pair".into()));
                }
                self.notes.push((op.id.clone(), t));
            }
            Some(b'P') => {
                let t = text(op, 1)?;
                self.paired.insert(t.clone());
                if let Some(id) = self.held.remove(&t) {
                    self.notes.push((id.clone(), t));
                    self.counted.push(id);
                }
            }
            // A note claimed only if no one noted it yet: the rule's apply
            // answers from the state, which others' versions make.
            Some(b'X') => {
                let t = text(op, 1)?;
                if self.notes.iter().any(|(_, n)| *n == t) {
                    return Err(MergeError(format!("{t} is noted already")));
                }
                self.notes.push((op.id.clone(), t));
            }
            Some(b'B') => {}
            _ => return Err(MergeError("not an operation of this rule".into())),
        }
        Ok(Counting::Counted)
    }

    fn now_counted(&mut self) -> Vec<VersionId> {
        std::mem::take(&mut self.counted)
    }

    fn value(&self) -> Value {
        let notes: BTreeSet<&str> = self.notes.iter().map(|(_, n)| n.as_str()).collect();
        Value::Rule(Bytes::from(
            notes.into_iter().collect::<Vec<_>>().join("\n"),
        ))
    }
}

pub(super) fn edit(basis: Option<[u8; 32]>, note: &str) -> Bytes {
    let mut b = vec![b'E'];
    b.extend_from_slice(&basis.unwrap_or([0; 32]));
    b.extend_from_slice(note.as_bytes());
    Bytes::from(b)
}

pub(super) fn checkpoint(notes: &[&str]) -> Bytes {
    Bytes::from([b"C".as_slice(), notes.join("\n").as_bytes()].concat())
}

fn hold(note: &str) -> Bytes {
    Bytes::from([b"W".as_slice(), note.as_bytes()].concat())
}

fn pair(note: &str) -> Bytes {
    Bytes::from([b"P".as_slice(), note.as_bytes()].concat())
}

pub(super) fn rules() -> MergeRules {
    MergeRules::standard().with(Arc::new(Notes { function: n(RULE) }))
}

/// `/alice/laptop`, knowing `rules`, owning `c()` merged by [`RULE`] and
/// written by Alice, Bob and Carol, on a forwarder that delivers nothing.
pub(super) async fn device(rules: MergeRules) -> Device {
    device_under(rules, &c(), RULE).await
}

/// `/alice/laptop`, knowing `rules`, owning `c` merged by `rule` and
/// written by Alice, Bob and Carol, on a forwarder that delivers nothing.
pub(super) async fn device_under(rules: MergeRules, c: &Name, rule: &str) -> Device {
    device_on(rules, c, rule, Arc::new(MemoryStore::new())).await
}

/// [`device_under`], keeping its data in `store`.
pub(super) async fn device_on(
    rules: MergeRules,
    c: &Name,
    rule: &str,
    store: Arc<dyn DataStore>,
) -> Device {
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        assert!(validator.adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns)))));
    }
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    let dev = Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        store,
        Config {
            rules,
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .unwrap();
    dev.share(
        c,
        crate::layer::Share {
            rule: Rule::Merge { function: n(rule) },
            writers: vec![n("/alice"), n("/bob"), n("/carol")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    dev
}

/// A log entry as fetched: its name, packet, signing key and record.
pub(super) struct Made {
    pub(super) name: Name,
    pub(super) packet: Bytes,
    pub(super) key: Name,
    pub(super) record: Record,
}

impl Made {
    pub(super) fn digest(&self) -> [u8; 32] {
        wire::implicit_digest(&self.packet)
    }

    pub(super) fn id(&self) -> VersionId {
        VersionId {
            writer: Writer::new(self.key.clone()),
            seq: Seq(parse_log_name(&self.name).unwrap().seq),
        }
    }
}

pub(super) fn key(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

pub(super) fn id(device: &str, seq: u64) -> VersionId {
    VersionId {
        writer: Writer::new(key(device)),
        seq: Seq(seq),
    }
}

/// A parent: the version `m` and the implicit digest of its packet.
pub(super) fn tip(m: &Made) -> (VersionId, [u8; 32]) {
    (m.id(), m.digest())
}

/// Entry `seq` of `device` about `c()` carrying `record`, signed (unchecked)
/// by the device's key.
pub(super) fn made(device: &str, seq: u64, record: Record) -> Made {
    made_in(&c(), device, seq, record)
}

/// Entry `seq` of `device` about `c` carrying `record`, signed (unchecked)
/// by the device's key.
pub(super) fn made_in(c: &Name, device: &str, seq: u64, record: Record) -> Made {
    let name = log_name(&n(device), Some(c), seq);
    let key = key(device);
    let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&key),
        |_| Bytes::from_static(&[0; 64]),
    );
    Made {
        name,
        packet,
        key,
        record,
    }
}

/// A version record of `c()` under [`RULE`] naming `parents`, carrying `op`
/// inline.
pub(super) fn body(parents: &[(VersionId, [u8; 32])], op: Bytes) -> VersionBody {
    body_in(&c(), RULE, parents, op)
}

/// A version record of `c`, made under `rule`, naming `parents`, carrying
/// `op` inline.
pub(super) fn body_in(
    c: &Name,
    rule: &str,
    parents: &[(VersionId, [u8; 32])],
    op: Bytes,
) -> VersionBody {
    VersionBody {
        collection: c.clone(),
        parents: parents
            .iter()
            .map(|(id, digest)| (id.clone(), Some(*digest)))
            .collect(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group: None,
        rule: Some(n(rule)),
        fields: Content::new(),
        op,
        sealed: None,
        chunks: None,
        block: None,
    }
}

/// Version `seq` of `device` naming `parents`, carrying `op` inline.
pub(super) fn version(
    device: &str,
    seq: u64,
    parents: &[(VersionId, [u8; 32])],
    op: Bytes,
) -> Made {
    made(device, seq, Record::Version(body(parents, op)))
}

/// Version `seq` of `device` naming `parents`, carrying `op` in pieces: the
/// version and its pieces.
pub(super) fn in_pieces(
    device: &str,
    seq: u64,
    parents: &[(VersionId, [u8; 32])],
    op: Bytes,
) -> (Made, Vec<pieces::Piece>) {
    let name = log_name(&n(device), Some(&c()), seq);
    let payload = wire::encode_payload(&Content::new(), &op);
    assert!(payload.len() > wire::INLINE_MAX);
    let (pieces, chunks) = pieces::split(&name, &payload);
    let mut b = body(parents, Bytes::new());
    b.chunks = Some(chunks);
    (made(device, seq, Record::Version(b)), pieces)
}

pub(super) fn give(dev: &Device, m: &Made) {
    let mut st = dev.inner.st.lock();
    dev.inner.take(
        &mut st,
        m.name.clone(),
        m.packet.clone(),
        Writer::new(m.key.clone()),
        m.record.clone(),
        false,
    );
}

pub(super) fn at(dev: &Device) -> Frontier {
    dev.inner.st.lock().colls[&c()].at()
}

pub(super) async fn state(dev: &Device) -> State {
    match dev.get(&c()).await.unwrap().got {
        Got::State(s) => s,
        other => panic!("not a state: {other:?}"),
    }
}

pub(super) fn notes(s: &State) -> Vec<String> {
    let b = s.value.bytes().expect("the rule's own encoding");
    String::from_utf8(b.to_vec())
        .unwrap()
        .split('\n')
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

pub(super) fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// Every change the watch has delivered so far.
async fn drain(changes: &mut Changes) -> Vec<Change> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(100), changes.next()).await
    {
        out.push(change);
    }
    out
}

#[tokio::test]
async fn a_collection_whose_rule_is_unknown_is_held_and_never_read_under_another_rule() {
    // This device knows `/merge/yrs`, not the collection's rule.
    let dev = device(MergeRules::standard()).await;
    let a = version("/bob/laptop", 10, &[], edit(None, "a"));
    give(&dev, &a);
    {
        let st = dev.inner.st.lock();
        let coll = &st.colls[&c()];
        assert!(coll.versions.contains_key(&a.id()), "held");
        assert!(coll.state.is_none(), "no state under another rule");
        assert!(coll.at().is_empty(), "nothing applied");
        assert!(dev.inner.store.contains(&a.name), "stored, so served");
    }
    let unknown = |r: Result<_, DataError>| {
        matches!(&r, Err(DataError::RuleUnknown { rule, .. }) if *rule == n(RULE))
            && r.as_ref().err().map(DataError::next) == Some(NextStep::UpdateProgram)
    };
    assert!(unknown(dev.get(&c()).await.map(|_| ())));
    let mut f = Frontier::new();
    f.include(&a.id());
    assert!(unknown(dev.get(&state_name(&c(), &f)).await.map(|_| ())));
    assert!(unknown(
        dev.put(&c(), Content::new().with("t", "x"), options())
            .await
            .map(|_| ())
    ));
    assert!(unknown(
        dev.put_op(&c(), edit(None, "x"), options())
            .await
            .map(|_| ())
    ));
    let st = dev.inner.st.lock();
    assert!(st.colls[&c()].at().is_empty(), "still nothing applied");
    drop(st);
    dev.shutdown();
}

#[tokio::test]
async fn an_operation_whose_basis_is_outside_its_past_is_refused_and_not_waited_for() {
    let dev = device(rules()).await;
    let carol = version("/carol/laptop", 5, &[], edit(None, "c"));
    let a = version("/bob/laptop", 10, &[], edit(None, "a"));
    // Carol's note is held here, but not in what Bob had seen.
    let outside = version(
        "/bob/laptop",
        11,
        &[tip(&a)],
        edit(Some(carol.digest()), "x"),
    );
    let inside = version(
        "/bob/laptop",
        12,
        &[tip(&outside)],
        edit(Some(a.digest()), "b"),
    );
    for m in [&carol, &a, &outside, &inside] {
        give(&dev, m);
    }
    let refused = dev.inner.st.lock().refused.get(&outside.name).cloned();
    assert!(matches!(refused, Some(Refusal::Rule { .. })), "{refused:?}");
    assert!(
        at(&dev).contains(&inside.id()),
        "a later version does not wait for it"
    );
    let s = state(&dev).await;
    assert!(!notes(&s).contains(&"x".to_owned()));
    assert!(notes(&s).contains(&"b".to_owned()));
    // The writer's own operation is judged alike, and refused unwritten.
    let head = dev.inner.st.lock().head;
    let own = dev.put_op(&c(), edit(Some([7; 32]), "y"), options()).await;
    assert!(matches!(own, Err(DataError::BadRequest { .. })), "{own:?}");
    assert_eq!(
        dev.inner.st.lock().head,
        head,
        "nothing signed into the log"
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_version_its_rule_does_not_count_is_applied_shown_and_counted_later() {
    let dev = device(rules()).await;
    let mut changes = dev.watch(&c(), &Frontier::new()).await.unwrap();
    let w = version("/bob/laptop", 10, &[], hold("w"));
    let a = version("/bob/laptop", 11, &[tip(&w)], edit(None, "a"));
    give(&dev, &w);
    give(&dev, &a);
    assert!(
        at(&dev).contains(&a.id()),
        "later versions do not wait for it"
    );
    let s = state(&dev).await;
    assert!(s.at.contains(&w.id()), "applied");
    assert!(!notes(&s).contains(&"w".to_owned()), "not in the value");
    assert!(s.not_counted.iter().any(|(id, _)| *id == w.id()));
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter()
            .any(|ch| matches!(ch, Change::Version(v) if v.id == w.id()))
    );
    assert!(
        seen.iter()
            .any(|ch| matches!(ch, Change::NotCounted { id, .. } if *id == w.id()))
    );
    let p = version("/bob/laptop", 12, &[tip(&a)], pair("w"));
    give(&dev, &p);
    let s = state(&dev).await;
    assert!(notes(&s).contains(&"w".to_owned()), "counted now");
    assert!(s.not_counted.is_empty());
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter()
            .any(|ch| matches!(ch, Change::Counted { id } if *id == w.id()))
    );
    dev.shutdown();
}

#[tokio::test]
async fn the_same_versions_give_the_same_state_in_any_order_with_a_checkpoint() {
    let b1 = version("/bob/laptop", 10, &[], edit(None, "a"));
    let b2 = version("/bob/laptop", 11, &[tip(&b1)], edit(Some(b1.digest()), "b"));
    // Carol's edit travels in pieces, which only one device ever gets.
    let big = "c".repeat(3 * wire::INLINE_MAX);
    let (c1, c1_pieces) = in_pieces(
        "/carol/laptop",
        5,
        &[tip(&b1)],
        edit(Some(b1.digest()), &big),
    );
    let cp = version(
        "/carol/laptop",
        6,
        &[tip(&b2), tip(&c1)],
        checkpoint(&["a", "b", big.as_str()]),
    );
    let b3 = version(
        "/bob/laptop",
        12,
        &[tip(&b2), tip(&cp)],
        edit(Some(cp.digest()), "d"),
    );
    let wanted = |dev: &Device| {
        dev.inner
            .st
            .lock()
            .wanted_pieces(&c())
            .iter()
            .any(|(v, _)| *v == c1.name)
    };
    // In order, Carol's edit's pieces never arriving.
    let first = device(rules()).await;
    for m in [&b1, &b2, &c1] {
        give(&first, m);
    }
    assert!(
        wanted(&first),
        "a version in pieces is fetched while it waits"
    );
    for m in [&cp, &b3] {
        give(&first, m);
    }
    assert!(at(&first).contains(&c1.id()), "the checkpoint covers it");
    assert!(
        !wanted(&first),
        "a covered version's pieces are never fetched"
    );
    // The checkpoint first.
    let second = device(rules()).await;
    for m in [&cp, &b3, &c1, &b2] {
        give(&second, m);
    }
    assert!(
        !at(&second).contains(&cp.id()),
        "a checkpoint waits for every version of its past, held"
    );
    give(&second, &b1);
    // In order, with every piece: Carol's edit applies before the checkpoint.
    let third = device(rules()).await;
    for p in c1_pieces {
        third.inner.store.insert(p.name, p.wire);
    }
    for m in [&b1, &b2, &c1] {
        give(&third, m);
    }
    assert!(at(&third).contains(&c1.id()));
    for m in [&cp, &b3] {
        give(&third, m);
    }
    let one = state(&first).await;
    assert!(one.at.contains(&b3.id()));
    for other in [&second, &third] {
        let s = state(other).await;
        assert_eq!(one.at, s.at);
        assert_eq!(one.value, s.value);
        assert_eq!(one.not_counted, s.not_counted);
    }
    // The state at the checkpoint, named after it moved on, is computed
    // again by the same procedure, alike everywhere.
    let at_cp: Frontier = [id("/bob/laptop", 11), cp.id()].into_iter().collect();
    let named = state_name(&c(), &at_cp);
    let mut values = Vec::new();
    for dev in [&first, &second, &third] {
        match dev.get(&named).await.unwrap().got {
            Got::State(s) => values.push(notes(&s)),
            other => panic!("not a state: {other:?}"),
        }
    }
    assert!(values.iter().all(|v| *v == values[0]));
    assert!(values[0].contains(&big) && !values[0].contains(&"d".to_owned()));
    first.shutdown();
    second.shutdown();
    third.shutdown();
}

#[tokio::test]
async fn a_merge_operation_in_pieces_waits_for_them_then_applies() {
    let dev = device(rules()).await;
    let big = "p".repeat(3 * wire::INLINE_MAX);
    let (large, pieces) = in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    let after = version("/bob/laptop", 11, &[tip(&large)], edit(None, "after"));
    give(&dev, &large);
    give(&dev, &after);
    {
        let st = dev.inner.st.lock();
        assert!(!st.refused.contains_key(&large.name), "admitted");
        assert!(
            !st.colls[&c()].at().contains(&large.id()),
            "it waits for its pieces"
        );
        assert!(
            !st.colls[&c()].at().contains(&after.id()),
            "and what names it waits"
        );
        assert!(
            st.wanted_pieces(&c()).iter().any(|(v, _)| *v == large.name),
            "its pieces are to be fetched"
        );
    }
    for p in pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &large.name);
    let s = state(&dev).await;
    assert!(s.at.contains(&after.id()));
    assert!(notes(&s).contains(&big));
    assert!(notes(&s).contains(&"after".to_owned()));
    // A writer's own large operation travels in pieces too.
    let own = dev
        .put_op(
            &c(),
            edit(None, &"q".repeat(3 * wire::INLINE_MAX)),
            options(),
        )
        .await
        .unwrap();
    assert!(
        dev.inner.st.lock().colls[&c()].versions[&own]
            .chunks
            .is_some()
    );
    assert!(notes(&state(&dev).await).contains(&"q".repeat(3 * wire::INLINE_MAX)));
    dev.shutdown();
}

#[tokio::test]
async fn a_version_a_checkpoint_covers_is_never_fetched_when_both_arrive_in_one_descent() {
    let dev = device(rules()).await;
    let big = "e".repeat(3 * wire::INLINE_MAX);
    let (covered, _) = in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    let (cp, cp_pieces) = in_pieces("/bob/laptop", 11, &[tip(&covered)], checkpoint(&[&big]));
    // One descent brings both: nothing is fetched while it lasts.
    let descending = Descending::new(&dev.inner.st);
    give(&dev, &covered);
    give(&dev, &cp);
    dev.inner.fetch_wanted(true);
    assert!(dev.inner.st.lock().fetching.is_empty());
    // It ends: the newest version's pieces are fetched first, not those of
    // what it may cover.
    assert!(descending.end());
    dev.inner.fetch_wanted(true);
    {
        let st = dev.inner.st.lock();
        assert!(!st.fetching.contains(&covered.name));
        assert!(st.fetching.contains(&cp.name));
    }
    // Whole, the checkpoint applies and covers the other, whose pieces are
    // never wanted.
    for p in cp_pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &cp.name);
    let st = dev.inner.st.lock();
    assert!(st.colls[&c()].at().contains(&covered.id()));
    assert!(st.wanted_pieces(&c()).is_empty());
    assert!(!st.fetching.contains(&covered.name));
    drop(st);
    assert!(
        dev.inner
            .store
            .scan_under(&covered.name, 0)
            .iter()
            .all(|(n, _)| *n == covered.name),
        "none of the covered version's pieces is stored"
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_version_whose_past_is_held_but_not_applied_is_checked_only_once_it_is_ready() {
    let dev = device(rules()).await;
    // Carol's version waits for its pieces; Bob's note "x" waits for it.
    let (carol, carol_pieces) = in_pieces(
        "/carol/phone",
        1,
        &[],
        edit(None, &"c".repeat(3 * wire::INLINE_MAX)),
    );
    let x = version("/bob/laptop", 10, &[tip(&carol)], edit(None, "x"));
    // Bob's follow-up of "x", in pieces and whole: its past is held, its
    // rule judges it against "x" applied.
    let op = Bytes::from(format!("Bx\n{}", "b".repeat(3 * wire::INLINE_MAX)));
    let (follow, follow_pieces) = in_pieces("/bob/laptop", 11, &[tip(&x)], op);
    for p in follow_pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    give(&dev, &carol);
    give(&dev, &x);
    give(&dev, &follow);
    {
        let st = dev.inner.st.lock();
        assert!(
            !st.refused.contains_key(&follow.name),
            "not refused before its past applied"
        );
        assert!(st.colls[&c()].pending.contains(&follow.id()));
    }
    for p in carol_pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &carol.name);
    let st = dev.inner.st.lock();
    assert!(!st.refused.contains_key(&follow.name));
    assert!(
        st.colls[&c()].at().contains(&follow.id()),
        "applied in turn"
    );
    drop(st);
    dev.shutdown();
}

#[tokio::test]
async fn merge_pieces_are_not_released_without_a_covering_checkpoint_proved_kept() {
    let dev = device(rules()).await;
    let hold_record = made(
        "/alice/laptop",
        1000,
        Record::Hold(HoldBody {
            collection: c(),
            copies: 1,
            until: Timestamp(u64::MAX / 2),
            at: Frontier::new(),
            holders: vec![n("/alice/holder")],
        }),
    );
    give(&dev, &hold_record);
    let big = "p".repeat(3 * wire::INLINE_MAX);
    let (large, pieces) = in_pieces("/bob/laptop", 10, &[], edit(None, &big));
    let chunk = pieces
        .iter()
        .map(|p| p.name.clone())
        .find(|p| {
            matches!(
                parse_piece_name(p).map(|x| x.kind),
                Some(PieceKind::Chunk(_))
            )
        })
        .unwrap();
    give(&dev, &large);
    for p in pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &large.name);
    assert!(at(&dev).contains(&large.id()));
    let none = dev.release(&c()).await;
    assert!(matches!(none, Err(DataError::NotHeld { .. })), "{none:?}");
    // A checkpoint covering it, held whole here, that no holder proved.
    let cp = version(
        "/carol/laptop",
        5,
        &[tip(&large)],
        checkpoint(&[big.as_str()]),
    );
    give(&dev, &cp);
    assert!(at(&dev).contains(&cp.id()));
    let unproved = dev.release(&c()).await;
    assert!(
        matches!(unproved, Err(DataError::NotHeld { .. })),
        "{unproved:?}"
    );
    assert!(dev.inner.store.contains(&chunk), "its pieces stay");
    dev.shutdown();
}
