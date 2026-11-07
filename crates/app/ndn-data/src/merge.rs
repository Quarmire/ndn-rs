//! Merge rules: the named functions a merge collection's readers all run
//! alike, so every device that holds the same versions computes the same
//! state.
//!
//! A rule turns a writer's edit into an operation carried in the version
//! (`MergeOp`) — or takes an operation the app built
//! ([`put_op`](crate::DataLayer::put_op)) — checks each operation against
//! the versions it was made over, and folds operations into a [`Value`].
//! The layer treats operations as opaque bytes; which function a
//! collection uses is named, exactly, in its members record
//! ([`Rule::Merge`](crate::Rule::Merge)). A device that does not know the
//! named rule holds the collection's versions and reads them under no other
//! rule ([`DataError::RuleUnknown`](crate::DataError::RuleUnknown)). This
//! module ships one: [`Yrs`], named `/merge/yrs`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;

use crate::version::{Content, Frontier, VersionId, Writer};

/// Why an operation cannot be made or applied: refused for good.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("merge: {0}")]
pub struct MergeError(pub String);

/// The merged value: the rule defines it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// Named fields (what `/merge/yrs` merges into).
    Fields(Content),
    /// The rule's own encoding; the crate that defines the rule decodes it.
    Rule(Bytes),
}

impl Value {
    /// The fields, when the rule merges into named fields.
    pub fn fields(&self) -> Option<&Content> {
        match self {
            Value::Fields(c) => Some(c),
            Value::Rule(_) => None,
        }
    }

    /// The rule's own encoding, when it has one.
    pub fn bytes(&self) -> Option<&Bytes> {
        match self {
            Value::Rule(b) => Some(b),
            Value::Fields(_) => None,
        }
    }
}

/// What the rule makes of one applied version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Counting {
    /// In the value.
    Counted,
    /// Applied (inside the state's frontier, so later versions do not wait
    /// for it), stored and shown, but not in the value, for this reason. The
    /// rule may count it later, as it may stop counting a version it counted
    /// ([`MergeState::counting_changed`]).
    NotCounted(String),
}

/// What an operation is to the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpKind {
    /// An edit: applied once every version it was made over is applied.
    Edit,
    /// A checkpoint: its operation stands for every version it was made
    /// over, so a reader applies it once those are held as signed records
    /// (applied or not, whole or not), and never applies them to the rule
    /// afterwards.
    Checkpoint,
}

/// The versions an operation was made over (spec §5.2): exactly down(P)
/// where P = the version's parents joined with (its writer, seq − 1) —
/// every version of the collection at or below P, writer by writer, that
/// applies at all. A version below P that never applies (refused for what
/// it carries, outside a cut, by a key no writer) is not in it, whether or
/// not this device holds it: every reader answers alike.
pub trait Past {
    /// Whether `id` lies inside it.
    fn contains(&self, id: &VersionId) -> bool;
    /// The version of this collection inside the past whose packet has this
    /// implicit digest (SHA-256 of the whole Data packet: the version's
    /// content address). An operation whose basis is a version that never
    /// applies finds none: the rule judges it as a basis outside its past
    /// (it refuses it, or counts it without that basis, as it defines).
    fn by_digest(&self, digest: &[u8; 32]) -> Option<VersionId>;
}

/// One version's operation as the layer hands it to the rule.
pub struct Op<'a> {
    /// Its writer (one key) and seq.
    pub id: &'a VersionId,
    /// The implicit digest of its packet.
    pub digest: &'a [u8; 32],
    /// Its parents.
    pub parents: &'a Frontier,
    /// The versions it was made over.
    pub past: &'a dyn Past,
    /// The `MergeOp` octets.
    pub bytes: &'a [u8],
}

/// A named merge function.
pub trait MergeRule: Send + Sync {
    /// Its versioned name, e.g. `/ndf/merge/element/v=1`; matched exactly,
    /// never by prefix. A change of meaning is a new name.
    fn function(&self) -> &Name;

    /// An empty state of `collection`, in which `local` (this device's
    /// writer) may edit. The collection's name says whose it is: its owner
    /// devices are those [`owns`] answers for.
    fn start(&self, collection: &Name, local: &Writer) -> Box<dyn MergeState>;
}

/// Whether `writer` is an owner device of `collection`: its device — the
/// key name `<D>/KEY/<key-id>` without `KEY/<key-id>` — lies under the
/// collection's namespace, the components before its `32=data` marker
/// (spec §3). Alice's laptop and phone both own `/alice/32=data/notes`;
/// Bob's laptop does not. It depends on the two names alone, never on what
/// a device holds, so every member judges a writer alike in any arrival
/// order; the layer judges its owner rule by this same test.
///
/// The owner rule also asks which held trust context governs the device:
/// a device of a longer namespace held beside the collection's (a
/// `/home/bob` device, for `/home/32=data/x`) is that namespace's device,
/// not an owner. Names alone cannot tell that, and a rule's answer may not
/// depend on the contexts one member holds, so `owns` answers the name
/// half: whether `D` lies under the namespace — what a reader holding the
/// collection's namespace and no longer one under it concludes.
///
/// A revoked owner device, or one outside a cut, needs no handling here:
/// its versions the layer refuses never reach [`MergeState::apply`].
pub fn owns(collection: &Name, writer: &Writer) -> bool {
    let key = writer.key();
    crate::wire::device_len(key)
        .is_some_and(|n| crate::wire::device_owns(collection, &key.components()[..n]))
}

/// One collection's state under a merge rule.
pub trait MergeState: Send {
    /// `put` with fields: make `local`'s edit as an operation — set every
    /// field of `edit`, remove those whose value is empty, keep every other
    /// field (model invariant 8). The layer then checks and applies the
    /// operation like any other; a rule whose `edit` already changed its
    /// state makes that `apply` idempotent (yrs: re-applying an integrated
    /// update is a no-op).
    fn edit(&mut self, edit: &Content) -> Result<Bytes, MergeError> {
        let _ = edit;
        Err(MergeError(
            "this rule takes operations the app builds, not fields; use put_op".into(),
        ))
    }

    /// Whether `op` is one its writer may have made: nothing outside its
    /// writer's identity, nothing outside `op.past`, nothing it cannot
    /// carry. A function of the operation and its past only, so every
    /// reader judges it alike. Err: refused for good — every reason in the
    /// operation itself belongs here. Says whether it is a checkpoint.
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError>;

    /// Apply a checked operation. The layer applies a version only after
    /// its writer's earlier ones and its parents (an edit), or once every
    /// version of its past is held (a checkpoint). `NotCounted`: stored,
    /// shown, not in the value — what an exclusion that depends on the
    /// state (on other writers' versions) answers. Whether a version counts
    /// MUST be a function of the set of versions applied (each with its
    /// past), never of the order they arrived in: two states holding the
    /// same applied versions count the same ones. Err: it does not apply to
    /// the state met here; the state MUST be left unchanged, and the layer
    /// keeps the version applied and not counted with this reason (never
    /// refused: the state is others' doing, so nothing apply answers
    /// withdraws a version or its group). An own operation that errs is not
    /// written.
    ///
    /// A checkpoint's application yields the state of its past and itself,
    /// plus whatever concurrent versions were applied, whichever subset of
    /// its past was applied before. It is applied only once each of its
    /// parents is held here as the very packet it names (spec §5.2).
    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError>;

    /// The applied versions, other than the one `apply` just answered for,
    /// whose counting changed since last asked, each with how it counts
    /// now: `Counted` for one that starts counting, `NotCounted` with why
    /// for one that stops, or whose reason changed. Counting moves both
    /// ways as the applied set grows (a lock arriving after a write made
    /// apart from it). The layer asks after every apply and tells the
    /// watchers each change.
    fn counting_changed(&mut self) -> Vec<(VersionId, Counting)> {
        Vec::new()
    }

    /// The merged value, leaving out `excluded`: applied versions the
    /// layer holds back (members of a group waiting on another member,
    /// spec §5.5). They stay applied — the rule's counting of every other
    /// version still sees them — and are only kept out of what is shown.
    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value;
}

/// The merge rules a device knows, by function name.
#[derive(Clone)]
pub struct MergeRules(Vec<Arc<dyn MergeRule>>);

impl MergeRules {
    /// The rules this crate ships: [`Yrs`].
    pub fn standard() -> Self {
        Self(vec![Arc::new(Yrs::new())])
    }

    /// These rules and `rule`, which replaces one of the same name.
    pub fn with(mut self, rule: Arc<dyn MergeRule>) -> Self {
        self.0.retain(|r| r.function() != rule.function());
        self.0.push(rule);
        self
    }

    /// The rule named exactly `function`, if this device knows it.
    pub fn get(&self, function: &Name) -> Option<&Arc<dyn MergeRule>> {
        self.0.iter().find(|r| r.function() == function)
    }
}

impl std::fmt::Debug for MergeRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|r| r.function().to_string()))
            .finish()
    }
}

/// `/merge/yrs`: a Yjs document (via `yrs`) whose root map `fields` holds
/// one entry per field, each value a binary (`Uint8Array` in Yjs).
///
/// The operation is the Yjs update (lib0 v1 encoding) of the edit, so a Yjs
/// peer — NDN Workspace, Ownly — can apply the same bytes. Concurrent sets of
/// one field resolve as Yjs resolves them (deterministically, by client id);
/// different fields never conflict. Each writer's Yjs client id is the low
/// 53 bits of SHA-256 over its key name; an operation may only insert
/// content under its writer's client id, and may place its items against,
/// and delete, only content inside its past: for each other client, below
/// the clock that client's writer had reached in the operation's past.
///
/// Every operation counts. The state keeps each applied update, so that it
/// can show the value without the versions the layer holds back
/// ([`MergeState::value`]): those are left out by integrating every other
/// update into a document of its own, in which an update placed against
/// content left out is not integrated either (Yjs integrates an update only
/// once what it builds on is there).
pub struct Yrs {
    function: Name,
}

impl Yrs {
    /// The rule.
    pub fn new() -> Self {
        Self {
            function: "/merge/yrs".parse().expect("a valid name"),
        }
    }
}

impl Default for Yrs {
    fn default() -> Self {
        Self::new()
    }
}

/// The root map's name in the Yjs document.
const FIELDS: &str = "fields";

/// The Yjs client id of `writer`.
pub fn yrs_client(writer: &Writer) -> u64 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(writer.key().encode_to_tlv());
    u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]) & ((1 << 53) - 1)
}

impl MergeRule for Yrs {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _collection: &Name, local: &Writer) -> Box<dyn MergeState> {
        let doc = yrs::Doc::with_client_id(yrs_client(local));
        let fields = doc.get_or_insert_map(FIELDS);
        Box::new(YrsState {
            doc,
            fields,
            clocks: HashMap::new(),
            updates: Vec::new(),
        })
    }
}

struct YrsState {
    doc: yrs::Doc,
    fields: yrs::MapRef,
    /// Per Yjs client, its writer and the client's clock after each of
    /// that writer's versions applied, by seq: what an operation's past
    /// holds of each client.
    clocks: HashMap<u64, (Writer, BTreeMap<u64, u32>)>,
    /// Each applied version's update, in the order applied: what the value
    /// without held-back versions is made from.
    updates: Vec<(VersionId, Bytes)>,
}

/// What a Yjs update reaches, read as yrs reads it (lib0 v1): the clock
/// ranges it carries content in, per client; every id its items are placed
/// against (left and right origins, parent items); and its delete set.
#[derive(Default)]
struct Reach {
    inserts: Vec<(u64, u32, u32)>,
    refs: Vec<(u64, u32)>,
    deletes: Vec<(u64, u32, u32)>,
}

fn reach(bytes: &[u8]) -> Result<Reach, yrs::encoding::read::Error> {
    use yrs::block::{
        BLOCK_GC_REF_NUMBER, BLOCK_SKIP_REF_NUMBER, HAS_ORIGIN, HAS_PARENT_SUB, HAS_RIGHT_ORIGIN,
        ItemContent,
    };
    use yrs::encoding::read::{Cursor, Read};
    use yrs::updates::decoder::{Decode, Decoder, DecoderV1};
    let mut d = DecoderV1::new(Cursor::new(bytes));
    let mut out = Reach::default();
    let clients: u32 = d.read_var()?;
    for _ in 0..clients {
        let blocks: u32 = d.read_var()?;
        let client = d.read_client()?.get();
        let mut clock: u32 = d.read_var()?;
        for _ in 0..blocks {
            let info = d.read_info()?;
            let len = match info {
                BLOCK_SKIP_REF_NUMBER => {
                    let len: u32 = d.read_var()?;
                    clock = clock.saturating_add(len);
                    continue;
                }
                BLOCK_GC_REF_NUMBER => d.read_len()?,
                _ => {
                    let (left, right) = (info & HAS_ORIGIN != 0, info & HAS_RIGHT_ORIGIN != 0);
                    if left {
                        let id = d.read_left_id()?;
                        out.refs.push((id.client.get(), id.clock));
                    }
                    if right {
                        let id = d.read_right_id()?;
                        out.refs.push((id.client.get(), id.clock));
                    }
                    if !left && !right {
                        if d.read_parent_info()? {
                            d.read_string()?;
                        } else {
                            let id = d.read_left_id()?;
                            out.refs.push((id.client.get(), id.clock));
                        }
                        if info & HAS_PARENT_SUB != 0 {
                            d.read_string()?;
                        }
                    }
                    ItemContent::decode(&mut d, info)?.len(yrs::OffsetKind::Utf16)
                }
            };
            if len > 0 {
                let end = clock.saturating_add(len);
                out.inserts.push((client, clock, end));
                clock = end;
            }
        }
    }
    let deleted = yrs::IdSet::decode(&mut d)?;
    for (client, ranges) in deleted.iter() {
        for r in ranges.iter() {
            out.deletes.push((client.get(), r.start, r.end));
        }
    }
    Ok(out)
}

impl YrsState {
    /// The clock of `client` in `op`'s past: what its writer's highest
    /// version applied inside the past reached.
    fn bound(&self, op: &Op<'_>, client: u64) -> u32 {
        let Some((writer, by_seq)) = self.clocks.get(&client) else {
            return 0;
        };
        let mut upto = op.parents.get(writer).map(|s| s.0);
        if *writer == op.id.writer {
            upto = upto.max(op.id.seq.0.checked_sub(1));
        }
        upto.and_then(|s| by_seq.range(..=s).next_back())
            .map_or(0, |(_, clock)| *clock)
    }
}

impl MergeState for YrsState {
    fn edit(&mut self, edit: &Content) -> Result<Bytes, MergeError> {
        use yrs::{Map, Transact};
        let mut txn = self.doc.transact_mut();
        for (name, value) in edit.fields() {
            if value.is_empty() {
                self.fields.remove(&mut txn, name);
            } else {
                self.fields
                    .insert(&mut txn, name, yrs::Any::Buffer(Arc::from(value.as_ref())));
            }
        }
        Ok(Bytes::from(txn.encode_update_v1()))
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        use yrs::updates::decoder::Decode;
        use yrs::{ReadTxn, Transact};
        let update = yrs::Update::decode_v1(op.bytes)
            .map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        // Content integrated already (this device's own edit) is skipped.
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| MergeError(format!("the Yjs update does not apply: {e}")))?;
        let client = yrs_client(&op.id.writer);
        let clock = self
            .doc
            .transact()
            .state_vector()
            .get(&yrs::ClientID::new(client));
        self.clocks
            .entry(client)
            .or_insert_with(|| (op.id.writer.clone(), BTreeMap::new()))
            .1
            .insert(op.id.seq.0, clock);
        self.updates
            .push((op.id.clone(), Bytes::copy_from_slice(op.bytes)));
        Ok(Counting::Counted)
    }

    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        let reach = reach(op.bytes).map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        let own = yrs_client(&op.id.writer);
        if let Some((other, ..)) = reach.inserts.iter().find(|(c, ..)| *c != own) {
            return Err(MergeError(format!(
                "the update inserts content as Yjs client {other}, not its writer's {own}"
            )));
        }
        // What each client's content in the past reaches; the writer's own
        // also what the update itself inserts.
        let own_end = reach.inserts.iter().map(|(_, _, end)| *end).max();
        let bound = |client: u64| {
            let past = self.bound(op, client);
            match client == own {
                true => past.max(own_end.unwrap_or(0)),
                false => past,
            }
        };
        if let Some((client, clock)) = reach.refs.iter().find(|(c, k)| *k >= bound(*c)) {
            return Err(MergeError(format!(
                "the update places content against Yjs client {client}'s item {clock}, which \
                 is not in the versions it was made over: an update is made only over content \
                 its writer held"
            )));
        }
        if let Some((client, from, to)) = reach.deletes.iter().find(|(c, _, to)| *to > bound(*c)) {
            return Err(MergeError(format!(
                "the update deletes Yjs client {client}'s items {from}..{to}, not all in the \
                 versions it was made over: an update deletes only content its writer held"
            )));
        }
        Ok(OpKind::Edit)
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        use yrs::Transact;
        use yrs::updates::decoder::Decode;
        if excluded.is_empty() || !self.updates.iter().any(|(id, _)| excluded.contains(id)) {
            return fields_of(&self.doc, &self.fields);
        }
        // Every update but those held back, into a document of its own.
        let doc = yrs::Doc::new();
        let fields = doc.get_or_insert_map(FIELDS);
        {
            let mut txn = doc.transact_mut();
            for (_, bytes) in self.updates.iter().filter(|(id, _)| !excluded.contains(id)) {
                // Each applied to the live document once, so each decodes
                // and applies here too; one that does not is left out.
                if let Ok(update) = yrs::Update::decode_v1(bytes) {
                    let _ = txn.apply_update(update);
                }
            }
        }
        fields_of(&doc, &fields)
    }
}

/// The fields `fields`, the root map of `doc`, holds.
fn fields_of(doc: &yrs::Doc, fields: &yrs::MapRef) -> Value {
    use yrs::{Map, Out, Transact};
    let txn = doc.transact();
    let mut c = Content::new();
    for (name, value) in fields.iter(&txn) {
        let bytes = match value {
            Out::Any(yrs::Any::Buffer(b)) => Bytes::copy_from_slice(&b),
            Out::Any(yrs::Any::String(s)) => Bytes::copy_from_slice(s.as_bytes()),
            // A Yjs peer may store other shapes; they are not fields of
            // this layer's content and are kept in the document untouched.
            _ => continue,
        };
        c = c.with(name, bytes);
    }
    Value::Fields(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Writer {
        Writer::new(s.parse().unwrap())
    }

    fn text(fields: &[(&str, &str)]) -> Content {
        fields.iter().fold(Content::new(), |c, (k, v)| {
            c.with(*k, v.as_bytes().to_vec())
        })
    }

    /// No version is needed for a Yjs update's check.
    struct Nothing;

    impl Past for Nothing {
        fn contains(&self, _: &VersionId) -> bool {
            false
        }
        fn by_digest(&self, _: &[u8; 32]) -> Option<VersionId> {
            None
        }
    }

    fn op<'a>(id: &'a VersionId, bytes: &'a [u8], parents: &'a Frontier) -> Op<'a> {
        Op {
            id,
            digest: &[0; 32],
            parents,
            past: &Nothing,
            bytes,
        }
    }

    fn id(writer: &Writer, seq: u64) -> VersionId {
        VersionId {
            writer: writer.clone(),
            seq: crate::version::Seq(seq),
        }
    }

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn concurrent_edits_merge_alike_in_any_order() {
        let (laptop, phone) = (w("/alice/laptop/KEY/1"), w("/alice/phone/KEY/1"));
        let c = n("/alice/32=data/trip");
        let none = Frontier::new();
        let shown = BTreeSet::new();
        let rule = Yrs::new();
        let mut a = rule.start(&c, &laptop);
        let base = a
            .edit(&text(&[("text", "day 1"), ("tags", "trip")]))
            .unwrap();
        let base_id = id(&laptop, 1);
        // Applying its own edit again changes nothing.
        let before = a.value(&shown);
        assert_eq!(
            a.apply(&op(&base_id, &base, &none)).unwrap(),
            Counting::Counted
        );
        assert_eq!(a.value(&shown), before);
        let mut b = rule.start(&c, &phone);
        b.apply(&op(&base_id, &base, &none)).unwrap();
        let plane = a.edit(&text(&[("text", "on the plane")])).unwrap();
        let taxi = b
            .edit(&text(&[("text", "in the taxi"), ("tags", "")]))
            .unwrap();
        let (plane_id, taxi_id) = (id(&laptop, 2), id(&phone, 1));
        a.apply(&op(&plane_id, &plane, &none)).unwrap();
        a.apply(&op(&taxi_id, &taxi, &none)).unwrap();
        b.apply(&op(&plane_id, &plane, &none)).unwrap();
        assert_eq!(a.value(&shown), b.value(&shown));
        assert_eq!(
            a.value(&shown).fields().and_then(|f| f.get("tags")),
            None,
            "the phone removed the tags"
        );
        // The taxi edit removes tags of the base: made over it, it passes;
        // made over nothing, it reaches outside its past.
        let over_base: Frontier = [base_id.clone()].into_iter().collect();
        assert_eq!(a.check(&op(&taxi_id, &taxi, &over_base)), Ok(OpKind::Edit));
        assert!(a.check(&op(&taxi_id, &taxi, &none)).is_err());
        assert!(
            a.check(&op(&id(&laptop, 3), &taxi, &over_base)).is_err(),
            "an op is its writer's own"
        );
    }

    /// A version the layer holds back stays applied and out of the value,
    /// on every state alike, and is shown again once it is not held back.
    #[test]
    fn a_held_back_version_is_left_out_of_the_value_alike() {
        let (laptop, phone) = (w("/alice/laptop/KEY/1"), w("/alice/phone/KEY/1"));
        let c = n("/alice/32=data/trip");
        let none = Frontier::new();
        let rule = Yrs::new();
        let mut a = rule.start(&c, &laptop);
        let base = a.edit(&text(&[("text", "day 1")])).unwrap();
        let base_id = id(&laptop, 1);
        a.apply(&op(&base_id, &base, &none)).unwrap();
        let mut b = rule.start(&c, &phone);
        b.apply(&op(&base_id, &base, &none)).unwrap();
        let tags = b.edit(&text(&[("tags", "trip")])).unwrap();
        let tags_id = id(&phone, 1);
        b.apply(&op(&tags_id, &tags, &none)).unwrap();
        a.apply(&op(&tags_id, &tags, &none)).unwrap();
        let held: BTreeSet<VersionId> = [tags_id.clone()].into();
        let without = a.value(&held);
        assert_eq!(without, b.value(&held));
        assert_eq!(without.fields().and_then(|f| f.get("tags")), None);
        assert!(without.fields().and_then(|f| f.get("text")).is_some());
        assert!(
            a.value(&BTreeSet::new())
                .fields()
                .and_then(|f| f.get("tags"))
                .is_some(),
            "held back is not dropped"
        );
    }

    #[test]
    fn owns_is_a_device_of_the_collections_namespace() {
        let notes = n("/alice/32=data/notes/p1");
        // Every device of the namespace owns it, the namespace's own key too.
        for key in [
            "/alice/laptop/KEY/1",
            "/alice/phone/KEY/7",
            "/alice/member/tablet/KEY/2",
            "/alice/KEY/1",
        ] {
            assert!(owns(&notes, &w(key)), "{key} owns {notes}");
        }
        // Another namespace's device, one whose name only starts alike, and
        // a name that is no key name do not.
        for key in [
            "/bob/laptop/KEY/1",
            "/alicia/laptop/KEY/1",
            "/alice/laptop",
            "/alice/laptop/KEY",
        ] {
            assert!(!owns(&notes, &w(key)), "{key} does not own {notes}");
        }
        // The namespace ends at the marker, however many components it has:
        // the folder and every collection under it alike.
        let home = n("/home/bob/32=data/x");
        assert!(owns(&home, &w("/home/bob/member/laptop/KEY/1")));
        assert!(!owns(&home, &w("/home/member/hub/KEY/1")));
        assert!(owns(
            &n("/home/32=data/x"),
            &w("/home/bob/member/laptop/KEY/1")
        ));
        assert!(owns(&n("/alice/32=data"), &w("/alice/laptop/KEY/1")));
        // A name that is no data name has no owner.
        assert!(!owns(&n("/alice/notes"), &w("/alice/laptop/KEY/1")));
    }
}
