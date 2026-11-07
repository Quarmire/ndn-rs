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
    /// rule may count it later ([`MergeState::now_counted`]).
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
/// where P = the version's parents joined with (its writer, seq − 1).
pub trait Past {
    /// Whether `id` lies inside it.
    fn contains(&self, id: &VersionId) -> bool;
    /// The version of this collection inside the past whose packet has this
    /// implicit digest (SHA-256 of the whole Data packet: the version's
    /// content address), if it is held here.
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

    /// An empty state, in which `local` (this device's writer) may edit.
    fn start(&self, local: &Writer) -> Box<dyn MergeState>;
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
    /// writer's identity, nothing outside `op.past`. A function of the
    /// operation and its past only, so every reader judges it alike. Err:
    /// refused for good. Says whether it is a checkpoint.
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError>;

    /// Apply a checked operation. The layer applies a version only after
    /// its writer's earlier ones and its parents (an edit), or once every
    /// version of its past is held (a checkpoint). Err: refused for good.
    /// `NotCounted`: stored, shown, not in the value.
    ///
    /// A checkpoint's application yields the state of its past and itself,
    /// plus whatever concurrent versions were applied, whichever subset of
    /// its past was applied before.
    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError>;

    /// Versions earlier answered `NotCounted` that now count, since last
    /// asked. The layer asks after every apply.
    fn now_counted(&mut self) -> Vec<VersionId> {
        Vec::new()
    }

    /// The merged value.
    fn value(&self) -> Value;
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
/// 53 bits of SHA-256 over its key name, and an operation may only insert
/// content under its writer's client id.
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

    fn start(&self, local: &Writer) -> Box<dyn MergeState> {
        let doc = yrs::Doc::with_client_id(yrs_client(local));
        let fields = doc.get_or_insert_map(FIELDS);
        Box::new(YrsState { doc, fields })
    }
}

struct YrsState {
    doc: yrs::Doc,
    fields: yrs::MapRef,
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
        use yrs::Transact;
        use yrs::updates::decoder::Decode;
        let update = yrs::Update::decode_v1(op.bytes)
            .map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        // Content integrated already (this device's own edit) is skipped.
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| MergeError(format!("the Yjs update does not apply: {e}")))?;
        Ok(Counting::Counted)
    }

    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        use yrs::updates::decoder::Decode;
        let update = yrs::Update::decode_v1(op.bytes)
            .map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        let own = yrs_client(&op.id.writer);
        match update
            .state_vector()
            .iter()
            .map(|(client, _)| client.get())
            .find(|c| *c != own)
        {
            Some(other) => Err(MergeError(format!(
                "the update inserts content as Yjs client {other}, not its writer's {own}"
            ))),
            None => Ok(OpKind::Edit),
        }
    }

    fn value(&self) -> Value {
        use yrs::{Map, Out, Transact};
        let txn = self.doc.transact();
        let mut c = Content::new();
        for (name, value) in self.fields.iter(&txn) {
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

    #[test]
    fn concurrent_edits_merge_alike_in_any_order() {
        let (laptop, phone) = (w("/alice/laptop/KEY/1"), w("/alice/phone/KEY/1"));
        let none = Frontier::new();
        let rule = Yrs::new();
        let mut a = rule.start(&laptop);
        let base = a
            .edit(&text(&[("text", "day 1"), ("tags", "trip")]))
            .unwrap();
        let base_id = id(&laptop, 1);
        // Applying its own edit again changes nothing.
        let before = a.value();
        assert_eq!(
            a.apply(&op(&base_id, &base, &none)).unwrap(),
            Counting::Counted
        );
        assert_eq!(a.value(), before);
        let mut b = rule.start(&phone);
        b.apply(&op(&base_id, &base, &none)).unwrap();
        let plane = a.edit(&text(&[("text", "on the plane")])).unwrap();
        let taxi = b
            .edit(&text(&[("text", "in the taxi"), ("tags", "")]))
            .unwrap();
        let (plane_id, taxi_id) = (id(&laptop, 2), id(&phone, 1));
        a.apply(&op(&taxi_id, &taxi, &none)).unwrap();
        b.apply(&op(&plane_id, &plane, &none)).unwrap();
        assert_eq!(a.value(), b.value());
        assert_eq!(
            a.value().fields().and_then(|f| f.get("tags")),
            None,
            "the phone removed the tags"
        );
        assert_eq!(a.check(&op(&taxi_id, &taxi, &none)), Ok(OpKind::Edit));
        assert!(
            a.check(&op(&id(&laptop, 3), &taxi, &none)).is_err(),
            "an op is its writer's own"
        );
    }
}
