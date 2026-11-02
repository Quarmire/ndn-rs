//! Merge rules: the named functions a merge collection's readers all run
//! alike, so every device that holds the same versions computes the same
//! state.
//!
//! A rule turns a writer's edit into an operation carried in the version
//! (`MergeOp`), and folds operations into a state. The layer treats
//! operations as opaque bytes; which function a collection uses is named in
//! its members record ([`Rule::Merge`](crate::Rule::Merge)). This module
//! ships one: [`Yrs`], named `/merge/yrs`.

use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;

use crate::version::{Content, Writer};

/// Why an operation cannot be made or applied.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("merge: {0}")]
pub struct MergeError(pub String);

/// A named merge function.
pub trait MergeRule: Send + Sync {
    /// The name members records give it, e.g. `/merge/yrs`.
    fn function(&self) -> &Name;

    /// An empty state, in which `local` (this device's writer) may edit.
    fn start(&self, local: &Writer) -> Box<dyn MergeState>;
}

/// One collection's state under a merge rule.
pub trait MergeState: Send {
    /// Make `local`'s edit: set every field of `edit`, remove those whose
    /// value is empty, keep every other field (model invariant 8). Applies it
    /// and returns the operation that carries it.
    fn edit(&mut self, edit: &Content) -> Result<Bytes, MergeError>;

    /// Apply `writer`'s operation. The caller applies a version only after
    /// its parents, so every operation's dependencies are present.
    fn apply(&mut self, writer: &Writer, op: &[u8]) -> Result<(), MergeError>;

    /// Whether `op` is one `writer` may have made: it may only add content
    /// under `writer`'s own identity.
    fn check(&self, writer: &Writer, op: &[u8]) -> Result<(), MergeError>;

    /// The merged value.
    fn value(&self) -> Content;
}

/// The merge rules a device knows, by function name.
#[derive(Clone)]
pub struct MergeRules(Vec<Arc<dyn MergeRule>>);

impl MergeRules {
    /// The rules this crate ships: [`Yrs`].
    pub fn standard() -> Self {
        Self(vec![Arc::new(Yrs::new())])
    }

    /// These rules and `rule`.
    pub fn with(mut self, rule: Arc<dyn MergeRule>) -> Self {
        self.0.push(rule);
        self
    }

    /// The rule named `function`, if this device knows it.
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

    fn apply(&mut self, _writer: &Writer, op: &[u8]) -> Result<(), MergeError> {
        use yrs::Transact;
        use yrs::updates::decoder::Decode;
        let update =
            yrs::Update::decode_v1(op).map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        self.doc
            .transact_mut()
            .apply_update(update)
            .map_err(|e| MergeError(format!("the Yjs update does not apply: {e}")))
    }

    fn check(&self, writer: &Writer, op: &[u8]) -> Result<(), MergeError> {
        use yrs::updates::decoder::Decode;
        let update =
            yrs::Update::decode_v1(op).map_err(|e| MergeError(format!("not a Yjs update: {e}")))?;
        let own = yrs_client(writer);
        match update
            .state_vector()
            .iter()
            .map(|(client, _)| client.get())
            .find(|c| *c != own)
        {
            Some(other) => Err(MergeError(format!(
                "the update inserts content as Yjs client {other}, not its writer's {own}"
            ))),
            None => Ok(()),
        }
    }

    fn value(&self) -> Content {
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
        c
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

    #[test]
    fn concurrent_edits_merge_alike_in_any_order() {
        let (laptop, phone) = (w("/alice/laptop/KEY/1"), w("/alice/phone/KEY/1"));
        let rule = Yrs::new();
        let mut a = rule.start(&laptop);
        let base = a
            .edit(&text(&[("text", "day 1"), ("tags", "trip")]))
            .unwrap();
        let mut b = rule.start(&phone);
        b.apply(&laptop, &base).unwrap();
        let plane = a.edit(&text(&[("text", "on the plane")])).unwrap();
        let taxi = b
            .edit(&text(&[("text", "in the taxi"), ("tags", "")]))
            .unwrap();
        a.apply(&phone, &taxi).unwrap();
        b.apply(&laptop, &plane).unwrap();
        assert_eq!(a.value(), b.value());
        assert_eq!(a.value().get("tags"), None, "the phone removed the tags");
        assert!(a.check(&phone, &taxi).is_ok());
        assert!(
            a.check(&laptop, &taxi).is_err(),
            "an op is its writer's own"
        );
    }
}
