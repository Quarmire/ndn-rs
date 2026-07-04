//! The frozen DAG: content-addressed documents, lock resolution, and the
//! acyclic import walk (obligation C5; F21's lockfile = snapshot rule).
//!
//! Definitional references are hash-only, so the definitional graph is a DAG
//! **by physics, not by discipline** (ndf-two-cruxes: "you cannot reference
//! what does not yet exist, because its hash is unknowable"). This module
//! never fetches anything — it resolves over what the caller inserted, and
//! reports what is missing (the C6′ *unresolved* regime), never guessing.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::canon::{decode_document, document_hash, encode_document, term_hash, EncodeError, Reject};
use crate::hash::Hash;
use crate::model::{Decoded, Document, Term};

/// A frozen, content-addressed set of decoded documents.
///
/// "Frozen" is literal: inserting is the only mutation, a document's key is
/// the SHA-256 of its canonical bytes, and nothing here can be rewritten
/// after snapshot (round-3 adversary denial: "rewriting a frozen DAG after
/// snapshot" is not granted).
#[derive(Default)]
pub struct FrozenDag {
    docs: BTreeMap<Hash, Entry>,
    /// term hash → (defining vocabulary hash, index into its `terms`).
    terms: BTreeMap<Hash, (Hash, usize)>,
}

struct Entry {
    bytes: Vec<u8>,
    decoded: Decoded,
}

impl FrozenDag {
    /// An empty DAG.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert canonical bytes. Decodes (which enforces R1–R13, including
    /// byte-identical re-emission), hashes, and indexes any vocabulary's
    /// terms. Returns the document hash.
    pub fn insert_bytes(&mut self, bytes: &[u8]) -> Result<Hash, Reject> {
        let decoded = decode_document(bytes)?;
        let h = document_hash(bytes);
        if let Document::Vocabulary(v) = &decoded.doc {
            for (i, t) in v.terms.iter().enumerate() {
                let th = term_hash(t).map_err(|_| Reject::ReencodeMismatch)?;
                self.terms.insert(th, (h, i));
            }
        }
        self.docs.insert(h, Entry { bytes: Vec::from(bytes), decoded });
        Ok(h)
    }

    /// Encode a model document canonically and insert it.
    pub fn insert_document(&mut self, doc: &Document) -> Result<Hash, EncodeError> {
        let bytes = encode_document(doc)?;
        // Freshly encoded canonical bytes must decode; a failure here is a
        // codec bug, surfaced as the encoder's own error kind.
        self.insert_bytes(&bytes).map_err(|_| EncodeError::NestedAttribute)
    }

    /// Look up a document by hash.
    pub fn get(&self, h: &Hash) -> Option<&Decoded> {
        self.docs.get(h).map(|e| &e.decoded)
    }

    /// The canonical bytes of a stored document.
    pub fn bytes(&self, h: &Hash) -> Option<&[u8]> {
        self.docs.get(h).map(|e| e.bytes.as_slice())
    }

    /// Whether the document is present.
    pub fn contains(&self, h: &Hash) -> bool {
        self.docs.contains_key(h)
    }

    /// Number of documents.
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Iterate `(hash, decoded)` in hash order (deterministic).
    pub fn iter(&self) -> impl Iterator<Item = (&Hash, &Decoded)> {
        self.docs.iter().map(|(h, e)| (h, &e.decoded))
    }

    /// Find a term by its identity hash: `(defining vocabulary, term)`.
    /// A `None` here is exactly the C6′ situation the matcher must render as
    /// *Unresolved*, never as a guess.
    pub fn find_term(&self, th: &Hash) -> Option<(Hash, &Term)> {
        let (vh, idx) = self.terms.get(th)?;
        let Document::Vocabulary(v) = &self.docs.get(vh)?.decoded.doc else {
            return None;
        };
        v.terms.get(*idx).map(|t| (*vh, t))
    }

    /// The vocabulary that defines a term, if known.
    pub fn defining_vocabulary(&self, th: &Hash) -> Option<Hash> {
        self.terms.get(th).map(|(vh, _)| *vh)
    }

    /// Walk the import closure from `root`. Termination is unconditional:
    /// hash references cannot cycle (C5), and the visited set bounds work by
    /// the number of stored documents. Missing imports are reported, not
    /// fetched and not guessed.
    pub fn import_closure(&self, root: &Hash) -> Resolution {
        let mut present = Vec::new();
        let mut missing = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = Vec::new();
        stack.push(*root);
        while let Some(h) = stack.pop() {
            if !seen.insert(h) {
                continue;
            }
            match self.docs.get(&h) {
                None => missing.push(h),
                Some(e) => {
                    present.push(h);
                    let imports: &[Hash] = match &e.decoded.doc {
                        Document::Vocabulary(v) => &v.imports,
                        Document::Contract(c) => &c.imports,
                        Document::Manifest(_) => &[],
                    };
                    for i in imports {
                        stack.push(*i);
                    }
                }
            }
        }
        if missing.is_empty() {
            Resolution::Complete(present)
        } else {
            Resolution::Unresolved { present, missing }
        }
    }
}

/// The outcome of an import walk: complete, or honestly partial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// Every transitively imported document is present.
    Complete(Vec<Hash>),
    /// Some imports are absent — the matcher's *Unresolved* feedstock.
    Unresolved {
        /// Documents found.
        present: Vec<Hash>,
        /// Hashes referenced but not inserted.
        missing: Vec<Hash>,
    },
}

/// The lockfile: petname → pinned content hash (F21 — "cargo's move, reused,
/// because it is exactly C5's snapshot rule made humane"). Authors never type
/// hashes; the artifact never contains petnames; the lock is the frozen-DAG
/// witness the matcher requires.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lock {
    pins: BTreeMap<String, Hash>,
}

impl Lock {
    /// An empty lock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin a petname. Returns the previous pin if the name was already taken
    /// (the bench treats a silent re-pin as an error; the calculus records it).
    pub fn pin(&mut self, petname: &str, hash: Hash) -> Option<Hash> {
        self.pins.insert(String::from(petname), hash)
    }

    /// Resolve a petname to its pinned hash. `None` is L-01's compile error:
    /// an unresolved petname is never a guess.
    pub fn resolve(&self, petname: &str) -> Option<Hash> {
        self.pins.get(petname).copied()
    }

    /// Iterate pins in name order (diffable, deterministic — the lock is a
    /// committed artifact).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Hash)> {
        self.pins.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Which pins point at documents the DAG does not hold. Non-empty means
    /// matching over this lock must go through the *Unresolved* path.
    pub fn missing_in(&self, dag: &FrozenDag) -> Vec<(&str, Hash)> {
        self.pins
            .iter()
            .filter(|(_, h)| !dag.contains(h))
            .map(|(k, h)| (k.as_str(), *h))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Manifest, Subject, Vocabulary};
    use alloc::vec;

    fn vocab(label: &str, imports: Vec<Hash>) -> Document {
        Document::Vocabulary(Vocabulary {
            label: String::from(label),
            doc: None,
            imports,
            terms: vec![Term { label: String::from("t"), doc: None, ty: None, attrs: Vec::new() }],
            edges: Vec::new(),
            supersedes: None,
        })
    }

    #[test]
    fn insert_indexes_terms_and_content_addresses() {
        let mut dag = FrozenDag::new();
        let h = dag.insert_document(&vocab("units", Vec::new())).unwrap();
        assert!(dag.contains(&h));
        let decoded = dag.get(&h).unwrap();
        let Document::Vocabulary(v) = &decoded.doc else { panic!() };
        let th = term_hash(&v.terms[0]).unwrap();
        let (vh, t) = dag.find_term(&th).unwrap();
        assert_eq!(vh, h);
        assert_eq!(t.label, "t");
    }

    #[test]
    fn import_closure_reports_missing_honestly() {
        let mut dag = FrozenDag::new();
        let missing_hash = [9u8; 32];
        let h = dag.insert_document(&vocab("apiary", vec![missing_hash])).unwrap();
        match dag.import_closure(&h) {
            Resolution::Unresolved { present, missing } => {
                assert_eq!(present, vec![h]);
                assert_eq!(missing, vec![missing_hash]);
            }
            r => panic!("expected unresolved, got {r:?}"),
        }
    }

    #[test]
    fn import_closure_completes_and_terminates() {
        let mut dag = FrozenDag::new();
        let base = dag.insert_document(&vocab("units", Vec::new())).unwrap();
        let mid = dag.insert_document(&vocab("measured", vec![base])).unwrap();
        // Diamond: two importers of `mid` + `base` — visited-set dedupe.
        let top = dag.insert_document(&vocab("hydro", vec![mid, base])).unwrap();
        match dag.import_closure(&top) {
            Resolution::Complete(present) => assert_eq!(present.len(), 3),
            r => panic!("expected complete, got {r:?}"),
        }
    }

    #[test]
    fn lock_resolves_and_reports_missing() {
        let mut dag = FrozenDag::new();
        let h = dag.insert_document(&vocab("units", Vec::new())).unwrap();
        let mut lock = Lock::new();
        lock.pin("units", h);
        lock.pin("loss", [3u8; 32]);
        assert_eq!(lock.resolve("units"), Some(h));
        assert_eq!(lock.resolve("nope"), None);
        let missing = lock.missing_in(&dag);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].0, "loss");
    }

    #[test]
    fn manifest_documents_insert_too() {
        let mut dag = FrozenDag::new();
        let m = Document::Manifest(Manifest {
            ty: [1u8; 32],
            label: None,
            describes: Subject::Name(String::from("a/b")),
            entries: Vec::new(),
            edges: Vec::new(),
        });
        let h = dag.insert_document(&m).unwrap();
        assert!(matches!(dag.get(&h).unwrap().doc, Document::Manifest(_)));
    }
}
