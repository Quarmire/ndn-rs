//! V₀.2 — the frozen 32-term kernel, published as data written in itself —
//! plus T₀ (the terminal contract) and IM₀ (the implicit-manifest stratum).
//!
//! D-49 (ratified 2026-07-03): the kernel is baked into every implementation
//! *and* published as a vocabulary authored in V₀; implementations verify
//! their baked-in kernel hash-matches the published artifact — "the chicken
//! and the egg collapse into a quine" (ndf-two-cruxes). Growth requires a
//! failing conformance vector (knob #1, standing law): **you may not add
//! words here.**
//!
//! IM₀ is a pinned stratum beside V₀.2, not kernel growth (D-K6/F41): its
//! `name`/`size`/`kind` field terms are not kernel words, which is exactly
//! why R14 pins H(IM₀) separately. T₀ expresses `raw.inspect` + `text.plain`
//! against IM₀'s `block` term and therefore matches every implicit manifest —
//! the reason refusal is safe everywhere else (C3).

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::canon::{document_hash, encode_document, term_hash};
use crate::hash::Hash;
use crate::kernel_hash;
use crate::model::{
    Clause, Contract, Document, Field, Intent, Manifest, ManifestEntry, PrimitiveKind, Subject,
    Term, TypeExpr, Value, Vocabulary,
};

fn term(label: &str, doc: &str) -> Term {
    Term {
        label: String::from(label),
        doc: Some(String::from(doc)),
        ty: None,
        attrs: Vec::new(),
    }
}

fn typed_term(label: &str, doc: &str, ty: TypeExpr) -> Term {
    Term {
        label: String::from(label),
        doc: Some(String::from(doc)),
        ty: Some(ty),
        attrs: Vec::new(),
    }
}

/// Build V₀.2 as a vocabulary document: the 32 kernel words, in the kernel's
/// own listing order (meta → types → links → escape → render), each carrying
/// its doc string (L-05: doc strings are load-bearing data — `bench doc v0`
/// renders these).
pub fn v0_2() -> Vocabulary {
    Vocabulary {
        label: String::from("v0"),
        doc: Some(String::from(
            "The manifest kernel, V0.2 - 32 frozen terms. Baked into every \
             implementation and published as data written in itself; a term's \
             identity is its hash; everything above is open strata (D-49).",
        )),
        imports: Vec::new(),
        terms: vec![
            // ── meta (7) ────────────────────────────────────────────────
            term("vocabulary", "A published vocabulary: a labeled, documented set of terms and semantic edges. Strata are vocabularies; V0 is one."),
            term("term", "A unit of meaning. Identity = SHA-256 of its canonical definition bytes; labels are for humans and never key anything."),
            term("imports", "Definitional references to other vocabularies, by content hash via the lock (C5: hash-only, acyclic by physics)."),
            term("supersedes", "Versioning edge: this document replaces that one. Editing a published term compiles to a new version plus this edge (F26)."),
            term("label", "A human-facing name. Display-layer duty only; homoglyphs are answered with short-hash + origin chips, never wire transforms (R5/F22)."),
            term("doc", "Documentation text. Load-bearing data (L-05): reference cards are a render of these strings, not a writing project."),
            term("attribute", "A flat annotation: key is a term ref; value is a primitive or a term ref ONLY. Structure routes to records or reification (knob #4, P2)."),
            // ── types & shape (9) ───────────────────────────────────────
            term("field", "A named, typed slot of a record, with cardinality and flat attributes."),
            term("primitive", "The seven ground types: bytes, text, integer, decimal, boolean, hash, name."),
            term("list-of", "An ordered sequence of one element type; author order is preserved on the wire (R9)."),
            term("map-of", "A keyed collection; keys are text, integer, hash, name, or a term ref; entries sort by canonical key bytes (R8)."),
            term("term-of", "A value that is a term: one drawn from the referenced vocabulary, or narrower-than-reachable from the referenced parent term (D-K4)."),
            term("record", "A structure of fields; fields serialize in the order of the definition (R11)."),
            term("of", "Parametric instantiation with ONE type parameter on the user side (knob #2); instantiation depth is bounded by document size (C6)."),
            term("rec-group", "Intra-document mutual recursion: a group of terms that may reference each other. Equality is standard mu-equivalence; recursion never crosses documents (C5)."),
            term("cardinality", "How many: one (default, omitted on the wire), optional, some (>=1), many (0+)."),
            // ── links & meaning (6) ─────────────────────────────────────
            term("manifest", "A description of data against strata: a typed set of field bindings about a subject."),
            term("describes", "The manifest's subject: a content hash, or a name/prefix for stream subjects - never dereferenced by the matcher (C5/F3)."),
            term("edge", "An instance edge: subject, kind (a term ref), object, flat attributes."),
            term("narrower-than", "Subsumption: the narrower term is usable where the broader is asked for. Fidelity-preserving; admitted per-consumer (C10)."),
            term("equivalent-to", "Symmetric, lossless identification of two terms. Cross-author use is audited toward maps-to (L-09)."),
            term("maps-to", "Directional, lossy translation; carries its loss term structurally (D-K5). Traversal demotes Express to Approximate; path fidelity is the minimum of its hops (C9)."),
            // ── escape hatch (3) ────────────────────────────────────────
            term("opaque", "Any byte-string, describable now and upgradeable later by supersession - describe-later, never migrate (C4)."),
            term("media-type", "A media-type annotation (text), the escape hatch's handle for renderers."),
            term("external-ref", "A reference outside the system (text/URI) - the honest boundary marker."),
            // ── render side (7) ─────────────────────────────────────────
            term("contract", "A renderer's promise: which intents it expresses, approximates, or refuses, over which terms. Below the chain (D-48); wrapping in a Block adds history and authority, never meaning."),
            term("intent", "A named rendering intention (e.g. raw.inspect, text.plain), with flat attributes such as sensitivity tags (L-11)."),
            term("express", "Full-fidelity offer of an intent over a target term. Unlisted intents are refused, never inferred."),
            term("approximate", "Declared-lossy offer of an intent over a target term; the loss path is accumulated at match time."),
            term("refuse", "Explicit refusal of an intent. Redundant with default-refuse; kept as documentation (L-14)."),
            term("binds", "Optional subject filter: hash exact-match or name-prefix against a manifest's describes (F45)."),
            term("via", "The renderer binding: wasm(hash) - immune by construction - or native(attested-id), the register's open attestation gap. Inert bytes to the matcher (C8)."),
        ],
        edges: Vec::new(),
        supersedes: None,
    }
}

/// IM₀ — the implicit-manifest stratum. Derivation rule (C3): every block
/// yields `{content(opaque), media-type, name, size, kind}` from its envelope
/// alone. Nothing is ever undescribed.
pub fn im0() -> Vocabulary {
    Vocabulary {
        label: String::from("im0"),
        doc: Some(String::from(
            "The implicit-manifest stratum, pinned beside V0.2 (D-K6). Every \
             block derives an im0:block manifest from its envelope alone; T0 \
             matches every such manifest - the total floor (C3).",
        )),
        imports: Vec::new(),
        terms: vec![
            typed_term("content", "The block's payload, undescribed: raw octets behind the escape hatch (C4).", TypeExpr::Opaque),
            typed_term("media-type", "Envelope-declared media type, or application/octet-stream when absent.", TypeExpr::Primitive(PrimitiveKind::Text)),
            typed_term("name", "The block's NDN name.", TypeExpr::Primitive(PrimitiveKind::Name)),
            typed_term("size", "Payload size in bytes.", TypeExpr::Primitive(PrimitiveKind::Integer)),
            typed_term("kind", "The envelope's block kind, as text.", TypeExpr::Primitive(PrimitiveKind::Text)),
            typed_term(
                "block",
                "The implicit manifest's type term: what IM0 derivation yields and what T0 targets.",
                TypeExpr::Record(vec![
                    Field { label: String::from("media-type"), doc: None, ty: TypeExpr::Primitive(PrimitiveKind::Text), cardinality: Default::default(), attrs: Vec::new() },
                    Field { label: String::from("name"), doc: None, ty: TypeExpr::Primitive(PrimitiveKind::Name), cardinality: Default::default(), attrs: Vec::new() },
                    Field { label: String::from("size"), doc: None, ty: TypeExpr::Primitive(PrimitiveKind::Integer), cardinality: Default::default(), attrs: Vec::new() },
                    Field { label: String::from("kind"), doc: None, ty: TypeExpr::Primitive(PrimitiveKind::Text), cardinality: Default::default(), attrs: Vec::new() },
                ]),
            ),
        ],
        edges: Vec::new(),
        supersedes: None,
    }
}

/// IM₀'s term hashes, resolved once.
#[derive(Clone, Copy, Debug)]
pub struct Im0Terms {
    /// im0:block — T₀'s target and every implicit manifest's type.
    pub block: Hash,
    /// im0:content.
    pub content: Hash,
    /// im0:media-type.
    pub media_type: Hash,
    /// im0:name.
    pub name: Hash,
    /// im0:size.
    pub size: Hash,
    /// im0:kind.
    pub kind: Hash,
}

/// Compute IM₀'s term hashes from the stratum itself.
pub fn im0_terms() -> Im0Terms {
    let v = im0();
    let h = |i: usize| term_hash(&v.terms[i]).expect("kernel terms encode");
    Im0Terms {
        content: h(0),
        media_type: h(1),
        name: h(2),
        size: h(3),
        kind: h(4),
        block: h(5),
    }
}

/// Derive the implicit manifest for a block (the C3 total floor): envelope
/// facts only — the payload itself is never parsed here.
pub fn derive_im0(name: &str, payload_len: u64, media_type: Option<&str>, kind: &str) -> Manifest {
    let t = im0_terms();
    Manifest {
        ty: t.block,
        label: None,
        describes: Subject::Name(String::from(name)),
        entries: vec![
            ManifestEntry {
                field: t.media_type,
                value: Value::Text(String::from(media_type.unwrap_or("application/octet-stream"))),
            },
            ManifestEntry { field: t.name, value: Value::Name(String::from(name)) },
            ManifestEntry { field: t.size, value: Value::Integer(payload_len) },
            ManifestEntry { field: t.kind, value: Value::Text(String::from(kind)) },
        ],
        edges: Vec::new(),
    }
}

/// T₀ — the terminal contract: expresses `raw.inspect` + `text.plain` and
/// matches every IM₀ (C3). Explicit refusal is never needed anywhere else
/// because this floor exists.
pub fn t0(im0_vocab_hash: Hash) -> Contract {
    let t = im0_terms();
    let intent = |name: &str| Intent { name: String::from(name), attrs: Vec::new() };
    Contract {
        label: String::from("T0"),
        doc: Some(String::from(
            "The terminal contract: hex+mime inspection of anything, and plain \
             text where the payload is text. Matches every IM0 - the reason \
             refusal is safe everywhere else (C3).",
        )),
        imports: vec![im0_vocab_hash],
        binds: Vec::new(),
        clauses: vec![
            Clause::Express { intent: intent("raw.inspect"), target: t.block, via: None, attrs: Vec::new() },
            Clause::Express { intent: intent("text.plain"), target: t.block, via: None, attrs: Vec::new() },
        ],
    }
}

/// The fixed-point trio, computed from the code path (R14): canonical bytes
/// and hashes for V₀.2, IM₀, and T₀.
pub struct FixedPoint {
    /// V₀.2 canonical bytes.
    pub v0_bytes: Vec<u8>,
    /// H(V₀.2).
    pub v0_hash: Hash,
    /// IM₀ canonical bytes.
    pub im0_bytes: Vec<u8>,
    /// H(IM₀).
    pub im0_hash: Hash,
    /// T₀ canonical bytes.
    pub t0_bytes: Vec<u8>,
    /// H(T₀).
    pub t0_hash: Hash,
}

/// Compile the trio (what `ndn-bench freeze` runs, and what L-12 re-emits on
/// every bench run).
pub fn fixed_point() -> FixedPoint {
    let v0_bytes = encode_document(&Document::Vocabulary(v0_2())).expect("kernel encodes");
    let v0_hash = document_hash(&v0_bytes);
    let im0_bytes = encode_document(&Document::Vocabulary(im0())).expect("im0 encodes");
    let im0_hash = document_hash(&im0_bytes);
    let t0_bytes = encode_document(&Document::Contract(t0(im0_hash))).expect("t0 encodes");
    let t0_hash = document_hash(&t0_bytes);
    FixedPoint { v0_bytes, v0_hash, im0_bytes, im0_hash, t0_bytes, t0_hash }
}

/// The verdict of comparing the computed fixed point against the pinned
/// published hashes (R14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixedPointStatus {
    /// Computed hashes match the pins.
    Verified,
    /// No pins yet — `ndn-bench freeze --pin` has not been run (D-K8). The
    /// re-emission check still holds; only the *published-artifact* half of
    /// the quine is pending.
    Unpinned,
    /// A pin disagrees with the computed hash — the implementation and the
    /// published kernel have diverged. Refuse to proceed.
    Mismatch {
        /// Which artifact disagreed: "v0" | "im0" | "t0".
        which: &'static str,
        /// The computed hash.
        actual: Hash,
    },
}

fn parse_hex32(s: &str) -> Option<Hash> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Verify the baked-in kernel against the pinned published fixed point
/// (D-49: "implementations verify their baked-in kernel hash-matches the
/// published artifact"). Call this at init.
pub fn verify_fixed_point() -> FixedPointStatus {
    let fp = fixed_point();
    let pins = [
        ("v0", kernel_hash::V0_2_HASH_HEX, fp.v0_hash),
        ("im0", kernel_hash::IM0_HASH_HEX, fp.im0_hash),
        ("t0", kernel_hash::T0_HASH_HEX, fp.t0_hash),
    ];
    let mut any_pinned = false;
    for (which, pin, actual) in pins {
        if let Some(hex) = pin {
            any_pinned = true;
            match parse_hex32(hex) {
                Some(expected) if expected == actual => {}
                _ => return FixedPointStatus::Mismatch { which, actual },
            }
        }
    }
    if any_pinned { FixedPointStatus::Verified } else { FixedPointStatus::Unpinned }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canon::decode_document;
    use crate::dag::FrozenDag;

    #[test]
    fn kernel_has_exactly_32_terms() {
        // Knob #1: the term budget is the freeze. 7+9+6+3+7 = 32.
        assert_eq!(v0_2().terms.len(), 32);
    }

    #[test]
    fn kernel_in_kernel_reemits_byte_identically() {
        // C1 / L-12: parse V0-as-data with V0-as-code; byte-identical
        // re-emission (decode_document enforces R13 internally).
        let fp = fixed_point();
        let decoded = decode_document(&fp.v0_bytes).expect("kernel decodes");
        let Document::Vocabulary(v) = &decoded.doc else { panic!("kernel is a vocabulary") };
        assert_eq!(v.terms.len(), 32);
        assert_eq!(document_hash(&fp.v0_bytes), fp.v0_hash);
    }

    #[test]
    fn every_kernel_term_is_documented() {
        // L-05: undocumented public terms fail. The kernel is maximally public.
        for t in v0_2().terms {
            assert!(t.doc.is_some(), "kernel term {} lacks a doc string", t.label);
        }
    }

    #[test]
    fn im0_derivation_matches_t0_target() {
        // C3: pylon-7's raw LoRa frame renders as hex+mime with zero
        // vocabulary present — the derived manifest's type IS T0's target.
        let m = derive_im0("riverwatch/pylon-7/lora/0417", 42, None, "data");
        let t = im0_terms();
        assert_eq!(m.ty, t.block);
        let fp = fixed_point();
        let Document::Contract(t0c) = decode_document(&fp.t0_bytes).unwrap().doc else { panic!() };
        for clause in &t0c.clauses {
            match clause {
                Clause::Express { target, .. } => assert_eq!(*target, t.block),
                _ => panic!("T0 has only express clauses"),
            }
        }
    }

    #[test]
    fn fixed_point_is_stable_and_insertable() {
        let a = fixed_point();
        let b = fixed_point();
        assert_eq!(a.v0_hash, b.v0_hash);
        assert_eq!(a.im0_hash, b.im0_hash);
        assert_eq!(a.t0_hash, b.t0_hash);
        let mut dag = FrozenDag::new();
        assert_eq!(dag.insert_bytes(&a.v0_bytes).unwrap(), a.v0_hash);
        assert_eq!(dag.insert_bytes(&a.im0_bytes).unwrap(), a.im0_hash);
        assert_eq!(dag.insert_bytes(&a.t0_bytes).unwrap(), a.t0_hash);
    }

    #[test]
    fn fixed_point_status_is_honest_when_unpinned_or_pinned() {
        // Whichever state the repo is in (pre- or post- `freeze --pin`),
        // the status must be consistent with the constants — never Mismatch.
        match verify_fixed_point() {
            FixedPointStatus::Verified | FixedPointStatus::Unpinned => {}
            FixedPointStatus::Mismatch { which, .. } => {
                panic!("baked kernel diverged from pinned {which} hash — rerun `ndn-bench freeze --pin` deliberately");
            }
        }
    }
}
