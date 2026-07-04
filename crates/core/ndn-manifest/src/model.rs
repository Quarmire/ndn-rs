//! The 32 kernel forms as types — V₀.2, frozen (D-49, ratified 2026-07-03).
//!
//! Every type here is one of the kernel's 32 words or a structural helper the
//! wire needs to carry them (ndf-the-landing Act IV: "model — the 32 kernel
//! forms as types"). Nothing else may be added: kernel growth requires a
//! failing conformance vector (knob #1, standing law).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hash::Hash;

// ───────────────────────────── primitives & values ──────────────────────────

/// The seven primitive kinds (kernel: `primitive {bytes, text, integer,
/// decimal, boolean, hash, name}`). Wire body is one code byte (D-K1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrimitiveKind {
    /// Raw octets.
    Bytes = 0,
    /// UTF-8 text; exact bytes, no normalization (R5).
    Text = 1,
    /// Unsigned varint on the wire; zigzag only where the term's type says
    /// signed (R3) — signedness is schema knowledge, not wire knowledge.
    Integer = 2,
    /// Canonical decimal string (R4).
    Decimal = 3,
    /// 0x00 / 0x01 only (R6).
    Boolean = 4,
    /// 32 raw bytes of SHA-256 (R7).
    Hash = 5,
    /// An NDN name (URI form), UTF-8, byte-wise comparison.
    Name = 6,
}

impl PrimitiveKind {
    /// Decode the single wire code byte.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Bytes,
            1 => Self::Text,
            2 => Self::Integer,
            3 => Self::Decimal,
            4 => Self::Boolean,
            5 => Self::Hash,
            6 => Self::Name,
            _ => return None,
        })
    }
}

/// A canonical decimal (wire rule R4, knob #6 closed): optional minus, no
/// leading zeros, no trailing fraction zeros, no exponent, no `-0`.
/// Comparison is numeric; the encoding is unique — `1`, `1.0`, `+1` are one
/// value with one encoding, and only `1` is that encoding (W-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decimal(String);

impl Decimal {
    /// Accept a string **only** if it is already in canonical form.
    /// This is the wire-facing constructor: aliases are rejects, not fixes.
    pub fn from_canonical(s: &str) -> Option<Self> {
        if Self::is_canonical(s) { Some(Self(String::from(s))) } else { None }
    }

    /// Authoring-side helper: normalize a (possibly aliased) human spelling
    /// (`+1`, `1.0`, `007`, `.5`) into the canonical form. Returns `None` for
    /// strings that aren't decimal numbers at all. The bench uses this; the
    /// wire never does.
    pub fn normalize(s: &str) -> Option<Self> {
        let s = s.trim();
        let (neg, rest) = match s.as_bytes().first()? {
            b'-' => (true, &s[1..]),
            b'+' => (false, &s[1..]),
            _ => (false, s),
        };
        if rest.is_empty() {
            return None;
        }
        let (int_part, frac_part) = match rest.find('.') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };
        if !int_part.bytes().all(|b| b.is_ascii_digit()) || !frac_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        let int_trimmed = int_part.trim_start_matches('0');
        let int_norm = if int_trimmed.is_empty() { "0" } else { int_trimmed };
        let frac_norm = frac_part.trim_end_matches('0');
        let mut out = String::new();
        let is_zero = int_norm == "0" && frac_norm.is_empty();
        if neg && !is_zero {
            out.push('-');
        }
        out.push_str(int_norm);
        if !frac_norm.is_empty() {
            out.push('.');
            out.push_str(frac_norm);
        }
        debug_assert!(Self::is_canonical(&out));
        Some(Self(out))
    }

    /// The R4 grammar, exactly.
    pub fn is_canonical(s: &str) -> bool {
        let b = s.as_bytes();
        let (neg, rest) = match b.first() {
            Some(b'-') => (true, &b[1..]),
            Some(_) => (false, b),
            None => return false,
        };
        // Split integer / fraction.
        let dot = rest.iter().position(|&c| c == b'.');
        let (int_p, frac_p) = match dot {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        if int_p.is_empty() || !int_p.iter().all(u8::is_ascii_digit) {
            return false; // ".5" is not canonical; digits only.
        }
        if int_p.len() > 1 && int_p[0] == b'0' {
            return false; // no leading zeros
        }
        if dot.is_some() {
            if frac_p.is_empty() || !frac_p.iter().all(u8::is_ascii_digit) {
                return false;
            }
            if *frac_p.last().expect("non-empty") == b'0' {
                return false; // no trailing fraction zeros
            }
        }
        if neg && int_p == b"0" && frac_p.is_empty() {
            return false; // "-0" forbidden
        }
        true
    }

    /// The canonical string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Numeric comparison (R4: "comparison is numeric"). Canonical form makes
    /// this a string-shape comparison: sign, then integer-part length, then
    /// lexicographic digits, then fraction digits (shorter fraction of a
    /// common prefix is smaller in magnitude).
    pub fn numeric_cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering::*;
        let (an, a) = split_sign(&self.0);
        let (bn, b) = split_sign(&other.0);
        match (an, bn) {
            (true, false) => return Less,
            (false, true) => return Greater,
            _ => {}
        }
        let mag = magnitude_cmp(a, b);
        if an { mag.reverse() } else { mag }
    }
}

fn split_sign(s: &str) -> (bool, &str) {
    match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    }
}

fn magnitude_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    let (ai, af) = match a.split_once('.') { Some(p) => p, None => (a, "") };
    let (bi, bf) = match b.split_once('.') { Some(p) => p, None => (b, "") };
    // Canonical integer parts have no leading zeros: longer wins, then lex.
    ai.len().cmp(&bi.len())
        .then_with(|| ai.cmp(bi))
        // Fractions compare digit-wise; canonical fractions have no trailing
        // zeros, so the plain lexicographic order on the raw digit strings is
        // the numeric order ("1" < "15" < "2", and prefix ⇒ smaller).
        .then_with(|| af.cmp(bf))
}

/// A value on the wire (D-K1 value space 0x40–0x4D).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// 0x40
    Bytes(Vec<u8>),
    /// 0x41
    Text(String),
    /// 0x42 — raw varint payload; interpretation (zigzag or not) is schema
    /// business per R3, never wire business.
    Integer(u64),
    /// 0x44
    Decimal(Decimal),
    /// 0x45
    Boolean(bool),
    /// 0x46
    Hash(Hash),
    /// 0x47
    Name(String),
    /// 0x48 — author order preserved (R9).
    List(Vec<Value>),
    /// 0x49 — entries sorted by canonical key bytes, duplicates reject (R8).
    Map(Vec<(Value, Value)>),
    /// 0x4A — fields in the order of the term's definition (R11).
    Record(Vec<Value>),
    /// 0x4B — a definitional reference: hash of a term.
    TermRef(Hash),
    /// 0x4C — µ-reference to a sibling inside a rec-group; illegal elsewhere.
    GroupRef(u64),
}

impl Value {
    /// True for the value shapes an attribute may carry: primitives or a term
    /// ref ONLY — flat, no structure (knob #4, standing law; L-04 routes
    /// structure to reification, Pattern P2).
    pub fn is_attribute_legal(&self) -> bool {
        !matches!(self, Value::List(_) | Value::Map(_) | Value::Record(_) | Value::GroupRef(_))
    }
}

// ───────────────────────────── types & shape ────────────────────────────────

/// Cardinality (kernel): `one`, `optional`, `some` (≥1), `many` (0+).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Cardinality {
    /// Exactly one — the default; canonically *omitted* on the wire (R10).
    #[default]
    One = 0,
    /// Zero or one.
    Optional = 1,
    /// One or more — "the non-negotiable" ≥1 (round 5, req 3).
    Some = 2,
    /// Zero or more.
    Many = 3,
}

impl Cardinality {
    /// Decode the single wire code byte.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::One,
            1 => Self::Optional,
            2 => Self::Some,
            3 => Self::Many,
            _ => return None,
        })
    }
}

/// A type expression — the kernel's type words, composed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeExpr {
    /// `primitive {…}` — 0x28.
    Primitive(PrimitiveKind),
    /// `list-of(T)` — 0x29.
    ListOf(Box<TypeExpr>),
    /// `map-of(K, V)` — 0x2A. K is constrained (see [`TypeExpr::map_key_legal`]).
    MapOf(Box<TypeExpr>, Box<TypeExpr>),
    /// `term-of(x)` — 0x2B. `x` may be a vocabulary or a parent term
    /// (D-K4 / FRICTION F39): membership is in-vocabulary or
    /// narrower-than-reachable.
    TermOf(Hash),
    /// `record{…}` — 0x2C.
    Record(Vec<Field>),
    /// `of(base, T)` — 0x2D. ONE type parameter, user side (knob #2:
    /// user arity 1, kernel constructors 2 — list-of/map-of are the kernel's).
    Of(Hash, Box<TypeExpr>),
    /// `rec-group{…}` — 0x2E. Intra-document mutual recursion; members may
    /// reference each other with [`TypeExpr::GroupRef`]. Equality is standard
    /// µ-equivalence (C6).
    RecGroup(Vec<Term>),
    /// `opaque` used as a type — 0x36 with empty body (escape hatch, C4).
    Opaque,
    /// µ-reference by index into the enclosing rec-group — 0x4C.
    GroupRef(u64),
}

impl TypeExpr {
    /// R8 / kernel law: map keys ∈ text | integer | hash | name | term ref.
    pub fn map_key_legal(&self) -> bool {
        matches!(
            self,
            TypeExpr::Primitive(
                PrimitiveKind::Text | PrimitiveKind::Integer | PrimitiveKind::Hash | PrimitiveKind::Name
            ) | TypeExpr::TermOf(_)
        )
    }
}

/// An attribute (kernel `attribute`): key = term ref; value = primitive or
/// term ref ONLY — flat by construction (knob #4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute's meaning: a term, by hash.
    pub key: Hash,
    /// Flat value; [`Value::is_attribute_legal`] is enforced by the codec.
    pub value: Value,
}

/// A field of a record (kernel `field`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Authoring label. Labels never key anything (R5 / F22) — identity is
    /// positional-and-hashed, labels are for humans.
    pub label: String,
    /// Documentation — load-bearing data (L-05), rendered by `bench doc`.
    pub doc: Option<String>,
    /// The field's type.
    pub ty: TypeExpr,
    /// Cardinality; `One` is canonically omitted on the wire.
    pub cardinality: Cardinality,
    /// Flat attributes.
    pub attrs: Vec<Attribute>,
}

/// A term (kernel `term`). **Identity = SHA-256 of its canonical TLV bytes**
/// ("a term's identity is its hash", D-49).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// Human label; never an identity.
    pub label: String,
    /// Documentation; public terms without one fail the bench (L-05).
    pub doc: Option<String>,
    /// The term's type, if it has one (pure marker terms carry none).
    pub ty: Option<TypeExpr>,
    /// Flat attributes.
    pub attrs: Vec<Attribute>,
}

// ───────────────────────────── links & meaning ──────────────────────────────

/// A descriptive subject: a hash, or a name/prefix for stream subjects —
/// **never dereferenced by the matcher** (C5 refined by F3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject {
    /// Content hash of the described block/document.
    Hash(Hash),
    /// A name or prefix (stream subjects).
    Name(String),
}

/// Semantic and instance edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EdgeForm {
    /// `narrower-than` — subsumption; fidelity-preserving hop (C9 = 1.0).
    NarrowerThan {
        /// The narrower term.
        narrower: Hash,
        /// The broader term.
        broader: Hash,
    },
    /// `equivalent-to` — symmetric, lossless. Cross-author use triggers the
    /// L-09 "did you mean maps-to?" audit at the bench.
    EquivalentTo {
        /// One side.
        a: Hash,
        /// The other.
        b: Hash,
    },
    /// `maps-to` — directional, lossy; the loss term is structural (D-K5).
    /// Traversal demotes Express → Approximate and accumulates the loss path;
    /// fidelity along any path is the min of its hops (C9).
    MapsTo {
        /// Source term.
        from: Hash,
        /// Destination term.
        to: Hash,
        /// The loss characterization — a term ref (e.g. loss:ordinal-coarsening).
        loss: Hash,
        /// Flat attributes.
        attrs: Vec<Attribute>,
    },
    /// A general instance edge: subject · kind · object · flat attrs.
    Edge {
        /// Subject (hash or name — never dereferenced).
        subject: Subject,
        /// The edge kind, a term ref (e.g. edge-kinds:justified-by).
        kind: Hash,
        /// Object.
        object: Subject,
        /// Flat attributes.
        attrs: Vec<Attribute>,
    },
}

/// One manifest entry: a field term (by hash) bound to a value (0x4D).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    /// The field's term hash.
    pub field: Hash,
    /// The value.
    pub value: Value,
}

/// A manifest (kernel `manifest`): data described against strata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The manifest's type: a term ref (e.g. apiary:inspection, im0:block).
    pub ty: Hash,
    /// Optional authoring label (e.g. `inspection-A7`).
    pub label: Option<String>,
    /// What this manifest describes.
    pub describes: Subject,
    /// Field bindings.
    pub entries: Vec<ManifestEntry>,
    /// Instance edges emitted with the manifest.
    pub edges: Vec<EdgeForm>,
}

// ───────────────────────────── vocabulary ───────────────────────────────────

/// A vocabulary (a published stratum, or V₀ itself).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vocabulary {
    /// Label (e.g. `units`, `apiary`).
    pub label: String,
    /// Documentation.
    pub doc: Option<String>,
    /// Imports, by hash via the lock (C5: hash-only definitional references).
    pub imports: Vec<Hash>,
    /// The terms.
    pub terms: Vec<Term>,
    /// Semantic edges published by this vocabulary — these count for a
    /// consumer only if this vocabulary is inside their TrustFrontier (C10).
    pub edges: Vec<EdgeForm>,
    /// Versioning: the vocabulary this one supersedes (F26: "mutate" is a
    /// compiler fiction — edits are new versions plus this edge).
    pub supersedes: Option<Hash>,
}

// ───────────────────────────── render side ──────────────────────────────────

/// A render intent (`intent`): a name plus flat attributes
/// (e.g. `alarm.attention @sensitivity = ui:high`, L-11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// The intent name (e.g. `raw.inspect`, `text.plain`).
    pub name: String,
    /// Flat attributes (sensitivity tags live here).
    pub attrs: Vec<Attribute>,
}

/// How a contract renders: sandboxed WASM by hash, or a native renderer by
/// attested id (`via {wasm(hash) | native(attested-id)}`). Computation is
/// invoked by description, never embedded in it — the matcher treats this as
/// inert bytes (C8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Via {
    /// WASM module by content hash — immune to attestation gaps by construction (R7 ruling).
    Wasm(Hash),
    /// Native renderer by attested identity — the register's open attestation gap.
    Native(String),
}

/// A contract clause. Unlisted intents are refused, never inferred
/// (default-refuse, round-4 law).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clause {
    /// Full-fidelity rendering of manifests whose type reaches `target`.
    Express {
        /// The intent offered.
        intent: Intent,
        /// The stratum term this clause applies to (FRICTION F44).
        target: Hash,
        /// Renderer binding, if any.
        via: Option<Via>,
        /// Flat attributes.
        attrs: Vec<Attribute>,
    },
    /// Declared-lossy rendering.
    Approximate {
        /// The intent offered.
        intent: Intent,
        /// Target term.
        target: Hash,
        /// Renderer binding, if any.
        via: Option<Via>,
        /// Flat attributes.
        attrs: Vec<Attribute>,
    },
    /// Explicit refusal — redundant with default-refuse, kept as
    /// documentation (L-14: info, not error).
    Refuse {
        /// The intent refused.
        intent: Intent,
    },
}

/// A render contract: a renderer's promise (D-48: below the chain; wrapping
/// it in a Block adds history and authority without changing its meaning).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// Label (e.g. `yard-beeper`, `T0`).
    pub label: String,
    /// Documentation.
    pub doc: Option<String>,
    /// Imports, by hash.
    pub imports: Vec<Hash>,
    /// Optional subject filter (FRICTION F45): hash exact / name prefix
    /// against a manifest's `describes`; absent ⇒ offered for all subjects.
    pub binds: Vec<Subject>,
    /// The clauses.
    pub clauses: Vec<Clause>,
}

// ───────────────────────────── documents ────────────────────────────────────

/// A raw retained extension TLV (R12, non-critical path): re-emitted
/// byte-identically so R13 holds in the presence of unknown extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawTlv {
    /// The decoded type number (≥ 0x80; odd ⇒ critical).
    pub ty: u64,
    /// The raw payload bytes.
    pub payload: Vec<u8>,
}

impl RawTlv {
    /// R12 / D-K1: the critical bit is bit 0 of the decoded type number.
    pub const fn is_critical(&self) -> bool {
        self.ty & 1 == 1
    }
}

/// A calculus document: one of the three top-level forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Document {
    /// A published vocabulary (stratum or kernel).
    Vocabulary(Vocabulary),
    /// A manifest.
    Manifest(Manifest),
    /// A render contract.
    Contract(Contract),
}

/// A decoded document plus its R12 status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The document.
    pub doc: Document,
    /// Extension TLVs retained from the document tail (trailing position is
    /// the canonical extension point — FRICTION F49).
    pub extensions: Vec<RawTlv>,
    /// True iff any extension carried the critical bit: the document's
    /// matches are **Unresolved** (R12/W-19) — never a crash, never a guess.
    pub critical: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_canonical_grammar() {
        for ok in ["0", "1", "-1", "10", "3.5", "-0.5", "41.2", "100.001"] {
            assert!(Decimal::is_canonical(ok), "{ok} should be canonical");
        }
        for bad in ["", "+1", "1.0", "01", "-0", "1.", ".5", "1e3", "0.50", "--1", "1..2"] {
            assert!(!Decimal::is_canonical(bad), "{bad} should NOT be canonical");
        }
    }

    #[test]
    fn decimal_normalize_dealiases() {
        for (raw, want) in [("+1", "1"), ("1.0", "1"), ("007", "7"), (".5", "0.5"), ("-0", "0"), ("-0.50", "-0.5")] {
            assert_eq!(Decimal::normalize(raw).expect(raw).as_str(), want);
        }
    }

    #[test]
    fn decimal_numeric_order() {
        use core::cmp::Ordering::*;
        let d = |s: &str| Decimal::from_canonical(s).expect(s);
        assert_eq!(d("2").numeric_cmp(&d("10")), Less);
        assert_eq!(d("1.5").numeric_cmp(&d("1.15")), Greater);
        assert_eq!(d("1").numeric_cmp(&d("1.1")), Less);
        assert_eq!(d("-2").numeric_cmp(&d("1")), Less);
        assert_eq!(d("-1.5").numeric_cmp(&d("-1.15")), Less);
        assert_eq!(d("0").numeric_cmp(&d("0")), Equal);
    }

    #[test]
    fn attribute_flatness_is_checkable() {
        assert!(Value::Text(String::from("x")).is_attribute_legal());
        assert!(Value::TermRef([0u8; 32]).is_attribute_legal());
        assert!(!Value::List(Vec::new()).is_attribute_legal());
        assert!(!Value::Map(Vec::new()).is_attribute_legal());
    }

    #[test]
    fn critical_bit_is_parity() {
        assert!(RawTlv { ty: 0x81, payload: Vec::new() }.is_critical());
        assert!(!RawTlv { ty: 0x80, payload: Vec::new() }.is_critical());
    }
}
