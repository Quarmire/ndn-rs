//! The canonical wire codec — rules R1–R13 (ndf-the-landing, Act III).
//!
//! One byte form per document; the document hash is SHA-256 over exactly
//! these bytes, signature envelope excluded. Every deviation from canonical
//! form is a typed *reject*, not a tolerance (R2), and decode∘encode must be
//! byte identity or reject (R13). Concrete type numbers are the W-map,
//! docs/keel/DECISIONS.md D-K1.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hash::{sha256, Hash};
use crate::model::{
    Attribute, Cardinality, Clause, Contract, Decimal, Decoded, Document, EdgeForm, Field, Intent,
    Manifest, ManifestEntry, PrimitiveKind, RawTlv, Subject, Term, TypeExpr, Value, Via, Vocabulary,
};

// ───────────────────────── W-map type numbers (D-K1) ────────────────────────

/// Kernel form and value-space type numbers. R1: kernel forms 0x20–0x3F;
/// 0x00–0x1F reserved; values/structural 0x40–0x4D; extensions ≥ 0x80.
pub mod ty {
    #![allow(missing_docs)]
    pub const VOCABULARY: u64 = 0x20;
    pub const TERM: u64 = 0x21;
    pub const IMPORTS: u64 = 0x22;
    pub const SUPERSEDES: u64 = 0x23;
    pub const LABEL: u64 = 0x24;
    pub const DOC: u64 = 0x25;
    pub const ATTRIBUTE: u64 = 0x26;
    pub const FIELD: u64 = 0x27;
    pub const PRIMITIVE: u64 = 0x28;
    pub const LIST_OF: u64 = 0x29;
    pub const MAP_OF: u64 = 0x2A;
    pub const TERM_OF: u64 = 0x2B;
    pub const RECORD: u64 = 0x2C;
    pub const OF: u64 = 0x2D;
    pub const REC_GROUP: u64 = 0x2E;
    pub const CARDINALITY: u64 = 0x2F;
    pub const MANIFEST: u64 = 0x30;
    pub const DESCRIBES: u64 = 0x31;
    pub const EDGE: u64 = 0x32;
    pub const NARROWER_THAN: u64 = 0x33;
    pub const EQUIVALENT_TO: u64 = 0x34;
    pub const MAPS_TO: u64 = 0x35;
    pub const OPAQUE: u64 = 0x36;
    pub const MEDIA_TYPE: u64 = 0x37;
    pub const EXTERNAL_REF: u64 = 0x38;
    pub const CONTRACT: u64 = 0x39;
    pub const INTENT: u64 = 0x3A;
    pub const EXPRESS: u64 = 0x3B;
    pub const APPROXIMATE: u64 = 0x3C;
    pub const REFUSE: u64 = 0x3D;
    pub const BINDS: u64 = 0x3E;
    pub const VIA: u64 = 0x3F;

    pub const V_BYTES: u64 = 0x40;
    pub const V_TEXT: u64 = 0x41;
    pub const V_INTEGER: u64 = 0x42;
    pub const V_DECIMAL: u64 = 0x44;
    pub const V_BOOLEAN: u64 = 0x45;
    pub const V_HASH: u64 = 0x46;
    pub const V_NAME: u64 = 0x47;
    pub const V_LIST: u64 = 0x48;
    pub const V_MAP: u64 = 0x49;
    pub const V_RECORD: u64 = 0x4A;
    pub const V_TERM_REF: u64 = 0x4B;
    pub const V_GROUP_REF: u64 = 0x4C;
    pub const MANIFEST_ENTRY: u64 = 0x4D;

    /// First extension type (R12 space). Critical bit = bit 0 (odd ⇒ critical).
    pub const EXTENSION_FLOOR: u64 = 0x80;
}

// ───────────────────────────── reject codes ─────────────────────────────────

/// A typed wire reject. `code()` strings are stable and are what `.ndfv`
/// vectors name (`expect: reject <Code>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Varint carries a redundant continuation group (R2/R3, W-03).
    NonMinimalVarint,
    /// Varint exceeds 64 bits (R3, W-22).
    VarintOverflow,
    /// Input ended inside a TLV header or body.
    Truncated,
    /// A body was shorter/longer than its form allows.
    LengthMismatch,
    /// A type in reserved (0x00–0x1F) or unassigned (< 0x80) space (R1/D-K1).
    UnknownReservedType,
    /// A TLV appeared where the form's definition does not allow it (R11).
    FormOrder,
    /// Map keys not in canonical ascending key-byte order (R8).
    UnsortedMapKeys,
    /// Duplicate map key (R8, W-07).
    DuplicateMapKey,
    /// Decimal not in the R4 canonical grammar (W-11).
    NonCanonicalDecimal,
    /// Boolean byte other than 0x00/0x01 (R6).
    InvalidBoolean,
    /// Hash body not exactly 32 bytes (R7).
    InvalidHashLength,
    /// Text/name bytes are not valid UTF-8 (R5 carries exact bytes, but the
    /// primitive is *text*: non-UTF-8 in a text slot is malformed).
    InvalidUtf8,
    /// Primitive code byte outside 0–6.
    InvalidPrimitiveCode,
    /// Cardinality code byte outside 1–3 …
    InvalidCardinality,
    /// … or an explicit `one` (0), which canonical form omits (R10).
    NonCanonicalDefault,
    /// An attribute value that is not a primitive or term ref (knob #4).
    NestedAttribute,
    /// A map-of key type outside text|integer|hash|name|term-ref.
    IllegalMapKeyType,
    /// A group-ref outside a rec-group.
    StrayGroupRef,
    /// Extension TLV (≥ 0x80) in a non-tail position (FRICTION F49).
    MisplacedExtension,
    /// Bytes after the document and its trailing extensions.
    TrailingBytes,
    /// Document is empty or its outer type is not a document form.
    NotADocument,
    /// decode∘encode failed byte identity (R13).
    ReencodeMismatch,
}

impl Reject {
    /// Stable code string for conformance vectors.
    pub const fn code(&self) -> &'static str {
        match self {
            Reject::NonMinimalVarint => "NonMinimalVarint",
            Reject::VarintOverflow => "VarintOverflow",
            Reject::Truncated => "Truncated",
            Reject::LengthMismatch => "LengthMismatch",
            Reject::UnknownReservedType => "UnknownReservedType",
            Reject::FormOrder => "FormOrder",
            Reject::UnsortedMapKeys => "UnsortedMapKeys",
            Reject::DuplicateMapKey => "DuplicateMapKey",
            Reject::NonCanonicalDecimal => "NonCanonicalDecimal",
            Reject::InvalidBoolean => "InvalidBoolean",
            Reject::InvalidHashLength => "InvalidHashLength",
            Reject::InvalidUtf8 => "InvalidUtf8",
            Reject::InvalidPrimitiveCode => "InvalidPrimitiveCode",
            Reject::InvalidCardinality => "InvalidCardinality",
            Reject::NonCanonicalDefault => "NonCanonicalDefault",
            Reject::NestedAttribute => "NestedAttribute",
            Reject::IllegalMapKeyType => "IllegalMapKeyType",
            Reject::StrayGroupRef => "StrayGroupRef",
            Reject::MisplacedExtension => "MisplacedExtension",
            Reject::TrailingBytes => "TrailingBytes",
            Reject::NotADocument => "NotADocument",
            Reject::ReencodeMismatch => "ReencodeMismatch",
        }
    }
}

// ───────────────────────────── varints (R2/R3) ──────────────────────────────

/// Append a minimal unsigned LEB128 varint.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read a minimal unsigned LEB128 varint. Rejects redundant trailing groups
/// (W-03 class) and > 64-bit values (W-22).
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, Reject> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut count: usize = 0;
    loop {
        let byte = *buf.get(*pos).ok_or(Reject::Truncated)?;
        *pos += 1;
        count += 1;
        if count > 10 {
            return Err(Reject::VarintOverflow);
        }
        let group = (byte & 0x7f) as u64;
        if shift == 63 && group > 1 {
            return Err(Reject::VarintOverflow);
        }
        if shift > 63 {
            return Err(Reject::VarintOverflow);
        }
        value |= group << shift;
        if byte & 0x80 == 0 {
            // Minimality: the final group must be non-zero unless the whole
            // varint is the single byte 0x00.
            if group == 0 && count > 1 {
                return Err(Reject::NonMinimalVarint);
            }
            return Ok(value);
        }
        shift += 7;
    }
}

// ───────────────────────────── writer ───────────────────────────────────────

/// Append one TLV (type varint · length varint · body). Public so the bench
/// and conformance vectors can author wire bytes — including malformed ones —
/// without a private back door.
pub fn put_tlv(out: &mut Vec<u8>, t: u64, body: &[u8]) {
    put_varint(out, t);
    put_varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn put_hash_tlv(out: &mut Vec<u8>, t: u64, h: &Hash) {
    put_tlv(out, t, h);
}

fn put_text_tlv(out: &mut Vec<u8>, t: u64, s: &str) {
    put_tlv(out, t, s.as_bytes());
}

/// Encode error — authoring-side (the decoder's rejects cover the wire side).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Two map entries with identical keys (R8).
    DuplicateMapKey,
    /// Attribute value not primitive/term-ref (knob #4).
    NestedAttribute,
    /// map-of key type outside the legal set.
    IllegalMapKeyType,
}

fn encode_value(out: &mut Vec<u8>, v: &Value) -> Result<(), EncodeError> {
    match v {
        Value::Bytes(b) => put_tlv(out, ty::V_BYTES, b),
        Value::Text(s) => put_text_tlv(out, ty::V_TEXT, s),
        Value::Integer(n) => {
            let mut body = Vec::new();
            put_varint(&mut body, *n);
            put_tlv(out, ty::V_INTEGER, &body);
        }
        Value::Decimal(d) => put_text_tlv(out, ty::V_DECIMAL, d.as_str()),
        Value::Boolean(b) => put_tlv(out, ty::V_BOOLEAN, &[u8::from(*b)]),
        Value::Hash(h) => put_hash_tlv(out, ty::V_HASH, h),
        Value::Name(s) => put_text_tlv(out, ty::V_NAME, s),
        Value::List(items) => {
            // R9: author order preserved.
            let mut body = Vec::new();
            for item in items {
                encode_value(&mut body, item)?;
            }
            put_tlv(out, ty::V_LIST, &body);
        }
        Value::Map(entries) => {
            // R8: sort by canonical key bytes; duplicates are an error.
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(entries.len());
            for (k, val) in entries {
                let mut kb = Vec::new();
                encode_value(&mut kb, k)?;
                let mut vb = Vec::new();
                encode_value(&mut vb, val)?;
                encoded.push((kb, vb));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            for w in encoded.windows(2) {
                if w[0].0 == w[1].0 {
                    return Err(EncodeError::DuplicateMapKey);
                }
            }
            let mut body = Vec::new();
            for (kb, vb) in &encoded {
                body.extend_from_slice(kb);
                body.extend_from_slice(vb);
            }
            put_tlv(out, ty::V_MAP, &body);
        }
        Value::Record(fields) => {
            // R11: field order is the definition's order — the caller's order.
            let mut body = Vec::new();
            for f in fields {
                encode_value(&mut body, f)?;
            }
            put_tlv(out, ty::V_RECORD, &body);
        }
        Value::TermRef(h) => put_hash_tlv(out, ty::V_TERM_REF, h),
        Value::GroupRef(i) => {
            let mut body = Vec::new();
            put_varint(&mut body, *i);
            put_tlv(out, ty::V_GROUP_REF, &body);
        }
    }
    Ok(())
}

fn encode_attr(out: &mut Vec<u8>, a: &Attribute) -> Result<(), EncodeError> {
    if !a.value.is_attribute_legal() {
        return Err(EncodeError::NestedAttribute);
    }
    let mut body = Vec::new();
    put_hash_tlv(&mut body, ty::V_TERM_REF, &a.key);
    encode_value(&mut body, &a.value)?;
    put_tlv(out, ty::ATTRIBUTE, &body);
    Ok(())
}

fn encode_type(out: &mut Vec<u8>, t: &TypeExpr) -> Result<(), EncodeError> {
    match t {
        TypeExpr::Primitive(p) => put_tlv(out, ty::PRIMITIVE, &[*p as u8]),
        TypeExpr::ListOf(inner) => {
            let mut body = Vec::new();
            encode_type(&mut body, inner)?;
            put_tlv(out, ty::LIST_OF, &body);
        }
        TypeExpr::MapOf(k, v) => {
            if !k.map_key_legal() {
                return Err(EncodeError::IllegalMapKeyType);
            }
            let mut body = Vec::new();
            encode_type(&mut body, k)?;
            encode_type(&mut body, v)?;
            put_tlv(out, ty::MAP_OF, &body);
        }
        TypeExpr::TermOf(h) => put_hash_tlv(out, ty::TERM_OF, h),
        TypeExpr::Record(fields) => {
            let mut body = Vec::new();
            for f in fields {
                encode_field(&mut body, f)?;
            }
            put_tlv(out, ty::RECORD, &body);
        }
        TypeExpr::Of(base, param) => {
            let mut body = Vec::new();
            put_hash_tlv(&mut body, ty::V_TERM_REF, base);
            encode_type(&mut body, param)?;
            put_tlv(out, ty::OF, &body);
        }
        TypeExpr::RecGroup(terms) => {
            let mut body = Vec::new();
            for t in terms {
                encode_term(&mut body, t)?;
            }
            put_tlv(out, ty::REC_GROUP, &body);
        }
        TypeExpr::Opaque => put_tlv(out, ty::OPAQUE, &[]),
        TypeExpr::GroupRef(i) => {
            let mut body = Vec::new();
            put_varint(&mut body, *i);
            put_tlv(out, ty::V_GROUP_REF, &body);
        }
    }
    Ok(())
}

fn encode_field(out: &mut Vec<u8>, f: &Field) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_text_tlv(&mut body, ty::LABEL, &f.label);
    if let Some(doc) = &f.doc {
        put_text_tlv(&mut body, ty::DOC, doc);
    }
    encode_type(&mut body, &f.ty)?;
    // R10: `one` is the default and is canonically omitted.
    if f.cardinality != Cardinality::One {
        put_tlv(&mut body, ty::CARDINALITY, &[f.cardinality as u8]);
    }
    for a in &f.attrs {
        encode_attr(&mut body, a)?;
    }
    put_tlv(out, ty::FIELD, &body);
    Ok(())
}

fn encode_term(out: &mut Vec<u8>, t: &Term) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_text_tlv(&mut body, ty::LABEL, &t.label);
    if let Some(doc) = &t.doc {
        put_text_tlv(&mut body, ty::DOC, doc);
    }
    if let Some(texpr) = &t.ty {
        encode_type(&mut body, texpr)?;
    }
    for a in &t.attrs {
        encode_attr(&mut body, a)?;
    }
    put_tlv(out, ty::TERM, &body);
    Ok(())
}

/// A term's identity is the SHA-256 of its canonical TLV bytes (D-49).
pub fn term_hash(t: &Term) -> Result<Hash, EncodeError> {
    let mut out = Vec::new();
    encode_term(&mut out, t)?;
    Ok(sha256(&out))
}

fn encode_subject(out: &mut Vec<u8>, s: &Subject) {
    match s {
        Subject::Hash(h) => put_hash_tlv(out, ty::V_HASH, h),
        Subject::Name(n) => put_text_tlv(out, ty::V_NAME, n),
    }
}

fn encode_edge(out: &mut Vec<u8>, e: &EdgeForm) -> Result<(), EncodeError> {
    match e {
        EdgeForm::NarrowerThan { narrower, broader } => {
            let mut body = Vec::with_capacity(64);
            body.extend_from_slice(narrower);
            body.extend_from_slice(broader);
            put_tlv(out, ty::NARROWER_THAN, &body);
        }
        EdgeForm::EquivalentTo { a, b } => {
            let mut body = Vec::with_capacity(64);
            body.extend_from_slice(a);
            body.extend_from_slice(b);
            put_tlv(out, ty::EQUIVALENT_TO, &body);
        }
        EdgeForm::MapsTo { from, to, loss, attrs } => {
            // D-K5: the loss slot is structural — @loss cannot be forgotten.
            let mut body = Vec::with_capacity(96);
            body.extend_from_slice(from);
            body.extend_from_slice(to);
            body.extend_from_slice(loss);
            for a in attrs {
                encode_attr(&mut body, a)?;
            }
            put_tlv(out, ty::MAPS_TO, &body);
        }
        EdgeForm::Edge { subject, kind, object, attrs } => {
            let mut body = Vec::new();
            encode_subject(&mut body, subject);
            put_hash_tlv(&mut body, ty::V_TERM_REF, kind);
            encode_subject(&mut body, object);
            for a in attrs {
                encode_attr(&mut body, a)?;
            }
            put_tlv(out, ty::EDGE, &body);
        }
    }
    Ok(())
}

fn encode_vocabulary(out: &mut Vec<u8>, v: &Vocabulary) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_text_tlv(&mut body, ty::LABEL, &v.label);
    if let Some(doc) = &v.doc {
        put_text_tlv(&mut body, ty::DOC, doc);
    }
    if !v.imports.is_empty() {
        let mut imp = Vec::with_capacity(v.imports.len() * 32);
        for h in &v.imports {
            imp.extend_from_slice(h);
        }
        put_tlv(&mut body, ty::IMPORTS, &imp);
    }
    for t in &v.terms {
        encode_term(&mut body, t)?;
    }
    for e in &v.edges {
        encode_edge(&mut body, e)?;
    }
    if let Some(s) = &v.supersedes {
        put_tlv(&mut body, ty::SUPERSEDES, s);
    }
    put_tlv(out, ty::VOCABULARY, &body);
    Ok(())
}

fn encode_manifest(out: &mut Vec<u8>, m: &Manifest) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_hash_tlv(&mut body, ty::V_TERM_REF, &m.ty);
    if let Some(label) = &m.label {
        put_text_tlv(&mut body, ty::LABEL, label);
    }
    let mut d = Vec::new();
    encode_subject(&mut d, &m.describes);
    put_tlv(&mut body, ty::DESCRIBES, &d);
    for e in &m.entries {
        let mut eb = Vec::new();
        put_hash_tlv(&mut eb, ty::V_TERM_REF, &e.field);
        encode_value(&mut eb, &e.value)?;
        put_tlv(&mut body, ty::MANIFEST_ENTRY, &eb);
    }
    for e in &m.edges {
        encode_edge(&mut body, e)?;
    }
    put_tlv(out, ty::MANIFEST, &body);
    Ok(())
}

fn encode_intent(out: &mut Vec<u8>, i: &Intent) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_text_tlv(&mut body, ty::V_TEXT, &i.name);
    for a in &i.attrs {
        encode_attr(&mut body, a)?;
    }
    put_tlv(out, ty::INTENT, &body);
    Ok(())
}

fn encode_via(out: &mut Vec<u8>, v: &Via) {
    let mut body = Vec::new();
    match v {
        Via::Wasm(h) => {
            body.push(0);
            body.extend_from_slice(h);
        }
        Via::Native(id) => {
            body.push(1);
            body.extend_from_slice(id.as_bytes());
        }
    }
    put_tlv(out, ty::VIA, &body);
}

fn encode_clause(out: &mut Vec<u8>, c: &Clause) -> Result<(), EncodeError> {
    match c {
        Clause::Express { intent, target, via, attrs }
        | Clause::Approximate { intent, target, via, attrs } => {
            let tag = if matches!(c, Clause::Express { .. }) { ty::EXPRESS } else { ty::APPROXIMATE };
            let mut body = Vec::new();
            encode_intent(&mut body, intent)?;
            put_hash_tlv(&mut body, ty::V_TERM_REF, target);
            if let Some(v) = via {
                encode_via(&mut body, v);
            }
            for a in attrs {
                encode_attr(&mut body, a)?;
            }
            put_tlv(out, tag, &body);
        }
        Clause::Refuse { intent } => {
            let mut body = Vec::new();
            encode_intent(&mut body, intent)?;
            put_tlv(out, ty::REFUSE, &body);
        }
    }
    Ok(())
}

fn encode_contract(out: &mut Vec<u8>, c: &Contract) -> Result<(), EncodeError> {
    let mut body = Vec::new();
    put_text_tlv(&mut body, ty::LABEL, &c.label);
    if let Some(doc) = &c.doc {
        put_text_tlv(&mut body, ty::DOC, doc);
    }
    if !c.imports.is_empty() {
        let mut imp = Vec::with_capacity(c.imports.len() * 32);
        for h in &c.imports {
            imp.extend_from_slice(h);
        }
        put_tlv(&mut body, ty::IMPORTS, &imp);
    }
    if !c.binds.is_empty() {
        let mut bb = Vec::new();
        for s in &c.binds {
            encode_subject(&mut bb, s);
        }
        put_tlv(&mut body, ty::BINDS, &bb);
    }
    for cl in &c.clauses {
        encode_clause(&mut body, cl)?;
    }
    put_tlv(out, ty::CONTRACT, &body);
    Ok(())
}

/// Encode a document (without extensions) to its canonical bytes.
pub fn encode_document(doc: &Document) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    match doc {
        Document::Vocabulary(v) => encode_vocabulary(&mut out, v)?,
        Document::Manifest(m) => encode_manifest(&mut out, m)?,
        Document::Contract(c) => encode_contract(&mut out, c)?,
    }
    Ok(out)
}

/// Encode a decoded document *with* its retained trailing extensions —
/// this is the function R13's byte-identity is checked against.
pub fn encode_decoded(d: &Decoded) -> Result<Vec<u8>, EncodeError> {
    let mut out = encode_document(&d.doc)?;
    for ext in &d.extensions {
        put_tlv(&mut out, ext.ty, &ext.payload);
    }
    Ok(out)
}

/// SHA-256 over canonical document bytes (signature envelope excluded — the
/// envelope never reaches this crate).
pub fn document_hash(canonical_bytes: &[u8]) -> Hash {
    sha256(canonical_bytes)
}

// ───────────────────────────── reader ───────────────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

struct Header {
    ty: u64,
    len: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn peek_type(&self) -> Result<Option<u64>, Reject> {
        if self.done() {
            return Ok(None);
        }
        let mut p = self.pos;
        Ok(Some(read_varint(self.buf, &mut p)?))
    }

    fn read_header(&mut self) -> Result<Header, Reject> {
        let t = read_varint(self.buf, &mut self.pos)?;
        let len = read_varint(self.buf, &mut self.pos)?;
        let len = usize::try_from(len).map_err(|_| Reject::VarintOverflow)?;
        if self.pos.checked_add(len).is_none_or(|end| end > self.buf.len()) {
            return Err(Reject::Truncated);
        }
        Ok(Header { ty: t, len })
    }

    fn read_body(&mut self, len: usize) -> &'a [u8] {
        let body = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        body
    }

    /// Read the next TLV, requiring the given type (R11 form order).
    fn expect(&mut self, want: u64) -> Result<&'a [u8], Reject> {
        let h = self.read_header()?;
        if h.ty != want {
            return Err(Reject::FormOrder);
        }
        Ok(self.read_body(h.len))
    }

    /// Read the next TLV if its type matches; otherwise leave it in place.
    fn take(&mut self, want: u64) -> Result<Option<&'a [u8]>, Reject> {
        if self.peek_type()? == Some(want) {
            let h = self.read_header()?;
            Ok(Some(self.read_body(h.len)))
        } else {
            Ok(None)
        }
    }
}

fn utf8(bytes: &[u8]) -> Result<String, Reject> {
    core::str::from_utf8(bytes)
        .map(String::from)
        .map_err(|_| Reject::InvalidUtf8)
}

fn hash32(bytes: &[u8]) -> Result<Hash, Reject> {
    let arr: &[u8; 32] = bytes.try_into().map_err(|_| Reject::InvalidHashLength)?;
    Ok(*arr)
}

fn decode_value(c: &mut Cursor<'_>, in_group: bool) -> Result<Value, Reject> {
    let h = c.read_header()?;
    let body = c.read_body(h.len);
    match h.ty {
        ty::V_BYTES => Ok(Value::Bytes(Vec::from(body))),
        ty::V_TEXT => Ok(Value::Text(utf8(body)?)),
        ty::V_INTEGER => {
            let mut p = 0usize;
            let v = read_varint(body, &mut p)?;
            if p != body.len() {
                return Err(Reject::LengthMismatch);
            }
            Ok(Value::Integer(v))
        }
        ty::V_DECIMAL => {
            let s = utf8(body)?;
            let d = Decimal::from_canonical(&s).ok_or(Reject::NonCanonicalDecimal)?;
            Ok(Value::Decimal(d))
        }
        ty::V_BOOLEAN => match body {
            [0x00] => Ok(Value::Boolean(false)),
            [0x01] => Ok(Value::Boolean(true)),
            _ => Err(Reject::InvalidBoolean),
        },
        ty::V_HASH => Ok(Value::Hash(hash32(body)?)),
        ty::V_NAME => Ok(Value::Name(utf8(body)?)),
        ty::V_LIST => {
            let mut inner = Cursor::new(body);
            let mut items = Vec::new();
            while !inner.done() {
                items.push(decode_value(&mut inner, in_group)?);
            }
            Ok(Value::List(items))
        }
        ty::V_MAP => {
            let mut inner = Cursor::new(body);
            let mut entries: Vec<(Value, Value)> = Vec::new();
            let mut prev_key: Option<(usize, usize)> = None; // byte range of previous key
            while !inner.done() {
                let key_start = inner.pos;
                let key = decode_value(&mut inner, in_group)?;
                let key_end = inner.pos;
                if let Some((ps, pe)) = prev_key {
                    let prev = &body[ps..pe];
                    let cur = &body[key_start..key_end];
                    match prev.cmp(cur) {
                        core::cmp::Ordering::Less => {}
                        core::cmp::Ordering::Equal => return Err(Reject::DuplicateMapKey),
                        core::cmp::Ordering::Greater => return Err(Reject::UnsortedMapKeys),
                    }
                }
                prev_key = Some((key_start, key_end));
                if inner.done() {
                    return Err(Reject::LengthMismatch); // key without value
                }
                let val = decode_value(&mut inner, in_group)?;
                entries.push((key, val));
            }
            Ok(Value::Map(entries))
        }
        ty::V_RECORD => {
            let mut inner = Cursor::new(body);
            let mut items = Vec::new();
            while !inner.done() {
                items.push(decode_value(&mut inner, in_group)?);
            }
            Ok(Value::Record(items))
        }
        ty::V_TERM_REF => Ok(Value::TermRef(hash32(body)?)),
        ty::V_GROUP_REF => {
            if !in_group {
                return Err(Reject::StrayGroupRef);
            }
            let mut p = 0usize;
            let v = read_varint(body, &mut p)?;
            if p != body.len() {
                return Err(Reject::LengthMismatch);
            }
            Ok(Value::GroupRef(v))
        }
        t if t < ty::EXTENSION_FLOOR => Err(Reject::UnknownReservedType),
        _ => Err(Reject::MisplacedExtension),
    }
}

fn is_type_expr_start(t: u64) -> bool {
    matches!(
        t,
        ty::PRIMITIVE
            | ty::LIST_OF
            | ty::MAP_OF
            | ty::TERM_OF
            | ty::RECORD
            | ty::OF
            | ty::REC_GROUP
            | ty::OPAQUE
            | ty::V_GROUP_REF
    )
}

fn decode_type(c: &mut Cursor<'_>, in_group: bool) -> Result<TypeExpr, Reject> {
    let h = c.read_header()?;
    let body = c.read_body(h.len);
    match h.ty {
        ty::PRIMITIVE => match body {
            [code] => PrimitiveKind::from_code(*code)
                .map(TypeExpr::Primitive)
                .ok_or(Reject::InvalidPrimitiveCode),
            _ => Err(Reject::LengthMismatch),
        },
        ty::LIST_OF => {
            let mut inner = Cursor::new(body);
            let t = decode_type(&mut inner, in_group)?;
            if !inner.done() {
                return Err(Reject::LengthMismatch);
            }
            Ok(TypeExpr::ListOf(Box::new(t)))
        }
        ty::MAP_OF => {
            let mut inner = Cursor::new(body);
            let k = decode_type(&mut inner, in_group)?;
            let v = decode_type(&mut inner, in_group)?;
            if !inner.done() {
                return Err(Reject::LengthMismatch);
            }
            if !k.map_key_legal() {
                return Err(Reject::IllegalMapKeyType);
            }
            Ok(TypeExpr::MapOf(Box::new(k), Box::new(v)))
        }
        ty::TERM_OF => Ok(TypeExpr::TermOf(hash32(body)?)),
        ty::RECORD => {
            let mut inner = Cursor::new(body);
            let mut fields = Vec::new();
            while !inner.done() {
                fields.push(decode_field(&mut inner, in_group)?);
            }
            Ok(TypeExpr::Record(fields))
        }
        ty::OF => {
            let mut inner = Cursor::new(body);
            let base_body = inner.expect(ty::V_TERM_REF)?;
            let base = hash32(base_body)?;
            // Knob #2: ONE type parameter on the user side.
            let param = decode_type(&mut inner, in_group)?;
            if !inner.done() {
                return Err(Reject::LengthMismatch);
            }
            Ok(TypeExpr::Of(base, Box::new(param)))
        }
        ty::REC_GROUP => {
            let mut inner = Cursor::new(body);
            let mut terms = Vec::new();
            while !inner.done() {
                let th = inner.read_header()?;
                if th.ty != ty::TERM {
                    return Err(Reject::FormOrder);
                }
                let tb = inner.read_body(th.len);
                terms.push(decode_term_body(tb, true)?);
            }
            Ok(TypeExpr::RecGroup(terms))
        }
        ty::OPAQUE => {
            if !body.is_empty() {
                return Err(Reject::LengthMismatch);
            }
            Ok(TypeExpr::Opaque)
        }
        ty::V_GROUP_REF => {
            if !in_group {
                return Err(Reject::StrayGroupRef);
            }
            let mut p = 0usize;
            let v = read_varint(body, &mut p)?;
            if p != body.len() {
                return Err(Reject::LengthMismatch);
            }
            Ok(TypeExpr::GroupRef(v))
        }
        t if t < ty::EXTENSION_FLOOR => Err(Reject::UnknownReservedType),
        _ => Err(Reject::MisplacedExtension),
    }
}

fn decode_attr_body(body: &[u8], in_group: bool) -> Result<Attribute, Reject> {
    let mut c = Cursor::new(body);
    let key = hash32(c.expect(ty::V_TERM_REF)?)?;
    let value = decode_value(&mut c, in_group)?;
    if !c.done() {
        return Err(Reject::LengthMismatch);
    }
    if !value.is_attribute_legal() {
        return Err(Reject::NestedAttribute);
    }
    Ok(Attribute { key, value })
}

fn decode_attrs(c: &mut Cursor<'_>, in_group: bool) -> Result<Vec<Attribute>, Reject> {
    let mut attrs = Vec::new();
    while let Some(body) = c.take(ty::ATTRIBUTE)? {
        attrs.push(decode_attr_body(body, in_group)?);
    }
    Ok(attrs)
}

fn decode_field(c: &mut Cursor<'_>, in_group: bool) -> Result<Field, Reject> {
    let h = c.read_header()?;
    if h.ty != ty::FIELD {
        return Err(Reject::FormOrder);
    }
    let body = c.read_body(h.len);
    let mut inner = Cursor::new(body);
    let label = utf8(inner.expect(ty::LABEL)?)?;
    let doc = match inner.take(ty::DOC)? {
        Some(b) => Some(utf8(b)?),
        None => None,
    };
    let ty_expr = decode_type(&mut inner, in_group)?;
    let cardinality = match inner.take(ty::CARDINALITY)? {
        Some([0]) => return Err(Reject::NonCanonicalDefault), // R10: `one` is omitted
        Some([code]) => Cardinality::from_code(*code).ok_or(Reject::InvalidCardinality)?,
        Some(_) => return Err(Reject::LengthMismatch),
        None => Cardinality::One,
    };
    let attrs = decode_attrs(&mut inner, in_group)?;
    if !inner.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Field { label, doc, ty: ty_expr, cardinality, attrs })
}

fn decode_term_body(body: &[u8], in_group: bool) -> Result<Term, Reject> {
    let mut inner = Cursor::new(body);
    let label = utf8(inner.expect(ty::LABEL)?)?;
    let doc = match inner.take(ty::DOC)? {
        Some(b) => Some(utf8(b)?),
        None => None,
    };
    let ty_expr = match inner.peek_type()? {
        Some(t) if is_type_expr_start(t) => Some(decode_type(&mut inner, in_group)?),
        _ => None,
    };
    let attrs = decode_attrs(&mut inner, in_group)?;
    if !inner.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Term { label, doc, ty: ty_expr, attrs })
}

fn decode_subject(c: &mut Cursor<'_>) -> Result<Subject, Reject> {
    let h = c.read_header()?;
    let body = c.read_body(h.len);
    match h.ty {
        ty::V_HASH => Ok(Subject::Hash(hash32(body)?)),
        ty::V_NAME => Ok(Subject::Name(utf8(body)?)),
        _ => Err(Reject::FormOrder),
    }
}

fn split_hashes(body: &[u8]) -> Result<Vec<Hash>, Reject> {
    if body.len() % 32 != 0 {
        return Err(Reject::InvalidHashLength);
    }
    Ok(body.chunks_exact(32).map(|c| hash32(c).expect("32")).collect())
}

fn decode_edge(c: &mut Cursor<'_>) -> Result<Option<EdgeForm>, Reject> {
    let Some(t) = c.peek_type()? else { return Ok(None) };
    match t {
        ty::NARROWER_THAN | ty::EQUIVALENT_TO => {
            let h = c.read_header()?;
            let body = c.read_body(h.len);
            if body.len() != 64 {
                return Err(Reject::LengthMismatch);
            }
            let a = hash32(&body[..32])?;
            let b = hash32(&body[32..])?;
            Ok(Some(if t == ty::NARROWER_THAN {
                EdgeForm::NarrowerThan { narrower: a, broader: b }
            } else {
                EdgeForm::EquivalentTo { a, b }
            }))
        }
        ty::MAPS_TO => {
            let h = c.read_header()?;
            let body = c.read_body(h.len);
            if body.len() < 96 {
                // D-K5: from + to + loss are structural — a maps-to without
                // its loss slot cannot be expressed on the wire at all.
                return Err(Reject::LengthMismatch);
            }
            let from = hash32(&body[..32])?;
            let to = hash32(&body[32..64])?;
            let loss = hash32(&body[64..96])?;
            let mut inner = Cursor::new(&body[96..]);
            let attrs = decode_attrs(&mut inner, false)?;
            if !inner.done() {
                return Err(Reject::FormOrder);
            }
            Ok(Some(EdgeForm::MapsTo { from, to, loss, attrs }))
        }
        ty::EDGE => {
            let h = c.read_header()?;
            let body = c.read_body(h.len);
            let mut inner = Cursor::new(body);
            let subject = decode_subject(&mut inner)?;
            let kind = hash32(inner.expect(ty::V_TERM_REF)?)?;
            let object = decode_subject(&mut inner)?;
            let attrs = decode_attrs(&mut inner, false)?;
            if !inner.done() {
                return Err(Reject::FormOrder);
            }
            Ok(Some(EdgeForm::Edge { subject, kind, object, attrs }))
        }
        _ => Ok(None),
    }
}

fn decode_vocabulary_body(body: &[u8]) -> Result<Vocabulary, Reject> {
    let mut c = Cursor::new(body);
    let label = utf8(c.expect(ty::LABEL)?)?;
    let doc = match c.take(ty::DOC)? {
        Some(b) => Some(utf8(b)?),
        None => None,
    };
    let imports = match c.take(ty::IMPORTS)? {
        Some(b) => split_hashes(b)?,
        None => Vec::new(),
    };
    let mut terms = Vec::new();
    while c.peek_type()? == Some(ty::TERM) {
        let h = c.read_header()?;
        let tb = c.read_body(h.len);
        terms.push(decode_term_body(tb, false)?);
    }
    let mut edges = Vec::new();
    while let Some(e) = decode_edge(&mut c)? {
        edges.push(e);
    }
    let supersedes = match c.take(ty::SUPERSEDES)? {
        Some(b) => Some(hash32(b)?),
        None => None,
    };
    if !c.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Vocabulary { label, doc, imports, terms, edges, supersedes })
}

fn decode_manifest_body(body: &[u8]) -> Result<Manifest, Reject> {
    let mut c = Cursor::new(body);
    let mty = hash32(c.expect(ty::V_TERM_REF)?)?;
    let label = match c.take(ty::LABEL)? {
        Some(b) => Some(utf8(b)?),
        None => None,
    };
    let describes_body = c.expect(ty::DESCRIBES)?;
    let mut dc = Cursor::new(describes_body);
    let describes = decode_subject(&mut dc)?;
    if !dc.done() {
        return Err(Reject::LengthMismatch);
    }
    let mut entries = Vec::new();
    while let Some(eb) = c.take(ty::MANIFEST_ENTRY)? {
        let mut ec = Cursor::new(eb);
        let field = hash32(ec.expect(ty::V_TERM_REF)?)?;
        let value = decode_value(&mut ec, false)?;
        if !ec.done() {
            return Err(Reject::LengthMismatch);
        }
        entries.push(ManifestEntry { field, value });
    }
    let mut edges = Vec::new();
    while let Some(e) = decode_edge(&mut c)? {
        edges.push(e);
    }
    if !c.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Manifest { ty: mty, label, describes, entries, edges })
}

fn decode_intent(c: &mut Cursor<'_>) -> Result<Intent, Reject> {
    let body = c.expect(ty::INTENT)?;
    let mut inner = Cursor::new(body);
    let name = utf8(inner.expect(ty::V_TEXT)?)?;
    let attrs = decode_attrs(&mut inner, false)?;
    if !inner.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Intent { name, attrs })
}

fn decode_via(body: &[u8]) -> Result<Via, Reject> {
    match body.first() {
        Some(0) => Ok(Via::Wasm(hash32(&body[1..])?)),
        Some(1) => Ok(Via::Native(utf8(&body[1..])?)),
        _ => Err(Reject::LengthMismatch),
    }
}

fn decode_contract_body(body: &[u8]) -> Result<Contract, Reject> {
    let mut c = Cursor::new(body);
    let label = utf8(c.expect(ty::LABEL)?)?;
    let doc = match c.take(ty::DOC)? {
        Some(b) => Some(utf8(b)?),
        None => None,
    };
    let imports = match c.take(ty::IMPORTS)? {
        Some(b) => split_hashes(b)?,
        None => Vec::new(),
    };
    let binds = match c.take(ty::BINDS)? {
        Some(b) => {
            let mut bc = Cursor::new(b);
            let mut subjects = Vec::new();
            while !bc.done() {
                subjects.push(decode_subject(&mut bc)?);
            }
            subjects
        }
        None => Vec::new(),
    };
    let mut clauses = Vec::new();
    loop {
        match c.peek_type()? {
            Some(t @ (ty::EXPRESS | ty::APPROXIMATE)) => {
                let h = c.read_header()?;
                let cb = c.read_body(h.len);
                let mut cc = Cursor::new(cb);
                let intent = decode_intent(&mut cc)?;
                let target = hash32(cc.expect(ty::V_TERM_REF)?)?;
                let via = match cc.take(ty::VIA)? {
                    Some(vb) => Some(decode_via(vb)?),
                    None => None,
                };
                let attrs = decode_attrs(&mut cc, false)?;
                if !cc.done() {
                    return Err(Reject::FormOrder);
                }
                clauses.push(if t == ty::EXPRESS {
                    Clause::Express { intent, target, via, attrs }
                } else {
                    Clause::Approximate { intent, target, via, attrs }
                });
            }
            Some(ty::REFUSE) => {
                let h = c.read_header()?;
                let cb = c.read_body(h.len);
                let mut cc = Cursor::new(cb);
                let intent = decode_intent(&mut cc)?;
                if !cc.done() {
                    return Err(Reject::FormOrder);
                }
                clauses.push(Clause::Refuse { intent });
            }
            _ => break,
        }
    }
    if !c.done() {
        return Err(Reject::FormOrder);
    }
    Ok(Contract { label, doc, imports, binds, clauses })
}

/// Decode a document from canonical bytes: the outer form, then any trailing
/// extension TLVs (R12; the tail is the canonical extension point, F49).
/// Enforces R13 internally: the decoded result must re-encode byte-identically.
pub fn decode_document(bytes: &[u8]) -> Result<Decoded, Reject> {
    if bytes.is_empty() {
        return Err(Reject::NotADocument);
    }
    let mut c = Cursor::new(bytes);
    let h = c.read_header()?;
    let body = c.read_body(h.len);
    let doc = match h.ty {
        ty::VOCABULARY => Document::Vocabulary(decode_vocabulary_body(body)?),
        ty::MANIFEST => Document::Manifest(decode_manifest_body(body)?),
        ty::CONTRACT => Document::Contract(decode_contract_body(body)?),
        t if t < ty::EXTENSION_FLOOR => return Err(Reject::NotADocument),
        _ => return Err(Reject::NotADocument),
    };
    // Trailing extensions (R12): retain byte-exactly; note criticality.
    let mut extensions = Vec::new();
    let mut critical = false;
    while !c.done() {
        let eh = c.read_header()?;
        if eh.ty < ty::EXTENSION_FLOOR {
            return Err(Reject::TrailingBytes);
        }
        let payload = Vec::from(c.read_body(eh.len));
        let ext = RawTlv { ty: eh.ty, payload };
        critical |= ext.is_critical();
        extensions.push(ext);
    }
    let decoded = Decoded { doc, extensions, critical };
    // R13: decode ∘ encode = byte identity, or reject. Canonical re-emission
    // is a conformance check, not a courtesy (ndf-the-landing Act III).
    let reemitted = encode_decoded(&decoded).map_err(|_| Reject::ReencodeMismatch)?;
    if reemitted != bytes {
        return Err(Reject::ReencodeMismatch);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn varint_roundtrip_and_minimality() {
        for v in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            put_varint(&mut buf, v);
            let mut p = 0;
            assert_eq!(read_varint(&buf, &mut p).unwrap(), v);
            assert_eq!(p, buf.len());
        }
        // W-03 class: 5 encoded as two groups (0x85 0x00) is non-minimal.
        let mut p = 0;
        assert_eq!(read_varint(&[0x85, 0x00], &mut p), Err(Reject::NonMinimalVarint));
        // W-22: an 11-byte varint overflows u64.
        let mut p = 0;
        assert_eq!(
            read_varint(&[0xff; 11], &mut p),
            Err(Reject::VarintOverflow)
        );
    }

    fn tiny_manifest() -> Document {
        Document::Manifest(Manifest {
            ty: [7u8; 32],
            label: Some(String::from("t")),
            describes: Subject::Name(String::from("yard.north/hive-a7/scale")),
            entries: vec![ManifestEntry {
                field: [1u8; 32],
                value: Value::Decimal(Decimal::from_canonical("41.2").unwrap()),
            }],
            edges: Vec::new(),
        })
    }

    #[test]
    fn document_roundtrip_byte_identity() {
        let doc = tiny_manifest();
        let bytes = encode_document(&doc).unwrap();
        let decoded = decode_document(&bytes).unwrap();
        assert_eq!(decoded.doc, doc);
        assert!(!decoded.critical);
        assert_eq!(encode_decoded(&decoded).unwrap(), bytes);
    }

    #[test]
    fn trailing_critical_extension_flags_unresolved_path() {
        // W-19: a critical unknown TLV must not crash; it flags the document.
        let mut bytes = encode_document(&tiny_manifest()).unwrap();
        put_tlv(&mut bytes, 0x81, &[0xde, 0xad]);
        let decoded = decode_document(&bytes).unwrap();
        assert!(decoded.critical);
        // …and re-emission is still byte-identical (R13 with extensions).
        assert_eq!(encode_decoded(&decoded).unwrap(), bytes);
        // Non-critical (even) extension: retained, not critical.
        let mut bytes2 = encode_document(&tiny_manifest()).unwrap();
        put_tlv(&mut bytes2, 0x80, &[0x00]);
        let d2 = decode_document(&bytes2).unwrap();
        assert!(!d2.critical);
    }

    #[test]
    fn duplicate_map_key_rejects() {
        // W-07: build a map with duplicate keys by hand.
        let mut kv = Vec::new();
        // key "a" -> true, key "a" -> false
        for b in [0x01u8, 0x00] {
            put_text_tlv(&mut kv, ty::V_TEXT, "a");
            put_tlv(&mut kv, ty::V_BOOLEAN, &[b]);
        }
        let mut map = Vec::new();
        put_tlv(&mut map, ty::V_MAP, &kv);
        let mut c = Cursor::new(&map);
        assert_eq!(decode_value(&mut c, false), Err(Reject::DuplicateMapKey));
    }

    #[test]
    fn decimal_alias_rejects_on_wire() {
        // W-11: "1.0" and "+1" alias "1" — the wire admits only "1".
        for alias in ["1.0", "+1", "01"] {
            let mut v = Vec::new();
            put_text_tlv(&mut v, ty::V_DECIMAL, alias);
            let mut c = Cursor::new(&v);
            assert_eq!(decode_value(&mut c, false), Err(Reject::NonCanonicalDecimal), "{alias}");
        }
        let mut ok = Vec::new();
        put_text_tlv(&mut ok, ty::V_DECIMAL, "1");
        let mut c = Cursor::new(&ok);
        assert!(decode_value(&mut c, false).is_ok());
    }

    #[test]
    fn nfc_confusable_labels_stay_distinct_bytes() {
        // W-14: NFC "café" vs NFD "café" — the wire stays honest: both legal,
        // different bytes, different hashes. Display-layer duty, never a
        // wire transform (R5/F34).
        let nfc = "caf\u{e9}";
        let nfd = "cafe\u{301}";
        let t = |label: &str| Term { label: String::from(label), doc: None, ty: None, attrs: Vec::new() };
        let h1 = term_hash(&t(nfc)).unwrap();
        let h2 = term_hash(&t(nfd)).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn explicit_cardinality_one_is_noncanonical() {
        // Hand-build a field with an explicit cardinality byte 0 (one).
        let mut fb = Vec::new();
        put_text_tlv(&mut fb, ty::LABEL, "f");
        put_tlv(&mut fb, ty::PRIMITIVE, &[1]); // text
        put_tlv(&mut fb, ty::CARDINALITY, &[0]);
        let mut out = Vec::new();
        put_tlv(&mut out, ty::FIELD, &fb);
        let mut c = Cursor::new(&out);
        assert_eq!(decode_field(&mut c, false), Err(Reject::NonCanonicalDefault));
    }

    #[test]
    fn maps_to_without_loss_is_unwritable() {
        // D-K5: a 64-byte maps-to body (no loss slot) is a LengthMismatch.
        let mut body = Vec::new();
        body.extend_from_slice(&[1u8; 32]);
        body.extend_from_slice(&[2u8; 32]);
        let mut out = Vec::new();
        put_tlv(&mut out, ty::MAPS_TO, &body);
        let mut c = Cursor::new(&out);
        assert_eq!(decode_edge(&mut c), Err(Reject::LengthMismatch));
    }

    #[test]
    fn nested_attribute_rejects() {
        // knob #4 / P2-04 shape: attribute carrying a list must reject.
        let mut ab = Vec::new();
        put_tlv(&mut ab, ty::V_TERM_REF, &[3u8; 32]);
        put_tlv(&mut ab, ty::V_LIST, &[]);
        assert_eq!(decode_attr_body(&ab, false), Err(Reject::NestedAttribute));
    }
}
