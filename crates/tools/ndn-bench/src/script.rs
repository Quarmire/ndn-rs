//! Script front-end: the three text grammars — `.ndfs` (stratum), `.ndfm`
//! (manifest), `.ndfc` (contract) — reconstructed from the corpus's worked
//! examples (round 5's graded exam; FRICTION F47; EBNF in
//! docs/keel/GRAMMAR.md). Line-oriented, comment-friendly, sugar-expanding —
//! and everything it compiles is shown, not hidden (L-06).

use std::fmt;

/// A reference in script position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ref {
    /// A label defined in the current document.
    Local(String),
    /// `pet:label` — resolved through the lock (L-01).
    Qualified {
        /// The petname bound by `use … as`.
        pet: String,
        /// The term label inside that vocabulary.
        label: String,
    },
    /// A literal 64-hex content hash.
    Hash([u8; 32]),
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ref::Local(l) => write!(f, "{l}"),
            Ref::Qualified { pet, label } => write!(f, "{pet}:{label}"),
            Ref::Hash(h) => {
                for b in &h[..4] {
                    write!(f, "{b:02x}")?;
                }
                write!(f, "…")
            }
        }
    }
}

/// A literal in attribute or manifest-entry position.
#[derive(Clone, Debug, PartialEq)]
pub enum Lit {
    /// `"text"`.
    Text(String),
    /// Unsigned integer.
    Int(u64),
    /// Canonical-form decimal (normalized at compile).
    Dec(String),
    /// `true` / `false`.
    Bool(bool),
    /// 64-hex hash.
    HashLit([u8; 32]),
    /// A bare `name/like/this` (contains `/` or `.`).
    Name(String),
    /// A term reference.
    Ref(Ref),
    /// The measured-literal sugar `41.2 ±0.3 kg` (F24/F29: the stranger's
    /// literal, adopted official, with its exact kernel expansion).
    Measured {
        /// The estimate, canonical decimal.
        estimate: String,
        /// The ± half-width, canonical decimal.
        plus_minus: String,
        /// The unit word (checked against the field's @unit when resolvable).
        unit: String,
    },
    /// `[ lit, lit, … ]`.
    List(Vec<Lit>),
}

/// A type expression in script position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeAst {
    /// One of the seven primitives, by keyword.
    Prim(&'static str),
    /// `opaque` (C4).
    Opaque,
    /// `list-of(T)`.
    ListOf(Box<TypeAst>),
    /// `map-of(K, V)` — the kernel's one arity-2 constructor (L-03).
    MapOf(Box<TypeAst>, Box<TypeAst>),
    /// `term-of <ref>`.
    TermOf(Ref),
    /// `<ref>(T)` — user parametric, arity-1 (L-03).
    Of(Ref, Box<TypeAst>),
    /// A bare reference used as a type (legal for defined terms; L-15 fires
    /// when the referent is an enum parent).
    Bare(Ref),
}

/// Cardinality keywords (fields only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CardAst {
    /// Default; omitted on the wire (R10).
    #[default]
    One,
    /// `optional`.
    Optional,
    /// `some` — ≥ 1, "the non-negotiable, carried".
    Some,
    /// `many`.
    Many,
}

/// `@key = value` (attributes stay flat — L-04).
#[derive(Clone, Debug, PartialEq)]
pub struct AttrAst {
    /// Attribute key: a bare word (`unit`, `loss`, `sensitivity`, …) which
    /// compiles against the well-known attribute terms, or a qualified ref.
    pub key: RefOrWord,
    /// The flat value.
    pub value: Lit,
    /// Source line, for diagnostics.
    pub line: usize,
}

/// Either a reference or a bare keyword-ish word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefOrWord {
    /// A reference.
    Ref(Ref),
    /// A bare word.
    Word(String),
}

impl fmt::Display for RefOrWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefOrWord::Ref(r) => write!(f, "{r}"),
            RefOrWord::Word(w) => write!(f, "{w}"),
        }
    }
}

/// A field row (inside `record { … }`).
#[derive(Clone, Debug, PartialEq)]
pub struct FieldAst {
    /// Field label.
    pub name: String,
    /// Cardinality keyword, if any.
    pub card: CardAst,
    /// The type.
    pub ty: TypeAst,
    /// Flat attributes.
    pub attrs: Vec<AttrAst>,
    /// Trailing doc string.
    pub doc: Option<String>,
    /// Source line.
    pub line: usize,
}

/// Top-level stratum items.
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    /// `use <stratum> as <pet>`.
    Use {
        /// Vocabulary name in the lock.
        name: String,
        /// Petname.
        pet: String,
        /// Line.
        line: usize,
    },
    /// `enum name "doc"? { members… }` — sugar; expands per L-06/F30 to
    /// N member terms + 1 parent term + N narrower-than edges.
    Enum {
        /// Parent term name.
        name: String,
        /// Doc string.
        doc: Option<String>,
        /// Member labels.
        members: Vec<String>,
        /// Line.
        line: usize,
    },
    /// A term row: `term name : type` or bare `name : type`.
    Term {
        /// Label.
        name: String,
        /// Type, if given.
        ty: Option<TypeAst>,
        /// Attributes.
        attrs: Vec<AttrAst>,
        /// Doc string.
        doc: Option<String>,
        /// Line.
        line: usize,
    },
    /// `record name "doc"? { field rows }`.
    Record {
        /// Label.
        name: String,
        /// Doc.
        doc: Option<String>,
        /// Fields.
        fields: Vec<FieldAst>,
        /// Attributes on the record term.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `narrower-than a b`.
    NarrowerThan {
        /// Narrower.
        a: Ref,
        /// Broader.
        b: Ref,
        /// Line.
        line: usize,
    },
    /// `equivalent-to a b`.
    EquivalentTo {
        /// One side.
        a: Ref,
        /// Other side.
        b: Ref,
        /// Line.
        line: usize,
    },
    /// `maps-to from -> to @loss = ref` (direction + @loss required — L-09).
    MapsTo {
        /// Source.
        from: Ref,
        /// Destination.
        to: Ref,
        /// Attributes; must include `@loss`.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `edge subject kind object` — schema/instance edge (F31 idiom).
    Edge {
        /// Subject.
        subject: Ref,
        /// Kind term.
        kind: Ref,
        /// Object.
        object: Ref,
        /// Attributes.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `supersedes <hash>` (L-07: editing published terms compiles to
    /// version + supersedes; in-place mutation does not exist).
    Supersedes {
        /// The superseded document's hash.
        hash: [u8; 32],
        /// Line.
        line: usize,
    },
}

/// A parsed `.ndfs` stratum.
#[derive(Clone, Debug, PartialEq)]
pub struct StratumAst {
    /// Stratum name (its label and default petname).
    pub name: String,
    /// Doc string.
    pub doc: Option<String>,
    /// Items in author order.
    pub items: Vec<Item>,
}

/// A parsed `.ndfm` manifest (round 5, wall 1: the stranger's layout,
/// adopted as the seed — F29).
#[derive(Clone, Debug, PartialEq)]
pub struct ManifestAst {
    /// Output name (petname for the emitted artifact).
    pub name: String,
    /// The manifest's type term.
    pub ty: Ref,
    /// `use` imports.
    pub uses: Vec<(String, String, usize)>,
    /// `describes <name-or-hash>` (prefix subjects legal — F3/C5).
    pub describes: Option<SubjectAst>,
    /// Optional label line.
    pub label: Option<String>,
    /// `<field-ref> = <literal>` rows.
    pub entries: Vec<(Ref, Lit, usize)>,
    /// Instance edges.
    pub edges: Vec<Item>,
    /// Line of the header.
    pub line: usize,
}

/// A manifest subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectAst {
    /// A name or prefix.
    Name(String),
    /// A content hash.
    Hash([u8; 32]),
}

/// A parsed `.ndfc` contract clause.
#[derive(Clone, Debug, PartialEq)]
pub enum ClauseAst {
    /// `intent name @attrs…` — a declaration attaching attrs (L-11 checks
    /// sensitivity tags here).
    IntentDecl {
        /// Intent name.
        name: String,
        /// Attributes.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `express intent -> ref [via …]`.
    Express {
        /// Intent name.
        intent: String,
        /// Target.
        target: Ref,
        /// Via, if any.
        via: Option<ViaAst>,
        /// Attributes.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `approximate intent -> ref`.
    Approximate {
        /// Intent name.
        intent: String,
        /// Target.
        target: Ref,
        /// Via.
        via: Option<ViaAst>,
        /// Attributes.
        attrs: Vec<AttrAst>,
        /// Line.
        line: usize,
    },
    /// `refuse intent` (kept as documentation — L-14).
    Refuse {
        /// Intent name.
        intent: String,
        /// Line.
        line: usize,
    },
}

/// `via wasm:<hash>` or `via native:<attested-id>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViaAst {
    /// Sandboxed WASM component by hash — "immune by construction".
    Wasm([u8; 32]),
    /// Native renderer by attested id — the register's open attestation gap.
    Native(String),
}

/// A parsed `.ndfc` contract.
#[derive(Clone, Debug, PartialEq)]
pub struct ContractAst {
    /// Contract name/label.
    pub name: String,
    /// Doc string.
    pub doc: Option<String>,
    /// Imports.
    pub uses: Vec<(String, String, usize)>,
    /// `binds` filters.
    pub binds: Vec<SubjectAst>,
    /// Clauses in author order.
    pub clauses: Vec<ClauseAst>,
}

/// Any parsed script.
#[derive(Clone, Debug, PartialEq)]
pub enum Script {
    /// `.ndfs`.
    Stratum(StratumAst),
    /// `.ndfm`.
    Manifest(ManifestAst),
    /// `.ndfc`.
    Contract(ContractAst),
}

/// A parse error with its line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number.
    pub line: usize,
    /// Message.
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

// ───────────────────────────── tokenizing ───────────────────────────────────

fn strip_comment(line: &str) -> &str {
    // `#` and `//` start comments outside strings.
    let mut in_str = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_str = !in_str,
            b'#' if !in_str => return &line[..i],
            b'/' if !in_str && i + 1 < bytes.len() && bytes[i + 1] == b'/' => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// Split a line into tokens: strings stay whole; punctuation `: = { } ( ) , ->`
/// and `±` are their own tokens; `·` separates like whitespace. A `:` binds
/// INTO a word when flanked by word characters (`u:kilogram` is one token);
/// a spaced `:` separates (`queen : term-of …`). `->` requires surrounding
/// spaces (labels may contain `-`).
fn tokens(line: &str) -> Result<Vec<String>, String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let is_wordish = |c: char| {
        c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '#' | '+')
    };
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() || c == '·' => i += 1,
            '"' => {
                i += 1;
                let mut s = String::new();
                loop {
                    if i >= chars.len() {
                        return Err("unterminated string".into());
                    }
                    match chars[i] {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\\' => {
                            i += 1;
                            if i >= chars.len() {
                                return Err("unterminated string".into());
                            }
                            s.push(if chars[i] == 'n' { '\n' } else { chars[i] });
                            i += 1;
                        }
                        other => {
                            s.push(other);
                            i += 1;
                        }
                    }
                }
                out.push(format!("\"{s}"));
            }
            ':' | '=' | '{' | '}' | '(' | ')' | ',' | '[' | ']' | '@' | '±' => {
                i += 1;
                out.push(c.to_string());
            }
            '-' if i + 1 < chars.len() && chars[i + 1] == '>' => {
                i += 2;
                out.push("->".into());
            }
            c if is_wordish(c) || c == '-' => {
                let mut w = String::new();
                while i < chars.len() {
                    let n = chars[i];
                    if is_wordish(n) || n == '-' {
                        w.push(n);
                        i += 1;
                    } else if n == ':'
                        && i + 1 < chars.len()
                        && is_wordish(chars[i + 1])
                        && !w.is_empty()
                    {
                        // unspaced colon: part of a qualified reference
                        w.push(':');
                        i += 1;
                    } else {
                        break;
                    }
                }
                out.push(w);
            }
            other => return Err(format!("unexpected character {other:?}")),
        }
    }
    Ok(out)
}

fn is_hash_word(w: &str) -> Option<[u8; 32]> {
    let s = w.strip_prefix("0x").unwrap_or(w);
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_ref(w: &str) -> Result<Ref, String> {
    if let Some(h) = is_hash_word(w) {
        return Ok(Ref::Hash(h));
    }
    if let Some((pet, label)) = w.split_once(':') {
        if pet.is_empty() || label.is_empty() {
            return Err(format!("malformed reference {w:?}"));
        }
        return Ok(Ref::Qualified { pet: pet.into(), label: label.into() });
    }
    Ok(Ref::Local(w.into()))
}

fn is_string_tok(t: &str) -> Option<&str> {
    t.strip_prefix('"')
}

// A small cursor over one line's tokens.
struct Cur<'a> {
    toks: &'a [String],
    i: usize,
    line: usize,
}

impl<'a> Cur<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.toks.get(self.i).map(String::as_str)
    }
    fn next(&mut self) -> Option<&'a str> {
        let t = self.peek()?;
        self.i += 1;
        Some(t)
    }
    fn expect(&mut self, want: &str) -> Result<(), ParseError> {
        match self.next() {
            Some(t) if t == want => Ok(()),
            got => Err(self.err(format!("expected {want:?}, got {got:?}"))),
        }
    }
    fn err(&self, msg: String) -> ParseError {
        ParseError { line: self.line, msg }
    }
    fn done(&self) -> bool {
        self.i >= self.toks.len()
    }
}

fn parse_attrs(c: &mut Cur<'_>) -> Result<Vec<AttrAst>, ParseError> {
    let mut attrs = Vec::new();
    while c.peek() == Some("@") {
        c.next();
        let key_word = c.next().ok_or_else(|| c.err("attribute key expected after @".into()))?;
        let key = if key_word.contains(':') {
            RefOrWord::Ref(parse_ref(key_word).map_err(|e| c.err(e))?)
        } else {
            RefOrWord::Word(key_word.into())
        };
        c.expect("=")?;
        let value = parse_lit(c)?;
        attrs.push(AttrAst { key, value, line: c.line });
    }
    Ok(attrs)
}

fn looks_decimal(w: &str) -> bool {
    let s = w.strip_prefix('-').unwrap_or(w);
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.') && s.bytes().filter(|&b| b == b'.').count() <= 1
}

fn parse_lit(c: &mut Cur<'_>) -> Result<Lit, ParseError> {
    let t = c.next().ok_or_else(|| c.err("literal expected".into()))?;
    if let Some(s) = is_string_tok(t) {
        return Ok(Lit::Text(s.into()));
    }
    if t == "[" {
        let mut items = Vec::new();
        loop {
            if c.peek() == Some("]") {
                c.next();
                break;
            }
            items.push(parse_lit(c)?);
            if c.peek() == Some(",") {
                c.next();
            }
        }
        return Ok(Lit::List(items));
    }
    if t == "true" {
        return Ok(Lit::Bool(true));
    }
    if t == "false" {
        return Ok(Lit::Bool(false));
    }
    if let Some(h) = is_hash_word(t) {
        return Ok(Lit::HashLit(h));
    }
    if looks_decimal(t) {
        // Measured literal? `41.2 ±0.3 kg` or `41.2 ± 0.3 kg`
        if c.peek() == Some("±") {
            c.next();
            let pm = c.next().ok_or_else(|| c.err("± needs a half-width".into()))?;
            if !looks_decimal(pm) {
                return Err(c.err(format!("± half-width must be a decimal, got {pm:?}")));
            }
            let unit = c
                .next()
                .ok_or_else(|| c.err("measured literal needs a unit word".into()))?;
            return Ok(Lit::Measured {
                estimate: t.into(),
                plus_minus: pm.into(),
                unit: unit.into(),
            });
        }
        if !t.contains('.') && !t.starts_with('-') {
            if let Ok(n) = t.parse::<u64>() {
                // Plain integer... unless a unit word follows a bare decimal
                // context; entries decide by declared type at compile.
                return Ok(Lit::Int(n));
            }
        }
        return Ok(Lit::Dec(t.into()));
    }
    if t.contains('/') || t.contains('.') {
        return Ok(Lit::Name(t.into()));
    }
    Ok(Lit::Ref(parse_ref(t).map_err(|e| c.err(e))?))
}

const PRIMS: [&str; 7] = ["bytes", "text", "integer", "decimal", "boolean", "hash", "name"];

fn parse_type(c: &mut Cur<'_>) -> Result<TypeAst, ParseError> {
    let t = c.next().ok_or_else(|| c.err("type expected".into()))?;
    if PRIMS.contains(&t) {
        return Ok(TypeAst::Prim(PRIMS[PRIMS.iter().position(|p| *p == t).unwrap()]));
    }
    match t {
        "opaque" => Ok(TypeAst::Opaque),
        "list-of" => {
            c.expect("(")?;
            let inner = parse_type(c)?;
            c.expect(")")?;
            Ok(TypeAst::ListOf(Box::new(inner)))
        }
        "map-of" => {
            c.expect("(")?;
            let k = parse_type(c)?;
            c.expect(",")?;
            let v = parse_type(c)?;
            c.expect(")")?;
            Ok(TypeAst::MapOf(Box::new(k), Box::new(v)))
        }
        "term-of" => {
            let r = c.next().ok_or_else(|| c.err("term-of needs a reference".into()))?;
            Ok(TypeAst::TermOf(parse_ref(r).map_err(|e| c.err(e))?))
        }
        other => {
            let r = parse_ref(other).map_err(|e| c.err(e))?;
            if c.peek() == Some("(") {
                c.next();
                let inner = parse_type(c)?;
                // L-03: user parametrics are arity-1 — a second parameter is
                // a parse error with the law named.
                if c.peek() == Some(",") {
                    return Err(c.err(
                        "user parametrics take ONE type parameter (L-03); only the kernel's map-of is arity-2"
                            .into(),
                    ));
                }
                c.expect(")")?;
                Ok(TypeAst::Of(r, Box::new(inner)))
            } else {
                Ok(TypeAst::Bare(r))
            }
        }
    }
}

fn take_doc(c: &mut Cur<'_>) -> Option<String> {
    if let Some(t) = c.peek() {
        if let Some(s) = is_string_tok(t) {
            c.next();
            return Some(s.into());
        }
    }
    None
}

// ───────────────────────────── parsers ──────────────────────────────────────

/// Parse a `.ndfs` stratum script.
pub fn parse_stratum(src: &str) -> Result<StratumAst, ParseError> {
    let mut name = None;
    let mut doc = None;
    let mut items = Vec::new();
    let mut record_ctx: Option<(String, Option<String>, Vec<AttrAst>, Vec<FieldAst>, usize)> = None;

    for (ln0, raw) in src.lines().enumerate() {
        let line = ln0 + 1;
        let stripped = strip_comment(raw).trim();
        if stripped.is_empty() {
            continue;
        }
        let toks = tokens(stripped).map_err(|msg| ParseError { line, msg })?;
        let mut c = Cur { toks: &toks, i: 0, line };

        // Inside a record block?
        if let Some(ctx) = &mut record_ctx {
            if c.peek() == Some("}") {
                let (rname, rdoc, rattrs, fields, rline) = record_ctx.take().unwrap();
                items.push(Item::Record { name: rname, doc: rdoc, fields, attrs: rattrs, line: rline });
                continue;
            }
            // field row: name : [card] type [@attrs] ["doc"]
            let fname = c.next().ok_or_else(|| c.err("field name expected".into()))?.to_string();
            c.expect(":")?;
            let card = match c.peek() {
                Some("optional") => {
                    c.next();
                    CardAst::Optional
                }
                Some("some") => {
                    c.next();
                    CardAst::Some
                }
                Some("many") => {
                    c.next();
                    CardAst::Many
                }
                Some("one") => {
                    c.next();
                    CardAst::One
                }
                _ => CardAst::One,
            };
            let ty = parse_type(&mut c)?;
            let attrs = parse_attrs(&mut c)?;
            let fdoc = take_doc(&mut c);
            if !c.done() {
                return Err(c.err(format!("unexpected trailing tokens: {:?}", &toks[c.i..])));
            }
            ctx.3.push(FieldAst { name: fname, card, ty, attrs, doc: fdoc, line });
            continue;
        }

        match c.peek() {
            Some("stratum") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("stratum needs a name".into()))?;
                name = Some(n.to_string());
                doc = take_doc(&mut c);
            }
            Some("use") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("use needs a name".into()))?.to_string();
                c.expect("as")?;
                let pet = c.next().ok_or_else(|| c.err("use … as needs a petname".into()))?.to_string();
                items.push(Item::Use { name: n, pet, line });
            }
            Some("enum") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("enum needs a name".into()))?.to_string();
                let edoc = take_doc(&mut c);
                c.expect("{")?;
                let mut members = Vec::new();
                while let Some(t) = c.next() {
                    if t == "}" {
                        break;
                    }
                    members.push(t.to_string());
                }
                items.push(Item::Enum { name: n, doc: edoc, members, line });
            }
            Some("record") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("record needs a name".into()))?.to_string();
                let rdoc = take_doc(&mut c);
                let rattrs = parse_attrs(&mut c)?;
                c.expect("{")?;
                record_ctx = Some((n, rdoc, rattrs, Vec::new(), line));
            }
            Some("narrower-than") => {
                c.next();
                let a = parse_ref(c.next().ok_or_else(|| c.err("narrower-than needs two refs".into()))?)
                    .map_err(|e| c.err(e))?;
                let b = parse_ref(c.next().ok_or_else(|| c.err("narrower-than needs two refs".into()))?)
                    .map_err(|e| c.err(e))?;
                items.push(Item::NarrowerThan { a, b, line });
            }
            Some("equivalent-to") => {
                c.next();
                let a = parse_ref(c.next().ok_or_else(|| c.err("equivalent-to needs two refs".into()))?)
                    .map_err(|e| c.err(e))?;
                let b = parse_ref(c.next().ok_or_else(|| c.err("equivalent-to needs two refs".into()))?)
                    .map_err(|e| c.err(e))?;
                items.push(Item::EquivalentTo { a, b, line });
            }
            Some("maps-to") => {
                c.next();
                let from = parse_ref(c.next().ok_or_else(|| c.err("maps-to needs a source".into()))?)
                    .map_err(|e| c.err(e))?;
                // The direction arrow is required (round 5, row 07: "missing
                // edge keyword" was a fix-it — the arrow IS the direction).
                c.expect("->")?;
                let to = parse_ref(c.next().ok_or_else(|| c.err("maps-to needs a destination".into()))?)
                    .map_err(|e| c.err(e))?;
                let attrs = parse_attrs(&mut c)?;
                items.push(Item::MapsTo { from, to, attrs, line });
            }
            Some("edge") => {
                c.next();
                let subject = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let kind = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let object = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let attrs = parse_attrs(&mut c)?;
                items.push(Item::Edge { subject, kind, object, attrs, line });
            }
            Some("supersedes") => {
                c.next();
                let h = c.next().ok_or_else(|| c.err("supersedes needs a hash".into()))?;
                let hash = is_hash_word(h).ok_or_else(|| c.err(format!("supersedes needs a 64-hex hash, got {h:?}")))?;
                items.push(Item::Supersedes { hash, line });
            }
            Some(word) if word == "term" || !word.starts_with('@') => {
                // `term name : …` or bare `name : …`
                if word == "term" {
                    c.next();
                }
                let n = c.next().ok_or_else(|| c.err("term needs a name".into()))?.to_string();
                let mut ty = None;
                if c.peek() == Some(":") {
                    c.next();
                    // Cardinality at TERM level is a category error the
                    // stranger's `justified-by : some hash` made famous —
                    // cardinality belongs to fields (round 5, answer #5).
                    if matches!(c.peek(), Some("optional" | "some" | "many")) {
                        return Err(c.err(format!(
                            "cardinality keyword {:?} is legal only on record fields; \
                             wrap this in a record (round 5, answer #5: 'the field enforces')",
                            c.peek().unwrap()
                        )));
                    }
                    ty = Some(parse_type(&mut c)?);
                }
                let attrs = parse_attrs(&mut c)?;
                let tdoc = take_doc(&mut c);
                if !c.done() {
                    return Err(c.err(format!("unexpected trailing tokens: {:?}", &toks[c.i..])));
                }
                items.push(Item::Term { name: n, ty, attrs, doc: tdoc, line });
            }
            other => return Err(c.err(format!("unexpected {other:?}"))),
        }
    }
    if record_ctx.is_some() {
        return Err(ParseError { line: src.lines().count(), msg: "unclosed record block".into() });
    }
    let name = name.ok_or(ParseError { line: 1, msg: "missing `stratum <name>` header".into() })?;
    Ok(StratumAst { name, doc, items })
}

/// Parse a `.ndfm` manifest script.
pub fn parse_manifest(src: &str) -> Result<ManifestAst, ParseError> {
    let mut out: Option<ManifestAst> = None;
    for (ln0, raw) in src.lines().enumerate() {
        let line = ln0 + 1;
        let stripped = strip_comment(raw).trim();
        if stripped.is_empty() {
            continue;
        }
        let toks = tokens(stripped).map_err(|msg| ParseError { line, msg })?;
        let mut c = Cur { toks: &toks, i: 0, line };
        match c.peek() {
            Some("manifest") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("manifest needs a name".into()))?.to_string();
                c.expect(":")?;
                let ty = parse_ref(c.next().ok_or_else(|| c.err("manifest needs a type term".into()))?)
                    .map_err(|e| c.err(e))?;
                out = Some(ManifestAst {
                    name: n,
                    ty,
                    uses: Vec::new(),
                    describes: None,
                    label: None,
                    entries: Vec::new(),
                    edges: Vec::new(),
                    line,
                });
            }
            Some("use") => {
                let m = out.as_mut().ok_or_else(|| c.err("`manifest` header must come first".into()))?;
                c.next();
                let n = c.next().ok_or_else(|| c.err("use needs a name".into()))?.to_string();
                c.expect("as")?;
                let pet = c.next().ok_or_else(|| c.err("use … as needs a petname".into()))?.to_string();
                m.uses.push((n, pet, line));
            }
            Some("describes") => {
                let m = out.as_mut().ok_or_else(|| c.err("`manifest` header must come first".into()))?;
                c.next();
                let s = c.next().ok_or_else(|| c.err("describes needs a subject".into()))?;
                m.describes = Some(match is_hash_word(s) {
                    Some(h) => SubjectAst::Hash(h),
                    None => SubjectAst::Name(s.into()),
                });
            }
            Some("label") => {
                let m = out.as_mut().ok_or_else(|| c.err("`manifest` header must come first".into()))?;
                c.next();
                let l = c.next().and_then(|t| is_string_tok(t).map(String::from));
                m.label = Some(l.ok_or_else(|| c.err("label needs a string".into()))?);
            }
            Some("edge") => {
                let m = out.as_mut().ok_or_else(|| c.err("`manifest` header must come first".into()))?;
                c.next();
                let subject = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let kind = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let object = parse_ref(c.next().ok_or_else(|| c.err("edge needs subject kind object".into()))?)
                    .map_err(|e| c.err(e))?;
                let attrs = parse_attrs(&mut c)?;
                m.edges.push(Item::Edge { subject, kind, object, attrs, line });
            }
            Some(_) => {
                // entry row: <field-ref> = <literal>
                let m = out.as_mut().ok_or_else(|| c.err("`manifest` header must come first".into()))?;
                let f = parse_ref(c.next().unwrap()).map_err(|e| c.err(e))?;
                c.expect("=")?;
                let lit = parse_lit(&mut c)?;
                if !c.done() {
                    return Err(c.err(format!("unexpected trailing tokens: {:?}", &toks[c.i..])));
                }
                m.entries.push((f, lit, line));
            }
            None => {}
        }
    }
    out.ok_or(ParseError { line: 1, msg: "missing `manifest <name> : <type>` header".into() })
}

/// Parse a `.ndfc` contract script.
pub fn parse_contract(src: &str) -> Result<ContractAst, ParseError> {
    let mut out: Option<ContractAst> = None;
    for (ln0, raw) in src.lines().enumerate() {
        let line = ln0 + 1;
        let stripped = strip_comment(raw).trim();
        if stripped.is_empty() {
            continue;
        }
        let toks = tokens(stripped).map_err(|msg| ParseError { line, msg })?;
        let mut c = Cur { toks: &toks, i: 0, line };
        match c.peek() {
            Some("contract") => {
                c.next();
                let n = c.next().ok_or_else(|| c.err("contract needs a name".into()))?.to_string();
                let doc = take_doc(&mut c);
                out = Some(ContractAst { name: n, doc, uses: Vec::new(), binds: Vec::new(), clauses: Vec::new() });
            }
            Some("use") => {
                let k = out.as_mut().ok_or_else(|| c.err("`contract` header must come first".into()))?;
                c.next();
                let n = c.next().ok_or_else(|| c.err("use needs a name".into()))?.to_string();
                c.expect("as")?;
                let pet = c.next().ok_or_else(|| c.err("use … as needs a petname".into()))?.to_string();
                k.uses.push((n, pet, line));
            }
            Some("binds") => {
                let k = out.as_mut().ok_or_else(|| c.err("`contract` header must come first".into()))?;
                c.next();
                let s = c.next().ok_or_else(|| c.err("binds needs a subject or prefix".into()))?;
                k.binds.push(match is_hash_word(s) {
                    Some(h) => SubjectAst::Hash(h),
                    None => SubjectAst::Name(s.into()),
                });
            }
            Some("intent") => {
                let k = out.as_mut().ok_or_else(|| c.err("`contract` header must come first".into()))?;
                c.next();
                let name = c.next().ok_or_else(|| c.err("intent needs a name".into()))?.to_string();
                let attrs = parse_attrs(&mut c)?;
                k.clauses.push(ClauseAst::IntentDecl { name, attrs, line });
            }
            Some(kw @ ("express" | "approximate")) => {
                let is_express = kw == "express";
                let k = out.as_mut().ok_or_else(|| c.err("`contract` header must come first".into()))?;
                c.next();
                let intent = c.next().ok_or_else(|| c.err("clause needs an intent name".into()))?.to_string();
                c.expect("->")?;
                let target = parse_ref(c.next().ok_or_else(|| c.err("clause needs a target term".into()))?)
                    .map_err(|e| c.err(e))?;
                let via = if c.peek() == Some("via") {
                    c.next();
                    let v = c.next().ok_or_else(|| c.err("via needs wasm:<hash> or native:<id>".into()))?;
                    Some(if let Some(rest) = v.strip_prefix("wasm:") {
                        ViaAst::Wasm(
                            is_hash_word(rest)
                                .ok_or_else(|| c.err("via wasm: needs a 64-hex hash".into()))?,
                        )
                    } else if let Some(rest) = v.strip_prefix("native:") {
                        ViaAst::Native(rest.into())
                    } else {
                        return Err(c.err(format!("via must be wasm:<hash> or native:<id>, got {v:?}")));
                    })
                } else {
                    None
                };
                let attrs = parse_attrs(&mut c)?;
                let clause = if is_express {
                    ClauseAst::Express { intent, target, via, attrs, line }
                } else {
                    ClauseAst::Approximate { intent, target, via, attrs, line }
                };
                k.clauses.push(clause);
            }
            Some("refuse") => {
                let k = out.as_mut().ok_or_else(|| c.err("`contract` header must come first".into()))?;
                c.next();
                let intent = c.next().ok_or_else(|| c.err("refuse needs an intent name".into()))?.to_string();
                k.clauses.push(ClauseAst::Refuse { intent, line });
            }
            other => return Err(c.err(format!("unexpected {other:?}"))),
        }
    }
    out.ok_or(ParseError { line: 1, msg: "missing `contract <name>` header".into() })
}

/// Parse any script by extension hint: "ndfs" | "ndfm" | "ndfc".
pub fn parse(src: &str, ext: &str) -> Result<Script, ParseError> {
    match ext {
        "ndfs" => parse_stratum(src).map(Script::Stratum),
        "ndfm" => parse_manifest(src).map(Script::Manifest),
        "ndfc" => parse_contract(src).map(Script::Contract),
        other => Err(ParseError { line: 0, msg: format!("unknown script extension {other:?}") }),
    }
}
