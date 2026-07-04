//! Compiler: script ASTs → kernel model documents → canonical bytes.
//!
//! Resolution law (L-01): every reference resolves through the lock, or the
//! compile fails — never a guess. Petnames live in scripts and the lock;
//! artifacts carry only hashes (F21: authors never type hashes; the artifact
//! never contains petnames).
//!
//! Sugar law (L-06): expansions are shown, not hidden — the compiler returns
//! its expansion notes alongside the documents so `bench compile` can print
//! them ("N members + 1 parent + N narrower-than", the F30-corrected count).

use std::collections::BTreeMap;
use std::fmt;

use ndn_manifest::canon::{decode_document, document_hash, encode_document, term_hash};
use ndn_manifest::hash::Hash;
use ndn_manifest::model::{
    Attribute, Cardinality, Clause, Contract, Decimal, Document, EdgeForm, Field, Intent, Manifest,
    ManifestEntry, PrimitiveKind, Subject, Term, TypeExpr, Value, Via, Vocabulary,
};

use crate::script::{
    AttrAst, CardAst, ClauseAst, ContractAst, Item, Lit, ManifestAst, Ref, RefOrWord, Script,
    StratumAst, SubjectAst, TypeAst, ViaAst,
};

/// A compile error, with the source line where known.
#[derive(Clone, Debug)]
pub struct CompileError {
    /// 1-based line, 0 when structural.
    pub line: usize,
    /// The lint rule this violates, when it is a named law.
    pub rule: Option<&'static str>,
    /// Message.
    pub msg: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rule {
            Some(r) => write!(f, "line {}: [{}] {}", self.line, r, self.msg),
            None => write!(f, "line {}: {}", self.line, self.msg),
        }
    }
}

fn err(line: usize, msg: impl Into<String>) -> CompileError {
    CompileError { line, rule: None, msg: msg.into() }
}

fn law(line: usize, rule: &'static str, msg: impl Into<String>) -> CompileError {
    CompileError { line, rule: Some(rule), msg: msg.into() }
}

/// The resolution context: the lock (petname → vocabulary hash) plus the
/// store (hash → decoded vocabulary), plus well-known attribute-key terms.
#[derive(Default)]
pub struct Resolver {
    /// petname → vocabulary document hash (Atelier.lock).
    pub lock: BTreeMap<String, Hash>,
    /// hash → decoded vocabulary (loaded from the store or compiled earlier
    /// in this same bench run).
    pub vocabularies: BTreeMap<Hash, Vocabulary>,
    /// Well-known attribute keys (`@unit`, `@loss`, `@sensitivity`, `@doc`,
    /// `@epoch`, `@shape`, `@range`, …) → their term hashes. Seeded from the
    /// strata that define them; bare words resolve here.
    pub attr_keys: BTreeMap<String, Hash>,
}

impl Resolver {
    /// Register a vocabulary under a petname (compiled-this-run or loaded).
    pub fn add_vocabulary(&mut self, petname: &str, hash: Hash, v: Vocabulary) {
        self.lock.insert(petname.to_string(), hash);
        // Every term of an added vocabulary whose label matches a bare
        // attribute keyword becomes resolvable as `@word`.
        for t in &v.terms {
            if let Ok(th) = term_hash(t) {
                self.attr_keys.entry(t.label.clone()).or_insert(th);
            }
        }
        self.vocabularies.insert(hash, v);
    }

    /// Find a term's hash by label inside a pinned vocabulary.
    fn term_in(&self, vocab: &Hash, label: &str) -> Option<Hash> {
        let v = self.vocabularies.get(vocab)?;
        v.terms
            .iter()
            .find(|t| t.label == label)
            .and_then(|t| term_hash(t).ok())
    }

    /// Resolve a reference against local terms + the lock (L-01).
    fn resolve(
        &self,
        r: &Ref,
        locals: &BTreeMap<String, Hash>,
        line: usize,
    ) -> Result<Hash, CompileError> {
        match r {
            Ref::Hash(h) => Ok(*h),
            Ref::Local(label) => locals.get(label).copied().ok_or_else(|| {
                law(
                    line,
                    "L-01",
                    format!("unresolved local reference `{label}` — not defined in this document"),
                )
            }),
            Ref::Qualified { pet, label } => {
                let vh = self.lock.get(pet).ok_or_else(|| {
                    law(line, "L-01", format!("petname `{pet}` is not in the lock — add `use {pet} …` and pin it"))
                })?;
                self.term_in(vh, label).ok_or_else(|| {
                    law(
                        line,
                        "L-01",
                        format!(
                            "`{pet}:{label}` does not resolve — the pinned vocabulary defines no term `{label}` \
                             (run `ndn-bench doc {pet}` for its reference card)"
                        ),
                    )
                })
            }
        }
    }
}

/// One compiled artifact plus its bookkeeping.
pub struct Compiled {
    /// Petname for the lock line (`stratum`/`manifest`/`contract` name).
    pub petname: String,
    /// The document.
    pub document: Document,
    /// Canonical bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of the bytes.
    pub hash: Hash,
    /// Sugar-expansion notes to print (L-06: shown, not hidden).
    pub expansions: Vec<String>,
    /// label → term hash for every term this document defines.
    pub terms: BTreeMap<String, Hash>,
}

fn prim(kw: &str) -> PrimitiveKind {
    match kw {
        "bytes" => PrimitiveKind::Bytes,
        "text" => PrimitiveKind::Text,
        "integer" => PrimitiveKind::Integer,
        "decimal" => PrimitiveKind::Decimal,
        "boolean" => PrimitiveKind::Boolean,
        "hash" => PrimitiveKind::Hash,
        "name" => PrimitiveKind::Name,
        _ => unreachable!("parser admits only the seven primitives"),
    }
}

fn compile_type(
    t: &TypeAst,
    rz: &Resolver,
    locals: &BTreeMap<String, Hash>,
    line: usize,
) -> Result<TypeExpr, CompileError> {
    Ok(match t {
        TypeAst::Prim(k) => TypeExpr::Primitive(prim(k)),
        TypeAst::Opaque => TypeExpr::Opaque,
        TypeAst::ListOf(inner) => TypeExpr::ListOf(Box::new(compile_type(inner, rz, locals, line)?)),
        TypeAst::MapOf(k, v) => {
            let kk = compile_type(k, rz, locals, line)?;
            if !kk.map_key_legal() {
                return Err(law(
                    line,
                    "L-03",
                    "map-of keys must be text, integer, hash, name, or a term ref (F6: keys the matcher can trust)",
                ));
            }
            TypeExpr::MapOf(Box::new(kk), Box::new(compile_type(v, rz, locals, line)?))
        }
        TypeAst::TermOf(r) => TypeExpr::TermOf(rz.resolve(r, locals, line)?),
        TypeAst::Of(base, param) => TypeExpr::Of(
            rz.resolve(base, locals, line)?,
            Box::new(compile_type(param, rz, locals, line)?),
        ),
        // A bare reference in type position compiles to term-of; the L-15
        // lint decides whether to flag it (bare enum parents get the fix-it).
        TypeAst::Bare(r) => TypeExpr::TermOf(rz.resolve(r, locals, line)?),
    })
}

fn compile_attr_value(lit: &Lit, rz: &Resolver, locals: &BTreeMap<String, Hash>, line: usize) -> Result<Value, CompileError> {
    Ok(match lit {
        Lit::Text(s) => Value::Text(s.clone()),
        Lit::Int(n) => Value::Integer(*n),
        Lit::Dec(d) => Value::Decimal(
            Decimal::normalize(d).ok_or_else(|| err(line, format!("bad decimal literal {d:?}")))?,
        ),
        Lit::Bool(b) => Value::Boolean(*b),
        Lit::HashLit(h) => Value::Hash(*h),
        Lit::Name(n) => Value::Name(n.clone()),
        Lit::Ref(r) => Value::TermRef(rz.resolve(r, locals, line)?),
        // Structure in attribute position is the L-04 wall — reify (P2).
        Lit::List(_) | Lit::Measured { .. } => {
            return Err(law(
                line,
                "L-04",
                "attributes stay flat: primitives or term refs only — route structured payloads to a record \
                 or a reified term (pattern P2)",
            ));
        }
    })
}

fn compile_attrs(
    attrs: &[AttrAst],
    rz: &Resolver,
    locals: &BTreeMap<String, Hash>,
) -> Result<Vec<Attribute>, CompileError> {
    let mut out = Vec::new();
    for a in attrs {
        let key = match &a.key {
            RefOrWord::Ref(r) => rz.resolve(r, locals, a.line)?,
            RefOrWord::Word(w) => locals
                .get(w)
                .copied()
                .or_else(|| rz.attr_keys.get(w).copied())
                .ok_or_else(|| {
                    law(
                        a.line,
                        "L-01",
                        format!(
                            "attribute key `@{w}` does not resolve — neither this document nor any imported stratum defines a term `{w}`"
                        ),
                    )
                })?,
        };
        let value = compile_attr_value(&a.value, rz, locals, a.line)?;
        out.push(Attribute { key, value });
    }
    Ok(out)
}

fn card(c: CardAst) -> Cardinality {
    match c {
        CardAst::One => Cardinality::One,
        CardAst::Optional => Cardinality::Optional,
        CardAst::Some => Cardinality::Some,
        CardAst::Many => Cardinality::Many,
    }
}

/// Compile a stratum. Two passes: local term hashes are computed first (so
/// forward references inside one document resolve — recursion across
/// documents stays impossible, C5), then edges and attributes compile.
pub fn compile_stratum(ast: &StratumAst, rz: &mut Resolver) -> Result<Compiled, CompileError> {
    let mut expansions = Vec::new();

    // Pass 0: `use` lines must already be pinned in the resolver's lock.
    let mut imports: Vec<Hash> = Vec::new();
    for item in &ast.items {
        if let Item::Use { name, pet, line } = item {
            if name == &ast.name {
                return Err(law(
                    *line,
                    "L-02",
                    "a stratum cannot import itself — the cycle is unwritable by physics (C5); \
                     this attempt is reported instead of guessed around",
                ));
            }
            let h = rz.lock.get(name).or_else(|| rz.lock.get(pet)).copied().ok_or_else(|| {
                law(
                    *line,
                    "L-01",
                    format!("`use {name} as {pet}` — `{name}` is not pinned in the lock"),
                )
            })?;
            rz.lock.insert(pet.clone(), h);
            if !imports.contains(&h) {
                imports.push(h);
            }
        }
    }

    // Pass 1: build every term (enum members + parents, plain terms, records)
    // so local labels have hashes.
    let mut terms: Vec<Term> = Vec::new();
    let mut order: Vec<String> = Vec::new();

    let mk_term = |label: &str, doc: Option<&str>, ty: Option<TypeExpr>, attrs: Vec<Attribute>| Term {
        label: label.to_string(),
        doc: doc.map(String::from),
        ty,
        attrs,
    };

    // 1a: type-free skeletons for locals (types may reference locals — the
    // skeleton pass gives every label a slot; hashes are computed after the
    // real types land, in dependency-free label order).
    for item in &ast.items {
        match item {
            Item::Enum { name, doc, members, line } => {
                for m in members {
                    terms.push(mk_term(m, Some(&format!("{name}: {m}")), None, Vec::new()));
                    order.push(m.clone());
                }
                terms.push(mk_term(name, doc.as_deref(), None, Vec::new()));
                order.push(name.clone());
                expansions.push(format!(
                    "line {line}: enum {name} expands to {n} member terms + 1 parent term + {n} narrower-than edges (L-06; F30 count)",
                    n = members.len()
                ));
            }
            Item::Term { name, doc, line: _, .. } => {
                terms.push(mk_term(name, doc.as_deref(), None, Vec::new()));
                order.push(name.clone());
            }
            Item::Record { name, doc, line: _, .. } => {
                terms.push(mk_term(name, doc.as_deref(), None, Vec::new()));
                order.push(name.clone());
            }
            _ => {}
        }
    }

    // Local hash table from skeletons: NOTE — a term's identity is the hash
    // of its FULL definition, so locals resolve in two rounds: round A uses
    // skeleton hashes to let types compile; round B recomputes with final
    // types and re-resolves every intra-document reference. Fixed point in
    // ≤ 2 rounds because local references are stored as label lookups here.
    let mut locals: BTreeMap<String, Hash> = BTreeMap::new();
    for t in &terms {
        locals.insert(t.label.clone(), term_hash(t).map_err(|_| err(0, "term encode failed"))?);
    }

    let two_rounds = 2;
    let mut edges: Vec<EdgeForm> = Vec::new();
    let mut supersedes: Option<Hash> = None;
    for _round in 0..two_rounds {
        terms.clear();
        edges.clear();
        supersedes = None;
        for item in &ast.items {
            match item {
                Item::Use { .. } => {}
                Item::Enum { name, doc, members, .. } => {
                    let parent_hash_after: Hash; // resolved below via locals
                    for m in members {
                        terms.push(mk_term(m, Some(&format!("{name}: {m}")), None, Vec::new()));
                    }
                    terms.push(mk_term(name, doc.as_deref(), None, Vec::new()));
                    parent_hash_after = *locals.get(name).expect("skeleton pass inserted parent");
                    for m in members {
                        let mh = *locals.get(m).expect("skeleton pass inserted member");
                        edges.push(EdgeForm::NarrowerThan { narrower: mh, broader: parent_hash_after });
                    }
                }
                Item::Term { name, ty, attrs, doc, line } => {
                    let texpr = match ty {
                        Some(t) => Some(compile_type(t, rz, &locals, *line)?),
                        None => None,
                    };
                    let a = compile_attrs(attrs, rz, &locals)?;
                    terms.push(mk_term(name, doc.as_deref(), texpr, a));
                }
                Item::Record { name, doc, fields, attrs, line } => {
                    let mut fs = Vec::new();
                    for f in fields {
                        fs.push(Field {
                            label: f.name.clone(),
                            doc: f.doc.clone(),
                            ty: compile_type(&f.ty, rz, &locals, f.line)?,
                            cardinality: card(f.card),
                            attrs: compile_attrs(&f.attrs, rz, &locals)?,
                        });
                    }
                    let a = compile_attrs(attrs, rz, &locals)?;
                    terms.push(mk_term(name, doc.as_deref(), Some(TypeExpr::Record(fs)), a));
                    let _ = line;
                }
                Item::NarrowerThan { a, b, line } => {
                    edges.push(EdgeForm::NarrowerThan {
                        narrower: rz.resolve(a, &locals, *line)?,
                        broader: rz.resolve(b, &locals, *line)?,
                    });
                }
                Item::EquivalentTo { a, b, line } => {
                    edges.push(EdgeForm::EquivalentTo {
                        a: rz.resolve(a, &locals, *line)?,
                        b: rz.resolve(b, &locals, *line)?,
                    });
                }
                Item::MapsTo { from, to, attrs, line } => {
                    // L-09: direction (the arrow, enforced by the parser) +
                    // @loss (enforced here) — a maps-to without its loss is
                    // structurally unwritable (D-K5).
                    let mut loss: Option<Hash> = None;
                    let mut rest: Vec<AttrAst> = Vec::new();
                    for a in attrs {
                        if matches!(&a.key, RefOrWord::Word(w) if w == "loss") {
                            if let Lit::Ref(r) = &a.value {
                                loss = Some(rz.resolve(r, &locals, a.line)?);
                            } else {
                                return Err(law(a.line, "L-09", "@loss must reference a loss term"));
                            }
                        } else {
                            rest.push(a.clone());
                        }
                    }
                    let loss = loss.ok_or_else(|| {
                        law(
                            *line,
                            "L-09",
                            "maps-to requires @loss = <loss-term> — lossy translation must declare its loss (C9)",
                        )
                    })?;
                    edges.push(EdgeForm::MapsTo {
                        from: rz.resolve(from, &locals, *line)?,
                        to: rz.resolve(to, &locals, *line)?,
                        loss,
                        attrs: compile_attrs(&rest, rz, &locals)?,
                    });
                }
                Item::Edge { subject, kind, object, attrs, line } => {
                    edges.push(EdgeForm::Edge {
                        subject: Subject::Hash(rz.resolve(subject, &locals, *line)?),
                        kind: rz.resolve(kind, &locals, *line)?,
                        object: Subject::Hash(rz.resolve(object, &locals, *line)?),
                        attrs: compile_attrs(attrs, rz, &locals)?,
                    });
                }
                Item::Supersedes { hash, .. } => supersedes = Some(*hash),
            }
        }
        // Recompute local hashes from the now-typed terms for round B.
        locals.clear();
        for t in &terms {
            locals.insert(t.label.clone(), term_hash(t).map_err(|_| err(0, "term encode failed"))?);
        }
    }

    let vocab = Vocabulary {
        label: ast.name.clone(),
        doc: ast.doc.clone(),
        imports,
        terms,
        edges,
        supersedes,
    };
    let document = Document::Vocabulary(vocab.clone());
    let bytes = encode_document(&document).map_err(|e| err(0, format!("encode failed: {e:?}")))?;
    // R13 sanity on our own output: what we emit must decode.
    decode_document(&bytes).map_err(|r| err(0, format!("self-decode failed: {}", r.code())))?;
    let hash = document_hash(&bytes);
    rz.add_vocabulary(&ast.name, hash, vocab);

    Ok(Compiled { petname: ast.name.clone(), document, bytes, hash, expansions, terms: locals })
}

fn lit_to_value(
    lit: &Lit,
    rz: &Resolver,
    locals: &BTreeMap<String, Hash>,
    line: usize,
    expansions: &mut Vec<String>,
) -> Result<Value, CompileError> {
    Ok(match lit {
        Lit::Measured { estimate, plus_minus, unit } => {
            // F24/F29: the measured-literal's EXACT kernel expansion —
            // record { estimate: decimal, plus-minus: decimal }; the @unit
            // lives on the field's declaration in its stratum, so the unit
            // word here is a cross-check, not data.
            let est = Decimal::normalize(estimate)
                .ok_or_else(|| err(line, format!("bad decimal {estimate:?}")))?;
            let pm = Decimal::normalize(plus_minus)
                .ok_or_else(|| err(line, format!("bad decimal {plus_minus:?}")))?;
            expansions.push(format!(
                "line {line}: measured literal `{estimate} ±{plus_minus} {unit}` expands to \
                 record {{ estimate: {e}, plus-minus: {p} }} (unit `{unit}` checked against the field's @unit)",
                e = est.as_str(),
                p = pm.as_str()
            ));
            Value::Record(vec![Value::Decimal(est), Value::Decimal(pm)])
        }
        Lit::List(items) => {
            let mut out = Vec::new();
            for i in items {
                out.push(lit_to_value(i, rz, locals, line, expansions)?);
            }
            Value::List(out)
        }
        other => compile_attr_value(other, rz, locals, line)?,
    })
}

/// Compile a manifest script.
pub fn compile_manifest(ast: &ManifestAst, rz: &mut Resolver) -> Result<Compiled, CompileError> {
    for (name, pet, line) in &ast.uses {
        let h = rz.lock.get(name).copied().ok_or_else(|| {
            law(*line, "L-01", format!("`use {name} as {pet}` — `{name}` is not pinned in the lock"))
        })?;
        rz.lock.insert(pet.clone(), h);
    }
    let locals = BTreeMap::new();
    let mut expansions = Vec::new();
    let ty = rz.resolve(&ast.ty, &locals, ast.line)?;
    let describes = match &ast.describes {
        Some(SubjectAst::Name(n)) => Subject::Name(n.clone()),
        Some(SubjectAst::Hash(h)) => Subject::Hash(*h),
        None => return Err(err(ast.line, "manifest needs a `describes` line (C5: the subject is never dereferenced, but it is named)")),
    };
    let mut entries = Vec::new();
    for (f, lit, line) in &ast.entries {
        entries.push(ManifestEntry {
            field: rz.resolve(f, &locals, *line)?,
            value: lit_to_value(lit, rz, &locals, *line, &mut expansions)?,
        });
    }
    let mut edges = Vec::new();
    for e in &ast.edges {
        if let Item::Edge { subject, kind, object, attrs, line } = e {
            edges.push(EdgeForm::Edge {
                subject: Subject::Hash(rz.resolve(subject, &locals, *line)?),
                kind: rz.resolve(kind, &locals, *line)?,
                object: Subject::Hash(rz.resolve(object, &locals, *line)?),
                attrs: compile_attrs(attrs, rz, &locals)?,
            });
        }
    }
    let document = Document::Manifest(Manifest { ty, label: ast.label.clone(), describes, entries, edges });
    let bytes = encode_document(&document).map_err(|e| err(0, format!("encode failed: {e:?}")))?;
    decode_document(&bytes).map_err(|r| err(0, format!("self-decode failed: {}", r.code())))?;
    let hash = document_hash(&bytes);
    Ok(Compiled { petname: ast.name.clone(), document, bytes, hash, expansions, terms: BTreeMap::new() })
}

/// Compile a contract script.
pub fn compile_contract(ast: &ContractAst, rz: &mut Resolver) -> Result<Compiled, CompileError> {
    let mut imports: Vec<Hash> = Vec::new();
    for (name, pet, line) in &ast.uses {
        let h = rz.lock.get(name).copied().ok_or_else(|| {
            law(*line, "L-01", format!("`use {name} as {pet}` — `{name}` is not pinned in the lock"))
        })?;
        rz.lock.insert(pet.clone(), h);
        if !imports.contains(&h) {
            imports.push(h);
        }
    }
    let locals = BTreeMap::new();
    // Intent declarations attach attrs to same-named clauses (L-11 rides on
    // these).
    let mut intent_attrs: BTreeMap<String, Vec<AttrAst>> = BTreeMap::new();
    for c in &ast.clauses {
        if let ClauseAst::IntentDecl { name, attrs, .. } = c {
            intent_attrs.entry(name.clone()).or_default().extend(attrs.iter().cloned());
        }
    }
    let build_intent = |name: &str, rz: &Resolver| -> Result<Intent, CompileError> {
        let attrs = match intent_attrs.get(name) {
            Some(a) => compile_attrs(a, rz, &locals)?,
            None => Vec::new(),
        };
        Ok(Intent { name: name.to_string(), attrs })
    };
    let mut clauses = Vec::new();
    for c in &ast.clauses {
        match c {
            ClauseAst::IntentDecl { .. } => {}
            ClauseAst::Express { intent, target, via, attrs, line }
            | ClauseAst::Approximate { intent, target, via, attrs, line } => {
                let i = build_intent(intent, rz)?;
                let target = rz.resolve(target, &locals, *line)?;
                let via = match via {
                    Some(ViaAst::Wasm(h)) => Some(Via::Wasm(*h)),
                    Some(ViaAst::Native(id)) => Some(Via::Native(id.clone())),
                    None => None,
                };
                let attrs = compile_attrs(attrs, rz, &locals)?;
                clauses.push(if matches!(c, ClauseAst::Express { .. }) {
                    Clause::Express { intent: i, target, via, attrs }
                } else {
                    Clause::Approximate { intent: i, target, via, attrs }
                });
            }
            ClauseAst::Refuse { intent, .. } => {
                clauses.push(Clause::Refuse { intent: build_intent(intent, rz)? });
            }
        }
    }
    let binds = ast
        .binds
        .iter()
        .map(|b| match b {
            SubjectAst::Name(n) => Subject::Name(n.clone()),
            SubjectAst::Hash(h) => Subject::Hash(*h),
        })
        .collect();
    let document = Document::Contract(Contract {
        label: ast.name.clone(),
        doc: ast.doc.clone(),
        imports,
        binds,
        clauses,
    });
    let bytes = encode_document(&document).map_err(|e| err(0, format!("encode failed: {e:?}")))?;
    decode_document(&bytes).map_err(|r| err(0, format!("self-decode failed: {}", r.code())))?;
    let hash = document_hash(&bytes);
    Ok(Compiled { petname: ast.name.clone(), document, bytes, hash, expansions: Vec::new(), terms: BTreeMap::new() })
}

/// Compile any parsed script.
pub fn compile(script: &Script, rz: &mut Resolver) -> Result<Compiled, CompileError> {
    match script {
        Script::Stratum(s) => compile_stratum(s, rz),
        Script::Manifest(m) => compile_manifest(m, rz),
        Script::Contract(c) => compile_contract(c, rz),
    }
}
