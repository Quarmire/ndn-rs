//! `bench doc` — reference cards rendered from the artifact itself.
//!
//! Round 5, wall 2: petnames shipped, inventories didn't — four of the
//! stranger's twelve questions were one wound. The fix was already built:
//! L-05 made doc strings load-bearing data, so a reference card is a
//! *render*, not a writing project (F28). This module is that render.

use std::fmt::Write as _;

use ndn_manifest::canon::term_hash;
use ndn_manifest::model::{Cardinality, Field, PrimitiveKind, Term, TypeExpr, Vocabulary};

fn prim_name(p: PrimitiveKind) -> &'static str {
    match p {
        PrimitiveKind::Bytes => "bytes",
        PrimitiveKind::Text => "text",
        PrimitiveKind::Integer => "integer",
        PrimitiveKind::Decimal => "decimal",
        PrimitiveKind::Boolean => "boolean",
        PrimitiveKind::Hash => "hash",
        PrimitiveKind::Name => "name",
    }
}

fn short(h: &[u8; 32]) -> String {
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn type_pretty(t: &TypeExpr) -> String {
    match t {
        TypeExpr::Primitive(p) => prim_name(*p).to_string(),
        TypeExpr::Opaque => "opaque".into(),
        TypeExpr::ListOf(i) => format!("list-of({})", type_pretty(i)),
        TypeExpr::MapOf(k, v) => format!("map-of({}, {})", type_pretty(k), type_pretty(v)),
        TypeExpr::TermOf(h) => format!("term-of {}…", short(h)),
        TypeExpr::Of(base, p) => format!("{}…({})", short(base), type_pretty(p)),
        TypeExpr::Record(fs) => format!("record {{ {} field{} }}", fs.len(), if fs.len() == 1 { "" } else { "s" }),
        TypeExpr::RecGroup(ts) => format!("rec-group {{ {} term{} }}", ts.len(), if ts.len() == 1 { "" } else { "s" }),
        TypeExpr::GroupRef(i) => format!("µ{i}"),
    }
}

fn card_pretty(c: Cardinality) -> &'static str {
    match c {
        Cardinality::One => "",
        Cardinality::Optional => " · optional",
        Cardinality::Some => " · some (≥1)",
        Cardinality::Many => " · many",
    }
}

fn render_field(out: &mut String, f: &Field) {
    let _ = write!(out, "    {} : {}{}", f.label, type_pretty(&f.ty), card_pretty(f.cardinality));
    if !f.attrs.is_empty() {
        let _ = write!(out, "  [{} attr{}]", f.attrs.len(), if f.attrs.len() == 1 { "" } else { "s" });
    }
    let _ = writeln!(out);
    if let Some(doc) = &f.doc {
        let _ = writeln!(out, "        {doc}");
    }
}

fn render_term(out: &mut String, t: &Term) {
    let h = term_hash(t).map(|h| short(&h)).unwrap_or_else(|_| "????????".into());
    let _ = write!(out, "  {}  {}", h, t.label);
    if let Some(ty) = &t.ty {
        let _ = write!(out, " : {}", type_pretty(ty));
    }
    let _ = writeln!(out);
    match &t.doc {
        Some(doc) => {
            let _ = writeln!(out, "      {doc}");
        }
        None => {
            let _ = writeln!(out, "      (no doc string — L-05 wound)");
        }
    }
    if let Some(TypeExpr::Record(fields)) = &t.ty {
        for f in fields {
            render_field(out, f);
        }
    }
    if !t.attrs.is_empty() {
        let _ = writeln!(out, "      attrs: {}", t.attrs.len());
    }
}

/// Render a vocabulary's reference card.
pub fn card(v: &Vocabulary, doc_hash_short: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "── {} · {} term{} · {} ─────", v.label, v.terms.len(), if v.terms.len() == 1 { "" } else { "s" }, doc_hash_short);
    if let Some(doc) = &v.doc {
        let _ = writeln!(out, "{doc}");
    }
    if !v.imports.is_empty() {
        let _ = writeln!(out, "imports: {}", v.imports.iter().map(short).collect::<Vec<_>>().join(", "));
    }
    let _ = writeln!(out);
    for t in &v.terms {
        render_term(&mut out, t);
    }
    if !v.edges.is_empty() {
        let _ = writeln!(out, "\nedges: {}", v.edges.len());
    }
    if let Some(s) = &v.supersedes {
        let _ = writeln!(out, "supersedes: {}…", short(s));
    }
    out
}
