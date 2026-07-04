//! The lint bench: L-01…L-15 (ndf-the-atelier L-01…L-13; round 5 added L-14
//! and L-15). Severity ladder: Error blocks publish; Warn publishes with a
//! wound recorded; Info is the bench being a good colleague.
//!
//! L-01/L-02/L-03/L-04/L-09 fire in the compiler (resolution and structure
//! are compile facts); this module owns the rules that need the whole
//! artifact or its neighbors — and it re-checks the compiler's laws so a
//! lint-only run still names them.

use std::collections::BTreeSet;
use std::fmt;

use ndn_manifest::canon::term_hash;
use ndn_manifest::kernel;
use ndn_manifest::model::{Clause, EdgeForm, TypeExpr};

use crate::compile::{Compiled, Resolver};
use crate::script::{AttrAst, ClauseAst, ContractAst, Item, Lit, Ref, RefOrWord, Script, StratumAst, TypeAst};

/// Lint severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Bench courtesy.
    Info,
    /// Publishes, but recorded.
    Warn,
    /// Blocks publish.
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warn => write!(f, "warn"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// One diagnostic.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    /// The rule id (`L-01` … `L-15`).
    pub rule: &'static str,
    /// Severity.
    pub severity: Severity,
    /// 1-based line (0 when whole-document).
    pub line: usize,
    /// Message, with fix-it where the corpus prescribes one.
    pub msg: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] line {}: {}", self.severity, self.rule, self.line, self.msg)
    }
}

fn d(rule: &'static str, severity: Severity, line: usize, msg: impl Into<String>) -> Diagnostic {
    Diagnostic { rule, severity, line, msg: msg.into() }
}

/// Words whose presence in vocabulary position means someone is trying to
/// smuggle evaluation past the matcher (C8 / L-08; vector C8-19).
const PREDICATE_WORDS: [&str; 8] = ["where", "when", "filter", "if", "unless", "query", "select", "match-if"];

/// Intent name prefixes that must carry a sensitivity tag (L-11): actuation,
/// capture, payment, attention.
const SENSITIVE_INTENT_PREFIXES: [&str; 6] =
    ["actuate.", "capture.", "pay.", "payment.", "alarm.", "attention."];

/// Constraint-flavored attribute keys that route to the constraints stratum
/// (L-13; F32: emit the sidecar stub instead of shrugging).
const CONSTRAINT_KEYS: [&str; 5] = ["shape", "range", "min", "max", "step"];

/// Lint a stratum AST + its compiled artifact.
pub fn lint_stratum(ast: &StratumAst, compiled: &Compiled, rz: &Resolver) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let mut constraint_lines: Vec<(usize, String)> = Vec::new();

    // Collect enum parents (for L-15) and all defined labels.
    let mut enum_parents: BTreeSet<&str> = BTreeSet::new();
    for item in &ast.items {
        if let Item::Enum { name, .. } = item {
            enum_parents.insert(name);
        }
    }

    // L-08: predicate smuggling — scan labels, attr keys, and doc-free
    // structural positions for evaluation-shaped words.
    let check_predicate = |label: &str, line: usize, out: &mut Vec<Diagnostic>| {
        let l = label.to_ascii_lowercase();
        if PREDICATE_WORDS.iter().any(|w| l == *w || l.starts_with(&format!("{w}-")) || l.ends_with(&format!("-{w}"))) {
            out.push(d(
                "L-08",
                Severity::Error,
                line,
                format!(
                    "`{label}` smells like a predicate — evaluation never enters vocabulary or matching (C8); \
                     route selections to the selections stratum as declarative data, or computation to `via`"
                ),
            ));
        }
    };

    let check_attrs = |attrs: &[AttrAst], out: &mut Vec<Diagnostic>, constraints: &mut Vec<(usize, String)>| {
        for a in attrs {
            if let RefOrWord::Word(w) = &a.key {
                if CONSTRAINT_KEYS.contains(&w.as_str()) {
                    out.push(d(
                        "L-13",
                        Severity::Info,
                        a.line,
                        format!(
                            "@{w} is a constraint — the matcher never sees it (C8); routed to the constraints \
                             stratum (sidecar stub emitted)"
                        ),
                    ));
                    constraints.push((a.line, format!("@{w} = {:?}", a.value)));
                }
            }
            if let Lit::List(_) | Lit::Measured { .. } = a.value {
                out.push(d(
                    "L-04",
                    Severity::Error,
                    a.line,
                    "attributes stay flat: primitives or term refs only — reify structured payloads (P2)",
                ));
            }
        }
    };

    for item in &ast.items {
        match item {
            Item::Term { name, ty, attrs, doc, line } => {
                check_predicate(name, *line, &mut out);
                check_attrs(attrs, &mut out, &mut constraint_lines);
                // L-05: undocumented terms warn; undocumented PUBLIC terms
                // fail. Convention (documented in GRAMMAR.md): a leading `_`
                // marks a stratum-internal term.
                if doc.is_none() {
                    if name.starts_with('_') {
                        out.push(d("L-05", Severity::Warn, *line, format!("internal term `{name}` has no doc string")));
                    } else {
                        out.push(d(
                            "L-05",
                            Severity::Error,
                            *line,
                            format!("public term `{name}` has no doc string — self-description includes humans; \
                                     reference cards are a render of these strings"),
                        ));
                    }
                }
                // L-15: bare enum parent as a type — fix-it to term-of.
                if let Some(TypeAst::Bare(Ref::Local(l))) = ty {
                    if enum_parents.contains(l.as_str()) {
                        out.push(d(
                            "L-15",
                            Severity::Error,
                            *line,
                            format!("`{name} : {l}` uses the enum parent bare — fix-it: `{name} : term-of {l}` (F30)"),
                        ));
                    }
                }
            }
            Item::Record { name, doc, fields, attrs, line } => {
                check_predicate(name, *line, &mut out);
                check_attrs(attrs, &mut out, &mut constraint_lines);
                if doc.is_none() && !name.starts_with('_') {
                    out.push(d("L-05", Severity::Error, *line, format!("public term `{name}` has no doc string")));
                }
                for f in fields {
                    check_predicate(&f.name, f.line, &mut out);
                    check_attrs(&f.attrs, &mut out, &mut constraint_lines);
                    if let TypeAst::Bare(Ref::Local(l)) = &f.ty {
                        if enum_parents.contains(l.as_str()) {
                            out.push(d(
                                "L-15",
                                Severity::Error,
                                f.line,
                                format!("`{} : {l}` uses the enum parent bare — fix-it: `{} : term-of {l}` (F30)", f.name, f.name),
                            ));
                        }
                    }
                }
            }
            Item::Enum { name, doc, line, .. } => {
                check_predicate(name, *line, &mut out);
                if doc.is_none() {
                    out.push(d("L-05", Severity::Warn, *line, format!("enum `{name}` has no doc string")));
                }
            }
            Item::EquivalentTo { a, b, line } => {
                // L-09 (second half): equivalent-to across authors triggers a
                // "did you mean maps-to?" audit. Heuristic: both sides
                // qualified through DIFFERENT petnames = cross-author.
                if let (Ref::Qualified { pet: pa, .. }, Ref::Qualified { pet: pb, .. }) = (a, b) {
                    if pa != pb {
                        out.push(d(
                            "L-09",
                            Severity::Warn,
                            *line,
                            format!(
                                "equivalent-to across authors ({pa} vs {pb}) — did you mean maps-to with @loss? \
                                 lossless identification across authorship is audited (L-09)"
                            ),
                        ));
                    }
                }
            }
            Item::MapsTo { attrs, line, .. } => {
                // Compiler enforces @loss; here we surface the admission
                // preview alongside (L-10).
                let has_loss = attrs.iter().any(|a| matches!(&a.key, RefOrWord::Word(w) if w == "loss"));
                if !has_loss {
                    out.push(d("L-09", Severity::Error, *line, "maps-to requires @loss (C9)"));
                }
                out.push(admission_preview(*line, &ast.name));
            }
            Item::NarrowerThan { line, .. } => out.push(admission_preview(*line, &ast.name)),
            Item::Edge { kind, line, .. } => {
                if let Ref::Local(l) = kind {
                    check_predicate(l, *line, &mut out);
                }
            }
            Item::Supersedes { line, .. } => {
                out.push(d(
                    "L-07",
                    Severity::Info,
                    *line,
                    "supersedes recorded — this document versions its predecessor; in-place mutation does not exist",
                ));
            }
            Item::Use { .. } => {}
        }
    }

    // L-07 (detection half): same label as an already-pinned vocabulary but
    // different hash, with no supersedes line → the author is editing a
    // published document in place.
    if let Some(prev) = rz.lock.get(&ast.name) {
        if *prev != compiled.hash && !ast.items.iter().any(|i| matches!(i, Item::Supersedes { .. })) {
            let short: String = prev.iter().take(4).map(|b| format!("{b:02x}")).collect();
            out.push(d(
                "L-07",
                Severity::Error,
                0,
                format!(
                    "`{}` is already pinned at {short}… — editing published terms compiles to a NEW \
                     version plus a `supersedes` line; in-place mutation does not exist (L-07)",
                    ast.name
                ),
            ));
        }
    }

    out
}

fn admission_preview(line: usize, stratum: &str) -> Diagnostic {
    // L-10: the honest minimal preview — which consumers honor this edge is
    // a per-frontier fact (C10); without a bundle config the bench states
    // the law instead of inventing bundles.
    d(
        "L-10",
        Severity::Info,
        line,
        format!(
            "admission preview: this edge binds only for consumers whose trust frontier admits `{stratum}` (C10); \
             consumers who don't admit it will honestly diverge"
        ),
    )
}

/// Lint a contract AST + compiled artifact.
pub fn lint_contract(ast: &ContractAst, compiled: &Compiled) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    // Collect declared intents by clause kind.
    let mut offered: BTreeSet<&str> = BTreeSet::new();
    for c in &ast.clauses {
        match c {
            ClauseAst::Express { intent, .. } | ClauseAst::Approximate { intent, .. } => {
                offered.insert(intent.as_str());
            }
            _ => {}
        }
    }
    // Which intents carry attrs (for L-11)?
    let mut tagged: BTreeSet<&str> = BTreeSet::new();
    for c in &ast.clauses {
        if let ClauseAst::IntentDecl { name, attrs, .. } = c {
            if attrs.iter().any(|a| matches!(&a.key, RefOrWord::Word(w) if w == "sensitivity")
                || matches!(&a.key, RefOrWord::Ref(Ref::Qualified { label, .. }) if label == "sensitivity"))
            {
                tagged.insert(name.as_str());
            }
        }
    }
    for c in &ast.clauses {
        match c {
            ClauseAst::Express { intent, line, .. } | ClauseAst::Approximate { intent, line, .. } => {
                // L-11: actuation, capture, payment, attention intents must
                // carry a sensitivity tag.
                if SENSITIVE_INTENT_PREFIXES.iter().any(|p| intent.starts_with(p)) && !tagged.contains(intent.as_str())
                {
                    out.push(d(
                        "L-11",
                        Severity::Error,
                        *line,
                        format!(
                            "intent `{intent}` is actuation/capture/payment/attention-class and carries no \
                             sensitivity tag — add `intent {intent} @sensitivity = ui:high` (L-11)"
                        ),
                    ));
                }
            }
            ClauseAst::Refuse { intent, line } => {
                // L-14: explicit refuses are redundant with default-refuse —
                // info, kept as documentation (round 5, row 12).
                if !offered.contains(intent.as_str()) {
                    out.push(d(
                        "L-14",
                        Severity::Info,
                        *line,
                        format!("`refuse {intent}` is redundant — unlisted intents are refused by default; kept as documentation"),
                    ));
                }
            }
            ClauseAst::IntentDecl { .. } => {}
        }
    }
    let _ = compiled;
    out
}

/// L-12: the kernel triple re-emits byte-identical from its own script form
/// on every bench run — run this on EVERY bench invocation (cheap, ~three
/// documents), and let `freeze` own the pin comparison.
pub fn lint_kernel_reemission() -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let fp = kernel::fixed_point();
    // Re-emission: decode each artifact and confirm byte identity (the
    // decoder enforces R13 internally; failure here is a codec wound).
    for (which, bytes) in [("V₀.2", &fp.v0_bytes), ("IM₀", &fp.im0_bytes), ("T₀", &fp.t0_bytes)] {
        if ndn_manifest::canon::decode_document(bytes).is_err() {
            out.push(d(
                "L-12",
                Severity::Error,
                0,
                format!("{which} failed byte-identical re-emission — the kernel and the codec have diverged"),
            ));
        }
    }
    match kernel::verify_fixed_point() {
        kernel::FixedPointStatus::Verified => {}
        kernel::FixedPointStatus::Unpinned => {
            out.push(d(
                "L-12",
                Severity::Info,
                0,
                "fixed point UNPINNED — run `ndn-bench freeze --pin` on a real toolchain to pin H(V₀.2)/H(IM₀)/H(T₀) (R14, D-K8)",
            ));
        }
        kernel::FixedPointStatus::Mismatch { which, .. } => {
            out.push(d(
                "L-12",
                Severity::Error,
                0,
                format!("pinned {which} hash disagrees with the computed kernel — refuse to proceed (R14)"),
            ));
        }
    }
    out
}

/// Lint anything compiled; dispatches by script kind. The kernel
/// re-emission check (L-12) is GLOBAL — the CLI runs it once per
/// invocation, not per file, so per-file gate counts (e.g. apiary's
/// 0 err / 2 info) stay honest.
pub fn lint(script: &Script, compiled: &Compiled, rz: &Resolver) -> Vec<Diagnostic> {
    match script {
        Script::Stratum(s) => lint_stratum(s, compiled, rz),
        Script::Contract(c) => lint_contract(c, compiled),
        Script::Manifest(_) => Vec::new(),
    }
}

/// The constraints-stratum sidecar stub (L-13/F32): the bench emits the file
/// the author will need instead of shrugging.
pub fn constraints_stub(stratum: &str, entries: &[(usize, String)]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut s = String::new();
    s.push_str(&format!(
        "stratum {stratum}-constraints \"Validator-facing constraints for `{stratum}` — the matcher never sees these (C8/L-13).\"\n"
    ));
    s.push_str(&format!("use {stratum} as base\n\n"));
    for (line, entry) in entries {
        s.push_str(&format!("# from {stratum} line {line}: {entry}\n"));
    }
    s.push_str("# TODO: express each constraint as declarative data for the validators' stratum.\n");
    Some(s)
}

/// Sanity used by tests: is the compiled kernel's own vocabulary form
/// still 32 terms with docs (the freeze's shape)?
pub fn kernel_shape_ok() -> bool {
    let v = kernel::v0_2();
    v.terms.len() == 32 && v.terms.iter().all(|t| t.doc.is_some() && term_hash(t).is_ok())
}

/// Extract constraint sidecar entries from a stratum's diagnostics-adjacent
/// pass (re-scan; kept separate so `lint` stays read-only).
pub fn collect_constraints(ast: &StratumAst) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let scan = |attrs: &[AttrAst], out: &mut Vec<(usize, String)>| {
        for a in attrs {
            if let RefOrWord::Word(w) = &a.key {
                if CONSTRAINT_KEYS.contains(&w.as_str()) {
                    out.push((a.line, format!("@{w} = {:?}", a.value)));
                }
            }
        }
    };
    for item in &ast.items {
        match item {
            Item::Term { attrs, .. } => scan(attrs, &mut out),
            Item::Record { attrs, fields, .. } => {
                scan(attrs, &mut out);
                for f in fields {
                    scan(&f.attrs, &mut out);
                }
            }
            _ => {}
        }
    }
    out
}

/// Post-compile structural double-checks against the DOCUMENT (not the AST):
/// belt for the parser's suspenders. Returns L-04 errors for any nested
/// attribute that slipped through and L-09 for any maps-to whose loss slot
/// is somehow zeroed.
pub fn lint_document(compiled: &Compiled) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if let ndn_manifest::model::Document::Vocabulary(v) = &compiled.document {
        for t in &v.terms {
            for a in &t.attrs {
                if !a.value.is_attribute_legal() {
                    out.push(d("L-04", Severity::Error, 0, format!("term `{}` carries a structured attribute", t.label)));
                }
            }
            if let Some(TypeExpr::Record(fields)) = &t.ty {
                for f in fields {
                    for a in &f.attrs {
                        if !a.value.is_attribute_legal() {
                            out.push(d("L-04", Severity::Error, 0, format!("field `{}` carries a structured attribute", f.label)));
                        }
                    }
                }
            }
        }
        for e in &v.edges {
            if let EdgeForm::MapsTo { loss, .. } = e {
                if loss == &[0u8; 32] {
                    out.push(d("L-09", Severity::Error, 0, "maps-to with a zeroed loss slot"));
                }
            }
        }
    }
    if let ndn_manifest::model::Document::Contract(c) = &compiled.document {
        // Default-refuse restated: nothing here to do — unlisted intents
        // simply do not exist in the artifact. This loop exists to keep the
        // invariant visible in code review.
        for _clause in &c.clauses {
            if let Clause::Refuse { .. } = _clause { /* documentation, L-14 */ }
        }
    }
    out
}
