//! ndn-explain — human traces for matcher verdicts (the hash-soup antidote).
//!
//! A deliberately tiny tool-tier crate: `FrozenDag` in, `String` out. It
//! exists as its own crate (F54) because of a layering law worth stating
//! once: **spec crates carry law; tool crates carry convenience.** Law
//! changes by ratification; display strings change by taste — putting
//! presentation inside `ndn-render-contract` (even feature-gated) would put
//! wording under ratification discipline. And a simulator shouldn't have to
//! depend on the conformance bench to print a verdict. So: one micro-crate,
//! zero transitive deps, consumable from any workspace (C7's consumability
//! corollary).
//!
//! First-user finding (F53): the Match carries everything an audit needs —
//! verdict, hop path, loss terms, missing payload — but as hashes. This
//! crate renders it against the DAG the way the Keel says everything
//! should be rendered: resolve the labels, show the path, name the losses.
//! `"apiary:brood-pattern → apiary:colony-strength [loss:
//! ordinal-coarsening] ⇒ Approximate"` instead of eight hex digits.
//!
//! Presentation lives in the tool tier on purpose: the spec crates stay
//! label-blind (a matcher that needed labels would be a matcher that could
//! be lied to by labels).

use std::fmt::Write as _;

use ndn_manifest::dag::FrozenDag;
use ndn_manifest::hash::Hash;
use ndn_manifest::model::Document;
use ndn_render_contract::{Match, Missing, Verdict};

fn hex8(h: &Hash) -> String {
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Resolve a term hash to `vocab-label:term-label`, falling back to short
/// hex for anything the DAG cannot name (unfetched terms stay honest hex —
/// a label the DAG cannot vouch for would be a guess).
pub fn term_label(dag: &FrozenDag, h: &Hash) -> String {
    match dag.find_term(h) {
        Some((vh, term)) => {
            let vocab = match dag.get(&vh).map(|d| &d.doc) {
                Some(Document::Vocabulary(v)) => v.label.as_str(),
                _ => "?",
            };
            format!("{vocab}:{}", term.label)
        }
        None => format!("{}…", hex8(h)),
    }
}

/// A short human handle for a document hash: its label if it has one, its
/// describes-subject for manifests, short hex otherwise.
pub fn document_label(dag: &FrozenDag, h: &Hash) -> String {
    match dag.get(h).map(|d| &d.doc) {
        Some(Document::Contract(c)) => format!("contract \"{}\"", c.label),
        Some(Document::Vocabulary(v)) => format!("vocabulary \"{}\"", v.label),
        Some(Document::Manifest(m)) => match &m.label {
            Some(l) => format!("manifest \"{l}\""),
            None => format!("manifest {}…", hex8(h)),
        },
        None => format!("{}…", hex8(h)),
    }
}

/// Render one Match as a single human-auditable line.
pub fn trace(dag: &FrozenDag, m: &Match) -> String {
    let mut out = String::new();
    let _ = write!(out, "{} ⇒ ", m.intent);
    match &m.verdict {
        Verdict::Express => {
            let _ = write!(out, "Express");
        }
        Verdict::Approximate(loss) => {
            let _ = write!(out, "Approximate");
            if !loss.0.is_empty() {
                let names: Vec<String> = loss.0.iter().map(|l| term_label(dag, l)).collect();
                let _ = write!(out, " [loss: {}]", names.join(" · "));
            }
        }
        Verdict::Refuse => {
            let _ = write!(out, "Refuse (declared; unlisted intents refuse by absence)");
        }
        Verdict::Unresolved(miss) => {
            let _ = write!(out, "Unresolved — ");
            match miss {
                Missing::Vocabulary(v) => {
                    let _ = write!(out, "vocabulary {} fetched but not admitted", document_label(dag, v));
                }
                Missing::Term(t) => {
                    let _ = write!(out, "no inserted vocabulary defines term {}…", hex8(t));
                }
                Missing::Import(i) => {
                    let _ = write!(out, "import {}… absent from the DAG", hex8(i));
                }
                Missing::CriticalExtension => {
                    let _ = write!(out, "critical unknown TLV on the document (R12): something load-bearing is unreadable");
                }
            }
            let _ = write!(out, " — never a guess");
        }
    }
    if m.path.len() > 1 {
        let hops: Vec<String> = m.path.iter().map(|h| term_label(dag, h)).collect();
        let _ = write!(out, "\n    path: {}", hops.join(" → "));
    }
    let _ = write!(
        out,
        "\n    {} over {}",
        document_label(dag, &m.contract),
        document_label(dag, &m.manifest)
    );
    out
}

/// Render a whole match set, in the deterministic order it arrived.
pub fn trace_all(dag: &FrozenDag, matches: &[Match]) -> String {
    let mut out = String::new();
    for m in matches {
        let _ = writeln!(out, "{}", trace(dag, m));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_manifest::model::*;
    use ndn_manifest::term_hash;
    use ndn_render_contract::{r#match, Budget, TrustFrontier};

    fn term(label: &str, doc: &str) -> Term {
        Term { label: label.into(), doc: Some(doc.into()), ty: None, attrs: Vec::new() }
    }

    #[test]
    fn trace_names_the_loss_and_the_path() {
        let mut dag = FrozenDag::new();
        let (m, t, loss) = (
            term_hash(&term("fine", "d")).unwrap(),
            term_hash(&term("coarse", "d")).unwrap(),
            term_hash(&term("ordinal-coarsening", "d")).unwrap(),
        );
        let vh = dag
            .insert_document(&Document::Vocabulary(Vocabulary {
                label: "demo".into(),
                doc: None,
                imports: Vec::new(),
                terms: vec![
                    term("fine", "d"),
                    term("coarse", "d"),
                    term("ordinal-coarsening", "d"),
                ],
                edges: vec![EdgeForm::MapsTo { from: m, to: t, loss, attrs: Vec::new() }],
                supersedes: None,
            }))
            .unwrap();
        dag.insert_document(&Document::Manifest(Manifest {
            ty: m,
            label: Some("obs 1".into()),
            describes: Subject::Name("demo/subject".into()),
            entries: Vec::new(),
            edges: Vec::new(),
        }))
        .unwrap();
        let ch = dag
            .insert_document(&Document::Contract(Contract {
                label: "chart".into(),
                doc: None,
                imports: Vec::new(),
                binds: Vec::new(),
                clauses: vec![Clause::Express {
                    intent: Intent { name: "series.window".into(), attrs: Vec::new() },
                    target: t,
                    via: None,
                    attrs: Vec::new(),
                }],
            }))
            .unwrap();
        let frontier = TrustFrontier::from_vocabularies([vh]);
        let ms = r#match(&dag, &[ch], &frontier, Budget::generous()).unwrap();
        let line = trace(&dag, &ms[0]);
        assert!(line.contains("series.window ⇒ Approximate"), "{line}");
        assert!(line.contains("demo:ordinal-coarsening"), "loss must be named: {line}");
        assert!(line.contains("demo:fine → demo:coarse"), "path must be labeled: {line}");
        assert!(line.contains("contract \"chart\""), "{line}");
        assert!(line.contains("manifest \"obs 1\""), "{line}");
    }
}
