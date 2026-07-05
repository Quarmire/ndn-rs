//! Matcher conformance vectors — the named attacks, replayed as tests.
//!
//! C9-07 "the sword" (mixed chain ⇒ Approximate) · C9-08 "the launder"
//! (lossy-out, equivalent-back ⇒ never Express) · C10 divergence (one DAG,
//! two frontiers, two honest verdicts) · the decidability bomb, scaled
//! (ndf-the-gauntlet: "10-deep µ-groups × nested arity-1 instantiation × a
//! 50k-term subsumption DAG — reachability memoizes") · budget exhaustion is
//! typed, not a fifth verdict (D-K7).

use ndn_manifest::model::*;
use ndn_manifest::{term_hash, FrozenDag, Hash};
use ndn_render_contract::{
    r#match, select, select_best, select_best_for, Budget, BudgetExceeded, Floor, Match, Missing,
    TrustFrontier, Verdict,
};

fn term(label: &str) -> Term {
    Term { label: label.into(), doc: None, ty: None, attrs: Vec::new() }
}

fn th(label: &str) -> Hash {
    term_hash(&term(label)).unwrap()
}

fn vocab(label: &str, terms: Vec<Term>, edges: Vec<EdgeForm>) -> Document {
    Document::Vocabulary(Vocabulary {
        label: label.into(),
        doc: None,
        imports: Vec::new(),
        terms,
        edges,
        supersedes: None,
    })
}

fn manifest_of(ty: Hash, subject: &str) -> Document {
    Document::Manifest(Manifest {
        ty,
        label: None,
        describes: Subject::Name(subject.into()),
        entries: Vec::new(),
        edges: Vec::new(),
    })
}

fn express_contract(label: &str, intent: &str, target: Hash) -> Document {
    Document::Contract(Contract {
        label: label.into(),
        doc: None,
        imports: Vec::new(),
        binds: Vec::new(),
        clauses: vec![Clause::Express {
            intent: Intent { name: intent.into(), attrs: Vec::new() },
            target,
            via: None,
            attrs: Vec::new(),
        }],
    })
}

fn verdict_of<'a>(matches: &'a [Match], intent: &str) -> Option<&'a Verdict> {
    matches.iter().find(|m| m.intent == intent).map(|m| &m.verdict)
}

/// C9-07 — the sword: narrower · maps-to · narrower. One lossy hop anywhere
/// demotes the whole chain (fidelity = min over hops).
#[test]
fn c9_07_mixed_chain_is_approximate() {
    let mut dag = FrozenDag::new();
    let (m, a, b, t, loss) = (th("m"), th("a"), th("b"), th("t"), th("loss-ordinal"));
    let vh = dag
        .insert_document(&vocab(
            "sword",
            vec![term("m"), term("a"), term("b"), term("t"), term("loss-ordinal")],
            vec![
                EdgeForm::NarrowerThan { narrower: m, broader: a },
                EdgeForm::MapsTo { from: a, to: b, loss, attrs: Vec::new() },
                EdgeForm::NarrowerThan { narrower: b, broader: t },
            ],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "basin/pylon-7/obs")).unwrap();
    let ch = dag.insert_document(&express_contract("chart", "series.window", t)).unwrap();

    let frontier = TrustFrontier::from_vocabularies([vh]);
    let ms = r#match(&dag, &[ch], &frontier, Budget::generous()).unwrap();
    match verdict_of(&ms, "series.window").expect("reachable") {
        Verdict::Approximate(lp) => assert_eq!(lp.0, vec![loss]),
        v => panic!("sword must demote to Approximate, got {v:?}"),
    }
}

/// C9-08 — the launder: maps-to out, equivalent-to back. The lossless hop
/// after the lossy one must NOT restore Express — a crafted chain claiming
/// express past a lossy hop fails (gauntlet F8 vector).
#[test]
fn c9_08_launder_never_restores_express() {
    let mut dag = FrozenDag::new();
    let (m, x, t, loss) = (th("m"), th("x"), th("t"), th("loss-visual-only"));
    let vh = dag
        .insert_document(&vocab(
            "launder",
            vec![term("m"), term("x"), term("t"), term("loss-visual-only")],
            vec![
                EdgeForm::MapsTo { from: m, to: x, loss, attrs: Vec::new() },
                EdgeForm::EquivalentTo { a: x, b: t },
            ],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "basin/pylon-7/obs")).unwrap();
    let ch = dag.insert_document(&express_contract("card", "value.latest", t)).unwrap();

    let frontier = TrustFrontier::from_vocabularies([vh]);
    let ms = r#match(&dag, &[ch], &frontier, Budget::generous()).unwrap();
    match verdict_of(&ms, "value.latest").expect("reachable") {
        Verdict::Approximate(lp) => assert_eq!(lp.0, vec![loss]),
        Verdict::Express => panic!("laundered Express — C9 violated"),
        v => panic!("unexpected verdict {v:?}"),
    }
}

/// C10 — divergence: the same DAG, two frontiers, two honest answers. An
/// edge exists per-consumer; under bundle A it is simply not in the world.
#[test]
fn c10_frontier_divergence_is_rendered_honestly() {
    let mut dag = FrozenDag::new();
    let (m, t) = (th("m"), th("t"));
    let base = dag
        .insert_document(&vocab("base", vec![term("m"), term("t")], Vec::new()))
        .unwrap();
    // A third party publishes the bridging edge in its own vocabulary.
    let bridge = dag
        .insert_document(&vocab(
            "bridge",
            Vec::new(),
            vec![EdgeForm::NarrowerThan { narrower: m, broader: t }],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "acme/court/filing")).unwrap();
    let ch = dag.insert_document(&express_contract("viewer", "text.plain", t)).unwrap();

    // Bundle A: bridge NOT admitted — the edge does not exist for this
    // consumer; the clause is a plain mismatch (no Match, no verdict).
    let a = TrustFrontier::from_vocabularies([base]);
    let ms_a = r#match(&dag, &[ch], &a, Budget::generous()).unwrap();
    assert!(verdict_of(&ms_a, "text.plain").is_none(), "bundle A must see a mismatch");

    // Bundle B: bridge admitted — Express, with the walkable path.
    let b = TrustFrontier::from_vocabularies([base, bridge]);
    let ms_b = r#match(&dag, &[ch], &b, Budget::generous()).unwrap();
    assert_eq!(verdict_of(&ms_b, "text.plain"), Some(&Verdict::Express));
    let m_b = ms_b.iter().find(|m| m.intent == "text.plain").unwrap();
    assert_eq!(m_b.path, vec![m, t]);
}

/// Unadmitted ≠ unfetched ≠ mismatch: a manifest whose type term's defining
/// vocabulary is present but NOT admitted renders Unresolved — never a guess.
#[test]
fn unadmitted_defining_vocabulary_is_unresolved() {
    let mut dag = FrozenDag::new();
    let (m, t) = (th("m"), th("t"));
    let base = dag
        .insert_document(&vocab(
            "base",
            vec![term("m"), term("t")],
            vec![EdgeForm::NarrowerThan { narrower: m, broader: t }],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "s")).unwrap();
    let ch = dag.insert_document(&express_contract("c", "value.latest", t)).unwrap();

    let empty = TrustFrontier::new();
    let ms = r#match(&dag, &[ch], &empty, Budget::generous()).unwrap();
    assert_eq!(
        verdict_of(&ms, "value.latest"),
        Some(&Verdict::Unresolved(Missing::Vocabulary(base)))
    );
}

/// A manifest whose type term no inserted vocabulary defines: Unresolved
/// with the missing term named (C6′ — unfetched knowledge, not a mismatch).
#[test]
fn unfetched_term_is_unresolved() {
    let mut dag = FrozenDag::new();
    let ghost = th("ghost");
    let t = th("t");
    dag.insert_document(&vocab("base", vec![term("t")], Vec::new())).unwrap();
    dag.insert_document(&manifest_of(ghost, "s")).unwrap();
    let ch = dag.insert_document(&express_contract("c", "value.latest", t)).unwrap();
    let frontier = TrustFrontier::new();
    let ms = r#match(&dag, &[ch], &frontier, Budget::generous()).unwrap();
    assert_eq!(
        verdict_of(&ms, "value.latest"),
        Some(&Verdict::Unresolved(Missing::Term(ghost)))
    );
}

/// R12/W-19 downstream: a manifest carrying a critical unknown TLV renders
/// every offer over it Unresolved(CriticalExtension) — skipping load-bearing
/// bytes would be a guess.
#[test]
fn critical_extension_makes_matches_unresolved() {
    use ndn_manifest::canon::{encode_document, put_tlv};
    let mut dag = FrozenDag::new();
    let t = th("t");
    dag.insert_document(&vocab("base", vec![term("t")], Vec::new())).unwrap();
    let mut mbytes = encode_document(&manifest_of(t, "s")).unwrap();
    put_tlv(&mut mbytes, 0x81, &[0xde, 0xad]); // critical (odd) extension
    dag.insert_bytes(&mbytes).unwrap();
    let ch = dag.insert_document(&express_contract("c", "raw.inspect", t)).unwrap();
    let ms = r#match(&dag, &[ch], &TrustFrontier::new(), Budget::generous()).unwrap();
    assert_eq!(
        verdict_of(&ms, "raw.inspect"),
        Some(&Verdict::Unresolved(Missing::CriticalExtension))
    );
}

/// T₀ over IM₀ — the C3 total floor: identity match, zero edges consulted,
/// works under an EMPTY frontier. Refusal is safe everywhere else because
/// this succeeds everywhere.
#[test]
fn t0_expresses_over_every_im0_manifest() {
    use ndn_manifest::{derive_im0, fixed_point};
    let fp = fixed_point();
    let mut dag = FrozenDag::new();
    dag.insert_bytes(&fp.im0_bytes).unwrap();
    let t0h = dag.insert_bytes(&fp.t0_bytes).unwrap();
    let m = derive_im0("riverwatch/pylon-7/lora/0417", 42, None, "data");
    dag.insert_document(&Document::Manifest(m)).unwrap();

    let ms = r#match(&dag, &[t0h], &TrustFrontier::new(), Budget::generous()).unwrap();
    assert_eq!(verdict_of(&ms, "raw.inspect"), Some(&Verdict::Express));
    assert_eq!(verdict_of(&ms, "text.plain"), Some(&Verdict::Express));
}

/// binds is a subject filter (F45): hash exact, name prefix. Out-of-scope
/// manifests get nothing at all — a filter, not a verdict.
#[test]
fn binds_filters_by_subject_prefix() {
    let mut dag = FrozenDag::new();
    let t = th("t");
    dag.insert_document(&vocab("base", vec![term("t")], Vec::new())).unwrap();
    let north = dag.insert_document(&manifest_of(t, "yard.north/hive-a7/scale")).unwrap();
    let south = dag.insert_document(&manifest_of(t, "yard.south/hive-b1/scale")).unwrap();
    let mut c = express_contract("card", "value.latest", t);
    if let Document::Contract(ct) = &mut c {
        ct.binds.push(Subject::Name("yard.north/".into()));
    }
    let ch = dag.insert_document(&c).unwrap();
    let ms = r#match(&dag, &[ch], &TrustFrontier::new(), Budget::generous()).unwrap();
    assert!(ms.iter().any(|m| m.manifest == north));
    assert!(!ms.iter().any(|m| m.manifest == south));
}

/// Refuse clauses are emitted as documentation (L-14); unlisted intents are
/// refused by default — by absence, never inferred.
#[test]
fn refuse_clause_is_documented_and_absence_is_default_refuse() {
    let mut dag = FrozenDag::new();
    let t = th("t");
    dag.insert_document(&vocab("base", vec![term("t")], Vec::new())).unwrap();
    dag.insert_document(&manifest_of(t, "s")).unwrap();
    let c = Document::Contract(Contract {
        label: "panel".into(),
        doc: None,
        imports: Vec::new(),
        binds: Vec::new(),
        clauses: vec![
            Clause::Express {
                intent: Intent { name: "value.latest".into(), attrs: Vec::new() },
                target: t,
                via: None,
                attrs: Vec::new(),
            },
            // riverwatch contract.panel/1: route.avoid — no map; refused.
            Clause::Refuse { intent: Intent { name: "route.avoid".into(), attrs: Vec::new() } },
        ],
    });
    let ch = dag.insert_document(&c).unwrap();
    let ms = r#match(&dag, &[ch], &TrustFrontier::new(), Budget::generous()).unwrap();
    assert_eq!(verdict_of(&ms, "route.avoid"), Some(&Verdict::Refuse));
    // Unlisted intent: nothing to find — refused by absence.
    assert!(verdict_of(&ms, "map.overlay").is_none());
}

/// The bomb, scaled: a 5 000-term subsumption chain (one tenth of the
/// gauntlet's 50k, same shape) plus a 10-deep rec-group term in the same
/// vocabulary. Must complete under a bounded budget with a full walkable
/// path — and a starved budget must fail TYPED, not partially (D-K7).
#[test]
fn the_bomb_completes_under_budget_and_starves_typed() {
    const N: usize = 5_000;
    let mut terms: Vec<Term> = (0..N).map(|i| term(&format!("t{i}"))).collect();
    let hashes: Vec<Hash> = terms.iter().map(|t| term_hash(t).unwrap()).collect();
    let edges: Vec<EdgeForm> = (0..N - 1)
        .map(|i| EdgeForm::NarrowerThan { narrower: hashes[i], broader: hashes[i + 1] })
        .collect();
    // 10-deep µ-group nesting riding along in the same vocabulary — the
    // codec half of the bomb (instantiation stays document-bounded, C6).
    let mut deep = TypeExpr::Primitive(PrimitiveKind::Integer);
    for _ in 0..10 {
        deep = TypeExpr::RecGroup(vec![Term {
            label: "mu".into(),
            doc: None,
            ty: Some(TypeExpr::ListOf(Box::new(deep))),
            attrs: Vec::new(),
        }]);
    }
    terms.push(Term { label: "deep".into(), doc: None, ty: Some(deep), attrs: Vec::new() });

    let mut dag = FrozenDag::new();
    let vh = dag.insert_document(&vocab("bomb", terms, edges)).unwrap();
    dag.insert_document(&manifest_of(hashes[0], "bomb/subject")).unwrap();
    let ch = dag
        .insert_document(&express_contract("survivor", "value.latest", hashes[N - 1]))
        .unwrap();
    let frontier = TrustFrontier::from_vocabularies([vh]);

    // Generous budget: completes, Express, path spans the whole chain.
    let ms = r#match(&dag, &[ch], &frontier, Budget::generous()).unwrap();
    let m = ms.iter().find(|m| m.intent == "value.latest").expect("reached");
    assert_eq!(m.verdict, Verdict::Express);
    assert_eq!(m.path.len(), N);

    // Starved budget: typed exhaustion of the whole call — never a partial
    // answer wearing a verdict's clothes.
    let starved = Budget { max_nodes: 1_000_000, max_edges: 16 };
    assert_eq!(
        r#match(&dag, &[ch], &frontier, starved),
        Err(BudgetExceeded::Edges)
    );
    let starved = Budget { max_nodes: 4, max_edges: 1_000_000 };
    assert_eq!(
        r#match(&dag, &[ch], &frontier, starved),
        Err(BudgetExceeded::Nodes)
    );
}

/// F46's second and third keys, walked (F57: "the corner I lit up the
/// entrance to but didn't walk into"): two Approximate offers for ONE
/// intent must tiebreak on loss-path LENGTH; equal lengths fall to
/// contract-hash order — arbitrary but eternal.
#[test]
fn tiebreak_prefers_shorter_loss_path_then_contract_hash() {
    let mut dag = FrozenDag::new();
    let (m, u, x, y) = (th("m"), th("u"), th("x"), th("y"));
    let (l1, l2, l3) = (th("loss-one"), th("loss-two"), th("loss-three"));
    let vh = dag
        .insert_document(&vocab(
            "tie",
            vec![
                term("m"),
                term("u"),
                term("x"),
                term("y"),
                term("loss-one"),
                term("loss-two"),
                term("loss-three"),
            ],
            vec![
                // one-hop lossy route to u
                EdgeForm::MapsTo { from: m, to: u, loss: l1, attrs: Vec::new() },
                // two-hop lossy route to y
                EdgeForm::MapsTo { from: m, to: x, loss: l2, attrs: Vec::new() },
                EdgeForm::MapsTo { from: x, to: y, loss: l3, attrs: Vec::new() },
            ],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "s")).unwrap();
    // Two competing Approximate offers for the SAME intent, different loss
    // depths…
    let c_short = dag.insert_document(&express_contract("one-hop", "series.window", u)).unwrap();
    let c_long = dag.insert_document(&express_contract("two-hop", "series.window", y)).unwrap();
    // …and a third offer at the SAME depth as c_short (also targets u).
    let c_dup = dag.insert_document(&express_contract("one-hop-b", "series.window", u)).unwrap();

    let frontier = TrustFrontier::from_vocabularies([vh]);
    let ms = r#match(&dag, &[c_short, c_long, c_dup], &frontier, Budget::generous()).unwrap();

    // All three are Approximate — no Express exists, Floor::Express is None.
    assert!(select_best_for(&ms, "series.window", Floor::Express).is_none());

    // Second key: the 1-loss offers beat the 2-loss offer.
    let best = select_best_for(&ms, "series.window", Floor::Approximate).expect("offers exist");
    assert_eq!(best.verdict.loss_len(), 1, "shorter loss path wins the tiebreak");
    assert_ne!(best.contract, c_long);

    // Third key: between the two 1-loss offers, the smaller contract hash —
    // arbitrary, deterministic, eternal.
    let expected = if c_short <= c_dup { c_short } else { c_dup };
    assert_eq!(best.contract, expected, "equal depth falls to contract-hash order");

    // And the intent-scoping half of F57: a decoy intent with an Express
    // offer must NOT leak into series.window's selection.
    let c_decoy = dag.insert_document(&express_contract("decoy", "value.latest", m)).unwrap();
    let ms2 = r#match(&dag, &[c_short, c_long, c_dup, c_decoy], &frontier, Budget::generous())
        .unwrap();
    let best2 = select_best_for(&ms2, "series.window", Floor::Approximate).expect("offers exist");
    assert!(matches!(best2.verdict, Verdict::Approximate(_)), "decoy Express must not leak across intents");
}

/// Selection under a floor is deterministic (F46): verdict rank, loss-path
/// length, contract hash, intent name — and the floor actually floors.
#[test]
fn selection_floor_is_deterministic_and_floors() {
    let mut dag = FrozenDag::new();
    let (m, t, u, loss) = (th("m"), th("t"), th("u"), th("loss"));
    let vh = dag
        .insert_document(&vocab(
            "sel",
            vec![term("m"), term("t"), term("u"), term("loss")],
            vec![
                EdgeForm::NarrowerThan { narrower: m, broader: t },
                EdgeForm::MapsTo { from: m, to: u, loss, attrs: Vec::new() },
            ],
        ))
        .unwrap();
    dag.insert_document(&manifest_of(m, "s")).unwrap();
    let c_express = dag.insert_document(&express_contract("a", "value.latest", t)).unwrap();
    let c_approx = dag.insert_document(&express_contract("b", "value.latest", u)).unwrap();

    let frontier = TrustFrontier::from_vocabularies([vh]);
    let ms = r#match(&dag, &[c_express, c_approx], &frontier, Budget::generous()).unwrap();

    // Approximate floor admits both; Express sorts first.
    let sel = select(ms.clone(), Floor::Approximate);
    assert_eq!(sel.len(), 2);
    assert_eq!(sel[0].verdict, Verdict::Express);
    // Express floor filters the approximate away.
    let best = select_best(ms, Floor::Express).expect("an express match exists");
    assert_eq!(best.verdict, Verdict::Express);
    assert_eq!(best.contract, c_express);
}
