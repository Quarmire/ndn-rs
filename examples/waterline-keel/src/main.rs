//! waterline-keel — the Keel walked end to end, Riverwatch-shaped.
//!
//! One DAG holds: the kernel trio (V₀.2 · IM₀ · T₀), a raw LoRa frame's
//! implicit manifest (C3: everything is at least bytes), a hydro-observation
//! manifest, a vendor manifest nobody admitted, and one card contract. One
//! match call renders all four verdicts:
//!
//!   Express      — the card expresses value.latest over the observation
//!   Approximate  — series.window reaches the series term through a lossy hop
//!   Refuse       — route.avoid, declared (and everything unlisted, by default)
//!   Unresolved   — the vendor manifest's vocabulary is fetched but unadmitted
//!
//! And per the Sextant pattern ("runs are named data"), the run report is
//! emitted AS a manifest — canonical bytes on stdout, fetchable, citable.

use ndn_manifest::canon::{document_hash, encode_document};
use ndn_manifest::kernel::{derive_im0, fixed_point};
use ndn_manifest::model::{
    Clause, Contract, Document, EdgeForm, Intent, Manifest, ManifestEntry, Subject, Term, Value,
    Vocabulary,
};
use ndn_manifest::{term_hash, FrozenDag};
use ndn_render_contract::{r#match, select_best, Budget, Floor, TrustFrontier, Verdict};

fn term(label: &str, doc: &str) -> Term {
    Term { label: label.into(), doc: Some(doc.into()), ty: None, attrs: Vec::new() }
}

fn hex8(h: &[u8; 32]) -> String {
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // ── the DAG ──────────────────────────────────────────────────────────
    let mut dag = FrozenDag::new();

    // The kernel trio: the fixed point rides in every DAG (R14/D-49).
    let fp = fixed_point();
    dag.insert_bytes(&fp.im0_bytes).expect("IM₀ decodes");
    let t0 = dag.insert_bytes(&fp.t0_bytes).expect("T₀ decodes");

    // C3: a raw LoRa frame gets an implicit manifest for free — the total
    // floor. 42 bytes off the air at pylon-7, kind "data", no media-type.
    let lora = derive_im0("riverwatch/pylon-7/lora/0417", 42, None, "data");
    dag.insert_document(&Document::Manifest(lora)).expect("IM₀ manifest encodes");

    // A minimal hydro vocabulary, built as data (the scripted twin lives in
    // conformance/strata/hydro.ndfs).
    let obs = term("observation", "One signed hourly reading.");
    let series = term("series", "A time-ordered reading sequence.");
    let sparkline = term("sparkline", "A decimated visual series (24 points on the panel).");
    let stage_m = term("stage-m", "Water stage in metres against the declared datum.");
    let visual_only = term("visual-only", "Loss: only appearance survives; machine meaning is dropped.");
    let (obs_h, series_h, spark_h, stage_h, loss_h) = (
        term_hash(&obs).unwrap(),
        term_hash(&series).unwrap(),
        term_hash(&sparkline).unwrap(),
        term_hash(&stage_m).unwrap(),
        term_hash(&visual_only).unwrap(),
    );
    let hydro = dag
        .insert_document(&Document::Vocabulary(Vocabulary {
            label: "hydro-mini".into(),
            doc: Some("Riverwatch, the small end: observation → series losslessly; series → sparkline lossily.".into()),
            imports: Vec::new(),
            terms: vec![obs, series, sparkline, stage_m, visual_only],
            edges: vec![
                EdgeForm::NarrowerThan { narrower: obs_h, broader: series_h },
                EdgeForm::MapsTo { from: series_h, to: spark_h, loss: loss_h, attrs: Vec::new() },
            ],
            supersedes: None,
        }))
        .expect("hydro-mini encodes");

    // A vendor vocabulary that is FETCHED but will not be ADMITTED (C10).
    let vendor_obs = term("vendor-obs", "A vendor's private observation kind.");
    let vendor_obs_h = term_hash(&vendor_obs).unwrap();
    dag.insert_document(&Document::Vocabulary(Vocabulary {
        label: "vendorware".into(),
        doc: Some("Fetched, never admitted: for this consumer its terms answer Unresolved.".into()),
        imports: Vec::new(),
        terms: vec![vendor_obs],
        edges: Vec::new(),
        supersedes: None,
    }))
    .expect("vendorware encodes");

    // The signed fact: stage 4.16 m and rising — one manifest; everything
    // after this line is a lens on it.
    let observation = dag
        .insert_document(&Document::Manifest(Manifest {
            ty: obs_h,
            label: Some("obs 000482".into()),
            describes: Subject::Name("basin/rio-verde/gauge/pylon-7/obs/000482".into()),
            entries: vec![ManifestEntry {
                field: stage_h,
                value: Value::Decimal(ndn_manifest::model::Decimal::normalize("4.16").unwrap()),
            }],
            edges: Vec::new(),
        }))
        .expect("observation encodes");

    // A vendor manifest over the unadmitted vocabulary.
    dag.insert_document(&Document::Manifest(Manifest {
        ty: vendor_obs_h,
        label: None,
        describes: Subject::Name("vendor/cloud/feed/9".into()),
        entries: Vec::new(),
        edges: Vec::new(),
    }))
    .expect("vendor manifest encodes");

    // The card contract (riverwatch contract.card/2, miniature): expresses
    // value.latest, approximates series.window (declared lossy shape),
    // refuses route.avoid. Everything else: refused by absence.
    let card = dag
        .insert_document(&Document::Contract(Contract {
            label: "card".into(),
            doc: Some("The pocket lens: value with a quality badge; sparkline ≤ 24 pts; no maps.".into()),
            imports: vec![hydro],
            binds: vec![Subject::Name("basin/rio-verde/".into())],
            clauses: vec![
                Clause::Express {
                    intent: Intent { name: "value.latest".into(), attrs: Vec::new() },
                    target: obs_h,
                    via: None,
                    attrs: Vec::new(),
                },
                Clause::Express {
                    intent: Intent { name: "series.window".into(), attrs: Vec::new() },
                    target: spark_h,
                    via: None,
                    attrs: Vec::new(),
                },
                Clause::Refuse { intent: Intent { name: "route.avoid".into(), attrs: Vec::new() } },
            ],
        }))
        .expect("card encodes");

    // A viewer contract with NO binds, over the vendor term — the
    // Unresolved witness.
    let viewer = dag
        .insert_document(&Document::Contract(Contract {
            label: "viewer".into(),
            doc: Some("Offers over the vendor kind; its vocabulary is unadmitted.".into()),
            imports: Vec::new(),
            binds: Vec::new(),
            clauses: vec![Clause::Express {
                intent: Intent { name: "vendor.view".into(), attrs: Vec::new() },
                target: vendor_obs_h,
                via: None,
                attrs: Vec::new(),
            }],
        }))
        .expect("viewer encodes");

    // ── the match ────────────────────────────────────────────────────────
    // This consumer admits hydro-mini. It does NOT admit vendorware.
    let frontier = TrustFrontier::from_vocabularies([hydro]);
    let matches = r#match(&dag, &[card, viewer, t0], &frontier, Budget::generous())
        .expect("generous budget suffices");

    println!("── waterline-keel · pylon-7 · one DAG, four verdicts ──\n");
    let (mut n_e, mut n_a, mut n_r, mut n_u) = (0u64, 0u64, 0u64, 0u64);
    for m in &matches {
        let (tag, detail) = match &m.verdict {
            Verdict::Express => {
                n_e += 1;
                ("EXPRESS    ", String::new())
            }
            Verdict::Approximate(loss) => {
                n_a += 1;
                ("APPROXIMATE", format!(" · declared loss: {}", loss.0.iter().map(hex8).collect::<Vec<_>>().join(" → ")))
            }
            Verdict::Refuse => {
                n_r += 1;
                ("REFUSE     ", " · rerouted by the resolver, safely".into())
            }
            Verdict::Unresolved(miss) => {
                n_u += 1;
                ("UNRESOLVED ", format!(" · missing: {miss:?} — never a guess"))
            }
        };
        println!(
            "{tag} {:<14} contract {} over manifest {}{}",
            m.intent,
            hex8(&m.contract),
            hex8(&m.manifest),
            detail
        );
        if m.path.len() > 1 {
            println!("            path: {}", m.path.iter().map(hex8).collect::<Vec<_>>().join(" → "));
        }
    }

    // Selection under a floor: the best offer for series.window when the
    // consumer accepts approximation.
    let series_offers: Vec<_> = matches.iter().filter(|m| m.intent == "series.window").cloned().collect();
    if let Some(best) = select_best(series_offers, Floor::Approximate) {
        println!(
            "\nselection (floor: Approximate) → series.window via contract {} · {:?}",
            hex8(&best.contract),
            best.verdict
        );
    }
    println!(
        "\nnote: the raw LoRa frame's implicit manifest answers T₀'s raw.inspect/text.plain by identity — the total floor (C3): refusal is safe everywhere because THIS succeeds everywhere (observation manifest: {})",
        hex8(&observation)
    );

    // ── the run report, AS a manifest (the Sextant pattern) ─────────────
    let f_e = term("express-count", "Express verdicts in this run.");
    let f_a = term("approximate-count", "Approximate verdicts in this run.");
    let f_r = term("refuse-count", "Refuse verdicts in this run.");
    let f_u = term("unresolved-count", "Unresolved verdicts in this run.");
    let run = term("tool-run", "A named tool run (Sextant: runs are named data).");
    let (h_e, h_a, h_r, h_u, h_run) = (
        term_hash(&f_e).unwrap(),
        term_hash(&f_a).unwrap(),
        term_hash(&f_r).unwrap(),
        term_hash(&f_u).unwrap(),
        term_hash(&run).unwrap(),
    );
    // The sextant vocabulary rides along so the report is self-describing.
    let sextant = Document::Vocabulary(Vocabulary {
        label: "sextant-mini".into(),
        doc: Some("Verdict-count fields for keel demo runs.".into()),
        imports: Vec::new(),
        terms: vec![run, f_e, f_a, f_r, f_u],
        edges: Vec::new(),
        supersedes: None,
    });
    let report = Document::Manifest(Manifest {
        ty: h_run,
        label: Some("waterline-keel run".into()),
        describes: Subject::Name("waterline-keel/run/1".into()),
        entries: vec![
            ManifestEntry { field: h_e, value: Value::Integer(n_e) },
            ManifestEntry { field: h_a, value: Value::Integer(n_a) },
            ManifestEntry { field: h_r, value: Value::Integer(n_r) },
            ManifestEntry { field: h_u, value: Value::Integer(n_u) },
        ],
        edges: Vec::new(),
    });
    let sextant_bytes = encode_document(&sextant).expect("sextant encodes");
    let report_bytes = encode_document(&report).expect("report encodes");
    println!("\n── the run report is itself a manifest ──");
    println!("sextant-mini vocabulary · {} bytes · {}", sextant_bytes.len(), hex8(&document_hash(&sextant_bytes)));
    println!("run manifest            · {} bytes · {}", report_bytes.len(), hex8(&document_hash(&report_bytes)));
    println!("run manifest bytes: {}", report_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());

    // The demo's own gate: all four verdicts must have appeared.
    assert!(n_e >= 1 && n_a >= 1 && n_r >= 1 && n_u >= 1, "all four verdicts must appear");
    println!("\nall four verdicts rendered · zero conversions · nobody exported anything");
}
