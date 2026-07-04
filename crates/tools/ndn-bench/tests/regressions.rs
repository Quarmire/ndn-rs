//! Bench regressions — the round-5 gates as tests.
//!
//! The strata under test are the REAL corpus files (include_str! from
//! conformance/strata), so the gate and the shipped corpus cannot drift.

use ndn_bench::compile::{compile, Resolver};
use ndn_bench::lint::{self, Severity};
use ndn_bench::script::{self, Script};

const UNITS: &str = include_str!("../../../../conformance/strata/units.ndfs");
const LOSS: &str = include_str!("../../../../conformance/strata/loss.ndfs");
const EDGE_KINDS: &str = include_str!("../../../../conformance/strata/edge-kinds.ndfs");
const CONSTRAINTS: &str = include_str!("../../../../conformance/strata/constraints.ndfs");
const APIARY: &str = include_str!("../../../../conformance/strata/apiary.ndfs");

fn compile_stratum(src: &str, rz: &mut Resolver) -> (Script, ndn_bench::compile::Compiled) {
    let ast = script::parse(src, "ndfs").expect("parses");
    let compiled = compile(&ast, rz).expect("compiles");
    (ast, compiled)
}

/// M5 gate: `ndn-bench lint conformance/strata/apiary.ndfs` publishes
/// 0 err / 0 warn / 2 info — exactly one L-10 admission preview (the
/// maps-to) and one L-13 constraint routing (the @range).
#[test]
fn apiary_round5_regression_is_0_err_2_info() {
    let mut rz = Resolver::default();
    compile_stratum(UNITS, &mut rz);
    compile_stratum(LOSS, &mut rz);
    compile_stratum(EDGE_KINDS, &mut rz);
    compile_stratum(CONSTRAINTS, &mut rz);
    let (ast, compiled) = compile_stratum(APIARY, &mut rz);

    let mut diags = lint::lint(&ast, &compiled, &rz);
    diags.extend(lint::lint_document(&compiled));

    let errors: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Error).collect();
    let warns: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Warn).collect();
    let infos: Vec<_> = diags.iter().filter(|d| d.severity == Severity::Info).collect();
    assert!(errors.is_empty(), "apiary must publish clean, got {errors:?}");
    assert!(warns.is_empty(), "apiary must not warn, got {warns:?}");
    assert_eq!(infos.len(), 2, "the gate is exactly 2 infos, got {infos:?}");
    let rules: Vec<_> = infos.iter().map(|d| d.rule).collect();
    assert!(rules.contains(&"L-10"), "expected the maps-to admission preview");
    assert!(rules.contains(&"L-13"), "expected the @range constraint routing");

    // The expansion notes are shown, not hidden (L-06): two enums.
    assert_eq!(
        compiled.expansions.iter().filter(|e| e.contains("narrower-than")).count(),
        2,
        "queen-status and frame-content each print their F30 expansion"
    );
}

/// C8-19: the predicate smuggle is rejected at authoring (L-08).
#[test]
fn c8_19_predicate_smuggle_rejected() {
    let src = r#"stratum smuggle "Trying it on."
term filter-strong-colonies "Only colonies above a threshold."
"#;
    let mut rz = Resolver::default();
    let ast = script::parse(src, "ndfs").expect("parses");
    let compiled = compile(&ast, &mut rz).expect("compiles structurally");
    let diags = lint::lint(&ast, &compiled, &rz);
    assert!(
        diags.iter().any(|d| d.rule == "L-08" && d.severity == Severity::Error),
        "L-08 must reject the predicate, got {diags:?}"
    );
}

/// P2-04: structure in attribute position is a compile error (L-04).
#[test]
fn p2_04_nested_attribute_rejected() {
    let src = r#"stratum flat "Attributes stay flat."
term tags "The @tags key."
term photo : hash @tags = [ "queen" "brood" ] "Nested payload."
"#;
    let mut rz = Resolver::default();
    let ast = script::parse(src, "ndfs").expect("parses");
    let err = match compile(&ast, &mut rz) {
        Err(e) => e,
        Ok(_) => panic!("nested attribute must fail compile (L-04)"),
    };
    assert_eq!(err.rule, Some("L-04"), "got {err}");
}

/// The measured literal expands to the exact F24 record — and says so.
#[test]
fn measured_literal_expands_and_prints() {
    let mut rz = Resolver::default();
    // A tiny stratum with a weighable term so the manifest can reference it.
    let s = r#"stratum scale "Weights."
term weight "A weight reading."
"#;
    compile_stratum(s, &mut rz);
    let m = r#"manifest hive-a7 : scale:weight
use scale as scale
describes yard.north/hive-a7/scale
scale:weight = 41.2 ±0.3 kg
"#;
    let ast = script::parse(m, "ndfm").expect("parses");
    let compiled = compile(&ast, &mut rz).expect("compiles");
    assert!(
        compiled.expansions.iter().any(|e| e.contains("estimate") && e.contains("41.2")),
        "expansion must be shown (L-06 spirit), got {:?}",
        compiled.expansions
    );
}
