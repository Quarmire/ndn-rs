//! End-to-end regression test against a real, upstream-compiled LVS binary.
//!
//! The fixture in `tests/fixtures/lvs_ndnd_test_model.tlv` is the
//! `TEST_MODEL` byte array embedded in
//! `std/security/trust_schema/lvs_test.go` at
//! <https://github.com/named-data/ndnd/blob/main/std/security/trust_schema/lvs_test.go>
//! — i.e. a python-ndn-compiled LVS binary that the ndnd project uses as
//! its own test vector. It compiles from this LVS source (also copied
//! verbatim from the Go file's leading comment):
//!
//! ```text
//! #site: "a"/"blog"
//! #root: #site/#KEY
//! #article: #site/"article"/category/year/month <= #author
//! #author: #site/role/author/#KEY & { role: "author" } <= #admin
//! #admin: #site/"admin"/admin/#KEY <= #root
//! #KEY: "KEY"/_/_/_
//! ```
//!
//! The assertions below are ported one-for-one from ndnd's
//! `TestModelSimpleCheck`. If ndn-rs's LVS parser and checker are
//! wire-compatible with python-ndn's compiler output and ndnd's checker,
//! every `allows(data, key)` outcome must match what ndnd asserts on the
//! identical byte sequence.
//!
//! Tracks #9. If this test fails after an upstream LVS binary-format bump,
//! re-pull the fixture from ndnd `main` and update `LVS_VERSION` in
//! `src/lvs.rs` accordingly.

use bytes::Bytes;
use ndn_security::TrustSchema;
use ndn_packet::{Name, NameComponent};

const NDND_TEST_MODEL: &[u8] = include_bytes!("fixtures/lvs_ndnd_test_model.tlv");

fn comp(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

fn name(parts: &[&str]) -> Name {
    Name::from_components(parts.iter().map(|p| comp(p)))
}

/// Loads the ndnd-upstream test model and confirms it parses cleanly.
#[test]
fn loads_upstream_ndnd_test_model() {
    let schema = TrustSchema::from_lvs_binary(NDND_TEST_MODEL)
        .expect("upstream ndnd LVS fixture should parse");
    let model = schema.lvs_model().expect("lvs_model is Some");
    // ndnd's TEST_MODEL has six rule names and 0x17 + 1 = 24 nodes after
    // compilation. Rather than pinning the exact node count (which the
    // compiler is free to change), just assert the sanity bounds: nonempty,
    // start_id in range, no user functions used.
    assert!(!model.nodes.is_empty(), "model has nodes");
    assert!((model.start_id as usize) < model.nodes.len());
    assert!(
        !model.uses_user_functions(),
        "simple test model does not use user functions"
    );
}

/// Reproduces ndnd's `TestModelSimpleCheck` assertions verbatim. If any of
/// these diverge from the Go test, either ndn-rs's parser is wrong or the
/// LVS binary format has drifted — either way, it's the thing to fix.
///
/// ndnd source:
/// `std/security/trust_schema/lvs_test.go::TestModelSimpleCheck`.
#[test]
fn check_matches_ndnd_assertions() {
    let schema = TrustSchema::from_lvs_binary(NDND_TEST_MODEL).unwrap();

    // ── True cases ────────────────────────────────────────────────────────

    // admin Data signed by site-level root key.
    assert!(
        schema.allows(
            &name(&["a", "blog", "admin", "000001", "KEY", "1", "root", "1"]),
            &name(&["a", "blog", "KEY", "1", "self", "1"]),
        ),
        "admin data should be signed by root"
    );

    // author Data signed by admin key.
    assert!(
        schema.allows(
            &name(&["a", "blog", "author", "100001", "KEY", "1", "000001", "1"]),
            &name(&["a", "blog", "admin", "000001", "KEY", "1", "root", "1"]),
        ),
        "author data should be signed by admin"
    );

    // ── False cases ───────────────────────────────────────────────────────

    // "VAL" is not "KEY" — the #KEY rule literal doesn't match, so the
    // data name never reaches a valid node.
    assert!(
        !schema.allows(
            &name(&["a", "blog", "admin", "000001", "VAL", "1", "root", "1"]),
            &name(&["a", "blog", "KEY", "1", "self", "1"]),
        ),
        "non-KEY component must not match #KEY rule"
    );

    // admin may not sign another admin — #admin's sign constraint is #root,
    // not #admin.
    assert!(
        !schema.allows(
            &name(&["a", "blog", "admin", "000002", "KEY", "1", "root", "1"]),
            &name(&["a", "blog", "admin", "000001", "KEY", "1", "root", "1"]),
        ),
        "admin cannot be signed by another admin"
    );

    // author may not be signed by root directly — #author's sign constraint
    // is #admin, so the root key at site-level is the wrong signing node.
    assert!(
        !schema.allows(
            &name(&["a", "blog", "author", "100001", "KEY", "1", "000001", "1"]),
            &name(&["a", "blog", "KEY", "1", "self", "1"]),
        ),
        "author cannot be signed by root"
    );
}
