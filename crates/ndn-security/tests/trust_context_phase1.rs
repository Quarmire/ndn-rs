//! Phase 1 witnesses for the SignedTrustContext keyring model.
//!
//! Backs `testbed/tests/audit/ctx02a_*.sh` and `ctx02b_*.sh`. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §15–§16.
//!
//! These exercise per-namespace validation dispatch (a node holding several
//! trust contexts validates each packet only against the context selected by
//! its name) and the hierarchical authorization floor (a cert under a context
//! anchor cannot sign outside its own subtree — the skeleton-key fix,
//! NFD #2856).

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{
    EnrollmentHint, SchemaBlob, SchemaFormat, SecurityManager, SignedTrustContext, TrustSchema,
    ValidationResult, Validator,
};

/// A real python-ndn-compiled LVS binary (ndnd's `TEST_MODEL`); see
/// `lvs_upstream_fixture.rs`. Used to prove the schema blob round-trips as
/// stock LVS bytes.
const NDND_LVS_MODEL: &[u8] = include_bytes!("fixtures/lvs_ndnd_test_model.tlv");

const ONE_YEAR_MS: u64 = 365 * 24 * 3600 * 1_000;

fn n(s: &str) -> Name {
    s.parse().expect("valid NDN name")
}

/// Self-signed anchor under `key_name`; returns the anchor certificate.
fn make_anchor(mgr: &SecurityManager, key_name: &Name) -> ndn_security::Certificate {
    mgr.generate_ed25519(key_name.clone()).unwrap();
    let pk = mgr.get_signer_sync(key_name).unwrap().public_key().unwrap();
    mgr.issue_self_signed(key_name, pk, u64::MAX).unwrap()
}

/// Leaf key `key_name` certified by `issuer_key`. Cert lands in the manager's
/// shared cert cache so chain walks can resolve it.
async fn make_leaf(mgr: &SecurityManager, key_name: &Name, issuer_key: &Name) {
    mgr.generate_ed25519(key_name.clone()).unwrap();
    let pk = mgr.get_signer_sync(key_name).unwrap().public_key().unwrap();
    mgr.certify(key_name, pk, issuer_key, ONE_YEAR_MS)
        .await
        .unwrap();
}

/// Sign `data_name` with the key registered under `key_name`.
fn sign_with(mgr: &SecurityManager, data_name: &str, key_name: &Name) -> Data {
    let signer = mgr.get_signer_sync(key_name).unwrap();
    let wire = DataBuilder::new(data_name, b"payload").sign_sync(
        signer.sig_type(),
        Some(key_name),
        |region| signer.sign_sync(region).unwrap_or_default(),
    );
    Data::decode(wire).unwrap()
}

/// A validator sharing `mgr`'s cert cache, with no ambient anchors — every
/// anchor lives on an adopted named context.
fn validator_over(mgr: &SecurityManager) -> Validator {
    Validator::with_chain(
        TrustSchema::hierarchical(),
        mgr.cert_cache_arc(),
        Arc::new(DashMap::new()),
        None,
        5,
    )
}

fn hier_context(namespace: &str, anchor: ndn_security::Certificate) -> Arc<SignedTrustContext> {
    let ctx = Arc::new(SignedTrustContext::hierarchical(n(namespace)));
    ctx.add_anchor(anchor);
    ctx
}

/// CTX.02 (positive): one node holds `/home/bob` and `/work/acme` at once and
/// validates Data under each by its own context.
#[tokio::test]
async fn ctx02_multi_context_keyring_validates_each() {
    let mgr = SecurityManager::new();

    let bob_root = n("/home/bob/KEY/root");
    let bob_anchor = make_anchor(&mgr, &bob_root);
    let bob_leaf = n("/home/bob/alice/KEY/k1");
    make_leaf(&mgr, &bob_leaf, &bob_root).await;

    let acme_root = n("/work/acme/KEY/root");
    let acme_anchor = make_anchor(&mgr, &acme_root);
    let acme_leaf = n("/work/acme/svc/KEY/k1");
    make_leaf(&mgr, &acme_leaf, &acme_root).await;

    let validator = validator_over(&mgr);
    validator.adopt_context(hier_context("/home/bob", bob_anchor));
    validator.adopt_context(hier_context("/work/acme", acme_anchor));

    let bob_data = sign_with(&mgr, "/home/bob/alice/doc", &bob_leaf);
    assert!(
        matches!(
            validator.validate_chain(&bob_data).await,
            ValidationResult::Valid(_)
        ),
        "Bob's data must validate under the /home/bob context"
    );

    let acme_data = sign_with(&mgr, "/work/acme/svc/report", &acme_leaf);
    assert!(
        matches!(
            validator.validate_chain(&acme_data).await,
            ValidationResult::Valid(_)
        ),
        "Acme's data must validate under the /work/acme context"
    );
}

/// CTX.02a: `/home/bob` Data signed by a `/work` key is rejected — the `/work`
/// anchor is not in the `/home/bob` context, and the name namespaces differ.
#[tokio::test]
async fn ctx02a_cross_namespace_forgery_rejected() {
    let mgr = SecurityManager::new();

    let bob_root = n("/home/bob/KEY/root");
    let bob_anchor = make_anchor(&mgr, &bob_root);

    let acme_root = n("/work/acme/KEY/root");
    let acme_anchor = make_anchor(&mgr, &acme_root);
    let acme_leaf = n("/work/acme/eve/KEY/k1");
    make_leaf(&mgr, &acme_leaf, &acme_root).await;

    let validator = validator_over(&mgr);
    validator.adopt_context(hier_context("/home/bob", bob_anchor));
    validator.adopt_context(hier_context("/work/acme", acme_anchor));

    // Eve (a legitimate /work/acme signer) forges a /home/bob name.
    let forged = sign_with(&mgr, "/home/bob/secret", &acme_leaf);
    match validator.validate_chain(&forged).await {
        ValidationResult::Valid(_) => {
            panic!("cross-namespace forgery accepted — per-namespace dispatch failed")
        }
        ValidationResult::Invalid(_) | ValidationResult::Pending => {}
    }

    // Eve signing within her own namespace still works.
    let legit = sign_with(&mgr, "/work/acme/eve/doc", &acme_leaf);
    assert!(
        matches!(
            validator.validate_chain(&legit).await,
            ValidationResult::Valid(_)
        ),
        "Eve's own-namespace data must still validate"
    );
}

/// CTX.02b (positive): a leaf key may sign anywhere in its own subtree.
#[tokio::test]
async fn ctx02b_hierarchical_floor_allows_own_subtree() {
    let mgr = SecurityManager::new();
    let bob_root = n("/home/bob/KEY/root");
    let bob_anchor = make_anchor(&mgr, &bob_root);
    let alice = n("/home/bob/alice/KEY/k1");
    make_leaf(&mgr, &alice, &bob_root).await;

    let validator = validator_over(&mgr);
    validator.adopt_context(hier_context("/home/bob", bob_anchor));

    for name in ["/home/bob/alice/doc", "/home/bob/alice/photos/2026/may"] {
        let data = sign_with(&mgr, name, &alice);
        assert!(
            matches!(
                validator.validate_chain(&data).await,
                ValidationResult::Valid(_)
            ),
            "{name} is in alice's subtree and must validate"
        );
    }
}

/// CTX.02b (skeleton-key): a cert valid under the context anchor cannot sign
/// *outside its own subtree*, even with the context adopted. The
/// `keyLocator.isPrefixOf(name)` floor rejects it.
#[tokio::test]
async fn ctx02b_skeleton_key_no_sign_outside_subtree() {
    let mgr = SecurityManager::new();
    let bob_root = n("/home/bob/KEY/root");
    let bob_anchor = make_anchor(&mgr, &bob_root);
    let alice = n("/home/bob/alice/KEY/k1");
    make_leaf(&mgr, &alice, &bob_root).await;

    let validator = validator_over(&mgr);
    validator.adopt_context(hier_context("/home/bob", bob_anchor));

    // Alice's key is valid under the /home/bob anchor, but charlie's subtree
    // is not hers. Under the loose first-component schema this would pass;
    // the hierarchy floor rejects it.
    let cross = sign_with(&mgr, "/home/bob/charlie/secret", &alice);
    match validator.validate_chain(&cross).await {
        ValidationResult::Valid(_) => {
            panic!("skeleton-key: cert signed outside its subtree — floor not enforced")
        }
        ValidationResult::Invalid(_) | ValidationResult::Pending => {}
    }
}

// ── Phase 2: SignedTrustContext wire object + versioning ──────────────────────────

/// CTX.07 (anti-rollback): the keyring refuses a strictly older context
/// version for the same namespace; a newer or equal version is accepted.
#[tokio::test]
async fn ctx07_context_version_monotonic() {
    let mgr = SecurityManager::new();
    let root = n("/home/bob/KEY/root");
    let anchor = make_anchor(&mgr, &root);

    let validator = validator_over(&mgr);
    let v2 = Arc::new(SignedTrustContext::hierarchical(n("/home/bob")).with_version(2));
    v2.add_anchor(anchor.clone());
    assert!(validator.adopt_context(v2), "v2 must be adopted");
    assert_eq!(validator.keyring().version_of(&n("/home/bob")), Some(2));

    // Rollback to v1 is refused — the held context stays at v2.
    let v1 = Arc::new(SignedTrustContext::hierarchical(n("/home/bob")).with_version(1));
    v1.add_anchor(anchor.clone());
    assert!(
        !validator.adopt_context(v1),
        "older version must be refused"
    );
    assert_eq!(validator.keyring().version_of(&n("/home/bob")), Some(2));

    // A newer version is accepted.
    let v3 = Arc::new(SignedTrustContext::hierarchical(n("/home/bob")).with_version(3));
    v3.add_anchor(anchor);
    assert!(validator.adopt_context(v3), "newer version must be adopted");
    assert_eq!(validator.keyring().version_of(&n("/home/bob")), Some(3));
}

/// CTX.13 (self-certifying root): a context whose namespace is rooted at a
/// self-signed key — no hierarchical naming authority, squat-proof — validates
/// its own data with no CA. Here the namespace is `/self-cert/<id>` standing in
/// for a key-digest/`did:key` root; the point is that the anchor's identity is
/// the namespace, so only the holder of that key can produce under it.
#[tokio::test]
async fn ctx13_self_cert_rooted_context_validates() {
    let mgr = SecurityManager::new();
    let ns = "/self-cert/z6Mk";
    let root = n(&format!("{ns}/KEY/root"));
    let anchor = make_anchor(&mgr, &root);
    let leaf = n(&format!("{ns}/dev/KEY/k1"));
    make_leaf(&mgr, &leaf, &root).await;

    let validator = validator_over(&mgr);
    validator.adopt_context(hier_context(ns, anchor));

    let data = sign_with(&mgr, &format!("{ns}/dev/telemetry"), &leaf);
    assert!(
        matches!(
            validator.validate_chain(&data).await,
            ValidationResult::Valid(_)
        ),
        "self-cert-rooted context must validate its own data with no CA"
    );

    // A squatter with their own key cannot produce under this namespace: their
    // chain does not terminate at the adopted anchor.
    let squat = SecurityManager::new();
    let squat_key = n(&format!("{ns}/dev/KEY/evil"));
    squat.generate_ed25519(squat_key.clone()).unwrap();
    let squat_data = sign_with(&squat, &format!("{ns}/dev/telemetry"), &squat_key);
    match validator.validate_chain(&squat_data).await {
        ValidationResult::Valid(_) => panic!("squatter accepted under self-cert namespace"),
        ValidationResult::Invalid(_) | ValidationResult::Pending => {}
    }
}

/// CTX.17 (stock-LVS interop): a context's schema round-trips as the exact
/// python-ndn/NDNts-compatible LVS binary it was published with.
#[test]
fn ctx17_schema_roundtrips_as_stock_lvs() {
    let lvs = Bytes::from_static(NDND_LVS_MODEL);
    let ctx = SignedTrustContext::hierarchical(n("/a/blog"))
        .with_version(1)
        .with_enrollment_hint(EnrollmentHint::hub_default())
        .with_schema_blob(SchemaBlob::lvs(lvs.clone()))
        .expect("LVS schema imports");

    let content = ctx.encode_content();
    let back = SignedTrustContext::decode_content(&content, 1).expect("context decodes");

    // The runtime schema parsed back as an LVS model (interop preserved)…
    assert!(
        back.schema_snapshot().lvs_model().is_some(),
        "decoded schema must be an LVS model"
    );
    // …and the published blob is the *identical* stock-LVS byte sequence.
    let published = back.published_schema();
    assert_eq!(published.format, SchemaFormat::Lvs);
    assert_eq!(
        published.body, lvs,
        "LVS binary must round-trip byte-for-byte"
    );
    assert_eq!(back.namespace(), &n("/a/blog"));
    assert_eq!(back.enrollment_hint(), Some(&EnrollmentHint::hub_default()));
}
