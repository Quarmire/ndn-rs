//! Phase-1 witnesses for the engine/identity synthesis (`.claude/prompts/
//! trust-context-synthesis-implementation-2026-05-25.md`). Each test backs
//! one of the `testbed/tests/audit/tcs0{1..5}_*.sh` witness scripts.

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use ndn_identity::CustodianRef;
use ndn_identity::custodian::{Custodian, CustodianRegistry, InPageCustodian, UnlockContext};
use ndn_identity::trust_context::{
    AdoptionProvenance, CapabilitySet, IdentityLifetime, IdentityRef, KeyId, TrustContext,
};
use ndn_packet::{Name, NameComponent, SignatureType};
use ndn_security::{
    Certificate, Ed25519Signer, Ed25519Verifier, NamePattern, PatternComponent, VerifyOutcome,
};

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn pat_under(prefix: &Name) -> NamePattern {
    let mut comps: Vec<PatternComponent> = prefix
        .components()
        .iter()
        .map(|c| PatternComponent::Literal(c.clone()))
        .collect();
    comps.push(PatternComponent::MultiCapture("_".into()));
    NamePattern(comps)
}

fn synth_cert(cert_name: &str, signed_region: &[u8]) -> Certificate {
    let n: Arc<Name> = Arc::new(cert_name.parse().unwrap());
    Certificate {
        name: n,
        public_key: Bytes::from_static(b""),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: Some(Bytes::copy_from_slice(signed_region)),
        sig_value: None,
        sig_type: SignatureType::SignatureSha256WithEcdsa,
    }
}

/// tcs01 — construct a TrustContext, export the sync bundle, and round-trip
/// the equality-critical subset (anchors, ca_endpoints, context_name).
#[test]
fn tcs01_trust_context_roundtrip() {
    let anchor = synth_cert("/home/bob/KEY/root", b"anchor-signed-region");
    let mut tc = TrustContext::adopted(name("/home/bob"), SystemTime::now(), "tcs01");
    tc.anchors.push(anchor.clone());
    tc.ca_endpoints.push(name("/home/bob/_/ca"));

    let bundle = tc.export_for_sync();
    assert_eq!(bundle.context_name, tc.name);
    assert_eq!(bundle.anchors.len(), 1);
    assert_eq!(bundle.anchors[0].name, anchor.name);
    assert_eq!(bundle.ca_endpoints, tc.ca_endpoints);
    assert!(!bundle.carries_private_keys());
}

/// tcs02 — an InPage custodian signs `content` with a held key; the
/// produced signature verifies against the public key.
#[tokio::test]
async fn tcs02_custodian_in_page_sign() {
    let custodian = InPageCustodian::new();
    let key_id = KeyId(name("/home/bob/alice/KEY/k1"));
    let signer = Ed25519Signer::from_seed(&[3u8; 32], key_id.0.clone());
    let pk = signer.public_key_bytes();
    custodian.insert(key_id.clone(), signer);

    let content = b"signed by alice";
    let sig = custodian
        .sign(&key_id, &name("/home/bob/alice/doc"), content)
        .await
        .expect("sign ok");
    assert_eq!(sig.len(), 64);
    let outcome = Ed25519Verifier.verify_sync(content, &sig, &pk);
    assert!(matches!(outcome, VerifyOutcome::Valid));
}

/// tcs03 — unlocking the same custodian twice does not error and leaves it
/// available.
#[tokio::test]
async fn tcs03_custodian_unlock_idempotent() {
    let custodian = InPageCustodian::new();
    custodian
        .unlock(UnlockContext::default())
        .await
        .expect("first unlock ok");
    custodian
        .unlock(UnlockContext::default())
        .await
        .expect("second unlock ok");
    assert!(custodian.is_available().await);
}

/// tcs04 — legacy flat anchor material lands inside the implicit `/`
/// TrustContext at first run; the resulting context is verify-only (no
/// identities held until the user enrolls).
#[test]
fn tcs04_legacy_anchors_in_root_tc() {
    let legacy = vec![
        synth_cert("/com/example/KEY/k0", b"e0"),
        synth_cert("/edu/ucla/KEY/k1", b"e1"),
    ];
    let tc = TrustContext::legacy_root(legacy.clone());
    assert_eq!(tc.name, Name::root());
    assert!(tc.identities.is_empty(), "verify-only on first import");
    assert_eq!(tc.anchors.len(), legacy.len());
    assert!(matches!(
        tc.provenance,
        AdoptionProvenance::Replicated { .. }
    ));
}

/// tcs05 — `can_sign` returns `None` for names outside the held identity's
/// `sign` patterns and `Some` for names inside.
#[test]
fn tcs05_capability_set_lvs_lookup() {
    let mut tc = TrustContext::adopted(name("/home/bob"), SystemTime::now(), "tcs05");
    let alice_id = IdentityRef {
        name: name("/home/bob/alice"),
        key_id: KeyId::placeholder_for(&name("/home/bob/alice")),
        custodian: CustodianRef::InPage,
        lifetime: IdentityLifetime::Persistent,
        derived_from: None,
        capabilities: CapabilitySet {
            sign: vec![pat_under(&name("/home/bob/alice"))],
            ..Default::default()
        },
    };
    tc.identities.push(alice_id);
    assert!(tc.can_sign(&name("/home/bob/alice/doc")).is_some());
    assert!(tc.can_sign(&name("/home/bob/alice/sub/deep")).is_some());
    assert!(tc.can_sign(&name("/home/bob/charlie/doc")).is_none());
    assert!(tc.can_sign(&name("/work/acme/doc")).is_none());
}

/// Bonus: contexts wired with a custodian registry sign through the
/// `TrustContext::sign` convenience method.
#[tokio::test]
async fn tcs02_sign_through_trust_context() {
    let mut tc = TrustContext::adopted(name("/home/bob"), SystemTime::now(), "tcs02b");
    let key_id = KeyId(name("/home/bob/alice/KEY/k1"));
    let signer = Ed25519Signer::from_seed(&[9u8; 32], key_id.0.clone());
    let pk = signer.public_key_bytes();

    let alice_id = IdentityRef {
        name: name("/home/bob/alice"),
        key_id: key_id.clone(),
        custodian: CustodianRef::InPage,
        lifetime: IdentityLifetime::Persistent,
        derived_from: None,
        capabilities: CapabilitySet {
            sign: vec![pat_under(&name("/home/bob/alice"))],
            ..Default::default()
        },
    };
    tc.identities.push(alice_id);

    let custodian = Arc::new(InPageCustodian::new());
    custodian.insert(key_id.clone(), signer);
    let mut reg = CustodianRegistry::new();
    reg.insert(custodian);

    let content = b"hello via TrustContext";
    let sig = tc
        .sign(&name("/home/bob/alice/doc"), content, &reg)
        .await
        .expect("sign via tc");
    assert_eq!(sig.len(), 64);
    let outcome = Ed25519Verifier.verify_sync(content, &sig, &pk);
    assert!(matches!(outcome, VerifyOutcome::Valid));
}

// Suppress unused-import warnings for NameComponent on this test target.
#[allow(dead_code)]
fn _kp_used() -> Option<NameComponent> {
    None
}
