//! Phase 5 witness: a clockless node enforces a monotonic context version and
//! single-use tokens with no wall-clock, and namespace init produces a coherent
//! anchor + context + `ndn-trust://anchor` envelope.
//!
//! Backs `testbed/tests/audit/ctx16_*.sh`. See §16 (N4).

use std::sync::Arc;

use dashmap::DashMap;
use ndn_cert::{
    TokenStore, ValidityMode, adopt_anchor_envelope, adopt_envelope_into_store,
    adopt_with_tofu, init_namespace, init_namespace_in_pib, load_persisted_contexts,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{
    FilePib, SecurityManager, SignedTrustContext, TrustSchema, ValidationResult, Validator,
};
use ndn_trust_envelope::TrustEnvelope;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn validator() -> Validator {
    Validator::with_chain(
        TrustSchema::hierarchical(),
        Arc::new(ndn_security::CertCache::new()),
        Arc::new(DashMap::new()),
        None,
        5,
    )
}

/// CTX.16 (clockless degradation): with no wall-clock, a node still refuses an
/// older context version (monotonic, version-compare only) and rejects a
/// reused token (set membership only) — neither check consults a clock.
#[test]
fn ctx16_clockless_monotonic_version_and_single_use() {
    // A clockless node cannot lean on TTL…
    let mode = ValidityMode::detect(/* has_wall_clock = */ false);
    assert_eq!(mode, ValidityMode::Clockless);
    assert!(!mode.ttl_enforceable(), "clockless must not rely on TTL");

    // …so it relies on monotonic context version (no clock involved).
    let v = validator();
    let mk = |ver: u64| {
        let c = SignedTrustContext::hierarchical(n("/home/bob")).with_version(ver);
        Arc::new(c)
    };
    assert!(v.adopt_context(mk(2)), "v2 adopted");
    assert!(!v.adopt_context(mk(1)), "older v1 refused with no clock");
    assert_eq!(v.keyring().version_of(&n("/home/bob")), Some(2));
    assert!(v.adopt_context(mk(3)), "newer v3 adopted");

    // …and single-use tokens (no TTL set ⇒ no clock dependence).
    let store = TokenStore::new();
    store.add("baked-invite"); // unbounded: no expiry, no scope
    assert!(store.consume("baked-invite"), "first use ok");
    assert!(!store.consume("baked-invite"), "reuse rejected, clock-free");
}

/// CTX.16 (namespace init coherence): `init_namespace` yields an anchor/context/envelope that a
/// fresh node can adopt via TOFU end to end — the envelope carries the
/// root-signed context Data, verified on adoption.
#[test]
fn ctx16_namespace_init_roundtrips_through_tofu() {
    let mgr = SecurityManager::new();
    let root_dev = init_namespace(&mgr, &n("/home/bob")).unwrap();

    // A fresh node scans the envelope: pinned namespace + fingerprint, with
    // the signed context carried inline (no fetch needed).
    let uri = root_dev.envelope.to_uri();
    let envelope = TrustEnvelope::from_uri(&uri).unwrap();
    let TrustEnvelope::Anchor {
        namespace: Some(ns),
        fingerprint: Some(fp),
        context_data: Some(wire),
        ..
    } = &envelope
    else {
        panic!("namespace envelope must be a fully-populated anchor");
    };
    let data = Data::decode(wire.clone()).unwrap();
    assert_eq!(data.content(), Some(&root_dev.published_content()));

    let v = validator();
    adopt_with_tofu(v.keyring(), &data, &n(ns), fp).unwrap();
    assert_eq!(v.keyring().version_of(&n("/home/bob")), Some(1));
    // The envelope-level entry point agrees.
    let other = validator();
    adopt_anchor_envelope(other.keyring(), &envelope).unwrap();
}

/// Sign `name` with `key_name` held by `mgr`.
fn signed(mgr: &SecurityManager, key_name: &Name, name: &str) -> Data {
    let signer = mgr.get_signer_sync(key_name).unwrap();
    let wire = DataBuilder::new(n(name), b"payload").sign_sync(
        signer.sig_type(),
        Some(key_name),
        |r| signer.sign_sync(r).unwrap_or_default(),
    );
    Data::decode(wire).unwrap()
}

/// Pairing-path acceptance: `ndn-fwd init` (persisted namespace) → envelope →
/// `ndn-fwd adopt` (TOFU + persist on another node) → a fresh keyring loaded
/// from that node's disk validates, under the generated schema, the CA cert
/// (signed by the root) and Data a member signs under its own name through a
/// CA-issued cert. An edited stored context is refused on load.
#[tokio::test]
async fn init_envelope_adopt_persists_and_validates_after_reload() {
    let root_dir = tempfile::tempdir().unwrap();
    let node_dir = tempfile::tempdir().unwrap();
    let ns = n("/home/bob");

    let root_pib = FilePib::new(root_dir.path()).unwrap();
    let root_dev = init_namespace_in_pib(&root_pib, &ns, "laptop", false).unwrap();
    let uri = root_dev.init.envelope.to_uri();

    // The adopting node only ever sees the scanned URI.
    let envelope = TrustEnvelope::from_uri(&uri).unwrap();
    let (ctx, path) = adopt_envelope_into_store(node_dir.path(), &envelope).unwrap();
    assert_eq!(ctx.namespace(), &ns);
    assert!(path.starts_with(node_dir.path().join("contexts")));

    // The CA cert as published (signed by the root), and Data signed by a
    // member whose cert the CA (loaded back from the root device's PIB) issued.
    let root_mgr = SecurityManager::new();
    root_mgr.register_signer(root_dev.ca_key.clone(), root_pib.get_signer(&root_dev.ca_key).unwrap());
    let member = n("/home/bob/member/phone/KEY/k1");
    root_mgr.generate_ed25519(member.clone()).unwrap();
    let member_pk = root_mgr.get_signer_sync(&member).unwrap().public_key().unwrap();
    let member_cert = root_mgr
        .certify(&member, member_pk, &root_dev.ca_key, 3_600_000)
        .await
        .unwrap();
    let ca_cert = Data::decode(bytes::Bytes::from(std::fs::read(&root_dev.ca_cert_path).unwrap()))
        .unwrap();
    let by_member = signed(&root_mgr, &member, "/home/bob/member/phone/msg");

    // "Restart": a brand-new validator whose keyring is filled from disk.
    let v = validator();
    assert!(v.keyring().is_empty());
    let loaded = load_persisted_contexts(node_dir.path(), v.keyring()).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0].1.is_ok(), "{:?}", loaded[0].1.as_ref().err());
    v.cert_cache().insert(member_cert);
    v.cert_cache().insert(root_dev.ca_cert.clone());
    assert!(matches!(v.validate_chain(&ca_cert).await, ValidationResult::Valid(_)));
    assert!(matches!(v.validate_chain(&by_member).await, ValidationResult::Valid(_)));

    // Re-adopting the same envelope keeps working (same version, idempotent).
    adopt_envelope_into_store(node_dir.path(), &envelope).unwrap();

    // Tamper with the stored context (flip a byte inside its Content): refused on load.
    let mut wire = std::fs::read(&path).unwrap();
    let content = Data::decode(bytes::Bytes::from(wire.clone()))
        .unwrap()
        .content()
        .unwrap()
        .to_vec();
    let at = wire
        .windows(content.len())
        .position(|w| w == content.as_slice())
        .unwrap();
    wire[at + content.len() / 2] ^= 0x01;
    std::fs::write(&path, &wire).unwrap();
    let fresh = validator();
    let loaded = load_persisted_contexts(node_dir.path(), fresh.keyring()).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded[0].1.is_err(), "edited context must be refused");
    assert!(fresh.keyring().is_empty());
}
