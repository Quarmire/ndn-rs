//! Phase 7 witnesses: context lifecycle — loosen (no re-touch), tighten
//! dry-run, cross-signed anchor rotation, and issuing-CA-compromise recovery
//! by pull. See `.claude/notes/trust-context/trust-context-model-2026-05-25.md`
//! §8.

use std::sync::Arc;

use dashmap::DashMap;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, SecurityManager, TrustContext, TrustError, TrustSchema, ValidationResult,
    Validator, dryrun_orphans,
};

const ONE_YEAR_MS: u64 = 365 * 24 * 3600 * 1_000;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn make_anchor(mgr: &SecurityManager, key: &Name) -> Certificate {
    mgr.generate_ed25519(key.clone()).unwrap();
    let pk = mgr.get_signer_sync(key).unwrap().public_key().unwrap();
    mgr.issue_self_signed(key, pk, u64::MAX).unwrap()
}

async fn make_leaf(mgr: &SecurityManager, key: &Name, issuer: &Name) -> Certificate {
    mgr.generate_ed25519(key.clone()).unwrap();
    let pk = mgr.get_signer_sync(key).unwrap().public_key().unwrap();
    mgr.certify(key, pk, issuer, ONE_YEAR_MS).await.unwrap()
}

fn sign_with(mgr: &SecurityManager, data_name: &str, key: &Name) -> Data {
    let signer = mgr.get_signer_sync(key).unwrap();
    let wire = DataBuilder::new(data_name, b"x").sign_sync(signer.sig_type(), Some(key), |r| {
        signer.sign_sync(r).unwrap_or_default()
    });
    Data::decode(wire).unwrap()
}

fn validator_over(mgr: &SecurityManager) -> Validator {
    Validator::with_chain(
        TrustSchema::hierarchical(),
        mgr.cert_cache_arc(),
        Arc::new(DashMap::new()),
        None,
        5,
    )
}

/// CTX.08 (loosen + bump → new node enrolls, zero re-touch): a v2 context with
/// a widened schema lets a new relationship validate; bumping the version is
/// accepted and leaves other namespaces untouched.
#[tokio::test]
async fn ctx08_schema_loosen_no_retouch() {
    let mgr = SecurityManager::new();
    let root = n("/home/bob/KEY/root");
    let anchor = make_anchor(&mgr, &root);

    // A guest device whose key sits *outside* a strict initial schema.
    let guest = n("/home/bob/guests/phone/KEY/k1");
    make_leaf(&mgr, &guest, &root).await;

    let validator = validator_over(&mgr);

    // v1: strict — only `/home/bob/admin/**` may be signed (guests excluded).
    let v1 = Arc::new(
        TrustContext::accept_all(n("/home/bob")) // start permissive base…
            .with_version(1),
    );
    // Tighten v1's schema to admin-only by replacing it.
    {
        let mut s = TrustSchema::new();
        s.add_rule(
            ndn_security::SchemaRule::parse("/home/bob/admin/<**r> => /home/bob/<**k>").unwrap(),
        );
        v1.set_schema(s);
    }
    v1.add_anchor(anchor.clone());
    assert!(validator.adopt_context(v1));

    let guest_data = sign_with(&mgr, "/home/bob/guests/phone/hello", &guest);
    assert!(
        !matches!(
            validator.validate_chain(&guest_data).await,
            ValidationResult::Valid(_)
        ),
        "under strict v1 the guest must not validate"
    );

    // v2: loosen — hierarchical floor admits any in-subtree signer. Pull bumps
    // the version; existing /work/* etc. namespaces are untouched.
    let v2 = Arc::new(TrustContext::hierarchical(n("/home/bob")).with_version(2));
    v2.add_anchor(anchor);
    assert!(
        validator.adopt_context(v2),
        "loosened v2 adopted by version bump"
    );
    assert_eq!(validator.keyring().version_of(&n("/home/bob")), Some(2));

    let guest_data = sign_with(&mgr, "/home/bob/guests/phone/hello", &guest);
    assert!(
        matches!(
            validator.validate_chain(&guest_data).await,
            ValidationResult::Valid(_)
        ),
        "after loosening to v2 the new guest validates"
    );
}

/// CTX.09 (tighten dry-run): the dry-run reports exactly the live signing
/// relationships a tighter candidate would orphan, before applying it.
#[test]
fn ctx09_schema_tighten_dryrun_reports_orphans() {
    // Live relationships: an admin and a guest, both currently valid.
    let live = vec![
        (
            n("/home/bob/admin/laptop/cfg"),
            n("/home/bob/admin/laptop/KEY/k1"),
        ),
        (
            n("/home/bob/guests/phone/note"),
            n("/home/bob/guests/phone/KEY/k2"),
        ),
    ];

    // Candidate: tighten to admins only.
    let candidate = TrustContext::hierarchical(n("/home/bob"));
    {
        let mut s = TrustSchema::new();
        s.add_rule(
            ndn_security::SchemaRule::parse("/home/bob/admin/<**r> => /home/bob/admin/<**k>")
                .unwrap(),
        );
        candidate.set_schema(s);
    }

    let orphans = dryrun_orphans(&candidate, &live);
    assert_eq!(orphans.len(), 1, "only the guest relationship is orphaned");
    assert_eq!(orphans[0].0, n("/home/bob/guests/phone/note"));
}

/// CTX.10 (cross-signed rotation): a node holding only the *old* anchor accepts
/// data signed by the *new* anchor, because the new anchor's cert is
/// cross-signed by the old; after the window the context drops the old anchor.
#[tokio::test]
async fn ctx10_anchor_rotation_bridged() {
    let mgr = SecurityManager::new();
    let old_root = n("/home/bob/KEY/old-root");
    let old_anchor = make_anchor(&mgr, &old_root);

    // The new anchor key is *certified by the old root* (cross-signed), so a
    // node trusting only the old anchor can chain to it.
    let new_root = n("/home/bob/KEY/new-root");
    make_leaf(&mgr, &new_root, &old_root).await;

    // A leaf under the new root signs data.
    let leaf = n("/home/bob/dev/KEY/k1");
    make_leaf(&mgr, &leaf, &new_root).await;
    let data = sign_with(&mgr, "/home/bob/dev/telemetry", &leaf);

    // During the window: node holds only the OLD anchor.
    let windowed = validator_over(&mgr);
    let ctx_window = Arc::new(TrustContext::hierarchical(n("/home/bob")).with_version(1));
    ctx_window.add_anchor(old_anchor.clone());
    windowed.adopt_context(ctx_window);
    assert!(
        matches!(
            windowed.validate_chain(&data).await,
            ValidationResult::Valid(_)
        ),
        "cross-signed new anchor must be accepted by a node holding only the old"
    );

    // After the window: a v2 context drops the old anchor, keeping only new.
    // Data still validates because the new root is now the anchor itself.
    let after = validator_over(&mgr);
    let new_anchor_cert = mgr.cert_cache().get(&Arc::new(new_root.clone())).unwrap();
    let ctx_after = Arc::new(TrustContext::hierarchical(n("/home/bob")).with_version(2));
    ctx_after.add_anchor(new_anchor_cert);
    after.adopt_context(ctx_after);
    let data2 = sign_with(&mgr, "/home/bob/dev/telemetry", &leaf);
    assert!(
        matches!(
            after.validate_chain(&data2).await,
            ValidationResult::Valid(_)
        ),
        "post-window node trusting only the new anchor still validates"
    );
}

/// CTX.11 (issuing-CA compromise recovery by pull): a two-tier root + issuing
/// CA. After the issuing CA is compromised, the root revokes it (in a bumped
/// context) and signs a fresh intermediate; nodes recover by *pulling* the new
/// context — no re-bootstrap. Data via the revoked CA is rejected; data via the
/// new CA validates, all under the same unchanged root anchor.
#[tokio::test]
async fn ctx11_intermediate_compromise_recovery() {
    let mgr = SecurityManager::new();
    let root = n("/home/bob/KEY/root");
    let root_anchor = make_anchor(&mgr, &root);

    // Old issuing CA + a leaf it signed.
    let old_ca = n("/home/bob/ca/KEY/v1");
    make_leaf(&mgr, &old_ca, &root).await;
    let old_leaf = n("/home/bob/dev1/KEY/k1");
    make_leaf(&mgr, &old_leaf, &old_ca).await;

    // New issuing CA + a leaf it signed (post-recovery).
    let new_ca = n("/home/bob/ca/KEY/v2");
    make_leaf(&mgr, &new_ca, &root).await;
    let new_leaf = n("/home/bob/dev2/KEY/k1");
    make_leaf(&mgr, &new_leaf, &new_ca).await;

    // Recovered context (v2): same root anchor, old CA revoked.
    let validator = validator_over(&mgr);
    let ctx = Arc::new(
        TrustContext::hierarchical(n("/home/bob"))
            .with_version(2)
            .with_revocation(old_ca.clone()),
    );
    ctx.add_anchor(root_anchor);
    validator.adopt_context(ctx);

    // Data via the revoked CA is rejected (chain passes through old_ca).
    let bad = sign_with(&mgr, "/home/bob/dev1/telemetry", &old_leaf);
    match validator.validate_chain(&bad).await {
        ValidationResult::Invalid(TrustError::Revoked { .. }) => {}
        other => panic!("revoked-CA chain must be rejected as Revoked, got {other:?}"),
    }

    // Data via the new CA validates — recovery by pull, no re-bootstrap.
    let good = sign_with(&mgr, "/home/bob/dev2/telemetry", &new_leaf);
    assert!(
        matches!(
            validator.validate_chain(&good).await,
            ValidationResult::Valid(_)
        ),
        "data via the fresh intermediate must validate under the unchanged root"
    );
}
