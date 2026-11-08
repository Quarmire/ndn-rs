//! Self-certifying namespaces `/user/<0xA1: SHA-256(raw Ed25519 key)>`: the
//! genesis rule (trust-context.md §4.5). Version 1 of such a namespace is
//! taken only when its signer is an Ed25519 key whose SHA-256 is the name's
//! last component, and the keyring never takes such a namespace any other
//! way than from that genesis.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::self_certifying::{
    Genesis, GenesisError, SELF_CERTIFYING, SelfCertifyingNameError, personal_prefix,
    self_certifying_digest, self_certifying_name,
};
use ndn_security::{
    AdoptRefusal, Certificate, Keyring, SecurityManager, SignedTrustContext, Signer,
};

/// An Ed25519 key `key` in `mgr`, and its self-signed anchor.
fn root_of(mgr: &SecurityManager, key: &Name) -> Certificate {
    mgr.generate_ed25519(key.clone()).unwrap();
    let pk = mgr.get_signer_sync(key).unwrap().public_key().unwrap();
    mgr.issue_self_signed(key, pk, u64::MAX).unwrap()
}

/// Version `version` of `namespace` listing `anchors`, signed by `signer`.
async fn context(
    mgr: &SecurityManager,
    namespace: &Name,
    version: u64,
    anchors: &[&Certificate],
    signer: &Name,
) -> (SignedTrustContext, Data) {
    let ctx = SignedTrustContext::hierarchical(namespace.clone()).with_version(version);
    for a in anchors {
        ctx.add_anchor((*a).clone());
    }
    let signer = mgr.get_signer_sync(signer).unwrap();
    let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
    (ctx, data)
}

/// A new person: their key `K` (from `seed`), the namespace it names, and
/// its anchor.
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, Certificate) {
    // The key's name depends on its own public key.
    let seed = [seed; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let key = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(key.clone(), &seed).unwrap();
    let anchor = mgr
        .issue_self_signed(&key, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    (ns, key, anchor)
}

#[test]
fn the_name_is_sha256_of_the_raw_ed25519_key_after_user() {
    let pk = [7u8; 32];
    let ns = self_certifying_name(&pk);
    use sha2::Digest;
    let digest: [u8; 32] = sha2::Sha256::digest(pk).into();
    assert_eq!(ns.len(), 2);
    assert_eq!(ns.components()[0], personal_prefix().components()[0]);
    assert_eq!(ns.components()[1].typ, 0xA1);
    assert_eq!(SELF_CERTIFYING, 0xA1);
    assert_eq!(ns.components()[1].value.as_ref(), &digest[..]);
    assert_eq!(self_certifying_digest(&ns), Ok(Some(digest)));
    let plain: Name = "/home/bob".parse().unwrap();
    assert_eq!(self_certifying_digest(&plain), Ok(None));
}

#[test]
fn a_self_certifying_component_anywhere_else_is_refused() {
    let digest = Bytes::from_static(&[1u8; 32]);
    let c = NameComponent::new(SELF_CERTIFYING, digest.clone());
    let elsewhere = Name::root().append("alice").append_component(c.clone());
    let under = personal_prefix().append_component(c.clone()).append("team");
    let short = personal_prefix().append_component(NameComponent::new(
        SELF_CERTIFYING,
        Bytes::from_static(&[1u8; 16]),
    ));
    assert!(matches!(
        self_certifying_digest(&elsewhere),
        Err(SelfCertifyingNameError::Misplaced { .. })
    ));
    assert!(matches!(
        self_certifying_digest(&under),
        Err(SelfCertifyingNameError::Under { .. })
    ));
    assert!(matches!(
        self_certifying_digest(&short),
        Err(SelfCertifyingNameError::Misplaced { .. })
    ));
    let keyring = Keyring::new();
    for ns in [elsewhere, under, short] {
        let refused = keyring.adopt(Arc::new(
            SignedTrustContext::hierarchical(ns.clone()).with_version(1),
        ));
        assert!(
            matches!(refused, Err(AdoptRefusal::Name(_))),
            "{ns}: {refused:?}"
        );
    }
}

#[tokio::test]
async fn a_genesis_whose_signer_hashes_to_the_name_is_accepted() {
    let mgr = SecurityManager::new();
    let (ns, key, anchor) = person(&mgr, 1);
    let (_, data) = context(&mgr, &ns, 1, &[&anchor], &key).await;
    let genesis = Genesis::open_received(&data).await.unwrap();
    assert_eq!(genesis.namespace(), &ns);
    assert_eq!(genesis.root().public_key, anchor.public_key);

    let keyring = Keyring::new();
    keyring
        .adopt_genesis(&genesis, Arc::clone(genesis.context()))
        .unwrap();
    assert_eq!(keyring.version_of(&ns), Some(1));
}

#[tokio::test]
async fn a_genesis_signed_by_a_key_that_does_not_hash_to_the_name_is_refused() {
    let mgr = SecurityManager::new();
    let (ns, _, _) = person(&mgr, 1);
    // Another key, named as the namespace's root, signs version 1.
    let other = ns.clone().append("KEY").append("other");
    let other_anchor = root_of(&mgr, &other);
    let (_, data) = context(&mgr, &ns, 1, &[&other_anchor], &other).await;
    let refused = Genesis::open_received(&data).await.err().unwrap();
    assert!(
        matches!(refused, GenesisError::Mismatch { .. }),
        "{refused}"
    );
    assert!(
        refused.to_string().contains("does not hash to"),
        "{refused}"
    );
}

/// A forged genesis lists the named key (its public anchor certificate is
/// public) beside the forger's own, and is signed by the forger's: refused,
/// because the signer, not an anchor listed, must hash to the name.
#[tokio::test]
async fn a_forged_genesis_listing_the_named_key_but_signed_by_another_is_refused() {
    let mgr = SecurityManager::new();
    let (ns, _, alice_anchor) = person(&mgr, 1);
    let mallory = ns.clone().append("KEY").append("mallory");
    let mallory_anchor = root_of(&mgr, &mallory);
    let (forged, data) = context(&mgr, &ns, 1, &[&alice_anchor, &mallory_anchor], &mallory).await;
    let refused = Genesis::open_received(&data).await.err().unwrap();
    assert!(
        matches!(refused, GenesisError::Mismatch { .. }),
        "{refused}"
    );
    // Nor does the keyring take it as anything but a genesis.
    let keyring = Keyring::new();
    let refused = keyring.adopt(Arc::new(forged));
    assert!(
        matches!(refused, Err(AdoptRefusal::GenesisRequired { .. })),
        "{refused:?}"
    );
    assert!(keyring.is_empty());
}

#[tokio::test]
async fn only_version_one_is_a_genesis() {
    let mgr = SecurityManager::new();
    let (ns, key, anchor) = person(&mgr, 1);
    let (_, v2) = context(&mgr, &ns, 2, &[&anchor], &key).await;
    let refused = Genesis::open_received(&v2).await.err().unwrap();
    assert!(
        matches!(refused, GenesisError::NotVersionOne { version: 2, .. }),
        "{refused}"
    );
}

#[tokio::test]
async fn a_genesis_root_that_is_not_ed25519_is_refused() {
    let mgr = SecurityManager::new();
    let seed = [9u8; 32];
    let pk = ndn_security::EcdsaP256Signer::from_seed(&seed, Name::root())
        .unwrap()
        .public_key()
        .unwrap();
    use sha2::Digest;
    let digest: [u8; 32] = sha2::Sha256::digest(&pk).into();
    let ns = personal_prefix().append_component(NameComponent::new(
        SELF_CERTIFYING,
        Bytes::copy_from_slice(&digest),
    ));
    let key = ns.clone().append("KEY").append("root");
    mgr.install_signer(ndn_security::EcdsaP256Signer::from_seed(&seed, key.clone()).unwrap());
    let anchor = mgr.issue_self_signed(&key, pk, u64::MAX).unwrap();
    let (_, data) = context(&mgr, &ns, 1, &[&anchor], &key).await;
    let refused = Genesis::open_received(&data).await.err().unwrap();
    assert!(
        matches!(refused, GenesisError::NotEd25519 { .. }),
        "{refused}"
    );
}

#[tokio::test]
async fn the_keyring_takes_a_self_certifying_namespace_only_from_its_genesis() {
    let mgr = SecurityManager::new();
    let (ns, key, anchor) = person(&mgr, 1);
    let (v1, v1_data) = context(&mgr, &ns, 1, &[&anchor], &key).await;
    let (v2, _) = context(&mgr, &ns, 2, &[&anchor], &key).await;
    let keyring = Keyring::new();
    // Neither the genuine version 1 nor a later version, without the
    // checked genesis.
    for ctx in [v1, v2] {
        let refused = keyring.adopt(Arc::new(ctx));
        assert!(
            matches!(refused, Err(AdoptRefusal::GenesisRequired { .. })),
            "{refused:?}"
        );
    }
    let genesis = Genesis::open_received(&v1_data).await.unwrap();
    // A context of another namespace never rides a genesis.
    let (bob, bob_key, bob_anchor) = person(&mgr, 2);
    let (bob_v1, _) = context(&mgr, &bob, 1, &[&bob_anchor], &bob_key).await;
    let refused = keyring.adopt_genesis(&genesis, Arc::new(bob_v1));
    assert!(
        matches!(refused, Err(AdoptRefusal::NotFromGenesis { .. })),
        "{refused:?}"
    );
    // A later version the caller checked from the genesis is taken.
    let (v3, _) = context(&mgr, &ns, 3, &[&anchor], &key).await;
    keyring.adopt_genesis(&genesis, Arc::new(v3)).unwrap();
    assert_eq!(keyring.version_of(&ns), Some(3));
    // Held now: the same rules as any held namespace.
    let refused = keyring.adopt_genesis(&genesis, Arc::clone(genesis.context()));
    assert!(
        matches!(refused, Err(AdoptRefusal::Older { .. })),
        "{refused:?}"
    );
}
