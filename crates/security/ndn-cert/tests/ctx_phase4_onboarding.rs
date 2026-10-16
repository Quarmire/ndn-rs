//! Phase 4 witnesses: adopt-to-verify with no CA, advert privacy, TOFU-gated
//! adoption against flooded fake adverts, and signature-verified adoption
//! (tampered / unsigned / mis-pinned contexts are refused).
//!
//! Backs `testbed/tests/audit/ctx0{1}_*.sh` and `ctx1{4,5}_*.sh`. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §3–§7, §16.

use std::sync::Arc;

use dashmap::DashMap;
use ndn_cert::{
    AdoptError, AdvertConfig, AnchorAdvert, adopt_anchor_envelope,
    adopt_unsigned_legacy_with_tofu, adopt_with_tofu, anchor_fingerprint,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, SignatureType};
use ndn_security::{
    Certificate, Keyring, SecurityManager, SignedTrustContext, TrustSchema, ValidationResult,
    Validator,
};
use ndn_trust_envelope::TrustEnvelope;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A `/home/bob` hub: a self-signed anchor + a published context, both as the
/// root-signed Data and (legacy) as bare unsigned content.
struct Hub {
    mgr: SecurityManager,
    anchor_key: Name,
    anchor: Certificate,
    published: bytes::Bytes,
    published_data: Data,
}

fn build_hub(namespace: &str) -> Hub {
    let mgr = SecurityManager::new();
    let anchor_key = n(&format!("{namespace}/KEY/root"));
    mgr.generate_ed25519(anchor_key.clone()).unwrap();
    let signer = mgr.get_signer_sync(&anchor_key).unwrap();
    let pk = signer.public_key().unwrap();
    let anchor = mgr.issue_self_signed(&anchor_key, pk, u64::MAX).unwrap();

    let ctx = SignedTrustContext::hierarchical(n(namespace)).with_version(1);
    ctx.add_anchor(anchor.clone());
    let published = ctx.encode_content();
    let published_data = ctx.sign_into_data(signer.as_ref()).unwrap();

    Hub {
        mgr,
        anchor_key,
        anchor,
        published,
        published_data,
    }
}

/// A fresh consumer node holding a validator + empty keyring sharing a cert
/// cache, so a decoded context's anchors are reachable for the chain walk.
fn fresh_node() -> Validator {
    Validator::with_chain(
        TrustSchema::hierarchical(),
        Arc::new(ndn_security::CertCache::new()),
        Arc::new(DashMap::new()),
        None,
        5,
    )
}

/// Make the consumer's cert cache see the context's anchors (a real fetch
/// would carry them in the context Data; here we copy them across).
fn seed_anchors(v: &Validator, ctx: &SignedTrustContext) {
    for r in ctx.anchors().iter() {
        v.cert_cache().insert(r.value().clone());
    }
}

/// CTX.01 (adopt-to-verify, no CA): a fresh node fetches `/home/bob`'s context,
/// TOFU-checks it against a scanned anchor envelope, adopts it, and verifies a
/// Bob-signed Data — with **no** CA interaction.
#[tokio::test]
async fn ctx01_adopt_to_verify_no_ca() {
    let hub = build_hub("/home/bob");

    // Bob hands out a by-reference anchor envelope (QR) committing to the
    // anchor fingerprint.
    let uri = TrustEnvelope::Anchor {
        namespace: Some("/home/bob".into()),
        fingerprint: Some(anchor_fingerprint(&hub.anchor)),
        version: None,
        context_data: None,
        context_content: None,
    }
    .to_uri();

    // ── Fresh node ──
    let TrustEnvelope::Anchor {
        namespace: Some(ns),
        fingerprint: Some(fp),
        ..
    } = TrustEnvelope::from_uri(&uri).unwrap()
    else {
        panic!("scanned envelope must be a pinned anchor");
    };
    // "Fetch" the published, root-signed context (in a deployment, RDR over a face).
    let node = fresh_node();
    let ctx = adopt_with_tofu(node.keyring(), &hub.published_data, &n(&ns), &fp)
        .expect("context signed by the pinned anchor must be adopted");
    seed_anchors(&node, &ctx);

    // Verify a Bob-signed Data — no CA was ever contacted.
    let signer = hub.mgr.get_signer_sync(&hub.anchor_key).unwrap();
    let wire = DataBuilder::new("/home/bob/note", b"hello").sign_sync(
        signer.sig_type(),
        Some(&hub.anchor_key),
        |r| signer.sign_sync(r).unwrap_or_default(),
    );
    let data = Data::decode(wire).unwrap();
    assert!(
        matches!(node.validate_chain(&data).await, ValidationResult::Valid(_)),
        "adopt-to-verify must validate Bob's data with no CA"
    );
}

/// CTX.14 (privacy): a passive listener of an advert sees only an opaque
/// fingerprint, never the namespace; advertising is off by default.
#[test]
fn ctx14_advert_hides_namespace_off_by_default() {
    let hub = build_hub("/home/bob");
    let ctx = SignedTrustContext::hierarchical(n("/home/bob"));
    ctx.add_anchor(hub.anchor.clone());

    let advert = AnchorAdvert::from_context(&ctx).expect("advert from anchored context");
    let wire = advert.encode();

    // The opaque payload is exactly the 32-byte fingerprint…
    assert_eq!(wire.len(), 32);
    // …and contains no trace of the "/home/bob" namespace.
    let needle = b"home";
    assert!(
        !wire.windows(needle.len()).any(|w| w == needle),
        "advert must not leak the namespace in cleartext"
    );
    // The advert prefix itself is link-local and namespace-free.
    assert_eq!(
        AnchorAdvert::advert_prefix().to_string(),
        "/localhop/trust-context"
    );
    // Advertising is opt-in: off unless a hub explicitly enables it.
    assert!(!AdvertConfig::default().enabled);
}

/// CTX.15 (anti-poisoning): a flooded fake advert / forged context does not
/// enter the keyring without a TOFU fingerprint match.
#[test]
fn ctx15_flooded_fake_advert_rejected() {
    let hub = build_hub("/home/bob");
    // The node trusts Bob's real fingerprint (from a scanned anchor envelope).
    let bob = n("/home/bob");
    let trusted = anchor_fingerprint(&hub.anchor);

    // An attacker floods a context for /home/bob rooted at — and signed by —
    // THEIR own anchor.
    let attacker = SecurityManager::new();
    let evil_key = n("/home/bob/KEY/evil");
    attacker.generate_ed25519(evil_key.clone()).unwrap();
    let evil_signer = attacker.get_signer_sync(&evil_key).unwrap();
    let evil_pk = evil_signer.public_key().unwrap();
    let evil_anchor = attacker
        .issue_self_signed(&evil_key, evil_pk, u64::MAX)
        .unwrap();
    let evil_ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(1);
    evil_ctx.add_anchor(evil_anchor);
    let evil_data = evil_ctx.sign_into_data(evil_signer.as_ref()).unwrap();

    let node = fresh_node();
    // TOFU against the trusted fingerprint rejects the forged context…
    assert!(
        matches!(
            adopt_with_tofu(node.keyring(), &evil_data, &bob, &trusted),
            Err(AdoptError::FingerprintMismatch(_))
        ),
        "forged context must fail TOFU and not enter the keyring"
    );
    assert!(node.keyring().is_empty(), "keyring must stay empty");

    // …and receiving an advert never auto-adopts anything.
    let _advert = AnchorAdvert::from_context(&evil_ctx);
    assert!(
        node.keyring().is_empty(),
        "adverts must not mutate the keyring"
    );

    // The genuine context (matching fingerprint) is still adoptable.
    adopt_with_tofu(node.keyring(), &hub.published_data, &bob, &trusted).unwrap();
    assert_eq!(node.keyring().len(), 1);
}

/// A context whose content was altered after signing — here the schema is
/// widened to accept-all while the genuine anchor is kept — is refused even
/// though its anchor matches the pin: the signature no longer covers it.
#[test]
fn tampered_context_keeping_the_anchor_is_refused() {
    let hub = build_hub("/home/bob");
    let bob = n("/home/bob");
    let trusted = anchor_fingerprint(&hub.anchor);

    let weakened = SignedTrustContext::accept_all(bob.clone()).with_version(1);
    weakened.add_anchor(hub.anchor.clone());
    assert_ne!(weakened.encode_content(), hub.published, "schema really changed");

    // (a) the genuine signature replayed over the weakened content…
    let genuine_sig = hub.published_data.sig_value().to_vec();
    let replayed = Data::decode(
        DataBuilder::new(weakened.rdr_name(), &weakened.encode_content()).sign_sync(
            SignatureType::SignatureEd25519,
            Some(&hub.anchor_key),
            |_| bytes::Bytes::from(genuine_sig.clone()),
        ),
    )
    .unwrap();
    // (b) …or the weakened content re-signed by another key claiming the root.
    let forger = ndn_security::Ed25519Signer::from_seed(&[9u8; 32], hub.anchor_key.clone());
    let resigned = weakened.sign_into_data(&forger).unwrap();

    let node = fresh_node();
    for tampered in [&replayed, &resigned] {
        assert!(
            matches!(
                adopt_with_tofu(node.keyring(), tampered, &bob, &trusted),
                Err(AdoptError::BadSignature(_))
            ),
            "tampered context must be refused"
        );
    }
    assert!(node.keyring().is_empty());
}

/// A pin for the wrong root, or the wrong namespace, refuses a genuine context.
#[test]
fn wrong_fingerprint_or_namespace_is_refused() {
    let hub = build_hub("/home/bob");
    let keyring = Keyring::new();
    assert!(matches!(
        adopt_with_tofu(&keyring, &hub.published_data, &n("/home/bob"), &[0u8; 32]),
        Err(AdoptError::FingerprintMismatch(_))
    ));
    assert!(matches!(
        adopt_with_tofu(
            &keyring,
            &hub.published_data,
            &n("/home/alice"),
            &anchor_fingerprint(&hub.anchor)
        ),
        Err(AdoptError::NamespaceMismatch { .. })
    ));
    assert!(keyring.is_empty());
}

/// Envelope routing: the signed inline form adopts; unsigned legacy content
/// and fingerprint-only envelopes are refused by default, and the unsigned
/// form needs the explicit legacy opt-in.
#[test]
fn envelope_adoption_requires_a_signed_inline_context() {
    let hub = build_hub("/home/bob");
    let fp = anchor_fingerprint(&hub.anchor);
    let anchor = |data: Option<&Data>, content: Option<&bytes::Bytes>| TrustEnvelope::Anchor {
        namespace: Some("/home/bob".into()),
        fingerprint: Some(fp),
        version: Some(1),
        context_data: data.map(|d| d.raw().clone()),
        context_content: content.cloned(),
    };
    let keyring = Keyring::new();

    assert!(matches!(
        adopt_anchor_envelope(&keyring, &anchor(None, Some(&hub.published))),
        Err(AdoptError::UnsignedLegacyContext)
    ));
    assert!(matches!(
        adopt_anchor_envelope(&keyring, &anchor(None, None)),
        Err(AdoptError::InlineContextRequired)
    ));
    assert!(keyring.is_empty(), "nothing adopted by default");

    let uri = anchor(Some(&hub.published_data), None).to_uri();
    let (ctx, data) =
        adopt_anchor_envelope(&keyring, &TrustEnvelope::from_uri(&uri).unwrap()).unwrap();
    assert_eq!(ctx.namespace(), &n("/home/bob"));
    assert_eq!(data.raw(), hub.published_data.raw());

    // The explicit, unverified legacy path still exists for operators who opt in.
    let legacy = Keyring::new();
    let ctx = SignedTrustContext::decode_content(&hub.published, 1).unwrap();
    adopt_unsigned_legacy_with_tofu(&legacy, ctx, &n("/home/bob"), &fp).unwrap();
    assert_eq!(legacy.version_of(&n("/home/bob")), Some(1));
}

/// A fresh node's keyring starts empty — adoption only happens via TOFU.
#[test]
fn fresh_node_keyring_starts_empty() {
    assert!(fresh_node().keyring().is_empty());
}
