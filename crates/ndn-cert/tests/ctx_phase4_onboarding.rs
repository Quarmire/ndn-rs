//! Phase 4 witnesses: adopt-to-verify with no CA, advert privacy, and
//! TOFU-gated adoption against flooded fake adverts.
//!
//! Backs `testbed/tests/audit/ctx0{1}_*.sh` and `ctx1{4,5}_*.sh`. See
//! `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §3–§7, §16.

use std::sync::Arc;

use dashmap::DashMap;
use ndn_cert::{AdvertConfig, AnchorAdvert, BootstrapTicket, adopt_with_tofu};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{
    Certificate, SecurityManager, TrustContext, TrustSchema, ValidationResult, Validator,
};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// A `/home/bob` hub: a self-signed anchor + a published (encoded) context.
struct Hub {
    mgr: SecurityManager,
    anchor_key: Name,
    anchor: Certificate,
    published: bytes::Bytes,
}

fn build_hub(namespace: &str) -> Hub {
    let mgr = SecurityManager::new();
    let anchor_key = n(&format!("{namespace}/KEY/root"));
    mgr.generate_ed25519(anchor_key.clone()).unwrap();
    let pk = mgr
        .get_signer_sync(&anchor_key)
        .unwrap()
        .public_key()
        .unwrap();
    let anchor = mgr.issue_self_signed(&anchor_key, pk, u64::MAX).unwrap();

    let ctx = TrustContext::hierarchical(n(namespace)).with_version(1);
    ctx.add_anchor(anchor.clone());
    let published = ctx.encode_content();

    Hub {
        mgr,
        anchor_key,
        anchor,
        published,
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
fn seed_anchors(v: &Validator, ctx: &TrustContext) {
    for r in ctx.anchors().iter() {
        v.cert_cache().insert(r.value().clone());
    }
}

/// CTX.01 (adopt-to-verify, no CA): a fresh node fetches `/home/bob`'s context,
/// TOFU-checks it against a scanned ticket, adopts it, and verifies a
/// Bob-signed Data — with **no** CA interaction.
#[tokio::test]
async fn ctx01_adopt_to_verify_no_ca() {
    let hub = build_hub("/home/bob");

    // Bob hands out a ticket (QR). It commits to the anchor fingerprint.
    let ticket = BootstrapTicket::new(&n("/home/bob"), &hub.anchor);
    let fragment = ticket.to_fragment();

    // ── Fresh node ──
    let parsed = BootstrapTicket::from_fragment(&fragment).unwrap();
    // "Fetch" the published context (in a deployment, RDR over a face).
    let ctx = Arc::new(TrustContext::decode_content(&hub.published, 1).unwrap());

    let node = fresh_node();
    seed_anchors(&node, &ctx);
    assert!(
        adopt_with_tofu(node.keyring(), Arc::clone(&ctx), &parsed),
        "context matching the ticket fingerprint must be adopted"
    );

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
    let ctx = TrustContext::hierarchical(n("/home/bob"));
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
    // The node trusts Bob's real fingerprint (from a scanned ticket).
    let trusted = BootstrapTicket::new(&n("/home/bob"), &hub.anchor);

    // An attacker floods a context for /home/bob rooted at THEIR own anchor.
    let attacker = SecurityManager::new();
    let evil_key = n("/home/bob/KEY/evil");
    attacker.generate_ed25519(evil_key.clone()).unwrap();
    let evil_pk = attacker
        .get_signer_sync(&evil_key)
        .unwrap()
        .public_key()
        .unwrap();
    let evil_anchor = attacker
        .issue_self_signed(&evil_key, evil_pk, u64::MAX)
        .unwrap();
    let evil_ctx = Arc::new(TrustContext::hierarchical(n("/home/bob")));
    evil_ctx.add_anchor(evil_anchor);

    let node = fresh_node();
    // TOFU against the trusted ticket rejects the forged context…
    assert!(
        !adopt_with_tofu(node.keyring(), Arc::clone(&evil_ctx), &trusted),
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
    let good = Arc::new(TrustContext::decode_content(&hub.published, 1).unwrap());
    assert!(adopt_with_tofu(node.keyring(), good, &trusted));
    assert_eq!(node.keyring().len(), 1);
}

/// A fresh node's keyring starts empty — adoption only happens via TOFU.
#[test]
fn fresh_node_keyring_starts_empty() {
    assert!(fresh_node().keyring().is_empty());
}
