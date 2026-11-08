//! A person's self-certifying namespace `/user/<0xA1: …>` is judged only by
//! its own trust context (trust-context.md §4.5.6, §6.1). A node that does
//! not hold it refuses every packet in it — whatever its ambient anchors
//! (the forwarder's default profile loads every PIB anchor, the node's own
//! self-certifying root included), under the anchored and the accept-signed
//! posture, a DigestSha256 packet included — and says to adopt it by name.
//! Ordinary names under the shared `/user` are not vouched for by another
//! `/user/<x>`'s keys either.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name, NameComponent, SignatureType};
use ndn_security::safe_data::TrustPath;
use ndn_security::self_certifying::{Genesis, self_certifying_name};
use ndn_security::{
    Certificate, InterestValidationOutcome, SecurityManager, SignedTrustContext, TrustSchema,
    ValidationResult, Validator,
};

/// A person's key (from `seed`) held by `mgr`: their namespace, their root
/// key and its self-signed anchor (which `mgr` also adds to its ambient
/// anchors, as a PIB's trust anchors are loaded).
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, Certificate) {
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

/// The checked genesis of `ns`, its version 1 signed by its root `key`.
async fn genesis(mgr: &SecurityManager, ns: &Name, key: &Name, anchor: &Certificate) -> Genesis {
    let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
    ctx.add_anchor(anchor.clone());
    let signer = mgr.get_signer_sync(key).unwrap();
    let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
    Genesis::open_received(&data).await.unwrap()
}

/// A key `key` in `mgr`, certified by `issuer`; its certificate.
async fn certified(mgr: &SecurityManager, key: &Name, issuer: &Name) -> Certificate {
    mgr.generate_ed25519(key.clone()).unwrap();
    let pk = mgr.get_signer_sync(key).unwrap().public_key().unwrap();
    mgr.certify(key, pk, issuer, 3_600_000).await.unwrap()
}

fn data(mgr: &SecurityManager, name: &Name, key: &Name) -> Data {
    let signer = mgr.get_signer_sync(key).unwrap();
    let wire = DataBuilder::new(name.clone(), b"payload").sign_sync(
        SignatureType::SignatureEd25519,
        Some(key),
        |region| signer.sign_sync(region).unwrap(),
    );
    Data::decode(wire).unwrap()
}

fn interest(mgr: &SecurityManager, name: &Name, key: &Name) -> Interest {
    let signer = mgr.get_signer_sync(key).unwrap();
    let wire = InterestBuilder::new(name.clone())
        .app_parameters(b"cmd".to_vec())
        .sign_sync(SignatureType::SignatureEd25519, Some(key), |region| {
            signer.sign_sync(region).unwrap()
        });
    Interest::decode(wire).unwrap()
}

/// Bob's node as the forwarder's default profile builds it: his security
/// manager holds his own `/user/<hB>` (its genesis adopted, its root a PIB
/// trust anchor in the ambient context), the ambient schema is
/// hierarchical, and his phone's key is certified by his root.
struct Bob {
    mgr: Arc<SecurityManager>,
    phone: Name,
}

async fn bob() -> Bob {
    let mgr = Arc::new(SecurityManager::new());
    let (ns, root, anchor) = person(&mgr, 1);
    let g = genesis(&mgr, &ns, &root, &anchor).await;
    mgr.keyring()
        .adopt_genesis(&g, Arc::clone(g.context()))
        .unwrap();
    mgr.keyring()
        .ambient()
        .set_schema(TrustSchema::hierarchical());
    let phone = ns.append("phone").append("KEY").append("d");
    certified(&mgr, &phone, &root).await;
    Bob { mgr, phone }
}

fn validator(bob: &Bob) -> Validator {
    Validator::with_keyring(
        Arc::clone(bob.mgr.keyring()),
        bob.mgr.cert_cache_arc(),
        None,
        5,
    )
}

/// The refusal of `result`, or a panic saying what was not refused.
fn refusal(result: ValidationResult, what: &str) -> String {
    match result {
        ValidationResult::Invalid(e) => e.to_string(),
        other => panic!("{what} was not refused: {other:?}"),
    }
}

/// The refusal names the namespace not held and says to adopt it by name.
fn assert_says_adopt(why: &str, alice: &Name) {
    let ns = alice.to_string();
    assert!(
        why.contains(&ns) && why.contains("adopt"),
        "the refusal does not name {ns} and say to adopt it: {why}"
    );
}

#[tokio::test]
async fn a_key_of_another_person_never_vouches_for_a_namespace_not_held() {
    let bob = bob().await;
    let alice_mgr = SecurityManager::new();
    let (alice, _, _) = person(&alice_mgr, 2);
    let doc = alice.clone().append("doc");
    let forged = || data(&bob.mgr, &doc, &bob.phone);

    let v = validator(&bob);
    let why = refusal(v.validate_durable(&forged()).await, "durable");
    assert_says_adopt(&why, &alice);
    assert_says_adopt(&refusal(v.validate_chain(&forged()).await, "chain"), &alice);
    assert_says_adopt(&refusal(v.validate(&forged()).await, "single hop"), &alice);
    let (cached, missing) = v.validate_durable_cached(&forged()).await;
    assert!(missing.is_none(), "nothing to fetch for a refusal");
    assert_says_adopt(&refusal(cached, "cached durable"), &alice);

    // Signature only (the accept-signed posture) is no way around it.
    let accept_signed = validator(&bob).accept_signed();
    assert_says_adopt(
        &refusal(
            accept_signed.validate_durable(&forged()).await,
            "accept-signed",
        ),
        &alice,
    );

    // Nor is a signed command in her namespace.
    let cmd = interest(&bob.mgr, &alice.clone().append("cmd"), &bob.phone);
    match v.validate_interest_chain(&cmd).await {
        InterestValidationOutcome::Invalid(e) => assert_says_adopt(&e.to_string(), &alice),
        other => panic!("a signed Interest in a namespace not held was not refused: {other:?}"),
    }
}

/// A digest names no signer and vouches for nothing, so in a namespace not
/// held it passes integrity-only, as a digest does under every name — a
/// device's wrapped `32=held` answers and the namespace's RDR metadata
/// pointer are such packets, and the consumer checks what they carry — while
/// a signed packet there, among the namespace's trust objects included, is
/// still refused.
#[tokio::test]
async fn a_digest_packet_in_a_namespace_not_held_is_integrity_only() {
    let bob = bob().await;
    let alice_mgr = SecurityManager::new();
    let (alice, _, _) = person(&alice_mgr, 2);
    let keyword = |k: &'static [u8]| NameComponent::keyword(Bytes::from_static(k));
    let pointer = alice
        .clone()
        .append_component(keyword(b"trust-context"))
        .append_component(keyword(b"metadata"));
    let held = alice
        .clone()
        .append("laptop")
        .append_component(keyword(b"held"))
        .append("piece");
    let v = validator(&bob);
    for name in [alice.clone().append("doc"), held, pointer.clone()] {
        let digest = || Data::decode(DataBuilder::new(name.clone(), b"x").sign_digest_sha256());
        for (how, result) in [
            ("durable", v.validate_durable(&digest().unwrap()).await),
            ("single hop", v.validate(&digest().unwrap()).await),
        ] {
            match result {
                ValidationResult::Valid(safe) => assert!(
                    matches!(safe.trust_path(), TrustPath::DigestSha256),
                    "{name} ({how}) passed as more than integrity-only"
                ),
                other => panic!("a digest packet {name} ({how}) was refused: {other:?}"),
            }
        }
    }
    assert_says_adopt(
        &refusal(
            v.validate_durable(&data(&bob.mgr, &pointer, &bob.phone))
                .await,
            "a signed packet among the namespace's trust objects",
        ),
        &alice,
    );
}

/// Once Bob holds Alice's namespace (adopted from her genesis), her genuine
/// Data (her phone's, under its identity) verifies, and his keys still sign
/// nothing in it.
#[tokio::test]
async fn a_persons_data_verifies_once_their_namespace_is_held() {
    let bob = bob().await;
    let alice_mgr = SecurityManager::new();
    let (alice, root, anchor) = person(&alice_mgr, 2);
    let g = genesis(&alice_mgr, &alice, &root, &anchor).await;
    bob.mgr
        .keyring()
        .adopt_genesis(&g, Arc::clone(g.context()))
        .unwrap();
    let phone = alice.clone().append("phone").append("KEY").append("a");
    let cert = certified(&alice_mgr, &phone, &root).await;
    bob.mgr.cert_cache().insert(cert);
    let doc = alice.clone().append("phone").append("doc");

    let v = validator(&bob);
    let genuine = v.validate_durable(&data(&alice_mgr, &doc, &phone)).await;
    assert!(
        matches!(genuine, ValidationResult::Valid(_)),
        "Alice's genuine Data in her held namespace: {genuine:?}"
    );
    refusal(
        v.validate_durable(&data(&bob.mgr, &doc, &bob.phone)).await,
        "Bob's key in Alice's held namespace",
    );
}

/// `/user` is shared by every person, so an ordinary name under it
/// (`/user/alice/doc`) is not vouched for by the keys of another
/// `/user/<x>` in the ambient context: neither by signing it, nor by
/// certifying a key named for it. A key under `/user/alice` that is itself
/// a trust anchor still signs it.
#[tokio::test]
async fn keys_of_one_user_name_never_vouch_for_another_in_the_ambient_context() {
    let bob = bob().await;
    let doc: Name = "/user/alice/doc".parse().unwrap();
    let v = validator(&bob);
    refusal(
        v.validate_durable(&data(&bob.mgr, &doc, &bob.phone)).await,
        "/user/alice/doc signed by Bob's phone",
    );
    let posing: Name = "/user/alice/KEY/x".parse().unwrap();
    certified(&bob.mgr, &posing, &bob.phone).await;
    refusal(
        v.validate_durable(&data(&bob.mgr, &doc, &posing)).await,
        "/user/alice/doc signed by a key Bob's phone certified",
    );

    let own: Name = "/user/alice/KEY/own".parse().unwrap();
    bob.mgr.generate_ed25519(own.clone()).unwrap();
    let pk = bob.mgr.get_signer_sync(&own).unwrap().public_key().unwrap();
    bob.mgr.issue_self_signed(&own, pk, u64::MAX).unwrap();
    let genuine = v.validate_durable(&data(&bob.mgr, &doc, &own)).await;
    assert!(
        matches!(genuine, ValidationResult::Valid(_)),
        "/user/alice/doc signed by the anchor /user/alice/KEY/own: {genuine:?}"
    );
}
