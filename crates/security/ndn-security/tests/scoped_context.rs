//! A person's self-certifying namespace adopted for one scope alone
//! (data-layer.md §6.3, trust-context.md §4.5.7): a [`ScopedContext`], made
//! only from a checked genesis, judges that namespace's names through a view
//! of a keyring or validator, and nothing that judges by the keyring itself
//! ever sees it; a context of the namespace the keyring holds is used as is,
//! never replaced by the scoped one.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, SignatureType};
use ndn_security::self_certifying::{Genesis, self_certifying_name};
use ndn_security::{
    AdoptRefusal, Certificate, ScopedContext, SecurityManager, SignedTrustContext, TrustSchema,
    ValidationResult, Validator,
};

/// A person (from `seed`) whose keys `mgr` holds: their namespace, root key
/// and its self-signed anchor, and a phone key certified by the root.
struct Person {
    mgr: Arc<SecurityManager>,
    ns: Name,
    root: Name,
    anchor: Certificate,
    phone: Name,
    phone_cert: Certificate,
}

async fn person(seed: u8) -> Person {
    let mgr = Arc::new(SecurityManager::new());
    let secret = [seed; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&secret, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let root = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(root.clone(), &secret)
        .unwrap();
    let anchor = mgr
        .issue_self_signed(&root, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    let phone = ns.clone().append("phone").append("KEY").append("p");
    mgr.generate_ed25519(phone.clone()).unwrap();
    let phone_pk = mgr.get_signer_sync(&phone).unwrap().public_key().unwrap();
    let phone_cert = mgr
        .certify(&phone, phone_pk, &root, 3_600_000)
        .await
        .unwrap();
    Person {
        mgr,
        ns,
        root,
        anchor,
        phone,
        phone_cert,
    }
}

impl Person {
    /// The checked genesis: version 1 listing the root alone, signed by it
    /// (the same bytes each time: Ed25519 signs deterministically).
    async fn genesis(&self) -> Genesis {
        let ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(1);
        ctx.add_anchor(self.anchor.clone());
        let signer = self.mgr.get_signer_sync(&self.root).unwrap();
        let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
        Genesis::open_received(&data).await.unwrap()
    }

    /// Adopted for a scope at its genesis.
    async fn scoped(&self) -> ScopedContext {
        let g = self.genesis().await;
        let v1 = Arc::clone(g.context());
        ScopedContext::new(g, v1).unwrap()
    }

    /// Data named `rest` under the namespace, signed by `key` of `mgr`.
    fn data(&self, rest: &str, mgr: &SecurityManager, key: &Name) -> Data {
        let mut name = self.ns.clone();
        for c in rest.split('/').filter(|c| !c.is_empty()) {
            name = name.append(c);
        }
        let signer = mgr.get_signer_sync(key).unwrap();
        let wire = DataBuilder::new(name, b"payload").sign_sync(
            SignatureType::SignatureEd25519,
            Some(key),
            |region| signer.sign_sync(region).unwrap(),
        );
        Data::decode(wire).unwrap()
    }
}

/// Bob's node: his own namespace held from its genesis, a hierarchical
/// ambient schema, and the certificates of Alice's and Carol's phones in
/// its cache (as a fetch would have put them); his validator.
async fn bob(others: &[&Person]) -> (Person, Validator) {
    let bob = person(1).await;
    let g = bob.genesis().await;
    bob.mgr
        .keyring()
        .adopt_genesis(&g, Arc::clone(g.context()))
        .unwrap();
    bob.mgr
        .keyring()
        .ambient()
        .set_schema(TrustSchema::hierarchical());
    for o in others {
        bob.mgr.cert_cache().insert(o.phone_cert.clone());
    }
    let v = Validator::with_keyring(
        Arc::clone(bob.mgr.keyring()),
        bob.mgr.cert_cache_arc(),
        None,
        5,
    );
    (bob, v)
}

fn refusal(result: ValidationResult, what: &str) -> String {
    match result {
        ValidationResult::Invalid(e) => e.to_string(),
        other => panic!("{what} was not refused: {other:?}"),
    }
}

/// `result` does not accept the packet: refused, or waiting for a
/// certificate the context judging it would need (the held context does not
/// anchor the key, so it would look for a certificate of it).
fn not_accepted(result: ValidationResult, what: &str) {
    assert!(
        !matches!(result, ValidationResult::Valid(_)),
        "{what} was accepted: {result:?}"
    );
}

/// Alice's namespace, adopted for one scope at Bob's, verifies her Data
/// through the scoped view alone: Bob's validator and keyring never see it,
/// a view scoped to Carol refuses it, Carol's namespace stays refused
/// through Alice's view, and Bob's keys sign nothing in Alice's namespace
/// there. A version 1 other than the genesis is no scoped context.
#[tokio::test]
async fn a_scoped_context_judges_its_namespace_through_its_view_alone() {
    let alice = person(2).await;
    let carol = person(3).await;
    let (bob, base) = bob(&[&alice, &carol]).await;
    let not_genesis = ScopedContext::new(
        alice.genesis().await,
        Arc::new(SignedTrustContext::hierarchical(alice.ns.clone()).with_version(1)),
    );
    assert!(
        matches!(not_genesis, Err(AdoptRefusal::NotFromGenesis { .. })),
        "a version 1 other than the genesis was taken as scoped: {not_genesis:?}"
    );

    let view = base.scoped_view(&alice.scoped().await);
    let genuine = alice.data("phone/doc", &alice.mgr, &alice.phone);
    let through_view = view.validate_durable(&genuine).await;
    assert!(
        matches!(through_view, ValidationResult::Valid(_)),
        "Alice's genuine Data through the scoped view: {through_view:?}"
    );
    let why = refusal(
        base.validate_durable(&genuine).await,
        "Alice's Data through Bob's own validator",
    );
    assert!(
        why.contains(&alice.ns.to_string()) && why.contains("adopt"),
        "Bob's validator does not refuse Alice's namespace as one not held: {why}"
    );
    assert!(
        bob.mgr
            .keyring()
            .contexts()
            .iter()
            .all(|c| c.namespace() != &alice.ns)
            && bob.mgr.keyring().held_for(&genuine.name).is_none(),
        "Bob's keyring holds Alice's scoped namespace"
    );
    let carols_view = base.scoped_view(&carol.scoped().await);
    refusal(
        carols_view.validate_durable(&genuine).await,
        "Alice's Data through a view scoped to Carol",
    );
    refusal(
        view.validate_durable(&carol.data("phone/doc", &carol.mgr, &carol.phone))
            .await,
        "Carol's Data through the view scoped to Alice",
    );
    refusal(
        view.validate_durable(&alice.data("phone/doc", &bob.mgr, &bob.phone))
            .await,
        "Bob's key signing in Alice's namespace through the scoped view",
    );
}

/// A context of the namespace the keyring holds is used as is: a scoped
/// context never replaces it, whether the namespace was adopted after the
/// view was made or before.
#[tokio::test]
async fn a_held_context_is_used_as_is_over_a_scoped_one() {
    let alice = person(2).await;
    let (bob, base) = bob(&[&alice]).await;
    // The scoped version anchors one more key than the genesis.
    let extra = alice.ns.clone().append("KEY").append("extra");
    alice.mgr.generate_ed25519(extra.clone()).unwrap();
    let extra_pk = alice
        .mgr
        .get_signer_sync(&extra)
        .unwrap()
        .public_key()
        .unwrap();
    let v2 = SignedTrustContext::hierarchical(alice.ns.clone()).with_version(2);
    v2.add_anchor(alice.anchor.clone());
    v2.add_anchor(
        alice
            .mgr
            .issue_self_signed(&extra, extra_pk, u64::MAX)
            .unwrap(),
    );
    let scoped = ScopedContext::new(alice.genesis().await, Arc::new(v2)).unwrap();
    let by_extra = alice.data("doc", &alice.mgr, &extra);

    let view = base.scoped_view(&scoped);
    let before = view.validate_durable(&by_extra).await;
    assert!(
        matches!(before, ValidationResult::Valid(_)),
        "a key the scoped version anchors, nothing of the namespace held: {before:?}"
    );
    // Bob's node adopts Alice's namespace at its genesis: the held context
    // judges her names in the view from now on.
    let g = alice.genesis().await;
    bob.mgr
        .keyring()
        .adopt_genesis(&g, Arc::clone(g.context()))
        .unwrap();
    not_accepted(
        view.validate_durable(&by_extra).await,
        "a key only the scoped version anchors, once the node holds the namespace",
    );
    not_accepted(
        base.scoped_view(&scoped).validate_durable(&by_extra).await,
        "a key only the scoped version anchors, in a view made while the namespace is held",
    );
    assert_eq!(
        bob.mgr.keyring().held(&alice.ns).map(|c| c.version()),
        Some(1),
        "the held version was replaced"
    );
}

/// A scoped context moves on only to a version of its own namespace that is
/// not older, keeping its genesis: an older one is a rollback, another one
/// of the same number a fork.
#[tokio::test]
async fn a_scoped_context_moves_on_only_forward() {
    let alice = person(2).await;
    let carol = person(3).await;
    let scoped = alice.scoped().await;
    let version =
        |ns: &Name, v: u64| Arc::new(SignedTrustContext::hierarchical(ns.clone()).with_version(v));
    let v3 = version(&alice.ns, 3);
    let moved = scoped.moved_on(Arc::clone(&v3)).unwrap();
    assert_eq!(moved.context().version(), 3);
    assert_eq!(moved.genesis().namespace(), &alice.ns);
    assert!(moved.moved_on(v3).is_ok(), "the same version again");
    assert!(matches!(
        moved.moved_on(version(&alice.ns, 2)),
        Err(AdoptRefusal::Older { .. })
    ));
    let other3 = SignedTrustContext::hierarchical(alice.ns.clone()).with_version(3);
    other3.add_anchor(alice.anchor.clone());
    assert!(matches!(
        moved.moved_on(Arc::new(other3)),
        Err(AdoptRefusal::Fork { .. })
    ));
    assert!(matches!(
        moved.moved_on(version(&carol.ns, 4)),
        Err(AdoptRefusal::NotFromGenesis { .. })
    ));
}

/// A key Mallory makes up under `ns` (`<ns>/m/KEY/1`), its certificate
/// issued by Mallory herself and put in `cache` (as a fetch through a path
/// that carries the namespace unvalidated would), and Data `<ns>/m/doc` it
/// signs.
fn made_up_device(ns: &Name, cache: &ndn_security::CertCache) -> Data {
    let mallory = SecurityManager::new();
    let key = ns.clone().append("m").append("KEY").append("1");
    mallory.generate_ed25519(key.clone()).unwrap();
    let pk = mallory.get_signer_sync(&key).unwrap().public_key().unwrap();
    cache.insert(mallory.issue_self_signed(&key, pk, u64::MAX).unwrap());
    let signer = mallory.get_signer_sync(&key).unwrap();
    let name = ns.clone().append("m").append("doc");
    let wire = DataBuilder::new(name, b"payload").sign_sync(
        SignatureType::SignatureEd25519,
        Some(&key),
        |region| signer.sign_sync(region).unwrap(),
    );
    Data::decode(wire).unwrap()
}

/// A scoped view walks every packet to the anchors of the writer's context,
/// whatever the posture of the validator it is made from: a view made from
/// an accept-signed validator (a forwarder's, which an embedded data layer
/// verifies with) refuses a device Mallory made up under Carol's namespace,
/// whose certificate she issued herself, and accepts Carol's own phone
/// (trust-context.md §4.5.7).
#[tokio::test]
async fn a_scoped_view_of_an_accept_signed_validator_walks_to_the_anchors() {
    let carol = person(3).await;
    let (bob, base) = bob(&[&carol]).await;
    let base = base.accept_signed();
    let forged = made_up_device(&carol.ns, bob.mgr.cert_cache());
    let view = base.scoped_view(&carol.scoped().await);

    let genuine = carol.data("phone/doc", &carol.mgr, &carol.phone);
    let through_view = view.validate_durable(&genuine).await;
    assert!(
        matches!(through_view, ValidationResult::Valid(_)),
        "Carol's genuine Data through the view: {through_view:?}"
    );
    not_accepted(
        view.validate_durable(&forged).await,
        "Data of a device Mallory made up under Carol's namespace, through the view",
    );
    not_accepted(
        view.validate_chain(&forged).await,
        "the same Data, by the live rule",
    );
}

/// A held person's namespace is judged to its anchors under every posture:
/// an accept-signed validator refuses a device Mallory made up under Bob's
/// own namespace, whose certificate she issued herself, and accepts Bob's
/// phone, certified by his root (trust-context.md §4.5.6 note 4).
#[tokio::test]
async fn a_held_personal_namespace_walks_to_its_anchors_under_accept_signed() {
    let (bob, base) = bob(&[]).await;
    let base = base.accept_signed();
    let forged = made_up_device(&bob.ns, bob.mgr.cert_cache());
    bob.mgr.cert_cache().insert(bob.phone_cert.clone());

    let genuine = bob.data("phone/doc", &bob.mgr, &bob.phone);
    let result = base.validate_durable(&genuine).await;
    assert!(
        matches!(result, ValidationResult::Valid(_)),
        "Bob's phone in his own namespace: {result:?}"
    );
    not_accepted(
        base.validate_durable(&forged).await,
        "Data of a device Mallory made up under Bob's namespace",
    );
    not_accepted(
        base.validate_chain(&forged).await,
        "the same Data, by the live rule",
    );
}
