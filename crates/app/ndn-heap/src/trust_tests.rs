//! Tests of the validator bridge and the adoption of persons per space.
//!
//! The adopter is a host that adopts as the real ones do
//! (`ndn_cert::adopt_scoped`) over a network serving what the test gives it;
//! the validators are real, built as `ndn-security`'s own tests build them.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, SignatureType};
use ndn_security::self_certifying::self_certifying_name;
use ndn_security::{
    CertCache, Certificate, Ed25519Signer, Keyring, RevocationCut, ScopedContext, SecurityManager,
    SignedTrustContext, Signer, TrustSchema, Validator,
};
use ndn_sync::{DataStore, MemoryStore};

use super::*;
use crate::error::{Cut, Refusal};
use crate::wire::{log_name, seal_key_name};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// What a host's network serves of persons' trust contexts: each Interest
/// whose name equals a registered name is answered with that Data.
struct Net(Vec<(Name, Bytes)>);

impl ndn_cert::CaExchange for Net {
    fn express(
        &mut self,
        interest: Bytes,
    ) -> impl Future<Output = Result<Data, ndn_cert::CertError>> + Send {
        let interest = Interest::decode(interest).expect("a well-formed Interest");
        let reply = self
            .0
            .iter()
            .find(|(name, _)| *name == *interest.name)
            .map(|(_, wire)| Data::decode(wire.clone()).expect("a well-formed Data"))
            .ok_or_else(|| {
                ndn_cert::CertError::Transport(format!("no reply for {}", interest.name))
            });
        std::future::ready(reply)
    }
}

/// A host that adopts as the hosts do, over a network serving what the test
/// gives it, and carries in transit what it adopted until released.
#[derive(Default)]
struct Host {
    net: std::sync::Mutex<Vec<(Name, Bytes)>>,
    asked: std::sync::Mutex<Vec<(Name, Option<u64>)>>,
    carried: std::sync::Mutex<BTreeSet<Name>>,
}

impl Host {
    /// The network now serves `versions` (signed context Data) and, as the
    /// newest of their namespace, the last.
    fn serve(&self, versions: &[&Data]) {
        let mut net = Vec::new();
        if let Some(newest) = versions.last() {
            let ns = ndn_security::self_certifying::personal_namespace_of(&newest.name).unwrap();
            let asked = ndn_cert::rdr_metadata_name(&ns);
            let named = asked.clone().append_version(1).append_segment(0);
            net.push((
                asked,
                DataBuilder::new(named, &newest.name.encode_to_tlv()).build(),
            ));
        }
        for v in versions {
            net.push(((*v.name).clone(), v.raw().clone()));
        }
        *self.net.lock().unwrap() = net;
    }

    fn asked(&self) -> BTreeSet<Name> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The version held each adoption of `ns` was asked from.
    fn asked_from(&self, ns: &Name) -> Vec<Option<u64>> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == ns)
            .map(|(_, v)| *v)
            .collect()
    }

    fn carries(&self, ns: &Name) -> bool {
        self.carried.lock().unwrap().contains(ns)
    }
}

impl Adopter for Host {
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        self.asked
            .lock()
            .unwrap()
            .push((namespace.clone(), held.map(|h| h.context().version())));
        let mut net = Net(self.net.lock().unwrap().clone());
        Box::pin(async move {
            let got = ndn_cert::adopt_scoped(None, &mut net, namespace, held)
                .await
                .map_err(|e| e.to_string())?;
            self.carried.lock().unwrap().insert(namespace.clone());
            Ok(got)
        })
    }

    fn release_scoped(&self, namespace: &Name) {
        self.carried.lock().unwrap().remove(namespace);
    }
}

/// A validator of Alice's node, holding Alice's namespace and no person's.
fn alice_validator() -> Arc<Validator> {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    validator
}

fn space() -> Name {
    n("/alice/32=data/docs")
}

fn other_space() -> Name {
    n("/alice/32=data/other")
}

/// Alice's judge over `store`, adopting through `host`, restored, with the
/// stream of what the log re-checks on.
async fn judge_and_events(
    host: &Arc<Host>,
    store: &Arc<dyn DataStore>,
) -> (Arc<Judge>, mpsc::UnboundedReceiver<Adoption>) {
    let (judge, events) = Judge::new(
        alice_validator(),
        Arc::clone(store),
        Some(Arc::clone(host) as Arc<dyn Adopter>),
    );
    judge.restore().await;
    (judge, events)
}

/// [`judge_and_events`], the events left unread.
async fn judge_of(host: &Arc<Host>, store: &Arc<dyn DataStore>) -> Arc<Judge> {
    judge_and_events(host, store).await.0
}

fn writers(persons: &[&Name]) -> Listing {
    Listing {
        writers: persons.iter().map(|p| (*p).clone()).collect(),
        ..Listing::default()
    }
}

/// A person's namespace, by a made-up key.
fn user(i: u8) -> Name {
    self_certifying_name(&[i; 32])
}

/// A person's root key (from `seed`) in `mgr`: the namespace it names, the
/// key's name and its self-signed anchor.
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, Certificate) {
    let seed = [seed; 32];
    let pk = Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let key = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(key.clone(), &seed).unwrap();
    let anchor = mgr
        .issue_self_signed(&key, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    (ns, key, anchor)
}

/// Carol's namespace with two root keys: `k1`, which names it, and `k2`,
/// which her versions hand the root over to.
struct Carol {
    mgr: SecurityManager,
    ns: Name,
    k1: (Name, Certificate),
    k2: (Name, Certificate),
}

impl Carol {
    fn new() -> Carol {
        let mgr = SecurityManager::new();
        let (ns, k1, a1) = person(&mgr, 0xc0);
        let k2 = ns.clone().append("KEY").append("k2");
        mgr.generate_ed25519_from_seed(k2.clone(), &[0xc2; 32])
            .unwrap();
        let pk2 = Ed25519Signer::from_seed(&[0xc2; 32], Name::root()).public_key_bytes();
        let a2 = mgr
            .issue_self_signed(&k2, Bytes::copy_from_slice(&pk2), u64::MAX)
            .unwrap();
        Carol {
            mgr,
            ns,
            k1: (k1, a1),
            k2: (k2, a2),
        }
    }

    /// Version `v` of her context anchored at `anchors`, signed by `by`
    /// (one of them): `extra` tells apart two versions of one number.
    async fn version(
        &self,
        v: u64,
        anchors: &[&Certificate],
        by: &Name,
        extra: Option<&str>,
    ) -> Data {
        let mut ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(v);
        if let Some(x) = extra {
            ctx = ctx.with_ca_endpoint(self.ns.clone().append(x));
        }
        for a in anchors {
            assert!(ctx.add_anchor((*a).clone()));
        }
        let signer = self.mgr.get_signer_sync(by).unwrap();
        let wire = ctx
            .sign_into_data_async(signer.as_ref())
            .await
            .unwrap()
            .raw()
            .clone();
        Data::decode(wire).unwrap()
    }

    /// Her genesis, served by a host from the start.
    async fn genesis(&self) -> Data {
        let (k1, a1) = &self.k1;
        self.version(1, &[a1], k1, None).await
    }
}

/// A device of a person's namespace: its key, certified by the person's
/// root key, which a context of the namespace anchors.
struct Phone {
    name: Name,
    key: Name,
    keys: SecurityManager,
    cert: Certificate,
}

impl Phone {
    /// `<ns>/<role>/<label>`, its key certified by `issuer` of `authority`.
    async fn new(
        authority: &SecurityManager,
        ns: &Name,
        issuer: &Name,
        role: &str,
        label: &str,
    ) -> Phone {
        let name = ns.clone().append(role).append(label);
        let keys = SecurityManager::new();
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = authority
            .certify(&key, public, issuer, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        Phone {
            name,
            key,
            keys,
            cert,
        }
    }

    /// A packet named `name` with `content`, signed by this device's key.
    fn signs(&self, name: &Name, content: &[u8]) -> Data {
        let signer = self.keys.get_signer_sync(&self.key).unwrap();
        let wire = DataBuilder::new(name.clone(), content).sign_sync(
            signer.sig_type(),
            Some(&self.key),
            |region| signer.sign_sync(region).unwrap(),
        );
        Data::decode(wire).unwrap()
    }

    /// Its entry `seq` of `space`, signed by it.
    fn entry(&self, space: &Name, seq: u64) -> Data {
        self.signs(&log_name(&self.name, space, seq), b"entry")
    }

    fn key_digest(&self) -> [u8; 32] {
        let public = self
            .keys
            .get_signer_sync(&self.key)
            .unwrap()
            .public_key()
            .unwrap();
        ndn_security::public_key_digest(&public)
    }
}

/// Wait, in paused time, until `f` holds or `secs` pass.
async fn until(mut f: impl FnMut() -> bool, secs: u64) -> bool {
    for _ in 0..secs * 10 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f()
}

/// Alice's judge, which has adopted Carol for `space()` by a listing, and
/// Carol's `phone`, whose certificate it holds.
async fn adopting(carol: &Carol, phone: &Phone) -> (Arc<Host>, Arc<Judge>) {
    let host = Arc::new(Host::default());
    host.serve(&[&carol.genesis().await]);
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let judge = judge_of(&host, &store).await;
    judge.validator.cert_cache().insert(phone.cert.clone());
    judge.note(&space(), &writers(&[&n("/alice"), &carol.ns]));
    assert!(
        until(|| judge.adopted_version(&carol.ns).is_some(), 30).await,
        "precondition: Carol is adopted for the space"
    );
    (host, judge)
}

fn valid(judged: Judged) -> Verified {
    match judged {
        Judged::Valid(v) => v,
        other => panic!("not valid: {other:?}"),
    }
}

// ---- adoption of persons per space (spec §9) ---------------------------------------------------

/// The listed person's entries are judged by the view adopted for the space
/// that lists her, and nowhere else: the same device's entry about another
/// space waits, for no fold of that space lists her.
#[tokio::test(start_paused = true)]
async fn a_person_listed_by_a_members_entry_is_adopted_for_that_space_only() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let (host, judge) = adopting(&carol, &phone).await;

    let verified = valid(judge.validate(&phone.entry(&space(), 1), &space()).await);
    assert_eq!(verified.person, carol.ns, "her namespace's context vouched");
    assert_eq!(verified.device, phone.name);
    assert_eq!(verified.key, phone.key);
    assert_eq!(verified.key_digest, phone.key_digest());

    let waiting = judge
        .validate(&phone.entry(&other_space(), 1), &other_space())
        .await;
    assert!(
        matches!(&waiting, Judged::Pending(Waiting::Adoption(p)) if *p == carol.ns),
        "a space that does not list her has no view of hers: {waiting:?}"
    );
    assert_eq!(host.asked(), BTreeSet::from([carol.ns.clone()]));
}

/// The persons no listing keeps are handed back to the host, and judged by
/// no view any more.
#[tokio::test(start_paused = true)]
async fn a_person_no_fold_lists_is_released() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let (host, judge) = adopting(&carol, &phone).await;
    assert!(host.carries(&carol.ns));

    // One of two spaces drops her: the other still lists her.
    judge.note(&other_space(), &writers(&[&carol.ns]));
    judge.note(&space(), &writers(&[&n("/alice")]));
    assert!(host.carries(&carol.ns), "another space lists her still");

    judge.note(&other_space(), &Listing::default());
    assert!(!host.carries(&carol.ns), "no fold lists her: released");
    assert_eq!(judge.adopted_version(&carol.ns), None);
    let waiting = judge.validate(&phone.entry(&space(), 1), &space()).await;
    assert!(
        matches!(&waiting, Judged::Pending(Waiting::Adoption(p)) if *p == carol.ns),
        "{waiting:?}"
    );
}

/// A person of an unheld namespace waits for adoption (the log judges her
/// entries again once she is adopted); without a host that adopts, she waits
/// for ever, and nothing of hers is taken.
#[tokio::test(start_paused = true)]
async fn an_unheld_person_is_judged_pending_until_adopted() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let host = Arc::new(Host::default());
    host.serve(&[&carol.genesis().await]);
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let (judge, mut events) = judge_and_events(&host, &store).await;
    judge.validator.cert_cache().insert(phone.cert.clone());
    let entry = phone.entry(&space(), 1);

    let before = judge.validate(&entry, &space()).await;
    assert!(
        matches!(&before, Judged::Pending(Waiting::Adoption(p)) if *p == carol.ns),
        "{before:?}"
    );
    judge.note(&space(), &writers(&[&carol.ns]));
    assert!(until(|| judge.adopted_version(&carol.ns).is_some(), 30).await);
    valid(judge.validate(&entry, &space()).await);
    match events.recv().await {
        Some(Adoption::Person {
            person,
            spaces,
            refuses,
        }) => {
            assert_eq!(person, carol.ns);
            assert_eq!(spaces, vec![space()], "the log judges that space again");
            assert!(refuses, "a first adoption may refuse what was taken");
        }
        other => panic!("announced: {other:?}"),
    }

    let (hostless, _) = Judge::new(alice_validator(), Arc::clone(&store), None);
    hostless.restore().await;
    hostless.note(&space(), &writers(&[&carol.ns]));
    tokio::time::sleep(Duration::from_secs(120)).await;
    let waiting = hostless.validate(&entry, &space()).await;
    assert!(
        matches!(&waiting, Judged::Pending(Waiting::Adoption(_))),
        "{waiting:?}"
    );
}

/// Carol is adopted at version 3 of her context, whose versions 2 and 3 hand
/// her root over from `k1` to `k2`. After a restart the judge holds version 3
/// at once and refreshes from it, never from the genesis again: a thief
/// holding `k1` who serves a branch from version 1 numbered past it is
/// refused, a path serving only version 1 is refused, and Carol's own
/// version 4, once reachable, is adopted from version 3.
#[tokio::test(start_paused = true)]
async fn adoption_survives_a_restart() {
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let carol = Carol::new();
    let ns = carol.ns.clone();
    let ((k1, a1), (k2, a2)) = (&carol.k1, &carol.k2);
    let v1 = carol.version(1, &[a1], k1, None).await;
    let v2 = carol.version(2, &[a1, a2], k1, None).await;
    let v3 = carol.version(3, &[a2], k2, None).await;
    let host = Arc::new(Host::default());
    host.serve(&[&v1, &v2, &v3]);
    let judge = judge_of(&host, &store).await;
    judge.note(&space(), &writers(&[&ns]));
    assert!(
        until(|| judge.adopted_version(&ns) == Some(3), 30).await,
        "precondition: Carol is adopted at version 3"
    );
    drop(judge);

    // The thief's branch, from version 1, numbered past version 3.
    let t2 = carol.version(2, &[a1], k1, Some("thief")).await;
    let t3 = carol.version(3, &[a1], k1, Some("thief")).await;
    let t4 = carol.version(4, &[a1], k1, Some("thief")).await;
    let host = Arc::new(Host::default());
    host.serve(&[&v1, &t2, &t3, &t4]);
    let alice = alice_validator();
    let (judge, _) = Judge::new(
        alice,
        Arc::clone(&store),
        Some(Arc::clone(&host) as Arc<dyn Adopter>),
    );
    judge.note(&space(), &writers(&[&ns]));
    judge.restore().await;
    assert_eq!(
        judge.adopted_version(&ns),
        Some(3),
        "the version kept judges again from the start"
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        judge.adopted_version(&ns),
        Some(3),
        "a branch numbered past the version kept that does not descend from it is refused"
    );
    let from = host.asked_from(&ns);
    assert!(
        !from.is_empty() && from.iter().all(|v| *v == Some(3)),
        "refreshed from the version kept, never from the genesis: {from:?}"
    );
    assert!(
        !host.carries(&ns),
        "a failed refresh leaves nothing carried"
    );
    drop(judge);

    // A path serving only version 1.
    let host = Arc::new(Host::default());
    host.serve(&[&v1]);
    let (judge, _) = Judge::new(
        alice_validator(),
        Arc::clone(&store),
        Some(Arc::clone(&host) as Arc<dyn Adopter>),
    );
    judge.note(&space(), &writers(&[&ns]));
    judge.restore().await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        judge.adopted_version(&ns),
        Some(3),
        "an older version is refused"
    );

    // Carol's own version 4 becomes reachable.
    let v4 = carol.version(4, &[a2], k2, None).await;
    host.serve(&[&v1, &v2, &v3, &v4]);
    assert!(
        until(|| judge.adopted_version(&ns) == Some(4), 300).await,
        "her next version is adopted from the version kept"
    );
    assert!(
        host.carries(&ns),
        "a refresh from a restored version has the host carry the namespace in transit"
    );
}

/// What was adopted judges at once after a restart, with no host reachable.
#[tokio::test(start_paused = true)]
async fn an_adopted_person_judges_at_once_after_a_restart_with_no_host_reachable() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let host = Arc::new(Host::default());
    host.serve(&[&carol.genesis().await]);
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let judge = judge_of(&host, &store).await;
    judge.note(&space(), &writers(&[&carol.ns]));
    assert!(until(|| judge.adopted_version(&carol.ns).is_some(), 30).await);
    drop(judge);

    let silent = Arc::new(Host::default());
    let (judge, _) = Judge::new(
        alice_validator(),
        Arc::clone(&store),
        Some(Arc::clone(&silent) as Arc<dyn Adopter>),
    );
    judge.validator.cert_cache().insert(phone.cert.clone());
    judge.note(&space(), &writers(&[&carol.ns]));
    judge.restore().await;
    valid(judge.validate(&phone.entry(&space(), 1), &space()).await);
}

// ---- a listed person's own devices ------------------------------------------------------------

/// What a device of a person a space lists is judged for: its seal key, as
/// that very device's own packet, and only for a person listed as a member
/// of the space; the same person kept only by a removal cut verifies her
/// entries, and no seal key.
#[tokio::test(start_paused = true)]
async fn a_listed_writers_own_device_packets_verify_and_nothing_else_of_hers_does() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let tablet = Phone::new(&carol.mgr, &carol.ns, k1, "member", "tablet").await;
    let (_, judge) = adopting(&carol, &phone).await;
    judge.validator.cert_cache().insert(tablet.cert.clone());
    let pk = [9u8; 32];
    let seal = seal_key_name(&phone.name, &pk);
    let packet = phone.signs(&seal, &pk);

    let verified = valid(
        judge
            .validate_device_packet(&packet, &phone.name, &space())
            .await,
    );
    assert_eq!(verified.key, phone.key);
    assert_eq!(verified.person, carol.ns);

    // Signed by another device of her namespace: the schema refuses it
    // (a key signs only under its own name).
    let forged = tablet.signs(&seal, &pk);
    let judged = judge
        .validate_device_packet(&forged, &phone.name, &space())
        .await;
    assert!(
        matches!(judged, Judged::Refused(_)),
        "a packet under the phone's name signed by the tablet's key: {judged:?}"
    );
    // Signed by a key the schema lets sign for it, the namespace's root key,
    // which belongs to no device: it is not that device's packet.
    let root = carol.mgr.get_signer_sync(k1).unwrap();
    let wire = DataBuilder::new(seal.clone(), &pk).sign_sync(root.sig_type(), Some(k1), |region| {
        root.sign_sync(region).unwrap()
    });
    let by_root = Data::decode(wire).unwrap();
    let judged = judge
        .validate_device_packet(&by_root, &phone.name, &space())
        .await;
    assert!(
        matches!(judged, Judged::Refused(Refusal::BadSignature)),
        "a packet under the phone's name signed by a key of another device: {judged:?}"
    );
    // Her seal key is no seal key of another space's.
    let elsewhere = judge
        .validate_device_packet(&packet, &phone.name, &other_space())
        .await;
    assert!(
        matches!(elsewhere, Judged::Pending(Waiting::Adoption(_))),
        "{elsewhere:?}"
    );

    // Kept only by a removal cut: her entries verify, her seal key is not
    // judged.
    judge.note(
        &space(),
        &Listing {
            writers: vec![n("/alice")],
            cut: vec![carol.ns.clone()],
            ..Listing::default()
        },
    );
    valid(judge.validate(&phone.entry(&space(), 1), &space()).await);
    let cut_only = judge
        .validate_device_packet(&packet, &phone.name, &space())
        .await;
    assert!(
        matches!(cut_only, Judged::Pending(Waiting::Adoption(_))),
        "a namespace kept only by a removal cut is no member: {cut_only:?}"
    );
}

/// A person no listing names is no signer: her device's packets wait for her
/// adoption, though her chain is her genesis-bound one.
#[tokio::test(start_paused = true)]
async fn a_person_no_listing_names_has_nothing_judged() {
    let carol = Carol::new();
    let (k1, _) = &carol.k1;
    let dave_mgr = SecurityManager::new();
    let dave = person(&dave_mgr, 0xd0);
    let phone = Phone::new(&carol.mgr, &carol.ns, k1, "member", "phone").await;
    let daves = Phone::new(&dave_mgr, &dave.0, &dave.1, "member", "phone").await;
    let (_, judge) = adopting(&carol, &phone).await;
    judge.validator.cert_cache().insert(daves.cert.clone());
    let judged = judge.validate(&daves.entry(&space(), 1), &space()).await;
    assert!(
        matches!(&judged, Judged::Pending(Waiting::Adoption(p)) if *p == dave.0),
        "{judged:?}"
    );
}

// ---- the caps ---------------------------------------------------------------------------------

/// A space lists at most `SCOPE_PER_SPACE` persons for adoption, the first it
/// lists (writers, then readers, then those kept by a cut), and the rest are
/// warned of once, with why and what to do; all spaces together list at most
/// `SCOPE_NAMESPACES`, the spaces served in name order.
#[test]
fn a_listing_past_the_caps_adopts_the_first_and_warns_once_of_the_rest() {
    let mut scopes = Scopes::default();
    let people: Vec<Name> = (0..100).map(user).collect();
    let listing = Listing {
        writers: people[..50].to_vec(),
        readers: people[50..90].to_vec(),
        cut: people[90..].to_vec(),
    };
    let warning = scopes.note(&space(), &listing).expect("one warning");
    assert!(
        warning.contains(&format!("{} are past", 100 - SCOPE_PER_SPACE))
            && warning.contains("too many")
            && warning.contains("list fewer"),
        "why, and what to do: {warning}"
    );
    assert_eq!(
        scopes.listed.keys().cloned().collect::<BTreeSet<_>>(),
        people[..SCOPE_PER_SPACE].iter().cloned().collect(),
        "the first the listing names"
    );
    assert!(
        scopes.note(&space(), &listing).is_none(),
        "warned once, not on every note of the same listing"
    );

    // Five spaces of 60 distinct persons each: 300 listed, 256 kept, the
    // spaces served in name order whatever order they were noted in.
    let mut scopes = Scopes::default();
    let spaces: Vec<Name> = (0..5).map(|i| n(&format!("/alice/32=data/s{i}"))).collect();
    let distinct = |i: usize, j: usize| {
        let mut key = [0u8; 32];
        key[0] = i as u8;
        key[1] = j as u8;
        self_certifying_name(&key)
    };
    for (i, s) in spaces.iter().enumerate().rev() {
        let persons: Vec<Name> = (0..60).map(|j| distinct(i, j)).collect();
        scopes.note(
            s,
            &Listing {
                writers: persons,
                ..Listing::default()
            },
        );
    }
    assert_eq!(scopes.listed.len(), SCOPE_NAMESPACES);
    assert_eq!(scopes.over, 300 - SCOPE_NAMESPACES);
    assert!(
        (0..60).all(|j| scopes.listed.contains_key(&distinct(0, j)))
            && (0..16).all(|j| scopes.listed.contains_key(&distinct(4, j)))
            && (16..60).all(|j| !scopes.listed.contains_key(&distinct(4, j))),
        "the cap falls on the last space by name, on the persons it lists last"
    );
}

// ---- the validator's verdicts (spec §9) --------------------------------------------------------

/// 2001-09-09, a NotBefore long past.
const PAST: u64 = 1_000_000_000_000_000_000;
/// 2017-07-14, a NotAfter long past.
const EXPIRED: u64 = 1_500_000_000_000_000_000;
const DEVICE: &str = "/home/bob/member/phone";
const PHONE_KEY: &str = "/home/bob/member/phone/KEY/k1";
const CA_KEY: &str = "/home/bob/CA/KEY/ca";

fn signer(name: &str, seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32], n(name))
}

/// The certificate `<key>/<issuer-id>/v=1` of `subject`, issued by `issuer`.
async fn cert(
    subject: &Ed25519Signer,
    issuer: &Ed25519Signer,
    issuer_id: &str,
    from: u64,
    until: u64,
) -> Certificate {
    let wire = ndn_security::manager::encode_cert_data(
        &subject
            .key_name()
            .clone()
            .append(issuer_id)
            .append_version(1),
        &subject.public_key_bytes(),
        issuer,
        from,
        until,
    )
    .await
    .unwrap();
    Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
}

fn signed(name: Name, by: &Ed25519Signer) -> Data {
    let wire = DataBuilder::new(name, b"v").sign_sync(
        SignatureType::SignatureEd25519,
        Some(by.key_name()),
        |region| by.sign_sync(region).unwrap(),
    );
    Data::decode(wire).unwrap()
}

fn bob_space() -> Name {
    n("/home/bob/32=data/notes")
}

fn bob_entry(seq: u64, by: &Ed25519Signer) -> Data {
    signed(log_name(&n(DEVICE), &bob_space(), seq), by)
}

/// The prefix a revocation cut's range names for Bob's phone's log of the
/// space: the entry name without its seq.
fn bob_log_prefix() -> Name {
    let entry = log_name(&n(DEVICE), &bob_space(), 0);
    Name::from_components(entry.components()[..entry.len() - 1].iter().cloned())
}

/// [`bob`], with the stream of what the log re-checks on.
async fn bob_and_events(
    leaf: (u64, u64),
    edit: impl FnOnce(SignedTrustContext) -> SignedTrustContext,
) -> (Arc<Judge>, mpsc::UnboundedReceiver<Adoption>, Ed25519Signer) {
    let root = signer("/home/bob/KEY/root", 70);
    let ca = signer(CA_KEY, 71);
    let phone = signer(PHONE_KEY, 72);
    let anchor = cert(&root, &root, "self", PAST, u64::MAX).await;
    let ca_cert = cert(&ca, &root, "root", PAST, u64::MAX).await;
    let leaf = cert(&phone, &ca, "CA", leaf.0, leaf.1).await;
    let ctx = edit(
        SignedTrustContext::hierarchical(n("/home/bob"))
            .with_ca_endpoint(n("/home/bob/CA"))
            .with_version(1),
    );
    ctx.anchors().insert(Arc::clone(&anchor.name), anchor);
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::new(ctx)).unwrap();
    let cache = Arc::new(CertCache::new());
    cache.insert(ca_cert);
    cache.insert(leaf);
    let validator = Arc::new(Validator::with_keyring(keyring, cache, None, 5));
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let (judge, events) = Judge::new(validator, store, None);
    (judge, events, phone)
}

/// A judge over the namespace `/home/bob`: root `/home/bob/KEY/root`, CA
/// `/home/bob/CA/KEY/ca` certified by the root, the phone's key certified by
/// the CA, valid `leaf`; `edit` shapes the context (revocations, cuts).
async fn bob(
    leaf: (u64, u64),
    edit: impl FnOnce(SignedTrustContext) -> SignedTrustContext,
) -> (Arc<Judge>, Ed25519Signer) {
    let (judge, _, phone) = bob_and_events(leaf, edit).await;
    (judge, phone)
}

/// A packet signed by a key of the namespace the node holds is ok, names the
/// digest of the public key that verified it, and the person is the
/// namespace of the context that vouched for the key.
#[tokio::test]
async fn a_signer_of_a_held_namespace_is_valid_and_named() {
    let (judge, phone) = bob((PAST, u64::MAX), |c| c).await;
    let v = valid(judge.validate(&bob_entry(1, &phone), &bob_space()).await);
    assert_eq!(v.person, n("/home/bob"));
    assert_eq!(v.device, n(DEVICE));
    assert_eq!(v.key, n(PHONE_KEY));
    assert_eq!(
        v.key_digest,
        ndn_security::public_key_digest(&phone.public_key_bytes())
    );
}

/// In a namespace that declares the role layout (its schema is authoritative: the generated
/// namespace schema, a marker the root signs), only `admin` and `member` devices are owner
/// devices; a guest, a node, any other role and a device with no role are not, whatever the
/// `DataRequiresCut` list says. A flat namespace tells its devices apart by nothing: all are.
#[test]
fn only_admin_and_member_devices_are_owner_devices_in_a_role_layout() {
    let layout = |cut: &[&str]| {
        let mut ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(1)
            .schema_authoritative();
        for role in cut {
            ctx = ctx.with_data_requires_cut(*role);
        }
        ctx
    };
    let key = |role: &str| n(&format!("/home/bob/{role}/phone/KEY/k1"));
    for ctx in [
        layout(&[]),
        layout(&["guest"]),
        layout(&["admin", "member", "node", "guest"]),
    ] {
        for (role, expected) in [
            ("admin", true),
            ("member", true),
            ("guest", false),
            ("node", false),
            ("shared", false),
            ("phone", false),
        ] {
            assert_eq!(owner_capable(&ctx, &key(role)), expected, "{role}");
        }
        assert!(
            !owner_capable(&ctx, &n("/home/bob/phone/KEY/k1")),
            "a device with no role in a role layout is none, even with the list narrowed to nothing"
        );
    }
    let flat = SignedTrustContext::hierarchical(n("/home/bob")).with_version(1);
    assert!(owner_capable(&flat, &key("guest")));
    assert!(owner_capable(&flat, &n("/home/bob/phone/KEY/k1")));
}

/// The judge decides it once, from the context that governs the key: a verified member device
/// carries it, and asked by name or key the judge says the same of any device.
#[tokio::test]
async fn the_judge_says_whether_a_device_is_an_owner_device() {
    let (judge, phone) = bob((PAST, u64::MAX), |c| c).await;
    let v = valid(judge.validate(&bob_entry(1, &phone), &bob_space()).await);
    assert!(v.owner_capable, "a flat namespace's device");

    let (judge, phone) = bob((PAST, u64::MAX), |c| c.schema_authoritative()).await;
    let v = valid(judge.validate(&bob_entry(1, &phone), &bob_space()).await);
    assert!(v.owner_capable, "{DEVICE} is a member device");
    assert!(judge.owner_capable(&n(PHONE_KEY), &bob_space()));
    assert!(!judge.owner_capable(&n("/home/bob/guest/phone/KEY/k1"), &bob_space()));
    assert!(!judge.owner_capable(&n("/home/bob/node/vps"), &bob_space()));
}

/// A key revoked with a cut refuses what the cut does not accept as outside
/// the cut, and the cut names the tip it keeps; with no cut it keeps nothing.
#[tokio::test]
async fn a_revoked_key_is_outside_its_cut() {
    let mut cut = RevocationCut::new(n(PHONE_KEY));
    cut.add_run(&bob_log_prefix(), 1, 3);
    let (judge, phone) = bob((PAST, u64::MAX), |c| {
        c.with_revocation(n(PHONE_KEY)).with_revocation_cut(cut)
    })
    .await;
    valid(judge.validate(&bob_entry(2, &phone), &bob_space()).await);
    match judge.validate(&bob_entry(4, &phone), &bob_space()).await {
        Judged::Refused(Refusal::OutsideCut(Cut { device, keeps_to })) => {
            assert_eq!(device, n(DEVICE));
            assert_eq!(keeps_to, 3, "the cut keeps the chain up to seq 3");
        }
        other => panic!("{other:?}"),
    }

    let (judge, phone) = bob((PAST, u64::MAX), |c| c.with_revocation(n(PHONE_KEY))).await;
    match judge.validate(&bob_entry(1, &phone), &bob_space()).await {
        Judged::Refused(Refusal::OutsideCut(Cut { device, keeps_to })) => {
            assert_eq!(device, n(DEVICE));
            assert_eq!(keeps_to, 0, "a revocation with no cut keeps nothing");
        }
        other => panic!("{other:?}"),
    }
}

/// A key of a role whose Data needs a cut, whose certificates all lapsed by
/// this clock, is lapsed, with the dates; it is not kept as refused, which is
/// the log's rule: judged again when fetched again.
#[tokio::test]
async fn a_key_lapsed_by_this_clock_is_lapsed() {
    let (judge, phone) = bob((PAST, EXPIRED), |c| c.with_data_requires_cut("member")).await;
    match judge.validate(&bob_entry(1, &phone), &bob_space()).await {
        Judged::Refused(Refusal::Lapsed { not_after, now }) => {
            assert_eq!(not_after.0, EXPIRED / 1_000_000);
            assert!(now > not_after);
        }
        other => panic!("{other:?}"),
    }
}

/// An issuer above the signer revoked: nothing a cut can excuse, so the entry
/// is untrusted, not outside a cut; a digest-signed packet names no signer and
/// is untrusted; a signature that does not verify is a bad signature.
#[tokio::test]
async fn the_other_refusals_are_untrusted_or_a_bad_signature() {
    let (judge, phone) = bob((PAST, u64::MAX), |c| c.with_revocation(n(CA_KEY))).await;
    let judged = judge.validate(&bob_entry(1, &phone), &bob_space()).await;
    assert!(
        matches!(&judged, Judged::Refused(Refusal::Untrusted { why }) if why.contains("revoked")),
        "{judged:?}"
    );

    let (judge, _) = bob((PAST, u64::MAX), |c| c).await;
    let wire = DataBuilder::new(log_name(&n(DEVICE), &bob_space(), 1), b"v").sign_digest_sha256();
    let digest = Data::decode(wire).unwrap();
    let judged = judge.validate(&digest, &bob_space()).await;
    assert!(
        matches!(&judged, Judged::Refused(Refusal::Untrusted { why }) if why.contains("digest")),
        "{judged:?}"
    );

    // The phone's key name, another key.
    let thief = signer(PHONE_KEY, 99);
    let forged = bob_entry(1, &thief);
    assert!(
        matches!(
            judge.validate(&forged, &bob_space()).await,
            Judged::Refused(Refusal::BadSignature)
        ),
        "a signature the certificate's key does not make"
    );
}

// ---- re-check support -------------------------------------------------------------------------

/// A trust context the keyring adopts is announced, so the log judges what it
/// holds of the persons affected again, and moves the generation only when
/// what is judged by revocation changed.
#[tokio::test]
async fn a_context_the_keyring_adopts_is_announced() {
    let (judge, mut events, _) = bob_and_events((PAST, u64::MAX), |c| c).await;
    let before = judge.generation();
    let revoking = SignedTrustContext::hierarchical(n("/home/bob"))
        .with_version(2)
        .with_revocation(n(PHONE_KEY));
    judge
        .validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .ok();
    match events.recv().await {
        Some(Adoption::Context(ctx)) => assert_eq!(ctx.version(), 2),
        other => panic!("{other:?}"),
    }
    assert_ne!(judge.generation(), before, "a revoking context moves it");
}
