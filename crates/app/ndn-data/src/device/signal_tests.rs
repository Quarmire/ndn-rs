//! Signals: the gate (spec §20): who is a member of a scope, by the record
//! in force and the trust context; the signal keys of a sealed scope; run
//! headers signed and admitted, or refused saying why.

use super::super::*;
use super::SIGNAL_CLOCK_RESERVE;
use crate::layer::Share;
use crate::signal::{SignalKey, SignalRefusal};
use ndn_app::AppError;
use ndn_foundation_types::NameComponent;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A forwarder that never delivers anything: the test hands the device the
/// packets it would have fetched.
struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

fn folder() -> Name {
    n("/alice/32=data/board")
}

const RUN: [u8; 16] = [7; 16];

/// One namespace's authority: its key store, its key, and its anchor.
struct Authority {
    ns: Name,
    keys: SecurityManager,
    issuer: Name,
    anchor: ndn_security::Certificate,
}

impl Authority {
    async fn new(ns: &str) -> Authority {
        let ns = n(ns);
        let keys = SecurityManager::new();
        let issuer = keys
            .generate_ed25519(ns.clone().append("KEY").append("ns"))
            .unwrap();
        let public = keys.get_signer_sync(&issuer).unwrap().public_key().unwrap();
        let anchor = keys
            .issue_self_signed_async(&issuer, public, VALIDITY_MS)
            .await
            .unwrap();
        Authority {
            ns,
            keys,
            issuer,
            anchor,
        }
    }

    /// Its trust context at `version`, revoking `revoked`.
    fn context(&self, version: u64, revoked: Option<&Name>) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(version);
        if let Some(k) = revoked {
            ctx = ctx.with_revocation(k.clone());
        }
        assert!(ctx.add_anchor(self.anchor.clone()));
        Arc::new(ctx)
    }
}

/// Namespaces `/alice`, `/bob`, `/rita` and `/eve`, each with its
/// authority, held by one validator every device here judges by.
struct World {
    validator: Arc<Validator>,
    people: Vec<Authority>,
}

impl World {
    async fn new() -> World {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let mut people = Vec::new();
        for ns in ["/alice", "/bob", "/rita", "/eve"] {
            let a = Authority::new(ns).await;
            validator.adopt_context(a.context(1, None)).unwrap();
            people.push(a);
        }
        World { validator, people }
    }

    fn authority(&self, device: &Name) -> &Authority {
        self.people
            .iter()
            .find(|a| device.has_prefix(&a.ns))
            .expect("a device of a namespace of the world")
    }

    /// A key store holding `device`'s key, certified by its namespace's
    /// authority; the certificate is held by the validator.
    async fn keys(&self, device: &Name) -> Arc<SecurityManager> {
        let a = self.authority(device);
        let keys = Arc::new(SecurityManager::new());
        let k = keys.generate_ed25519(key(device)).unwrap();
        let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
        let cert = a
            .keys
            .certify(&k, public, &a.issuer, VALIDITY_MS)
            .await
            .unwrap();
        keys.cert_cache().insert(cert.clone());
        self.validator.cert_cache().insert(cert);
        keys
    }

    /// Start `device`.
    async fn device(&self, device: &str) -> Device {
        self.device_on(device, Arc::new(MemoryStore::new())).await
    }

    /// Start `device` on `store`.
    async fn device_on(&self, device: &str, store: Arc<dyn DataStore>) -> Device {
        let device = n(device);
        let keys = self.keys(&device).await;
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
        Device::start(
            Transport {
                node: Node::from_connection(Arc::clone(&conn)),
                sync: conn,
            },
            device,
            keys,
            Arc::clone(&self.validator),
            store,
            Config {
                first_look: Duration::from_millis(50),
                ..Config::new()
            },
        )
        .await
        .unwrap()
    }

    /// `ns`'s trust context, version `version`, revoking `revoked`, adopted.
    fn revoke(&self, ns: &str, version: u64, revoked: &Name) {
        let a = self.authority(&n(ns));
        self.validator
            .keyring()
            .adopt_update(a.context(version, Some(revoked)))
            .unwrap();
    }
}

fn share(writers: &[&str], readers: Vec<Audience>) -> Share {
    Share {
        rule: Rule::Log,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers,
    }
}

/// `owner` shares folder `f` as `share`; the seq of the record it signed.
async fn share_folder(owner: &Device, f: &Name, share: Share) -> u64 {
    owner.share_folder(f, share.into()).await.unwrap();
    owner.inner.st.lock().head
}

/// Hand `to` the members record `from` signed at `seq` about `f`, as if
/// fetched and verified.
fn relay(from: &Device, to: &Device, f: &Name, seq: u64) {
    let name = log_name(from.name(), Some(f), seq);
    let wire = from.inner.store.get(&name).expect("signed and stored");
    let data = Data::decode(wire.clone()).unwrap();
    let record = wire::decode_record(data.content().unwrap().clone()).unwrap();
    let writer = from.inner.writer.clone();
    let mut st = to.inner.st.lock();
    to.inner
        .take(&mut st, name.clone(), wire, writer, record, false);
    assert_eq!(st.refused.get(&name), None, "the owner's record is taken");
}

/// A packet named `name` carrying `content`, signed by `device`'s key in
/// `keys`.
fn signed(keys: &SecurityManager, device: &Name, name: Name, content: &[u8]) -> Data {
    let k = key(device);
    let signer = keys.get_signer_sync(&k).unwrap();
    let wire = DataBuilder::new(name, content).sign_sync(signer.sig_type(), Some(&k), |region| {
        signer.sign_sync(region).unwrap()
    });
    Data::decode(wire).unwrap()
}

/// A member, for signals, is a key a writer prefix of the record in force
/// covers or a device its audience admits — for the folder and for a
/// collection under it that takes its record — and no other key.
#[tokio::test]
async fn a_scopes_members_are_its_writers_and_its_audience_and_no_stranger() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let f = folder();
    share_folder(
        &alice,
        &f,
        share(
            &["/alice", "/bob/phone"],
            vec![Audience::Person(n("/rita"))],
        ),
    )
    .await;
    let plan = f.clone().append("plan");
    for scope in [&f, &plan] {
        for (device, member) in [
            ("/alice/laptop", true),
            ("/bob/phone", true),
            ("/rita/pad", true),
            ("/bob/tablet", false),
            ("/eve/pc", false),
        ] {
            assert_eq!(
                alice.signal_member(scope, &key(&n(device))),
                member,
                "{device} in {scope}"
            );
        }
    }
    assert!(
        !alice.signal_member(&n("/alice/32=data/other"), &key(&n("/bob/phone"))),
        "nothing is a member of a scope no record is held over"
    );
    alice.shutdown();
}

/// Once the owner's record removing a writer is held, its key is no member
/// at once — a writer kept only by the removal's cut is none — and the
/// removed device's own gate refuses.
#[tokio::test]
async fn a_removed_writer_is_no_member_from_the_record_that_removes_it() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let bob = world.device("/bob/phone").await;
    let f = folder();
    let bob_key = key(&n("/bob/phone"));
    let one = share_folder(&alice, &f, share(&["/alice", "/bob/phone"], Vec::new())).await;
    relay(&alice, &bob, &f, one);
    assert!(bob.signal_member(&f, &bob_key));
    let scope = bob.signal_scope(&f).expect("a writer uses signals");
    assert_eq!(scope.share, share(&["/alice", "/bob/phone"], Vec::new()));
    assert!(scope.keys.is_empty(), "not sealed");
    assert_eq!(scope.listen, sync_group(&n("/bob")));
    assert!(scope.groups.contains(&sync_group(&n("/alice"))));
    assert!(scope.groups.contains(&sync_group(&n("/bob"))));
    bob.signal_header(&f, &RUN, b"run")
        .expect("a writer signs a run header");

    let two = share_folder(&alice, &f, share(&["/alice"], Vec::new())).await;
    relay(&alice, &bob, &f, two);
    let kept = bob
        .inner
        .st
        .lock()
        .record_in_force(&f)
        .unwrap()
        .into_owned();
    assert!(
        kept.cuts.iter().any(|c| bob_key.has_prefix(&c.of)),
        "the removal keeps the writer by a cut"
    );
    assert!(!alice.signal_member(&f, &bob_key));
    assert!(!bob.signal_member(&f, &bob_key));
    for refused in [
        bob.signal_scope(&f).map(|_| ()),
        bob.signal_header(&f, &RUN, b"run").map(|_| ()),
    ] {
        match refused {
            Err(e @ DataError::NotAllowed { .. }) => {
                assert_eq!(e.next(), crate::NextStep::AskOwner, "{e}");
            }
            other => panic!("a removed writer's gate: {other:?}"),
        }
    }
    alice.shutdown();
    bob.shutdown();
}

/// A key the trust context governing it revokes is no member, whatever the
/// record lists: its device's gate refuses, and others refuse its packets.
#[tokio::test]
async fn a_revoked_key_is_no_member_once_its_revocation_is_held() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let bob = world.device("/bob/phone").await;
    let f = folder();
    let bob_key = key(&n("/bob/phone"));
    let one = share_folder(&alice, &f, share(&["/alice", "/bob/phone"], Vec::new())).await;
    relay(&alice, &bob, &f, one);
    assert!(alice.signal_member(&f, &bob_key));
    bob.signal_scope(&f)
        .expect("a member before its revocation");

    world.revoke("/bob", 2, &bob_key);
    assert!(!alice.signal_member(&f, &bob_key));
    assert!(
        matches!(bob.signal_scope(&f), Err(DataError::NotAllowed { .. })),
        "a device whose key is revoked uses no signals"
    );
    assert!(matches!(
        bob.signal_header(&f, &RUN, b"run"),
        Err(DataError::NotAllowed { .. })
    ));
    alice.shutdown();
    bob.shutdown();
}

/// Two members derive one signal key and id for a sealed scope's epoch in
/// force; one that does not hold the epoch's key yet is NotReady, its ask
/// started; a new epoch gives another key and id, the old one still held
/// after it.
#[tokio::test]
async fn two_members_derive_one_signal_key_per_epoch_and_a_new_epoch_another() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let rita = world.device("/rita/pad").await;
    let f = folder();
    match rita.signal_scope(&f) {
        Err(e @ DataError::NotReady { .. }) => assert!(e.retry(), "{e}"),
        other => panic!("no record held: {other:?}"),
    }
    let one = share_folder(
        &alice,
        &f,
        share(&["/alice"], vec![Audience::Person(n("/rita"))]),
    )
    .await;
    let at_alice = alice.signal_scope(&f).expect("the owner holds the key");
    let [first] = &at_alice.keys[..] else {
        panic!("one epoch: {:?}", at_alice.keys);
    };
    let e = alice.inner.st.lock().folders[&f]
        .members
        .as_ref()
        .unwrap()
        .epoch
        .clone()
        .unwrap();
    assert_eq!(first.epoch, e);
    assert!(
        !format!("{first:?}").contains(&format!("{:?}", first.expose())),
        "Debug shows no key"
    );

    relay(&alice, &rita, &f, one);
    match rita.signal_scope(&f) {
        Err(e @ DataError::NotReady { .. }) => assert!(e.to_string().contains("key"), "{e}"),
        other => panic!("the epoch's key is not held: {other:?}"),
    }
    let asked = || {
        rita.inner
            .st
            .lock()
            .asking
            .contains(&(f.clone(), e.clone()))
    };
    for _ in 0..100 {
        if asked() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(asked(), "the key's ask is started");
    let k = alice.inner.st.lock().keys.key(&f, &e).unwrap();
    assert!(rita.inner.st.lock().take_key(&f, &e, k));
    let at_rita = rita.signal_scope(&f).expect("a reader with the key");
    assert_eq!(at_rita.keys.len(), 1);
    assert_eq!(at_rita.keys[0].epoch, first.epoch);
    assert_eq!(at_rita.keys[0].id, first.id);
    assert_eq!(at_rita.keys[0].expose(), first.expose());
    assert_eq!(at_rita.listen, sync_group(&n("/rita")));

    // Rita as a person dropped: a new epoch.
    share_folder(
        &alice,
        &f,
        share(&["/alice"], vec![Audience::Device(n("/rita/pad"))]),
    )
    .await;
    let again = alice.signal_scope(&f).unwrap();
    assert_ne!(again.keys[0].epoch, e, "a new epoch is in force");
    assert_ne!(again.keys[0].id, first.id);
    assert_ne!(again.keys[0].expose(), first.expose());
    assert_eq!(
        again.keys[1..]
            .iter()
            .map(|k| (k.epoch.clone(), k.id))
            .collect::<Vec<_>>(),
        vec![(e, first.id)],
        "the old epoch's key follows the one in force"
    );
    alice.shutdown();
    rita.shutdown();
}

/// The signal key binds the scope and the epoch, not only the epoch's
/// content key: one content key gives other keys and ids for another scope
/// or another epoch.
#[test]
fn a_signal_key_is_bound_to_its_scope_and_epoch() {
    let content = ndn_security::confidentiality::ContentKey::from_bytes([3; 32]);
    let e = |creator: &str, seq| Epoch {
        creator: n(creator),
        seq: Seq(seq),
    };
    let base = SignalKey::derive(&content, &folder(), &e("/alice/laptop", 4));
    for other in [
        SignalKey::derive(&content, &n("/alice/32=data/other"), &e("/alice/laptop", 4)),
        SignalKey::derive(&content, &folder(), &e("/alice/laptop", 5)),
        SignalKey::derive(&content, &folder(), &e("/alice/phone", 4)),
    ] {
        assert_ne!(other.expose(), base.expose());
        assert_ne!(other.id, base.id);
    }
    let same = SignalKey::derive(&content, &folder(), &e("/alice/laptop", 4));
    assert_eq!((same.expose(), same.id), (base.expose(), base.id));
}

/// A member's run header is admitted, its signer's key name answered; a
/// stranger's, one of another scope, one misnamed, one named under another
/// device than its signer's and one whose signature is damaged are refused,
/// each saying why; a revoked key's header is refused; and nothing about a
/// scope no record is held over is decided.
#[tokio::test]
async fn a_members_header_is_admitted_and_every_other_refused_saying_why() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let bob = world.device("/bob/phone").await;
    let f = folder();
    let phone = n("/bob/phone");
    let bob_key = key(&phone);
    let one = share_folder(&alice, &f, share(&["/alice", "/bob/phone"], Vec::new())).await;
    relay(&alice, &bob, &f, one);
    let header = Data::decode(bob.signal_header(&f, &RUN, b"run").unwrap()).unwrap();
    assert_eq!(*header.name, wire::signal_run_name(&phone, &f, &RUN));
    assert_eq!(
        alice.signal_admit(&f, &header).await.map(|s| s.key),
        Ok(bob_key.clone())
    );
    let held = alice.inner.store.get(&header.name);
    assert!(held.is_none(), "a run header is not kept");

    let malformed = |got: Result<crate::signal::SignalSender, SignalRefusal>| match got {
        Err(r @ SignalRefusal::Malformed { .. }) => r.to_string(),
        other => panic!("not a run header of the scope: {other:?}"),
    };
    // A collection under the folder: Bob is a member there too, but this
    // header is the folder's.
    let other = f.clone().append("plan");
    malformed(alice.signal_admit(&other, &header).await);
    // A run id of 15 octets.
    let mut comps = wire::signal_run_name(&phone, &f, &RUN)
        .components()
        .to_vec();
    comps.pop();
    comps.push(NameComponent::generic(Bytes::from_static(&[7; 15])));
    let short = Name::from_components(comps);
    let phone_keys = &bob.inner.keys;
    malformed(
        alice
            .signal_admit(&f, &signed(phone_keys, &phone, short, b"run"))
            .await,
    );
    let elsewhere = wire::signal_run_name(&n("/bob/tablet"), &f, &RUN);
    let why = malformed(
        alice
            .signal_admit(&f, &signed(phone_keys, &phone, elsewhere, b"run"))
            .await,
    );
    assert!(why.contains("another device"), "{why}");

    let mut damaged = header.raw().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged = Data::decode(Bytes::from(damaged)).unwrap();
    assert_eq!(
        alice.signal_admit(&f, &damaged).await,
        Err(SignalRefusal::BadSignature {
            key: bob_key.clone()
        })
    );

    let eve = n("/eve/pc");
    let eve_keys = world.keys(&eve).await;
    let stranger = signed(
        &eve_keys,
        &eve,
        wire::signal_run_name(&eve, &f, &RUN),
        b"run",
    );
    assert_eq!(
        alice.signal_admit(&f, &stranger).await,
        Err(SignalRefusal::NotMember {
            scope: f.clone(),
            key: key(&eve)
        })
    );

    let rita = world.device("/rita/pad").await;
    match rita.signal_admit(&f, &header).await {
        Err(r @ SignalRefusal::NotReady { .. }) => assert!(r.to_string().contains("again"), "{r}"),
        other => panic!("no record held: {other:?}"),
    }

    world.revoke("/bob", 2, &bob_key);
    assert_eq!(
        alice.signal_admit(&f, &header).await,
        Err(SignalRefusal::BadSignature { key: bob_key })
    );
    alice.shutdown();
    bob.shutdown();
    rita.shutdown();
}

/// `device`'s key `KEY/<id>` in a key store of its own, certified by its
/// namespace's authority for `validity_ms` from now; the certificate held
/// by the validator only when `held`.
async fn keys_for(
    world: &World,
    device: &Name,
    id: &str,
    validity_ms: u64,
    held: bool,
) -> (SecurityManager, Name) {
    let a = world.authority(device);
    let keys = SecurityManager::new();
    let k = keys
        .generate_ed25519(device.clone().append("KEY").append(id))
        .unwrap();
    let public = keys.get_signer_sync(&k).unwrap().public_key().unwrap();
    let cert = a
        .keys
        .certify(&k, public, &a.issuer, validity_ms)
        .await
        .unwrap();
    if held {
        world.validator.cert_cache().insert(cert);
    }
    (keys, k)
}

/// A run header of `f` for `device`, signed by key `k` in `keys`.
fn header_by(keys: &SecurityManager, k: &Name, device: &Name, f: &Name) -> Data {
    let signer = keys.get_signer_sync(k).unwrap();
    let wire = DataBuilder::new(wire::signal_run_name(device, f, &RUN), b"run").sign_sync(
        signer.sig_type(),
        Some(k),
        |region| signer.sign_sync(region).unwrap(),
    );
    Data::decode(wire).unwrap()
}

/// Live data is admitted by the live rule (spec §20): a header signed by a
/// device key whose certificate has expired is refused, though the key is
/// a member and revoked by nothing.
#[tokio::test]
async fn a_header_signed_under_an_expired_certificate_is_refused() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let f = folder();
    share_folder(&alice, &f, share(&["/alice", "/bob/phone"], Vec::new())).await;
    let phone = n("/bob/phone");
    let (keys, k) = keys_for(&world, &phone, "1", 1, true).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let header = header_by(&keys, &k, &phone, &f);
    assert!(alice.signal_member(&f, &k), "a member, revoked by nothing");
    match alice.signal_admit(&f, &header).await {
        Err(r @ SignalRefusal::BadSignature { .. }) => {
            assert!(r.to_string().contains("expired"), "{r}")
        }
        other => panic!("a header under an expired certificate: {other:?}"),
    }
    alice.shutdown();
}

/// What `fetch` was asked, in order.
type Asked = Arc<std::sync::Mutex<Vec<Name>>>;

/// The validator fetches missing certificates through a fetch that notes
/// every name asked, never answers a name under `/bob/slow`, and answers
/// every other that none is to be had.
fn fetching(world: &World) -> Asked {
    let asked: Asked = Arc::default();
    let noted = Arc::clone(&asked);
    let fetch: ndn_security::FetchFn = Arc::new(move |name: Name| {
        noted.lock().unwrap().push(name.clone());
        Box::pin(async move {
            if name.has_prefix(&n("/bob/slow")) {
                futures::future::pending::<()>().await;
            }
            Err(ndn_security::FetchMiss::Absent)
        })
    });
    let fetcher = ndn_security::CertFetcher::new(
        world.validator.cert_cache_arc(),
        fetch,
        Duration::from_secs(60),
    )
    .with_negative_ttl(Duration::ZERO);
    assert!(world.validator.set_cert_fetcher(Arc::new(fetcher)).is_ok());
    asked
}

/// A header's signer is found a member before anything is verified, its
/// chain is walked from the certificates held first, and a certificate not
/// held is fetched only within its namespace's budget (spec §20): a
/// stranger's header costs no fetch, devices of one namespace whose
/// certificates can't be had hold at most its budget of fetches, and a
/// member whose certificate is held is admitted meanwhile.
#[tokio::test]
async fn a_headers_certificates_are_fetched_for_a_member_only_within_its_namespaces_budget() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let asked = fetching(&world);
    let f = folder();
    share_folder(&alice, &f, share(&["/alice", "/bob"], Vec::new())).await;
    let soon = Duration::from_secs(2);

    let eve = n("/eve/pc");
    let (eve_keys, eve_key) = keys_for(&world, &eve, "1", VALIDITY_MS, false).await;
    let stranger = header_by(&eve_keys, &eve_key, &eve, &f);
    let got = tokio::time::timeout(soon, alice.signal_admit(&f, &stranger))
        .await
        .expect("a stranger's header is refused at once");
    assert!(
        matches!(got, Err(SignalRefusal::NotMember { .. })),
        "{got:?}"
    );
    assert!(
        asked.lock().unwrap().is_empty(),
        "a stranger costs no fetch"
    );

    let alice = Arc::new(alice);
    let mut slow = Vec::new();
    for d in ["/bob/slow/1", "/bob/slow/2", "/bob/slow/3", "/bob/slow/4"] {
        let device = n(d);
        let (keys, k) = keys_for(&world, &device, "1", VALIDITY_MS, false).await;
        let header = header_by(&keys, &k, &device, &f);
        let (alice, f) = (Arc::clone(&alice), f.clone());
        slow.push(tokio::spawn(async move {
            alice.signal_admit(&f, &header).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let fetching = asked.lock().unwrap().len();
    assert!(
        (1..=2).contains(&fetching),
        "one namespace holds at most 2 fetches at once: {fetching}"
    );
    let refused: Vec<_> = slow.iter().filter(|t| t.is_finished()).collect();
    assert_eq!(
        refused.len(),
        4 - fetching,
        "the others are refused at once"
    );
    for t in slow.into_iter().filter(|t| t.is_finished()) {
        match t.await.unwrap() {
            Err(r @ SignalRefusal::Unverified { .. }) => {
                assert!(r.to_string().contains("again"), "{r}")
            }
            other => panic!("over its namespace's fetches: {other:?}"),
        }
    }

    let phone = n("/bob/phone");
    let (keys, k) = keys_for(&world, &phone, "1", VALIDITY_MS, true).await;
    let header = header_by(&keys, &k, &phone, &f);
    let got = tokio::time::timeout(soon, alice.signal_admit(&f, &header))
        .await
        .expect("a member whose certificate is held is admitted meanwhile");
    assert_eq!(got.map(|s| s.key), Ok(k));
    alice.shutdown();
}

/// A device whose certificate could not be had is not fetched for again
/// while its back-off lasts, whatever key id its next header names: a
/// fresh key id per header drives no fetch per header (spec §20).
#[tokio::test]
async fn a_device_whose_certificate_could_not_be_had_drives_no_fetch_per_key_id() {
    let world = World::new().await;
    let alice = world.device("/alice/laptop").await;
    let asked = fetching(&world);
    let f = folder();
    share_folder(&alice, &f, share(&["/alice", "/bob"], Vec::new())).await;
    let tablet = n("/bob/tablet");
    for (i, id) in ["1", "2", "3"].into_iter().enumerate() {
        let (keys, k) = keys_for(&world, &tablet, id, VALIDITY_MS, false).await;
        let got = alice
            .signal_admit(&f, &header_by(&keys, &k, &tablet, &f))
            .await;
        assert!(got.is_err(), "no certificate of {k} is to be had");
        assert_eq!(
            asked.lock().unwrap().len(),
            1,
            "header {i}: one fetch for the device, then none while it backs off"
        );
    }
    alice.shutdown();
}

/// A store whose disk keeps only what a returned flush made durable: writes wait in `pending`
/// until `sync` moves them to `durable`, and a crash is the store that `durable` is. While
/// held, `sync` waits.
#[derive(Default)]
struct Lossy {
    durable: Mutex<HashMap<Name, Bytes>>,
    pending: Mutex<HashMap<Name, Bytes>>,
    held: std::sync::Mutex<bool>,
    let_go: std::sync::Condvar,
    /// Writes of the signal clock floor.
    clock_writes: AtomicUsize,
}

impl Lossy {
    /// The store a power loss leaves: what was durable.
    fn crash(&self) -> Arc<Lossy> {
        let after = Lossy::default();
        *after.durable.lock() = self.durable.lock().clone();
        Arc::new(after)
    }

    fn hold(&self, on: bool) {
        *self.held.lock().unwrap() = on;
        self.let_go.notify_all();
    }
}

impl DataStore for Lossy {
    fn insert(&self, name: Name, wire: Bytes) {
        if name == signal_clock_name() {
            self.clock_writes.fetch_add(1, Ordering::SeqCst);
        }
        self.pending.lock().insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        let pending = self.pending.lock().get(name).cloned();
        pending.or_else(|| self.durable.lock().get(name).cloned())
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.scan_under(prefix, 1).pop().map(|(_, w)| w)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        let mut all: HashMap<Name, Bytes> = self.durable.lock().clone();
        all.extend(self.pending.lock().clone());
        all.into_iter()
            .filter(|(n, _)| n.has_prefix(prefix))
            .take(limit)
            .collect()
    }
    fn remove(&self, name: &Name) {
        self.pending.lock().remove(name);
        self.durable.lock().remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.let_go.wait(held).unwrap();
        }
        let moved: Vec<_> = self.pending.lock().drain().collect();
        self.durable.lock().extend(moved);
        Ok(())
    }
}

/// The signal clock floor (spec signals.md §3.5): `signal_clock_dated(t)` answers a floor above
/// `t` by no more than the reserve, only once it is durable; a time below the floor writes
/// nothing; a crash while the barrier is held leaves the floor at what was answered before, and
/// no time above it was answered; and a restart reads the floor back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_signal_clock_floor_is_durable_before_it_is_answered_and_a_crash_never_lowers_it() {
    let world = World::new().await;
    let store = Arc::new(Lossy::default());
    let laptop = world
        .device_on("/alice/laptop", Arc::clone(&store) as Arc<dyn DataStore>)
        .await;
    assert_eq!(laptop.signal_clock_floor(), 0, "a new device has no floor");
    let reserve = SIGNAL_CLOCK_RESERVE.as_micros() as u64;
    assert!(reserve <= 10_000_000, "the reserve is at most 10 s");
    let first = laptop.signal_clock_dated(1_000_000).await.unwrap();
    assert_eq!(first, 1_000_000 + reserve);
    assert_eq!(laptop.signal_clock_floor(), first);

    // What a power loss leaves holds it.
    let after = store.crash();
    let restarted = world
        .device_on("/alice/laptop", Arc::clone(&after) as Arc<dyn DataStore>)
        .await;
    assert_eq!(restarted.signal_clock_floor(), first);
    restarted.shutdown();

    // Inside the reserve nothing is written.
    let writes = store.clock_writes.load(Ordering::SeqCst);
    assert_eq!(laptop.signal_clock_dated(first).await.unwrap(), first);
    assert_eq!(store.clock_writes.load(Ordering::SeqCst), writes);

    // Past it, with the barrier held: the answer waits, and a crash now leaves the floor where
    // it was answered last, below the time asked, which no signal was dated by.
    store.hold(true);
    let asked = first + 1;
    let waiting = {
        let laptop = laptop.clone();
        tokio::spawn(async move { laptop.signal_clock_dated(asked).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiting.is_finished(), "not answered before it is durable");
    let crashed = world
        .device_on("/alice/laptop", store.crash() as Arc<dyn DataStore>)
        .await;
    assert_eq!(
        crashed.signal_clock_floor(),
        first,
        "a restart after the dropped barrier is below the time asked, never below one answered"
    );
    crashed.shutdown();
    store.hold(false);
    let second = waiting.await.unwrap().unwrap();
    assert_eq!(second, asked + reserve);
    let restarted = world
        .device_on("/alice/laptop", store.crash() as Arc<dyn DataStore>)
        .await;
    assert_eq!(restarted.signal_clock_floor(), second);
    restarted.shutdown();
    laptop.shutdown();
}
