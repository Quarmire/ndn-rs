//! Signals: the gate (spec §20): who is a member of a scope, by the record
//! in force and the trust context; the signal keys of a sealed scope; run
//! headers signed and admitted, or refused saying why.

use super::super::*;
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
            Arc::new(MemoryStore::new()),
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
    assert_eq!(alice.signal_admit(&f, &header).await, Ok(bob_key.clone()));
    let held = alice.inner.store.get(&header.name);
    assert!(held.is_none(), "a run header is not kept");

    let malformed = |got: Result<Name, SignalRefusal>| match got {
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
