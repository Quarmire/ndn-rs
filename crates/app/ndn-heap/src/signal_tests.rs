//! The signal gate (spec §11): who is a member of a space for signals, by the
//! operation fold and the trust context; the signal keys of a sealed space;
//! run headers signed and admitted, or refused saying why.
//!
//! The logs are real (own writes signed by real Ed25519 keys, entries relayed
//! between them through `Log::admit`), the judge is real over a validator
//! holding each person's trust context, and certificates are fetched through a
//! fetch function the case controls.

use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{ContentKey, RecipientKey};
use ndn_security::{
    Certificate, FetchMiss, SecurityManager, SignedTrustContext, Signer, TrustSchema, Validator,
    public_key_digest,
};
use ndn_sync::DataStore;
use parking_lot::Mutex;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use super::*;
use crate::error::NextStep;
use crate::log::{Outcome, Params, Signed, Step};
use crate::reserve::Flusher;
use crate::revocation::Suspicion;
use crate::seal::{self, Keys};
use crate::store::Stage;
use crate::test_kit::{CrashStore, n};
use crate::trust::Verified;
use crate::wire::{
    EpochId, MembersBody, Op, Role, log_name, parse_signal_run_name, signal_run_name,
};

const NOW: u64 = 1_000;
const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;
const RUN: [u8; RUN_ID_LEN] = [7; RUN_ID_LEN];

fn space() -> Name {
    n("/alice/32=data/board")
}

fn other_space() -> Name {
    n("/alice/32=data/other")
}

fn key_of(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

// -- The world: persons with trust contexts, devices with certified keys ----------

/// One person's authority: its key store, its key and its anchor.
struct Authority {
    ns: Name,
    keys: SecurityManager,
    issuer: Name,
    anchor: Certificate,
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

/// A device with its key: what signs, and what the judge says of it.
#[derive(Clone)]
struct Dev {
    name: Name,
    key: Name,
    person: Name,
    signer: Arc<dyn Signer>,
}

impl Dev {
    fn verified(&self) -> Verified {
        Verified {
            key: self.key.clone(),
            device: self.name.clone(),
            person: self.person.clone(),
            key_digest: public_key_digest(&self.signer.public_key().unwrap()),
        }
    }
}

/// The persons `/alice`, `/bob`, `/carol`, `/rita` and `/eve`, each with its
/// authority, held by the one validator every seat here judges by.
struct World {
    validator: Arc<Validator>,
    people: Vec<Authority>,
}

impl World {
    async fn new() -> World {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let mut people = Vec::new();
        for ns in ["/alice", "/bob", "/carol", "/rita", "/eve"] {
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
            .expect("a device of a person of the world")
    }

    /// `device`'s key `KEY/<id>`, certified by its person's authority for
    /// `validity_ms` from now; the certificate is held by the validator only
    /// when `held`. The certificate is returned too, for a fetch to serve.
    async fn dev_key(
        &self,
        device: &str,
        id: &str,
        validity_ms: u64,
        held: bool,
    ) -> (Dev, Certificate) {
        let name = n(device);
        let a = self.authority(&name);
        let keys = SecurityManager::new();
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append(id))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = a
            .keys
            .certify(&key, public, &a.issuer, validity_ms)
            .await
            .unwrap();
        if held {
            self.validator.cert_cache().insert(cert.clone());
        }
        let dev = Dev {
            person: a.ns.clone(),
            signer: keys.get_signer_sync(&key).unwrap(),
            name,
            key,
        };
        (dev, cert)
    }

    /// A device whose certificate every seat holds.
    async fn dev(&self, device: &str) -> Dev {
        self.dev_key(device, "1", VALIDITY_MS, true).await.0
    }

    /// `ns`'s trust context at `version`, revoking `revoked`, adopted.
    fn revoke(&self, ns: &str, version: u64, revoked: &Name) {
        self.validator
            .keyring()
            .adopt_update(self.authority(&n(ns)).context(version, Some(revoked)))
            .unwrap();
    }

    /// A seat of `device`: its log of the space and its judge.
    async fn seat(&self, device: &str) -> Seat {
        let dev = self.dev(device).await;
        let store = Arc::new(CrashStore::new());
        let raw = Arc::clone(&store) as Arc<dyn DataStore>;
        let stage = Stage::new(Arc::clone(&raw));
        let flusher = Flusher::spawn(Arc::clone(&raw));
        let log = Log::open(
            Params {
                space: space(),
                device: dev.name.clone(),
                person: dev.person.clone(),
                signer: Arc::clone(&dev.signer),
                keys: Keys::new(RecipientKey::generate()),
                suspicion: Suspicion::open(Arc::clone(&raw)),
                block: 8,
            },
            Arc::clone(&raw),
            stage,
            Arc::clone(&flusher),
        )
        .unwrap();
        Seat {
            log: Mutex::new(log),
            judge: Judge::new(Arc::clone(&self.validator), raw, None),
            gate: SignalGate::default(),
            store,
            flusher,
            dev,
        }
    }
}

/// What one node holds of the space: the log and the judge the gate reads.
struct Seat {
    log: Mutex<Log>,
    judge: Arc<Judge>,
    gate: SignalGate,
    store: Arc<CrashStore>,
    flusher: Arc<Flusher>,
    dev: Dev,
}

fn add(id: u8, who: &str, role: Role) -> Op {
    Op::Add {
        id: [id; 16],
        who: n(who),
        role,
        epoch: None,
    }
}

fn remove(id: u8) -> Op {
    Op::Remove {
        id: [id; 16],
        tips: Vec::new(),
    }
}

fn members(create: Option<bool>, ops: Vec<Op>) -> MembersBody {
    MembersBody { create, ops }
}

impl Seat {
    /// The owner signs a Members entry, waiting for the reservation's flush as
    /// the node does.
    async fn members(&self, body: MembersBody) -> Signed {
        loop {
            let step = self.log.lock().sign_members(body.clone(), NOW).unwrap();
            match step {
                Step::Done(signed) => return signed,
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    /// The owner signs an Epoch entry for `audience`.
    async fn epoch(&self, audience: &[&str]) -> (Signed, EpochId) {
        loop {
            let step = self
                .log
                .lock()
                .sign_epoch(audience.iter().map(|p| n(p)).collect(), NOW)
                .unwrap();
            match step {
                Step::Done(signed) => {
                    let epoch = EpochId {
                        creator: self.dev.name.clone(),
                        seq: signed.id.seq,
                    };
                    return (signed, epoch);
                }
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    /// Hand `to` the entry this seat signed, as if fetched and judged.
    fn relay(&self, signed: &Signed, to: &Seat) {
        self.relay_seq(signed.id.seq, to);
    }

    /// [`Self::relay`] by the seq of the entry (the creation is seq 1).
    fn relay_seq(&self, seq: u64, to: &Seat) {
        let wire = self
            .store
            .get(&log_name(&self.dev.name, &space(), seq))
            .expect("signed and stored");
        let data = Data::decode(wire.clone()).unwrap();
        let got = to.log.lock().admit(&wire, &data, &self.dev.verified(), NOW);
        assert_eq!(got.outcome, Outcome::Applied, "{:?}", got.effects.alerts);
    }

    fn scope(&self) -> Result<SignalScope, HeapError> {
        signal_scope(&self.log.lock(), &self.judge)
    }

    fn member(&self, key: &Name) -> bool {
        signal_member(&self.log.lock(), &self.judge, &space(), key)
    }

    fn header(&self, run: &[u8; RUN_ID_LEN]) -> Result<Bytes, HeapError> {
        signal_header(
            &self.log.lock(),
            &self.judge,
            &*self.dev.signer,
            &space(),
            run,
            b"run",
        )
    }

    fn sender(&self, data: &Data) -> Result<SignalSender, SignalRefusal> {
        signal_sender(&self.log.lock(), &self.judge, &space(), data)
    }

    async fn admit(&self, data: &Data) -> Result<SignalSender, SignalRefusal> {
        signal_admit(&self.gate, &self.log, &self.judge, &space(), data).await
    }
}

/// A run header of `space` for `dev`, signed by its key.
fn header_by(dev: &Dev, space: &Name) -> Data {
    named(dev, signal_run_name(&dev.name, space, &RUN))
}

/// A packet named `name` carrying `run`, signed by `dev`'s key.
fn named(dev: &Dev, name: Name) -> Data {
    let wire = seal::sign(DataBuilder::new(name, b"run"), &*dev.signer).unwrap();
    Data::decode(wire).unwrap()
}

/// What the fetch was asked, in order.
type Asked = Arc<std::sync::Mutex<Vec<Name>>>;

/// The validator fetches missing certificates through a fetch that notes
/// every name asked, never answers a name under `/bob/slow` or `/rita/slow`,
/// answers a name `serve` holds a certificate of with it, and answers every
/// other that none is to be had.
fn fetching(world: &World, serve: Vec<Certificate>) -> Asked {
    let asked: Asked = Arc::default();
    let noted = Arc::clone(&asked);
    let serve: Vec<Bytes> = serve.iter().map(|c| c.data_wire().unwrap()).collect();
    let fetch: ndn_security::FetchFn = Arc::new(move |name: Name| {
        noted.lock().unwrap().push(name.clone());
        let served = serve
            .iter()
            .map(|w| Data::decode(w.clone()).unwrap())
            .find(|d| d.name.has_prefix(&name));
        Box::pin(async move {
            if name.has_prefix(&n("/bob/slow")) || name.has_prefix(&n("/rita/slow")) {
                pending::<()>().await;
            }
            served.ok_or(FetchMiss::Absent)
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

/// The owner's seat creating the space public with Bob a writer, and the
/// seat of a reader device that holds that record.
async fn bob_may_write(world: &World) -> (Seat, Seat) {
    let alice = world.seat("/alice/laptop").await;
    let observer = world.seat("/rita/pad").await;
    let one = alice
        .members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    alice.relay(&one, &observer);
    (alice, observer)
}

// -- Membership -------------------------------------------------------------------------

/// A member, for signals, is a key of a device of a person the fold lists as
/// a writer (the owner always is), judged by the trust context that governs
/// the key: any device of the person, no stranger's, no other space's.
#[tokio::test]
async fn a_spaces_members_are_its_writers_by_person_and_no_stranger() {
    let world = World::new().await;
    let (alice, observer) = bob_may_write(&world).await;
    for (device, member) in [
        ("/alice/laptop", true),
        ("/alice/phone", true),
        ("/bob/phone", true),
        ("/bob/tablet", true),
        ("/rita/pad", false),
        ("/eve/pc", false),
    ] {
        for seat in [&alice, &observer] {
            assert_eq!(seat.member(&key_of(device)), member, "{device}");
        }
    }
    assert!(
        !alice.member(&n("/bob/phone")),
        "a device name is no key name"
    );
    assert!(
        !signal_member(
            &alice.log.lock(),
            &alice.judge,
            &other_space(),
            &key_of("/bob/phone")
        ),
        "a key is a member of the space the log holds and of no other"
    );
    let empty = world.seat("/eve/pc").await;
    assert!(
        !empty.member(&key_of("/bob/phone")),
        "nothing is a member of a space whose creation is not held"
    );
}

/// Membership is answered from what is held: a removal changes it at the
/// first call after the owner's entry is held here, not before and not later.
#[tokio::test]
async fn signal_member_flips_after_a_removal() {
    let world = World::new().await;
    let (alice, observer) = bob_may_write(&world).await;
    let bob = key_of("/bob/phone");
    assert!(observer.member(&bob));

    let removal = alice.members(members(None, vec![remove(1)])).await;
    assert!(!alice.member(&bob), "the owner holds its own removal");
    assert!(observer.member(&bob), "this seat does not hold it yet");

    alice.relay(&removal, &observer);
    assert!(!observer.member(&bob), "the first call after it is held");
    assert!(observer.member(&key_of("/alice/phone")), "the owner stays");
}

/// A key the trust context governing it revokes is no member, whatever the
/// fold lists, and the revocation count a transport compares moves.
#[tokio::test]
async fn a_revoked_key_is_no_member_once_its_revocation_is_held() {
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let bob = key_of("/bob/phone");
    let before = alice.judge.generation();
    assert!(alice.member(&bob));

    world.revoke("/bob", 2, &bob);
    assert!(!alice.member(&bob));
    assert!(alice.member(&key_of("/bob/tablet")), "only that key");
    assert_ne!(alice.judge.generation(), before);
}

/// A device that is no member (removed, revoked, never listed) uses no
/// signals and is told to ask the owner; one that has not seen the space's
/// creation is told to retry; a member signs run headers and gets the group.
#[tokio::test]
async fn a_device_that_is_no_member_uses_no_signals() {
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let bob = world.seat("/bob/phone").await;
    match bob.scope() {
        Err(e @ HeapError::NotReady { .. }) => assert!(e.retry(), "{e}"),
        other => panic!("no record held: {other:?}"),
    }
    alice.relay_seq(1, &bob); // the creation
    let scope = bob.scope().expect("a writer uses signals");
    assert_eq!(scope.space, space());
    assert!(scope.keys.is_empty(), "not sealed");
    let group = n("/alice/32=sync/board");
    assert_eq!(scope.groups, vec![group.clone()]);
    assert_eq!(scope.listen, group);
    let header = Data::decode(bob.header(&RUN).expect("a writer signs a run header")).unwrap();
    assert_eq!(*header.name, signal_run_name(&bob.dev.name, &space(), &RUN));
    assert_eq!(parse_signal_run_name(&header.name).unwrap().run, RUN);

    let removal = alice.members(members(None, vec![remove(1)])).await;
    alice.relay(&removal, &bob);
    match bob.header(&RUN) {
        Err(e @ HeapError::NotAllowed { .. }) => assert_eq!(e.next(), NextStep::AskOwner),
        other => panic!("a removed writer sends nothing: {other:?}"),
    }
    bob.scope()
        .expect("a public space is read by everybody, a removed writer included");

    // A listed writer whose own key is revoked.
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let bob = world.seat("/bob/phone").await;
    alice.relay_seq(1, &bob);
    bob.scope().expect("a member before its revocation");
    world.revoke("/bob", 2, &bob.dev.key);
    assert!(matches!(bob.scope(), Err(HeapError::NotAllowed { .. })));
    assert!(matches!(
        bob.header(&RUN),
        Err(HeapError::NotAllowed { .. })
    ));
}

// -- Keys -------------------------------------------------------------------------------

/// A signal key is secret for as long as it lives: it zeroizes on drop, shows
/// nothing of itself in `Debug`, and is bound to the scope and epoch it was
/// derived for, not only to the epoch's content key.
#[test]
fn signal_keys_are_per_epoch_and_zeroized() {
    fn zeroizes<T: ZeroizeOnDrop>() {}
    zeroizes::<SignalKey>();

    let content = ContentKey::from_bytes([3; 32]);
    let e = |creator: &str, seq| EpochId {
        creator: n(creator),
        seq,
    };
    let base = SignalKey::derive(&content, &space(), &e("/alice/laptop", 4));
    assert!(
        !format!("{base:?}").contains(&format!("{:?}", base.expose())),
        "Debug shows no key"
    );
    for other in [
        SignalKey::derive(&content, &other_space(), &e("/alice/laptop", 4)),
        SignalKey::derive(&content, &space(), &e("/alice/laptop", 5)),
        SignalKey::derive(&content, &space(), &e("/alice/phone", 4)),
        SignalKey::derive(
            &ContentKey::from_bytes([4; 32]),
            &space(),
            &e("/alice/laptop", 4),
        ),
    ] {
        assert_ne!(other.expose(), base.expose());
        assert_ne!(other.id, base.id);
    }
    let same = SignalKey::derive(&content, &space(), &e("/alice/laptop", 4));
    assert_eq!((same.expose(), same.id), (base.expose(), base.id));
}

/// The derivation is the one the spec fixes, so a surface of another build
/// derives the same key and id: HKDF-SHA256, no salt, the content key as input
/// key material, `ndn-heap/signal/1 ‖ scope TLV ‖ creator TLV ‖ seq BE` as
/// info, 32 octets; the id is 8 octets of HKDF of that key under
/// `ndn-heap/signal/id/1`.
#[test]
fn a_signal_key_is_the_hkdf_the_spec_fixes() {
    let content = ContentKey::from_bytes([9; 32]);
    let epoch = EpochId {
        creator: n("/alice/laptop"),
        seq: 258,
    };
    let mut info = b"ndn-heap/signal/1".to_vec();
    info.extend_from_slice(&space().encode_to_tlv());
    info.extend_from_slice(&epoch.creator.encode_to_tlv());
    info.extend_from_slice(&258u64.to_be_bytes());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, content.expose())
        .expand(&info, &mut key)
        .unwrap();
    let mut id = [0u8; KEY_ID_LEN];
    Hkdf::<Sha256>::new(None, &key)
        .expand(b"ndn-heap/signal/id/1", &mut id)
        .unwrap();
    let derived = SignalKey::derive(&content, &space(), &epoch);
    assert_eq!((derived.expose(), derived.id), (&key, id));
}

/// A sealed space's signal keys: the epoch in force first, the older epochs
/// whose keys are held after it, highest first; a member of the audience that
/// does not hold the key yet is told to retry, and derives the very key the
/// owner holds once it arrives; a writer outside the audience is told it may
/// not hold it.
#[tokio::test]
async fn a_sealed_space_gives_its_audience_the_keys_of_its_epochs() {
    let world = World::new().await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let carol = world.seat("/carol/pad").await;
    let creation = alice
        .members(members(
            Some(false),
            vec![
                add(1, "/bob", Role::Writer),
                add(2, "/bob", Role::Reader),
                add(3, "/carol", Role::Writer),
            ],
        ))
        .await;
    let (first, e1) = alice.epoch(&["/alice", "/bob"]).await;
    for seat in [&bob, &carol] {
        alice.relay(&creation, seat);
        alice.relay(&first, seat);
    }

    let at_alice = alice.scope().expect("the owner holds the key");
    let [one] = &at_alice.keys[..] else {
        panic!("one epoch: {:?}", at_alice.keys);
    };
    assert_eq!(one.epoch, e1);

    match bob.scope() {
        Err(e @ HeapError::NotReady { .. }) => {
            assert!(e.retry() && e.to_string().contains("key"), "{e}")
        }
        other => panic!("the epoch's key is not held: {other:?}"),
    }
    assert!(
        matches!(carol.scope(), Err(HeapError::Sealed { .. })),
        "a writer outside the audience may not hold the key"
    );
    let key = {
        let log = alice.log.lock();
        let held = log.keys().key(&space(), &e1).unwrap();
        ContentKey::from_bytes(*held.expose())
    };
    assert!(bob.log.lock().key_arrived(e1.clone(), key).0);
    let at_bob = bob.scope().expect("a writer with the key");
    assert_eq!(at_bob.keys.len(), 1);
    assert_eq!(
        (
            &at_bob.keys[0].epoch,
            at_bob.keys[0].id,
            at_bob.keys[0].expose()
        ),
        (&one.epoch, one.id, one.expose())
    );

    // Bob stops being a reader: a new epoch is in force, the old one follows.
    alice.members(members(None, vec![remove(2)])).await;
    let (_, e2) = alice.epoch(&["/alice"]).await;
    let again = alice.scope().unwrap();
    assert_eq!(again.keys[0].epoch, e2, "the new epoch is in force");
    assert_ne!(again.keys[0].id, one.id);
    assert_ne!(again.keys[0].expose(), one.expose());
    assert_eq!(
        again.keys[1..]
            .iter()
            .map(|k| (k.epoch.clone(), k.id))
            .collect::<Vec<_>>(),
        vec![(e1, one.id)],
        "the old epoch's key follows the one in force"
    );
}

/// A reader of a sealed space holds the epoch key, so it gets the scope and
/// the keys it needs to receive signals; it is no writer, so it cannot send
/// (no header is signed) and the headers it signs are not admitted anywhere. A
/// person the space does not list at all gets no scope.
#[tokio::test]
async fn a_reader_of_a_sealed_space_gets_scope_and_keys_but_cannot_send_and_its_headers_are_not_admitted()
 {
    let world = World::new().await;
    let alice = world.seat("/alice/laptop").await;
    let rita = world.seat("/rita/pad").await;
    let eve = world.seat("/eve/pc").await;
    let creation = alice
        .members(members(Some(false), vec![add(1, "/rita", Role::Reader)]))
        .await;
    let (first, epoch) = alice.epoch(&["/alice", "/rita"]).await;
    for seat in [&rita, &eve] {
        alice.relay(&creation, seat);
        alice.relay(&first, seat);
    }

    match rita.scope() {
        Err(e @ HeapError::NotReady { .. }) => assert!(e.retry(), "{e}"),
        other => panic!("the reader's key has not arrived: {other:?}"),
    }
    let key = {
        let log = alice.log.lock();
        ContentKey::from_bytes(*log.keys().key(&space(), &epoch).unwrap().expose())
    };
    assert!(rita.log.lock().key_arrived(epoch.clone(), key).0);
    let theirs = rita
        .scope()
        .expect("a reader with the key receives signals");
    let owners = alice.scope().unwrap();
    assert_eq!(theirs.keys.len(), 1);
    assert_eq!(
        (theirs.keys[0].id, theirs.keys[0].expose()),
        (owners.keys[0].id, owners.keys[0].expose())
    );
    assert_eq!(theirs.listen, owners.listen);

    match rita.header(&RUN) {
        Err(e @ HeapError::NotAllowed { .. }) => assert_eq!(e.next(), NextStep::AskOwner),
        other => panic!("a reader sends nothing: {other:?}"),
    }
    let forged = header_by(&rita.dev, &space());
    assert!(!alice.member(&rita.dev.key), "a reader is no member");
    assert!(!rita.member(&rita.dev.key));
    assert_eq!(
        alice.admit(&forged).await,
        Err(SignalRefusal::NotMember {
            scope: space(),
            key: rita.dev.key.clone()
        })
    );
    assert!(matches!(
        alice.sender(&forged),
        Err(SignalRefusal::NotMember { .. })
    ));

    assert!(
        matches!(eve.scope(), Err(HeapError::NotAllowed { .. })),
        "a person the space does not list gets no scope"
    );
}

// -- Run headers ------------------------------------------------------------------------

/// A header of a member is admitted, its signer answered, and nothing is
/// kept. A stranger's, one of another space, one misnamed, one named under
/// another device than its signer's, one whose signature is damaged and one
/// of a revoked key are each refused saying why; a space whose creation is not
/// held decides nothing.
#[tokio::test]
async fn a_header_signed_by_a_non_member_is_refused_with_the_reason() {
    let world = World::new().await;
    let (alice, observer) = bob_may_write(&world).await;
    let asked = fetching(&world, Vec::new());
    let bob = world.dev("/bob/phone").await;
    let header = header_by(&bob, &space());
    let got = alice.admit(&header).await.expect("a member's header");
    assert_eq!(
        (got.key, got.device, got.namespace),
        (bob.key.clone(), bob.name.clone(), n("/bob"))
    );
    assert!(
        alice.store.get(&header.name).is_none(),
        "a run header is not kept"
    );

    let malformed = |got: Result<SignalSender, SignalRefusal>| match got {
        Err(r @ SignalRefusal::Malformed { .. }) => r.to_string(),
        other => panic!("not a run header of the space: {other:?}"),
    };
    malformed(alice.admit(&header_by(&bob, &other_space())).await);
    let mut comps = signal_run_name(&bob.name, &space(), &RUN)
        .components()
        .to_vec();
    comps.pop();
    comps.push(NameComponent::generic(Bytes::from_static(&[7; 15])));
    malformed(
        alice
            .admit(&named(&bob, Name::from_components(comps)))
            .await,
    );
    let elsewhere = signal_run_name(&n("/bob/tablet"), &space(), &RUN);
    let why = malformed(alice.admit(&named(&bob, elsewhere)).await);
    assert!(why.contains("another device"), "{why}");

    let mut damaged = header.raw().to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    assert_eq!(
        alice
            .admit(&Data::decode(Bytes::from(damaged)).unwrap())
            .await,
        Err(SignalRefusal::BadSignature {
            key: bob.key.clone()
        })
    );

    let eve = world.dev("/eve/pc").await;
    let why = alice.admit(&header_by(&eve, &space())).await;
    assert_eq!(
        why,
        Err(SignalRefusal::NotMember {
            scope: space(),
            key: eve.key.clone()
        })
    );
    let text = why.unwrap_err().to_string();
    assert!(
        text.contains("no member") && text.contains("owner adds it"),
        "{text}"
    );
    assert!(
        asked.lock().unwrap().is_empty(),
        "a stranger costs no fetch"
    );

    let fresh = world.seat("/eve/laptop").await;
    match fresh.admit(&header).await {
        Err(r @ SignalRefusal::NotReady { .. }) => {
            assert!(r.to_string().contains("again"), "{r}")
        }
        other => panic!("no creation held: {other:?}"),
    }

    // The owner removes Bob: his header is the stranger's from the first
    // call after the entry is held, and until then a member's.
    let removal = alice.members(members(None, vec![remove(1)])).await;
    assert!(observer.admit(&header).await.is_ok());
    alice.relay(&removal, &observer);
    assert!(matches!(
        observer.admit(&header).await,
        Err(SignalRefusal::NotMember { .. })
    ));

    let (alice, _) = bob_may_write(&world).await;
    world.revoke("/bob", 2, &bob.key);
    assert_eq!(
        alice.admit(&header).await,
        Err(SignalRefusal::BadSignature { key: bob.key })
    );
}

/// Live data is admitted by the live rule: a header signed by a key whose
/// certificate has expired is refused though the key is a member and revoked
/// by nothing.
#[tokio::test]
async fn a_header_under_an_expired_certificate_is_refused() {
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let (bob, _) = world.dev_key("/bob/phone", "2", 1, true).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(alice.member(&bob.key), "a member, revoked by nothing");
    match alice.admit(&header_by(&bob, &space())).await {
        Err(r @ SignalRefusal::BadSignature { .. }) => {
            assert!(r.to_string().contains("expired"), "{r}")
        }
        other => panic!("a header under an expired certificate: {other:?}"),
    }
}

/// A member's header whose certificate is not held is admitted once the chain
/// is fetched, by asking for exactly the certificate its chain needs.
#[tokio::test]
async fn a_member_header_admitted_after_the_chain_fetch() {
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let (bob, cert) = world.dev_key("/bob/phone", "3", VALIDITY_MS, false).await;
    let asked = fetching(&world, vec![cert.clone()]);
    let header = header_by(&bob, &space());

    let got = alice
        .admit(&header)
        .await
        .expect("admitted after the fetch");
    assert_eq!(got.key, bob.key);
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "one certificate: {asked:?}");
    assert!(cert.name.has_prefix(&asked[0]), "the signer's: {asked:?}");
    assert!(alice.store.get(&header.name).is_none(), "nothing is kept");
}

/// A header's certificates are fetched for a member only within its
/// namespace's budget: 2 headers of one namespace wait for certificates at a
/// time, the others are refused at once and asked again; a stranger costs no
/// fetch, a member whose certificate is held is admitted meanwhile and another
/// namespace has a budget of its own. Time is tokio's, paused.
#[tokio::test]
async fn the_fetch_budget_bounds_waiting_headers() {
    let world = World::new().await;
    let alice = Arc::new(world.seat("/alice/laptop").await);
    alice
        .members(members(
            Some(true),
            vec![add(1, "/bob", Role::Writer), add(2, "/rita", Role::Writer)],
        ))
        .await;
    let asked = fetching(&world, Vec::new());
    let mut slow = Vec::new();
    for d in ["/bob/slow/1", "/bob/slow/2", "/bob/slow/3", "/bob/slow/4"] {
        slow.push(header_by(
            &world.dev_key(d, "1", VALIDITY_MS, false).await.0,
            &space(),
        ));
    }
    let rita = header_by(
        &world
            .dev_key("/rita/slow/1", "1", VALIDITY_MS, false)
            .await
            .0,
        &space(),
    );
    let held = world.dev("/bob/phone").await;
    tokio::time::pause();

    let tasks: Vec<_> = slow
        .iter()
        .chain([&rita])
        .map(|h| {
            let (alice, h) = (Arc::clone(&alice), Data::decode(h.raw().clone()).unwrap());
            tokio::spawn(async move { alice.admit(&h).await })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fetching: Vec<Name> = asked.lock().unwrap().clone();
    let of = |ns: &str| fetching.iter().filter(|x| x.has_prefix(&n(ns))).count();
    assert_eq!(
        of("/bob"),
        2,
        "a namespace holds 2 fetches at once: {fetching:?}"
    );
    assert_eq!(of("/rita"), 1, "another namespace has its own budget");
    let refused: Vec<usize> = (0..slow.len())
        .filter(|i| tasks[*i].is_finished())
        .collect();
    assert_eq!(refused.len(), 2, "the others are refused at once");

    // A member whose certificate is held is not asked to wait.
    let got = alice.admit(&header_by(&held, &space())).await;
    assert_eq!(got.map(|s| s.key), Ok(held.key.clone()));

    let mut waiting = Vec::new();
    for (i, task) in tasks.into_iter().enumerate() {
        if refused.contains(&i) {
            match task.await.unwrap() {
                Err(r @ SignalRefusal::Unverified { .. }) => {
                    let text = r.to_string();
                    assert!(
                        text.contains("2 run headers of /bob wait") && text.contains("again"),
                        "{text}"
                    );
                }
                other => panic!("over its namespace's fetches: {other:?}"),
            }
        } else {
            waiting.push(task);
        }
    }
    // The fetches that never answer end with the fetcher's own timeout and
    // each refuses its header: the slots are given back.
    for task in waiting {
        assert!(matches!(
            task.await.unwrap(),
            Err(SignalRefusal::Unverified { .. })
        ));
    }
    let slots = alice.gate.fetches.lock().waiting.len();
    assert_eq!(slots, 0, "every place is given back");
}

/// A device whose certificate could not be had is not fetched for again for
/// 30 s, whatever key id its next header names, and is fetched for again once
/// they are over: a fresh key id per header drives no fetch per header.
#[tokio::test]
async fn a_device_whose_certificate_could_not_be_had_is_not_asked_again_for_30_seconds() {
    let world = World::new().await;
    let alice = world.seat("/alice/laptop").await;
    alice
        .members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let asked = fetching(&world, Vec::new());
    let mut headers = Vec::new();
    for id in ["1", "2", "3", "4"] {
        let (dev, _) = world.dev_key("/bob/tablet", id, VALIDITY_MS, false).await;
        headers.push(header_by(&dev, &space()));
    }
    tokio::time::pause();

    for (i, header) in headers[..3].iter().enumerate() {
        match alice.admit(header).await {
            Err(r @ SignalRefusal::Unverified { .. }) => {
                if i > 0 {
                    assert!(r.to_string().contains("30 s"), "{r}");
                }
            }
            other => panic!("no certificate of the key is to be had: {other:?}"),
        }
        assert_eq!(
            asked.lock().unwrap().len(),
            1,
            "header {i}: one fetch for the device, then none while it backs off"
        );
    }
    tokio::time::advance(Duration::from_secs(31)).await;
    assert!(alice.admit(&headers[3]).await.is_err());
    assert_eq!(asked.lock().unwrap().len(), 2, "asked again after 30 s");
}
