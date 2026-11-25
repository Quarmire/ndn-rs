//! The signal gate (spec §11): who is a member of a space for signals, by the
//! operation fold and the trust context; the signal keys of a sealed space;
//! run headers signed and admitted, or refused saying why.
//!
//! The logs are real (own writes signed by real Ed25519 keys, entries relayed
//! between them through `Log::admit`), the judge is real over a validator
//! holding each person's trust context.

use std::sync::Arc;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{ContentKey, RecipientKey};
use ndn_security::{
    Certificate, SecurityManager, SignedTrustContext, Signer, TrustSchema, Validator,
    public_key_digest,
};
use ndn_sync::DataStore;
use parking_lot::Mutex;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use super::*;
use crate::Timestamp;
use crate::error::NextStep;
use crate::log::{Outcome, Params, Step};
use crate::register::EntryId;
use crate::reserve::Flusher;
use crate::revocation::Suspicion;
use crate::seal::{self, Keys};
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
    /// Whether its context declares the role layout.
    layered: bool,
}

impl Authority {
    async fn new(ns: &str, layered: bool) -> Authority {
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
            layered,
        }
    }

    /// Its trust context at `version`, revoking `revoked`.
    fn context(&self, version: u64, revoked: Option<&Name>) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(version);
        if self.layered {
            ctx = ctx.schema_authoritative();
        }
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
            owner_capable: true,
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
        World::build(false).await
    }

    /// As [`World::new`], with every context declaring the role layout (its
    /// schema is authoritative): only `admin` and `member` devices are owner
    /// devices.
    async fn layered() -> World {
        World::build(true).await
    }

    async fn build(layered: bool) -> World {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let mut people = Vec::new();
        for ns in ["/alice", "/bob", "/carol", "/rita", "/eve"] {
            let a = Authority::new(ns, layered).await;
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

    /// A device with its key `KEY/1`, certified by its person's authority;
    /// every seat holds the certificate.
    async fn dev(&self, device: &str) -> Dev {
        let name = n(device);
        let a = self.authority(&name);
        let keys = SecurityManager::new();
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = a
            .keys
            .certify(&key, public, &a.issuer, VALIDITY_MS)
            .await
            .unwrap();
        self.validator.cert_cache().insert(cert);
        Dev {
            person: a.ns.clone(),
            signer: keys.get_signer_sync(&key).unwrap(),
            name,
            key,
        }
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
        let flusher = Flusher::spawn(Arc::clone(&raw));
        let owner_capable =
            crate::trust::owner_capable(&self.validator.keyring().context_for(&dev.key), &dev.key);
        let suspicion = Suspicion::open(Arc::clone(&raw));
        let log = Log::open(
            Params {
                space: space(),
                device: dev.name.clone(),
                person: dev.person.clone(),
                owner_capable,
                signer: Arc::clone(&dev.signer),
                keys: Keys::new(RecipientKey::generate()),
                suspicion: Arc::clone(&suspicion),
                block: 8,
            },
            Arc::clone(&raw),
            Arc::clone(&flusher),
        )
        .unwrap();
        Seat {
            log: Mutex::new(log),
            judge: Judge::new(Arc::clone(&self.validator), raw, None).0,
            store,
            flusher,
            suspicion,
            dev,
        }
    }
}

/// What one node holds of the space: the log and the judge the gate reads.
struct Seat {
    log: Mutex<Log>,
    judge: Arc<Judge>,
    store: Arc<CrashStore>,
    flusher: Arc<Flusher>,
    dev: Dev,
    suspicion: Arc<Suspicion>,
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

/// An own entry a seat signed.
struct Signed {
    id: EntryId,
}

impl Seat {
    /// An own write of the seat's log, waiting for the reservation's flush as
    /// the node does.
    async fn signed(&self, mut write: impl FnMut(&mut Log) -> Result<Step, HeapError>) -> Signed {
        loop {
            let step = write(&mut self.log.lock()).unwrap();
            match step {
                Step::Done(id, _) => return Signed { id },
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    /// The owner signs a Members entry.
    async fn members(&self, body: MembersBody) -> Signed {
        self.signed(|log| log.sign_members(body.clone(), NOW)).await
    }

    /// The owner signs an Epoch entry for `audience`.
    async fn epoch(&self, audience: &[&str]) -> (Signed, EpochId) {
        let signed = self
            .signed(|log| log.sign_epoch(audience.iter().map(|p| n(p)).collect(), NOW))
            .await;
        let epoch = EpochId {
            creator: self.dev.name.clone(),
            seq: signed.id.seq,
        };
        (signed, epoch)
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
        let (outcome, fx) = to
            .log
            .lock()
            .admit(&wire, &data, &self.dev.verified(), NOW, false);
        assert_eq!(outcome, Outcome::Applied, "{:?}", fx.alerts);
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

/// Where the owner's namespace declares the role layout, the owner's person stands for signals
/// only through its `admin` and `member` devices: a guest or node device of the owner is no
/// member (it sends no header and its headers are refused), and gets no scope.
#[tokio::test]
async fn a_guest_or_node_device_of_the_owner_is_no_member_for_signals() {
    let world = World::layered().await;
    let owner = world.seat("/alice/member/laptop").await;
    let observer = world.seat("/rita/pad").await;
    let guest = world.seat("/alice/guest/kid").await;
    let one = owner
        .members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    owner.relay(&one, &observer);
    owner.relay(&one, &guest);
    for (device, member) in [
        ("/alice/member/laptop", true),
        ("/alice/admin/phone", true),
        ("/alice/guest/kid", false),
        ("/alice/node/vps", false),
        ("/bob/member/phone", true),
    ] {
        for seat in [&owner, &observer] {
            assert_eq!(seat.member(&key_of(device)), member, "{device}");
        }
    }
    assert!(
        matches!(guest.scope(), Err(HeapError::NotAllowed { .. })),
        "a guest device of the owner gets no scope"
    );
    assert!(matches!(
        guest.header(&RUN),
        Err(HeapError::NotAllowed { .. })
    ));
}

/// Stage-7 M2: the same holds for a member's devices. Where Bob's namespace declares the role
/// layout, his `guest` and `node` devices are no member for signals though his person is a
/// writer (an `admin` or `member` device of his is one); they get no scope and send nothing.
#[tokio::test]
async fn a_guest_or_node_device_of_a_member_is_no_member_for_signals() {
    let world = World::layered().await;
    let owner = world.seat("/alice/member/laptop").await;
    let observer = world.seat("/rita/pad").await;
    let guest = world.seat("/bob/guest/kid").await;
    let one = owner
        .members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    owner.relay(&one, &observer);
    owner.relay(&one, &guest);
    for (device, member) in [
        ("/bob/member/phone", true),
        ("/bob/admin/tablet", true),
        ("/bob/guest/kid", false),
        ("/bob/node/vps", false),
        ("/bob/phone", false),
    ] {
        for seat in [&owner, &observer] {
            assert_eq!(
                seat.member(&key_of(device)),
                member,
                "{device}: a member's guest or node device stood for signals"
            );
        }
    }
    assert!(
        matches!(guest.scope(), Err(HeapError::NotAllowed { .. })),
        "a guest device of a member gets no scope"
    );
    assert!(matches!(
        guest.header(&RUN),
        Err(HeapError::NotAllowed { .. })
    ));
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

/// A key this node marks suspected (reported stolen, or caught signing two
/// packets at one name) is no member for signals either, before any revocation
/// is held: its run headers are refused saying so, and its own device uses no
/// signals. Lifting the mark restores it; a revocation held refuses it as a
/// revoked key.
#[tokio::test]
async fn a_suspected_key_is_no_member_for_signals_until_unsuspected() {
    let world = World::new().await;
    let (alice, _) = bob_may_write(&world).await;
    let bob = world.seat("/bob/phone").await;
    alice.relay_seq(1, &bob);
    let phone = bob.dev.key.clone();
    let tablet = key_of("/bob/tablet");
    assert!(alice.member(&phone));
    bob.scope().expect("a member before the mark");

    alice.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    bob.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    assert!(!alice.member(&phone), "a suspected key is no member");
    assert!(alice.member(&tablet), "only that key");
    let header = header_by(&bob.dev, &space());
    match alice.sender(&header) {
        Err(r @ SignalRefusal::Suspected { .. }) => {
            let text = r.to_string();
            assert!(
                text.contains("suspected") && text.contains("unsuspects"),
                "{text}"
            );
        }
        other => panic!("a suspected key's header: {other:?}"),
    }
    match bob.header(&RUN) {
        Err(e @ HeapError::NotAllowed { .. }) => {
            assert!(e.to_string().contains("suspected"), "{e}")
        }
        other => panic!("a suspected device signs no run header: {other:?}"),
    }
    assert!(matches!(bob.scope(), Err(HeapError::NotAllowed { .. })));

    assert!(alice.suspicion.lift(&phone));
    assert!(alice.member(&phone), "unsuspected: a member again");

    alice.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    world.revoke("/bob", 2, &phone);
    assert_eq!(
        alice.sender(&header),
        Err(SignalRefusal::BadSignature { key: phone }),
        "a revoked key is refused as revoked, whether or not it is suspected"
    );
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
        let held = log.keys.key(&space(), &e1).unwrap();
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
        ContentKey::from_bytes(*log.keys.key(&space(), &epoch).unwrap().expose())
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
        alice.sender(&forged),
        Err(SignalRefusal::NotMember {
            scope: space(),
            key: rita.dev.key.clone()
        })
    );

    assert!(
        matches!(eve.scope(), Err(HeapError::NotAllowed { .. })),
        "a person the space does not list gets no scope"
    );
}

// -- Run headers ------------------------------------------------------------------------

/// A header of a member names its signer and nothing is kept. A stranger's,
/// one of another space, one misnamed, one named under another device than its
/// signer's and one of a revoked key are each refused saying why; a space
/// whose creation is not held decides nothing. (Verifying the signature is the
/// transport's: `ndn_surface`'s admission.)
#[tokio::test]
async fn a_header_signed_by_a_non_member_is_refused_with_the_reason() {
    let world = World::new().await;
    let (alice, observer) = bob_may_write(&world).await;
    let bob = world.dev("/bob/phone").await;
    let header = header_by(&bob, &space());
    let got = alice.sender(&header).expect("a member's header");
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
    malformed(alice.sender(&header_by(&bob, &other_space())));
    let mut comps = signal_run_name(&bob.name, &space(), &RUN)
        .components()
        .to_vec();
    comps.pop();
    comps.push(NameComponent::generic(Bytes::from_static(&[7; 15])));
    malformed(alice.sender(&named(&bob, Name::from_components(comps))));
    let elsewhere = signal_run_name(&n("/bob/tablet"), &space(), &RUN);
    let why = malformed(alice.sender(&named(&bob, elsewhere)));
    assert!(why.contains("another device"), "{why}");

    let eve = world.dev("/eve/pc").await;
    let why = alice.sender(&header_by(&eve, &space()));
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

    let fresh = world.seat("/eve/laptop").await;
    match fresh.sender(&header) {
        Err(r @ SignalRefusal::NotReady { .. }) => {
            assert!(r.to_string().contains("again"), "{r}")
        }
        other => panic!("no creation held: {other:?}"),
    }

    // The owner removes Bob: his header is the stranger's from the first
    // call after the entry is held, and until then a member's.
    let removal = alice.members(members(None, vec![remove(1)])).await;
    assert!(observer.sender(&header).is_ok());
    alice.relay(&removal, &observer);
    assert!(matches!(
        observer.sender(&header),
        Err(SignalRefusal::NotMember { .. })
    ));

    let (alice, _) = bob_may_write(&world).await;
    world.revoke("/bob", 2, &bob.key);
    assert_eq!(
        alice.sender(&header),
        Err(SignalRefusal::BadSignature { key: bob.key })
    );
}
