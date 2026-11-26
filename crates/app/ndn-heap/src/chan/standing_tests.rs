//! Who stands for a channel (heap.md §11.1, channel.md §4.1): by the operation fold and the
//! trust context, never by time.
//!
//! The logs are real (own writes signed by real Ed25519 keys, entries relayed between them
//! through `Log::admit`), the judge is real over a validator holding each person's trust context.
//! What the channel's setup tests cover (a removal, a revocation, a stranger, a sealed audience)
//! is not repeated here: this file holds what only the function itself can show, the roles of a
//! device, a suspected key, and the difference between a writer and a listed reader.

use std::sync::Arc;

use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::confidentiality::RecipientKey;
use ndn_security::{
    Certificate, SecurityManager, SignedTrustContext, Signer, TrustSchema, Validator,
    public_key_digest,
};
use ndn_sync::DataStore;
use parking_lot::Mutex;

use super::standing::{Unstanding, Who, gate, standing};
use crate::Timestamp;
use crate::error::HeapError;
use crate::log::{Log, Outcome, Params, Step};
use crate::reserve::Flusher;
use crate::revocation::Suspicion;
use crate::seal::Keys;
use crate::test_kit::{CrashStore, n};
use crate::trust::{Judge, Verified};
use crate::wire::{MembersBody, Op, Role, log_name};

const NOW: u64 = 1_000;
const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

fn space() -> Name {
    n("/alice/32=data/board")
}

fn key_of(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

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

/// A device with its key.
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
            tip: None,
        }
    }
}

/// The persons `/alice`, `/bob`, `/carol` and `/rita`, each with its authority, held by the one
/// validator every seat judges by.
struct World {
    validator: Arc<Validator>,
    people: Vec<Authority>,
}

impl World {
    /// With every context declaring the role layout (`layered`): only `admin` and `member`
    /// devices are owner devices; else every device of a person is.
    async fn new(layered: bool) -> World {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        let mut people = Vec::new();
        for ns in ["/alice", "/bob", "/carol", "/rita"] {
            let a = Authority::new(ns, layered).await;
            validator.adopt_context(a.context(1, None)).unwrap();
            people.push(a);
        }
        World { validator, people }
    }

    /// A device with its key `KEY/1`, certified by its person's authority.
    async fn dev(&self, device: &str) -> Dev {
        let name = n(device);
        let a = self
            .people
            .iter()
            .find(|a| name.has_prefix(&a.ns))
            .expect("a device of a person of the world");
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

impl Seat {
    /// The owner signs a Members entry (the first one creates the space, public when
    /// `create` is `Some(true)`), waiting for the reservation's flush as the node does; its seq.
    async fn members(&self, create: Option<bool>, ops: Vec<Op>) -> u64 {
        loop {
            let step = self
                .log
                .lock()
                .sign_members(
                    MembersBody {
                        create,
                        ops: ops.clone(),
                    },
                    NOW,
                )
                .unwrap();
            match step {
                Step::Done(id, _) => return id.seq,
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    /// Hand `to` the entry of `seq` this seat signed, as if fetched and judged.
    fn relay(&self, seq: u64, to: &Seat) {
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

    /// Whether `key` stands as `who` by what this seat holds.
    fn stands(&self, key: &Name, who: Who) -> Result<Name, Unstanding> {
        standing(&self.log.lock(), &self.judge, key, who)
    }

    /// This seat's own device asked the gate as `who`.
    fn gate(&self, who: Who) -> Result<(), HeapError> {
        gate(&self.log.lock(), &self.judge, who, "test")
    }
}

/// Where a person's namespace declares the role layout it stands only through its `admin` and
/// `member` devices, in any role asked: a `guest` or a `node` device of the owner, or of a
/// member whose person is a writer, does not stand, and its own gate refuses it saying why.
#[tokio::test]
async fn a_guest_or_node_device_does_not_stand_in_any_role() {
    let world = World::new(true).await;
    let owner = world.seat("/alice/member/laptop").await;
    let observer = world.seat("/rita/pad").await;
    let guest_of_owner = world.seat("/alice/guest/kid").await;
    let guest_of_member = world.seat("/bob/guest/kid").await;
    let one = owner
        .members(Some(true), vec![add(1, "/bob", Role::Writer)])
        .await;
    for to in [&observer, &guest_of_owner, &guest_of_member] {
        owner.relay(one, to);
    }
    for (device, stands) in [
        ("/alice/member/laptop", true),
        ("/alice/admin/phone", true),
        ("/alice/guest/kid", false),
        ("/alice/node/vps", false),
        ("/bob/member/phone", true),
        ("/bob/admin/tablet", true),
        ("/bob/guest/kid", false),
        ("/bob/node/vps", false),
        // a device with no role at all, in a namespace that declares the layout
        ("/bob/phone", false),
    ] {
        for seat in [&owner, &observer] {
            for who in [Who::Writer, Who::Listed] {
                assert_eq!(
                    seat.stands(&key_of(device), who).is_ok(),
                    stands,
                    "{device} as {who:?}: a guest, a node or a role-less device stood"
                );
            }
        }
    }
    for guest in [&guest_of_owner, &guest_of_member] {
        for who in [Who::Writer, Who::Listed] {
            match guest.gate(who) {
                Err(HeapError::NotAllowed { why, .. }) => {
                    assert!(why.contains("ask the owner"), "{why}")
                }
                other => panic!("{} as {who:?}: {other:?}", guest.dev.name),
            }
        }
    }
}

/// A key this node marks suspected (reported stolen, or caught signing two packets at one name)
/// does not stand before any revocation is held, in any role: its own device is refused saying
/// so. Lifting the mark restores it; a revocation held refuses it as revoked, marked or not.
#[tokio::test]
async fn a_suspected_key_does_not_stand_until_unsuspected() {
    let world = World::new(false).await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let one = alice
        .members(Some(true), vec![add(1, "/bob", Role::Writer)])
        .await;
    alice.relay(one, &bob);
    let phone = bob.dev.key.clone();
    let tablet = key_of("/bob/tablet");
    for who in [Who::Writer, Who::Listed] {
        assert!(alice.stands(&phone, who).is_ok(), "{who:?} before the mark");
    }
    bob.gate(Who::Writer).expect("a writer before the mark");

    alice.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    bob.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    for who in [Who::Writer, Who::Listed] {
        assert_eq!(
            alice.stands(&phone, who),
            Err(Unstanding::Suspected),
            "{who:?}: a suspected key stood"
        );
        assert!(alice.stands(&tablet, who).is_ok(), "only that key");
    }
    match bob.gate(Who::Writer) {
        Err(e @ HeapError::NotAllowed { .. }) => {
            assert!(e.to_string().contains("suspected"), "{e}")
        }
        other => panic!("a suspected device takes no part: {other:?}"),
    }

    assert!(alice.suspicion.lift(&phone));
    assert!(alice.stands(&phone, Who::Writer).is_ok(), "unsuspected");

    alice.suspicion.mark(&phone, Timestamp(NOW)).unwrap();
    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(2, Some(&phone)))
        .unwrap();
    assert_eq!(
        alice.stands(&phone, Who::Writer),
        Err(Unstanding::Revoked),
        "a revoked key is refused as revoked, whether or not it is suspected"
    );
}

/// A context that revokes the key that certified a device's key revokes that device's key too, as
/// a chain walk of a packet it signed would find; another person's keys are not touched. Nothing
/// is fetched: the certificates are the ones held.
#[tokio::test]
async fn a_key_certified_by_a_revoked_issuer_does_not_stand() {
    let world = World::new(false).await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let carol = world.seat("/carol/phone").await;
    let one = alice
        .members(
            Some(true),
            vec![add(1, "/bob", Role::Writer), add(2, "/carol", Role::Writer)],
        )
        .await;
    alice.relay(one, &bob);
    let (phone, carols) = (bob.dev.key.clone(), carol.dev.key.clone());
    let tablet = world.dev("/bob/tablet").await.key;
    for key in [&phone, &tablet, &carols] {
        assert!(alice.stands(key, Who::Writer).is_ok(), "{key} before");
    }

    let bobs_issuer = world.people[1].issuer.clone();
    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(2, Some(&bobs_issuer)))
        .unwrap();
    for key in [&phone, &tablet] {
        assert_eq!(
            alice.stands(key, Who::Writer),
            Err(Unstanding::Revoked),
            "{key}: the key that certified it is revoked"
        );
    }
    assert!(
        alice.stands(&carols, Who::Writer).is_ok(),
        "another person's key is not touched"
    );
}

/// A key of `/bob` certified through an intermediate issuer (`/bob/KEY/mid`, which the person's
/// anchor key certified): the key, its certificate and the intermediate's. Nothing is cached.
async fn bobs_key_under_an_intermediate(
    world: &World,
    device: &str,
) -> (Name, Certificate, Certificate) {
    let bob = &world.people[1];
    let mid = bob
        .keys
        .generate_ed25519(n("/bob").append("KEY").append("mid"))
        .unwrap();
    let mid_public = bob
        .keys
        .get_signer_sync(&mid)
        .unwrap()
        .public_key()
        .unwrap();
    let mid_cert = bob
        .keys
        .certify(&mid, mid_public, &bob.issuer, VALIDITY_MS)
        .await
        .unwrap();
    let keys = SecurityManager::new();
    let key = keys
        .generate_ed25519(n(device).append("KEY").append("1"))
        .unwrap();
    let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
    let cert = bob
        .keys
        .certify(&key, public, &mid, VALIDITY_MS)
        .await
        .unwrap();
    (key, cert, mid_cert)
}

/// A certificate no one vouched for was written by whoever served it, its `issuer` included: it
/// neither revokes a key (a forged one naming a revoked issuer) nor hides a revoked issuer (a
/// forged one naming a good issuer). Where no certificate vouched for answers for a key and the
/// context revokes keys, the chain is unknown and the key does not stand, whatever a fetched
/// copy says.
#[tokio::test]
async fn a_certificate_no_one_vouched_for_neither_revokes_nor_hides_an_issuer() {
    let world = World::new(false).await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let one = alice
        .members(Some(true), vec![add(1, "/bob", Role::Writer)])
        .await;
    alice.relay(one, &bob);
    let cache = world.validator.cert_cache();
    let (lost, good) = (n("/bob/KEY/lost"), n("/bob/KEY/good"));

    // The context revokes a key nothing here was certified by, then the person's own issuer.
    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(2, Some(&lost)))
        .unwrap();
    let (tablet, forged, _) = bobs_key_under_an_intermediate(&world, "/bob/tablet").await;
    let mut names_revoked = forged.clone();
    names_revoked.issuer = Some(Arc::new(lost.clone()));
    assert!(cache.insert_unverified(names_revoked));
    let got = alice.stands(&tablet, Who::Writer);
    assert!(
        matches!(&got, Err(why) if *why != Unstanding::Revoked),
        "{got:?}: a fetched certificate naming a revoked issuer revoked the key it is for"
    );

    let bobs_issuer = world.people[1].issuer.clone();
    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(3, Some(&bobs_issuer)))
        .unwrap();
    let (hider, real, _) = bobs_key_under_an_intermediate(&world, "/bob/watch").await;
    let mut names_good = real.clone();
    names_good.issuer = Some(Arc::new(good));
    assert!(cache.insert_unverified(names_good));
    assert!(
        alice.stands(&hider, Who::Writer).is_err(),
        "a fetched certificate naming a good issuer hid the revoked issuer of the chain"
    );
}

/// A chain of vouched certificates that does not reach an anchor of the context (an intermediate
/// certificate is not held) cannot be read for a revoked issuer. While the context revokes
/// nothing there is nothing to find and the key stands (a fresh ask is judged by a walk that
/// vouches its chain); once the context revokes a key the chain may hold, the key does not stand
/// until the chain is complete, so a session is not kept alive by a gap in what is cached. A
/// complete chain is followed to the revoked key above it.
#[tokio::test]
async fn a_chain_that_cannot_be_followed_does_not_stand_while_the_context_revokes() {
    let world = World::new(false).await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let one = alice
        .members(Some(true), vec![add(1, "/bob", Role::Writer)])
        .await;
    alice.relay(one, &bob);
    let (key, cert, mid_cert) = bobs_key_under_an_intermediate(&world, "/bob/tablet").await;
    let cache = world.validator.cert_cache();
    cache.insert(cert);
    assert!(
        alice.stands(&key, Who::Writer).is_ok(),
        "nothing is revoked: the gap hides nothing"
    );

    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(2, Some(&n("/bob/KEY/lost"))))
        .unwrap();
    let got = alice.stands(&key, Who::Writer);
    assert!(
        got.is_err(),
        "an intermediate issuer is not held and the context revokes a key: the chain is unknown, \
         yet the key stood"
    );
    cache.insert(mid_cert);
    assert!(
        alice.stands(&key, Who::Writer).is_ok(),
        "the chain reaches the anchor, no revoked key on it"
    );

    let bobs_issuer = world.people[1].issuer.clone();
    world
        .validator
        .keyring()
        .adopt_update(world.people[1].context(3, Some(&bobs_issuer)))
        .unwrap();
    assert_eq!(
        alice.stands(&key, Who::Writer),
        Err(Unstanding::Revoked),
        "the anchor key two hops above is revoked"
    );
}

/// A reader the record lists stands as **listed** and never as a writer; a person a public
/// space does not list at all stands in neither role (everybody may read a public space's kept
/// data, but a channel's key is wrapped only to a listed person's key), and the owner always
/// stands as a writer.
#[tokio::test]
async fn a_reader_stands_as_listed_and_not_as_a_writer() {
    let world = World::new(false).await;
    let alice = world.seat("/alice/laptop").await;
    let bob = world.seat("/bob/phone").await;
    let carol = world.seat("/carol/phone").await;
    let rita = world.seat("/rita/pad").await;
    let one = alice
        .members(
            Some(true),
            vec![add(1, "/bob", Role::Writer), add(2, "/carol", Role::Reader)],
        )
        .await;
    for to in [&bob, &carol, &rita] {
        alice.relay(one, to);
    }
    for (device, writer, listed) in [
        ("/alice/laptop", true, true),
        ("/bob/phone", true, true),
        ("/carol/phone", false, true),
        ("/rita/pad", false, false),
    ] {
        for seat in [&alice, &bob, &carol, &rita] {
            assert_eq!(
                seat.stands(&key_of(device), Who::Writer).is_ok(),
                writer,
                "{device} as a writer"
            );
            assert_eq!(
                seat.stands(&key_of(device), Who::Listed).is_ok(),
                listed,
                "{device} as listed"
            );
        }
    }
    assert_eq!(
        alice.stands(&key_of("/carol/phone"), Who::Listed),
        Ok(n("/carol")),
        "the answer names the person"
    );
    assert!(matches!(
        carol.gate(Who::Writer),
        Err(HeapError::NotAllowed { .. })
    ));
    carol.gate(Who::Listed).expect("a listed reader takes part");
    assert!(matches!(
        rita.gate(Who::Listed),
        Err(HeapError::NotAllowed { .. })
    ));
}
