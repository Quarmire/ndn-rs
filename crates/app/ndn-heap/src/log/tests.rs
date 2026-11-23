//! The log's invariants, over real Ed25519 keys and the crash store: what is
//! admitted, what a cut keeps, what a restart finds, what the first entry
//! after an unclean open says. The judge is the caller's: a case hands the
//! log the `Verified` the judge would have made.

use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{ContentKey, RecipientKey};
use ndn_security::{Ed25519Signer, Signer, public_key_digest};
use ndn_sync::DataStore;
use proptest::prelude::*;

use super::*;
use crate::error::{Cut, NextStep, Refusal};
use crate::reserve::{Flusher, Reservation};
use crate::seal::{self, Keys};
use crate::store::{
    self, Marker, ReserveRecord, Stage, equivocal_key, ledger_key, read_reserve, status_key,
    structural_key, verified_key, walk_chain, write_reserve,
};
use crate::test_kit::{CrashStore, n};
use crate::wire::{
    self, Body, Entry, EntryRef, EpochBody, EpochId, MembersBody, Op, Payload, Prev, PutBody, Role,
    SealedBody, log_name, signed_digest,
};

const NOW: u64 = 1_000;
const BLOCK: u64 = 8;

fn space() -> Name {
    n("/alice/32=data/notes")
}

/// One device with its key: what signs, and what the judge would say of it.
#[derive(Clone)]
struct Dev {
    name: Name,
    key: Name,
    person: Name,
    signer: Arc<Ed25519Signer>,
}

fn dev(name: &str, person: &str, seed: u8) -> Dev {
    let key = n(&format!("{name}/KEY/k1"));
    Dev {
        name: n(name),
        key: key.clone(),
        person: n(person),
        signer: Arc::new(Ed25519Signer::from_seed(&[seed; 32], key)),
    }
}

fn laptop() -> Dev {
    dev("/alice/laptop", "/alice", 1)
}
fn phone() -> Dev {
    dev("/alice/phone", "/alice", 2)
}
fn bob() -> Dev {
    dev("/bob/phone", "/bob", 3)
}
fn carol() -> Dev {
    dev("/carol/phone", "/carol", 4)
}

fn verified(d: &Dev) -> Verified {
    Verified {
        key: d.key.clone(),
        device: d.name.clone(),
        person: d.person.clone(),
        key_digest: public_key_digest(&d.signer.public_key_bytes()),
    }
}

/// A signed packet and what the judge says of it.
#[derive(Clone)]
struct Packet {
    dev: Dev,
    seq: u64,
    wire: Bytes,
    digest: [u8; 32],
}

impl Packet {
    fn name(&self) -> Name {
        log_name(&self.dev.name, &space(), self.seq)
    }
    fn entry_ref(&self) -> EntryRef {
        EntryRef {
            device: self.dev.name.clone(),
            seq: self.seq,
            digest: self.digest,
        }
    }
}

fn sign_raw(d: &Dev, seq: u64, content: &[u8]) -> Packet {
    let name = log_name(&d.name, &space(), seq);
    let wire = seal::sign(DataBuilder::new(name, content), &*d.signer).unwrap();
    Packet {
        dev: d.clone(),
        seq,
        digest: signed_digest(&wire),
        wire,
    }
}

fn sign_entry(d: &Dev, seq: u64, entry: &Entry) -> Packet {
    sign_raw(d, seq, &entry.encode().unwrap())
}

/// A device's chain: each entry names the one before.
struct Chain {
    dev: Dev,
    seq: u64,
    last: Option<[u8; 32]>,
}

impl Chain {
    fn new(dev: &Dev) -> Chain {
        Chain {
            dev: dev.clone(),
            seq: 0,
            last: None,
        }
    }

    /// The next entry, dense after the last.
    fn entry(&mut self, body: Body, after: Vec<EntryRef>) -> Packet {
        let prev = self.last.map(|digest| Prev { digest, seq: None });
        self.seq += 1;
        let p = sign_entry(&self.dev, self.seq, &Entry { prev, after, body });
        self.last = Some(p.digest);
        p
    }

    fn put(&mut self, path: &str, bytes: &str) -> Packet {
        self.put_after(path, bytes, vec![])
    }

    fn put_after(&mut self, path: &str, bytes: &str, after: Vec<EntryRef>) -> Packet {
        self.entry(
            Body::Put(PutBody {
                path: n(path),
                payload: Payload::Inline(Bytes::from(bytes.to_owned())),
            }),
            after,
        )
    }

    fn members(&mut self, body: MembersBody) -> Packet {
        self.entry(Body::Members(body), vec![])
    }

    /// Skip `n` seqs without signing them, and say so in the next entry.
    fn skip(&mut self, n: u64) {
        self.seq += n;
    }

    /// The next entry after a skip: `PREV_SEQ` names the entry before it.
    fn entry_after_gap(&mut self, body: Body, from: u64, digest: [u8; 32]) -> Packet {
        self.seq += 1;
        let prev = Some(Prev {
            digest,
            seq: Some(from),
        });
        let p = sign_entry(
            &self.dev,
            self.seq,
            &Entry {
                prev,
                after: vec![],
                body,
            },
        );
        self.last = Some(p.digest);
        p
    }
}

fn add(id: u8, who: &str, role: Role) -> Op {
    Op::Add {
        id: [id; 16],
        who: n(who),
        role,
        epoch: None,
    }
}

fn remove(id: u8, tips: Vec<EntryRef>) -> Op {
    Op::Remove { id: [id; 16], tips }
}

fn members(create: Option<bool>, ops: Vec<Op>) -> MembersBody {
    MembersBody { create, ops }
}

/// A log over a crash store, as the node holds it.
struct Rig {
    log: Log,
    store: Arc<CrashStore>,
    stage: Arc<Stage>,
    flusher: Arc<Flusher>,
    me: Dev,
}

fn open_on(store: &Arc<CrashStore>, me: &Dev) -> Rig {
    let raw = Arc::clone(store) as Arc<dyn DataStore>;
    let stage = Stage::new(Arc::clone(&raw));
    let flusher = Flusher::spawn(Arc::clone(&raw));
    let log = Log::open(
        Params {
            space: space(),
            device: me.name.clone(),
            person: me.person.clone(),
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            block: BLOCK,
        },
        raw,
        Arc::clone(&stage),
        Arc::clone(&flusher),
    )
    .unwrap();
    Rig {
        log,
        store: Arc::clone(store),
        stage,
        flusher,
        me: me.clone(),
    }
}

fn rig(me: &Dev) -> Rig {
    open_on(&Arc::new(CrashStore::new()), me)
}

impl Rig {
    fn admit(&mut self, p: &Packet) -> Admitted {
        let data = Data::decode(p.wire.clone()).unwrap();
        self.log.admit(&p.wire, &data, &verified(&p.dev), NOW)
    }

    fn applied(&mut self, p: &Packet) -> Admitted {
        let a = self.admit(p);
        assert_eq!(a.outcome, Outcome::Applied, "{:?}", a.effects.alerts);
        a
    }

    /// Own put, waiting for the reservation's flush as the node does.
    async fn put(&mut self, path: &str, bytes: &str) -> Signed {
        loop {
            let step = self
                .log
                .put(
                    &n(path),
                    Payload::Inline(Bytes::from(bytes.to_owned())),
                    vec![],
                    NOW,
                )
                .unwrap();
            match step {
                Step::Done(signed) => return signed,
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    async fn members(&mut self, body: MembersBody) -> Signed {
        loop {
            match self.log.sign_members(body.clone(), NOW).unwrap() {
                Step::Done(signed) => return signed,
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    fn value(&self, path: &str) -> Option<String> {
        self.log
            .get(&n(path))
            .unwrap()
            .map(|i| String::from_utf8(i.bytes.to_vec()).unwrap())
    }

    fn crash(&self) -> Arc<CrashStore> {
        Arc::new(self.store.crash())
    }
}

/// The owner's phone signs the creation: Bob a writer, a public space.
fn creation(owner: &mut Chain) -> Packet {
    owner.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
}

fn has_alert(a: &Admitted, f: impl Fn(&Alert) -> bool) -> bool {
    a.effects.alerts.iter().any(f)
}

// -- Admission and the register ------------------------------------------------

#[tokio::test]
async fn withdrawing_a_head_restores_the_entry_it_superseded() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    r.applied(&creation(&mut owner));
    let first = b.put("/a", "v1");
    let second = b.put_after("/a", "v2", vec![first.entry_ref()]);
    r.applied(&first);
    r.applied(&second);
    assert_eq!(r.value("/a").as_deref(), Some("v2"));

    let fx = r
        .log
        .withdraw(&second.dev.name, second.seq, Refusal::NotMember);
    assert_eq!(r.value("/a").as_deref(), Some("v1"), "v1 is the head again");
    assert!(
        fx.changes
            .iter()
            .any(|c| matches!(c, Change::Withdrawn { id, why: Refusal::NotMember } if id.seq == 2))
    );
    assert!(
        fx.changes
            .iter()
            .any(|c| matches!(c, Change::Put(i) if i.bytes == "v1"))
    );
}

#[tokio::test]
async fn a_late_cut_withdraws_what_it_does_not_keep() {
    // o1/k4: Bob's entries were taken while he was a writer; the removal
    // that arrives later keeps the chain to seq 2 and nothing above.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    r.applied(&creation(&mut owner));
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    for p in [&p1, &p2, &p3] {
        r.applied(p);
    }
    let cut = owner.members(members(None, vec![remove(1, vec![p2.entry_ref()])]));
    let a = r.applied(&cut);
    assert_eq!(r.value("/p1").as_deref(), Some("1"));
    assert_eq!(r.value("/p2").as_deref(), Some("2"));
    assert_eq!(r.value("/p3"), None, "the cut does not keep seq 3");
    assert!(a.effects.changes.iter().any(
        |c| matches!(c, Change::Withdrawn { id, why: Refusal::OutsideCut(Cut { keeps_to: 2, .. }) } if id.seq == 3)
    ));
}

#[tokio::test]
async fn a_removed_writers_entry_inside_the_cut_is_kept_and_outside_it_refused() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    r.applied(&creation(&mut owner));
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    r.applied(&owner.members(members(None, vec![remove(1, vec![p2.entry_ref()])])));

    // The tip first: it is the entry the cut names, so it is kept; what it
    // chains to is wanted.
    let a = r.applied(&p2);
    assert!(
        a.effects
            .wants
            .iter()
            .any(|w| w.device == p2.dev.name && w.first == 1 && w.digest == Some(p1.digest))
    );
    r.applied(&p1);
    let a = r.admit(&p3);
    assert!(matches!(
        a.outcome,
        Outcome::Refused(Refusal::OutsideCut(Cut { keeps_to: 2, .. }))
    ));
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::OutsideCut { id } if id.seq == 3)
    ));
    assert_eq!(r.value("/p3"), None);
    assert_eq!(r.value("/p2").as_deref(), Some("2"));
}

#[tokio::test]
async fn other_bytes_at_a_kept_seq_are_refused() {
    // k9, r5: the cut keeps the entry whose digest it names; another packet
    // Bob's key signed at that seq is not it.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    r.applied(&creation(&mut owner));
    let p1 = b.put("/p1", "1");
    let p2 = b.put("/p2", "2");
    let other = sign_entry(
        &bob(),
        2,
        &Entry {
            prev: Some(Prev {
                digest: p1.digest,
                seq: None,
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/p2"),
                payload: Payload::Inline(Bytes::from_static(b"forged")),
            }),
        },
    );
    r.applied(&owner.members(members(None, vec![remove(1, vec![p2.entry_ref()])])));
    let a = r.admit(&other);
    assert!(
        matches!(a.outcome, Outcome::Refused(Refusal::OutsideCut(_))),
        "{:?}",
        a.outcome
    );
    assert_eq!(r.value("/p2"), None);
    r.applied(&p2);
    r.applied(&p1);
    assert_eq!(r.value("/p2").as_deref(), Some("2"));
    assert_eq!(r.value("/p1").as_deref(), Some("1"));
}

#[tokio::test]
async fn an_orphan_inside_a_gap_is_kept() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    r.applied(&creation(&mut owner));
    let p1 = b.put("/p1", "1");
    let orphan = b.put("/orphan", "2");
    // Bob's device restarted without seq 2 and says so.
    let p3 = b.entry_after_gap(
        Body::Put(PutBody {
            path: n("/p3"),
            payload: Payload::Inline(Bytes::from_static(b"3")),
        }),
        1,
        p1.digest,
    );
    r.applied(&p1);
    r.applied(&p3);
    assert_eq!(r.log.voids(&bob().name), vec![(2, 2)]);
    let a = r.applied(&orphan);
    assert!(!has_alert(&a, |al| matches!(
        al,
        Alert::Equivocation { .. }
    )));
    assert_eq!(r.value("/orphan").as_deref(), Some("2"));
}

#[tokio::test]
async fn two_packets_at_one_name_are_evidence_and_the_key_is_suspected() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let first = Chain::new(&bob()).put("/a", "one");
    let second = Chain::new(&bob()).put("/a", "two");
    assert_eq!(first.name(), second.name());
    assert_ne!(first.digest, second.digest);
    r.applied(&first);
    let a = r.admit(&second);
    assert_eq!(a.outcome, Outcome::Evidence);
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::Equivocation { device, seq: 1 } if *device == bob().name)
    ));
    assert_eq!(a.effects.suspect, vec![bob().key]);
    assert!(r.log.suspected(&bob().key).is_some());
    assert_eq!(
        r.store.get(&equivocal_key(&first.name())),
        Some(second.wire.clone())
    );
    assert_eq!(r.value("/a").as_deref(), Some("one"), "the first stands");

    // Its later entries are not taken while the mark stands.
    let next = Chain::new(&bob()).put("/b", "x");
    let later = {
        let mut c = Chain::new(&bob());
        c.seq = 1;
        c.last = Some(first.digest);
        c.put("/b", "x")
    };
    let _ = next;
    let a = r.admit(&later);
    assert!(matches!(
        a.outcome,
        Outcome::Refused(Refusal::Suspected { .. })
    ));
}

#[tokio::test]
async fn a_relays_high_s_copy_changes_nothing() {
    // The same signed region under another signature value is one signed
    // object: no equivocation, no new head, and a successor's PREV (the
    // signed digest) matches whichever copy was taken.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let p1 = b.put("/a", "one");
    let p2 = b.put_after("/a", "two", vec![p1.entry_ref()]);
    let name = p1.name();
    let content = Data::decode(p1.wire.clone())
        .unwrap()
        .content()
        .unwrap()
        .clone();
    let relayed = {
        let wire = DataBuilder::new(name, &content).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&bob().key),
            |_| Bytes::from(vec![0x5a; 64]),
        );
        Packet {
            digest: signed_digest(&wire),
            wire,
            ..p1.clone()
        }
    };
    assert_ne!(relayed.wire, p1.wire);
    assert_eq!(relayed.digest, p1.digest);

    r.applied(&relayed);
    let a = r.admit(&p1);
    assert_eq!(a.outcome, Outcome::Duplicate);
    assert!(a.effects.alerts.is_empty() && a.effects.suspect.is_empty());
    // p2 chains to the signed digest: the relayed copy satisfies it.
    r.applied(&p2);
    assert_eq!(r.value("/a").as_deref(), Some("two"));
    assert!(r.log.suspected(&bob().key).is_none());
    // The marker records the signed digest, not the wire's.
    let m = Marker::decode(&r.store.get(&verified_key(&p1.name())).unwrap()).unwrap();
    assert_eq!(m.signed_digest, p1.digest);
}

#[tokio::test]
async fn an_entry_that_verifies_but_does_not_decode_is_recorded_as_refused_and_walks_complete() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let p1 = b.put("/a", "one");
    r.applied(&p1);
    let junk = sign_raw(&bob(), 2, b"\xff\xfenot an entry");
    let a = r.admit(&junk);
    assert_eq!(a.outcome, Outcome::Unreadable);
    assert!(
        r.store.contains(&verified_key(&junk.name())),
        "a marker records it"
    );
    assert!(r.store.contains(&status_key(&space(), &bob().name, 2)));
    let walk = walk_chain(
        &*r.store,
        &bob().name,
        &space(),
        store::Link {
            seq: 2,
            digest: junk.digest,
        },
    );
    assert!(walk.is_complete(), "{walk:?}");
    assert_eq!(r.log.held_prefix(&bob().name), 2);
    assert!(
        r.log.missing().iter().all(|w| w.device != bob().name),
        "it is not fetched again"
    );
    // Offered again it is a duplicate, never decoded again.
    assert_eq!(r.admit(&junk).outcome, Outcome::Duplicate);
}

#[tokio::test]
async fn equivocation_in_a_members_or_epoch_entry_is_reported_to_the_host() {
    let mut r = rig(&carol());
    let one = Chain::new(&phone()).members(members(Some(true), vec![add(1, "/bob", Role::Writer)]));
    let two =
        Chain::new(&phone()).members(members(Some(true), vec![add(2, "/carol", Role::Writer)]));
    r.applied(&one);
    let a = r.admit(&two);
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::Equivocation { device, seq: 1 } if *device == phone().name)
    ));
    assert_eq!(a.effects.suspect, vec![phone().key]);
    // Both are facts of the space: the fold lists both Adds whichever came
    // first.
    assert!(r.log.fold().is_writer(&n("/bob")));
    assert!(r.log.fold().is_writer(&n("/carol")));
}

#[tokio::test]
async fn a_members_entry_from_a_device_outside_the_owner_namespace_is_refused() {
    let mut r = rig(&carol());
    let forged =
        Chain::new(&bob()).members(members(Some(true), vec![add(1, "/bob", Role::Writer)]));
    let a = r.admit(&forged);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::NotMember));
    assert!(!r.log.fold().is_writer(&n("/bob")));
}

#[tokio::test]
async fn an_entry_before_the_members_entry_that_admits_its_writer_waits_for_it() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let p1 = Chain::new(&bob()).put("/a", "one");
    let a = r.admit(&p1);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::NotMember));
    assert_eq!(r.value("/a"), None);
    let a = r.applied(&creation(&mut owner));
    assert_eq!(r.value("/a").as_deref(), Some("one"));
    assert!(
        a.effects
            .changes
            .iter()
            .any(|c| matches!(c, Change::Put(i) if i.bytes == "one"))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn an_entry_by_a_removed_person_after_the_tip_never_counts_in_any_arrival_order(
        order in Just((0..5usize).collect::<Vec<_>>()).prop_shuffle()
    ) {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let _in = rt.enter();
        let mut owner = Chain::new(&phone());
        let mut b = Chain::new(&bob());
        let add_bob = creation(&mut owner);
        let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
        let cut = owner.members(members(None, vec![remove(1, vec![p2.entry_ref()])]));
        let all = [add_bob, p1, p2, p3, cut];
        let mut r = rig(&carol());
        for i in order {
            r.admit(&all[i]);
        }
        prop_assert_eq!(r.value("/p1"), Some("1".to_owned()));
        prop_assert_eq!(r.value("/p2"), Some("2".to_owned()));
        prop_assert_eq!(r.value("/p3"), None);
        prop_assert!(!r.log.fold().is_writer(&n("/bob")));
    }
}

// -- Sealed spaces ---------------------------------------------------------------

/// A sealed space with Carol a reader, Bob a writer and epoch 2 of the
/// owner's phone for the owner and Carol.
struct Sealed {
    key: [u8; 32],
    epoch: EpochId,
    created: Packet,
    epoch_entry: Packet,
}

fn sealed_space() -> Sealed {
    let key = [7u8; 32];
    let mut owner = Chain::new(&phone());
    let created = owner.members(members(
        Some(false),
        vec![add(1, "/bob", Role::Writer), add(2, "/carol", Role::Reader)],
    ));
    let epoch = EpochId {
        creator: phone().name,
        seq: 2,
    };
    let epoch_entry = owner.entry(
        Body::Epoch(EpochBody {
            key_check: seal::key_check(&ContentKey::from_bytes(key), &space(), &epoch),
            audience: vec![n("/alice"), n("/carol")],
        }),
        vec![],
    );
    Sealed {
        key,
        epoch,
        created,
        epoch_entry,
    }
}

fn sealed_put(s: &Sealed, path: &str, bytes: &str) -> Packet {
    // The AAD is the entry's own name, so the name is fixed first.
    let name = log_name(&bob().name, &space(), 1);
    let plain = wire::encode_sealed_plain(&PutBody {
        path: n(path),
        payload: Payload::Inline(Bytes::from(bytes.to_owned())),
    })
    .unwrap();
    let sealed = seal::seal_payload(&ContentKey::from_bytes(s.key), &name, &plain);
    sign_entry(
        &bob(),
        1,
        &Entry {
            prev: None,
            after: vec![],
            body: Body::Sealed(SealedBody {
                epoch: s.epoch.clone(),
                sealed,
            }),
        },
    )
}

#[tokio::test]
async fn a_sealed_entry_without_the_key_is_held_closed_and_opens_when_the_key_arrives() {
    let s = sealed_space();
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    let put = sealed_put(&s, "/secret", "hush");
    let a = r.admit(&put);
    assert_eq!(a.outcome, Outcome::Closed);
    assert!(r.log.has_closed());
    // A closed entry's path is unknown, so no read of the space can say.
    assert!(matches!(
        r.log.get(&n("/secret")),
        Err(HeapError::Sealed { .. })
    ));

    let (taken, fx) = r
        .log
        .key_arrived(s.epoch.clone(), ContentKey::from_bytes(s.key));
    assert!(taken);
    assert!(
        fx.changes
            .iter()
            .any(|c| matches!(c, Change::Put(i) if i.path == n("/secret") && i.bytes == "hush"))
    );
    assert_eq!(r.value("/secret").as_deref(), Some("hush"));
    assert!(!r.log.has_closed());
    // A key that does not match the Epoch entry's check is dropped.
    let (taken, _) = r
        .log
        .key_arrived(s.epoch.clone(), ContentKey::from_bytes([9; 32]));
    assert!(!taken || r.value("/secret").is_some());
}

#[tokio::test]
async fn an_unsealed_entry_in_a_sealed_space_is_refused() {
    let s = sealed_space();
    let mut r = rig(&carol());
    r.applied(&s.created);
    let plain = Chain::new(&bob()).put("/a", "in the clear");
    let a = r.admit(&plain);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::Unsealed));
    assert!(has_alert(&a, |al| matches!(
        al,
        Alert::Refused {
            why: Refusal::Unsealed,
            next: NextStep::None,
            ..
        }
    )));
}

#[tokio::test]
async fn a_sealed_entry_in_a_public_space_is_refused() {
    let s = sealed_space();
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let a = r.admit(&sealed_put(&s, "/a", "x"));
    assert_eq!(a.outcome, Outcome::Refused(Refusal::Sealed));
}

// -- Own writes --------------------------------------------------------------------

#[tokio::test]
async fn a_non_writer_put_is_refused_not_allowed() {
    let mut r = rig(&carol());
    let put = |r: &mut Rig| {
        r.log.put(
            &n("/a"),
            Payload::Inline(Bytes::from_static(b"x")),
            vec![],
            NOW,
        )
    };
    // Before it has seen the space's creation the device cannot say.
    let err = put(&mut r).err().unwrap();
    assert!(matches!(err, HeapError::NotReady { .. }), "{err:?}");
    assert_eq!(err.next(), NextStep::RetryLater);

    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let err = put(&mut r).err().unwrap();
    assert!(matches!(err, HeapError::NotAllowed { .. }), "{err:?}");
    assert_eq!(err.next(), NextStep::AskOwner);
}

#[tokio::test]
async fn an_own_put_is_signed_chained_stored_in_one_batch_and_applied() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    let batches = r.store.unsynced();
    let a = r.put("/a", "one").await;
    // One batch holds the entry and every record that goes with it.
    assert_eq!(r.store.unsynced(), batches + 1);
    let b = r.put("/a", "two").await;
    assert_eq!((a.id.seq, b.id.seq), (2, 3));
    assert_eq!(
        a.effects.publish,
        Some(Publish {
            seq: 2,
            structural: false
        })
    );
    let wire = r.store.get(&log_name(&me.name, &space(), 3)).unwrap();
    let data = Data::decode(wire).unwrap();
    let entry = Entry::decode(data.content().unwrap()).unwrap();
    assert_eq!(
        entry.prev,
        Some(Prev {
            digest: a.id.digest,
            seq: None
        })
    );
    assert_eq!(
        entry.after,
        vec![EntryRef::from(&a.id)],
        "it supersedes the head it saw"
    );
    assert_eq!(r.value("/a").as_deref(), Some("two"));
    let marker = Marker::decode(
        &r.store
            .get(&verified_key(&log_name(&me.name, &space(), 3)))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(marker.signed_digest, b.id.digest);
    assert_eq!(
        store::read_head(&*r.store, &space()).unwrap().unwrap().seq,
        3
    );
    assert!(r.store.contains(&structural_key(&space(), &me.name, 1)));
}

#[tokio::test]
async fn a_structural_entry_says_so_for_the_publisher() {
    let mut r = rig(&laptop());
    let s = r
        .members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    assert_eq!(
        s.effects.publish,
        Some(Publish {
            seq: 1,
            structural: true
        })
    );
    assert!(s.effects.membership);
}

#[tokio::test]
async fn an_epoch_key_is_stored_in_the_batch_of_its_entry() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(false), vec![])).await;
    let s = loop {
        match r.log.sign_epoch(vec![n("/alice")], NOW).unwrap() {
            Step::Done(s) => break s,
            Step::Wait(t) => r.flusher.wait_durable(t).await.unwrap(),
        }
    };
    let epoch = EpochId {
        creator: me.name.clone(),
        seq: s.id.seq,
    };
    assert!(
        r.store
            .contains(&store::epoch_key(&space(), &me.name, s.id.seq))
    );
    assert_eq!(r.log.fold().in_force(), Some(epoch));
    // Sealed puts now work, and a relay cannot read the path.
    r.put("/secret/path", "hush").await;
    let wire = r.store.get(&log_name(&me.name, &space(), 3)).unwrap();
    assert!(!wire.windows(6).any(|w| w == b"secret"));
    assert_eq!(r.value("/secret/path").as_deref(), Some("hush"));
}

// -- Restart, gaps and the own head --------------------------------------------------

#[tokio::test]
async fn a_restart_finds_the_fold_the_register_and_the_held_ranges() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    r.put("/a", "one").await;
    let mut b = Chain::new(&bob());
    let (p1, p2) = (b.put("/b", "1"), b.put("/c", "2"));
    r.applied(&p1);
    r.applied(&p2);
    r.flusher.flush().await.unwrap();
    let again = open_on(&r.crash(), &me);
    assert!(again.log.fold().is_writer(&n("/bob")));
    assert_eq!(again.value("/a").as_deref(), Some("one"));
    assert_eq!(again.value("/c").as_deref(), Some("2"));
    assert_eq!(again.log.held_prefix(&bob().name), 2);
    assert_eq!(again.log.head(), 2);
    assert_eq!(again.log.removal_tips(&n("/bob")), vec![p2.entry_ref()]);
}

#[tokio::test]
async fn the_first_entry_after_an_unclean_open_states_the_gap() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    r.put("/a", "1").await;
    let last = r.put("/a", "2").await;
    r.flusher.flush().await.unwrap();
    // No clean close: the record says R = BLOCK, not the head.
    let mut again = open_on(&r.crash(), &me);
    let first = again.put("/a", "3").await;
    assert!(first.id.seq > BLOCK, "resumes above R, not at head + 1");
    assert!(
        first.effects.alerts.iter().any(
            |a| matches!(a, Alert::GapSigned { after: 3, resumed } if *resumed == first.id.seq)
        )
    );
    let entry = {
        let wire = again
            .store
            .get(&log_name(&me.name, &space(), first.id.seq))
            .unwrap();
        Entry::decode(Data::decode(wire).unwrap().content().unwrap()).unwrap()
    };
    assert_eq!(
        entry.prev,
        Some(Prev {
            digest: last.id.digest,
            seq: Some(3)
        })
    );
    assert_eq!(again.log.voids(&me.name), vec![(4, first.id.seq - 1)]);
    // The next one is dense again.
    let next = again.put("/a", "4").await;
    let entry = {
        let wire = again
            .store
            .get(&log_name(&me.name, &space(), next.id.seq))
            .unwrap();
        Entry::decode(Data::decode(wire).unwrap().content().unwrap()).unwrap()
    };
    assert_eq!(entry.prev.unwrap().seq, None);
}

#[tokio::test]
async fn the_first_entry_after_losing_everything_uses_the_zero_digest_form() {
    let me = laptop();
    let store = Arc::new(CrashStore::new());
    // A record of a reservation, and no entry: the entries were lost.
    write_reserve(
        &*store,
        &space(),
        ReserveRecord {
            r: BLOCK,
            clean: false,
        },
    );
    let mut r = open_on(&store, &me);
    let s = r.members(members(Some(true), vec![])).await;
    assert_eq!(s.id.seq, BLOCK + 1);
    let wire = r
        .store
        .get(&log_name(&me.name, &space(), s.id.seq))
        .unwrap();
    let entry = Entry::decode(Data::decode(wire).unwrap().content().unwrap()).unwrap();
    assert_eq!(
        entry.prev,
        Some(Prev {
            digest: [0; 32],
            seq: Some(0)
        })
    );
    assert!(
        s.effects
            .alerts
            .iter()
            .any(|a| matches!(a, Alert::GapSigned { after: 0, .. }))
    );
}

#[tokio::test]
async fn a_clean_open_states_no_gap() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    r.put("/a", "1").await;
    let head = r.log.head();
    r.log.reservation().close_clean(head).await.unwrap();
    let mut again = open_on(&r.crash(), &me);
    let s = again.put("/a", "2").await;
    assert_eq!(s.id.seq, head + 1);
    assert!(s.effects.alerts.is_empty());
    let wire = again
        .store
        .get(&log_name(&me.name, &space(), s.id.seq))
        .unwrap();
    let entry = Entry::decode(Data::decode(wire).unwrap().content().unwrap()).unwrap();
    assert_eq!(entry.prev.unwrap().seq, None);
}

#[tokio::test]
async fn a_devices_own_head_after_restart_comes_from_every_stored_own_entry_name_even_if_one_does_not_decode()
 {
    let me = laptop();
    let store = Arc::new(CrashStore::new());
    // The entry at seq 5 is under this device's name and is not a packet
    // at all; seq 3 is a real one.
    let three = sign_raw(&me, 3, b"anything");
    store.insert(three.name(), three.wire.clone());
    store.insert(log_name(&me.name, &space(), 5), Bytes::from_static(b"torn"));
    let mut r = open_on(&store, &me);
    assert_eq!(r.log.head(), 5);
    let s = r.members(members(Some(true), vec![])).await;
    assert!(
        s.id.seq >= 6,
        "never signs again at a seq it has a name for"
    );
    let entry = {
        let wire = r
            .store
            .get(&log_name(&me.name, &space(), s.id.seq))
            .unwrap();
        Entry::decode(Data::decode(wire).unwrap().content().unwrap()).unwrap()
    };
    assert_eq!(
        entry.prev,
        Some(Prev {
            digest: signed_digest(&Bytes::from_static(b"torn")),
            seq: None
        })
    );
    assert_eq!(s.id.seq, 6);
}

#[tokio::test]
async fn an_own_entry_above_r_durable_raises_rolledback_and_is_not_applied() {
    let me = laptop();
    let image = Arc::new(CrashStore::new());
    write_reserve(
        &*image,
        &space(),
        ReserveRecord {
            r: BLOCK,
            clean: false,
        },
    );
    let mut r = open_on(&image, &me);
    r.members(members(Some(true), vec![])).await;
    let durable = BLOCK;
    // A copy of this device's key signed seq 500.
    let copy = sign_entry(
        &me,
        500,
        &Entry {
            prev: Some(Prev {
                digest: [1; 32],
                seq: Some(499),
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/stolen"),
                payload: Payload::Inline(Bytes::from_static(b"x")),
            }),
        },
    );
    let a = r.admit(&copy);
    assert_eq!(a.outcome, Outcome::Evidence);
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::RolledBack { reserved, seen: 500 } if *reserved == durable)
    ));
    assert_eq!(r.value("/stolen"), None);
    assert!(r.log.next_seq() > 500, "resumes above it");
    assert!(r.store.contains(&copy.name()), "kept as evidence");
}

#[tokio::test]
async fn an_unbacked_counter_does_not_raise_the_head() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    let head = r.log.head();
    let fx = r.log.note_counter(&me.name, 9_999);
    assert!(fx.alerts.contains(&Alert::UnbackedCounter {
        device: me.name.clone(),
        seen: 9_999
    }));
    assert_eq!(r.log.head(), head);
    let next = r.put("/a", "x").await;
    assert_eq!(next.id.seq, head + 1);
}

#[tokio::test]
async fn recovery_adopts_only_own_entries_that_verify_chain_and_lie_within_r_durable() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    r.put("/a", "1").await;
    r.put("/a", "2").await;
    let packet = |seq: u64| {
        let wire = r.store.get(&log_name(&me.name, &space(), seq)).unwrap();
        Packet {
            dev: me.clone(),
            seq,
            digest: signed_digest(&wire),
            wire,
        }
    };
    let (p1, p2, p3) = (packet(1), packet(2), packet(3));

    // A device that lost everything but its reservation record; peers
    // still hold what it signed.
    let image = Arc::new(CrashStore::new());
    write_reserve(
        &*image,
        &space(),
        ReserveRecord {
            r: BLOCK,
            clean: false,
        },
    );
    let mut lost = open_on(&image, &me);
    lost.flusher.flush().await.unwrap();
    assert!(lost.log.reservation().durable_r() >= 3);
    // 3 chains to 2, which is not held: not adopted, nothing stored.
    let a = lost.admit(&p3);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::Chain));
    assert!(!lost.store.contains(&p3.name()));
    // 1 is the device's first entry; 2 and 3 chain to what was adopted.
    for p in [&p1, &p2, &p3] {
        assert_eq!(lost.admit(p).outcome, Outcome::Applied);
    }
    assert_eq!(lost.log.head(), 3);
    assert_eq!(lost.value("/a").as_deref(), Some("2"));
    // What a copy of the device would sign with another key of the device is
    // not this device's entry.
    let other = Dev {
        key: n("/alice/laptop/KEY/k2"),
        signer: Arc::new(Ed25519Signer::from_seed(
            &[99; 32],
            n("/alice/laptop/KEY/k2"),
        )),
        ..me.clone()
    };
    let forged = sign_entry(
        &other,
        4,
        &Entry {
            prev: Some(Prev {
                digest: p3.digest,
                seq: None,
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from_static(b"x")),
            }),
        },
    );
    assert_eq!(
        lost.admit(&forged).outcome,
        Outcome::Refused(Refusal::BadSignature)
    );
}

// -- Catch-up bookkeeping --------------------------------------------------------------

#[tokio::test]
async fn a_replayed_stale_notice_state_never_lowers_what_is_wanted() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let ps: Vec<Packet> = (1..=3).map(|i| b.put("/a", &i.to_string())).collect();
    r.log.note_high(&bob().name, 10);
    r.applied(&ps[0]);
    r.applied(&ps[2]);
    let wanted = |r: &Rig| {
        r.log
            .missing()
            .into_iter()
            .filter(|w| w.device == bob().name)
            .map(|w| (w.first, w.last))
            .collect::<Vec<_>>()
    };
    assert_eq!(wanted(&r), vec![(2, 2), (4, 10)]);
    // A replayed older vector.
    r.log.note_high(&bob().name, 3);
    assert_eq!(wanted(&r), vec![(2, 2), (4, 10)]);
    assert_eq!(r.log.high(&bob().name), 10);
    assert_eq!(r.log.held_prefix(&bob().name), 1);
    r.applied(&ps[1]);
    assert_eq!(wanted(&r), vec![(4, 10)]);
    assert_eq!(r.log.held_prefix(&bob().name), 3);
    assert_eq!(r.log.frontier().get(&bob().name), 3);
}

#[tokio::test]
async fn an_entry_naming_other_bytes_than_the_one_held_at_its_prev_is_refused_as_a_fork() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let p1 = Chain::new(&bob()).put("/a", "one");
    r.applied(&p1);
    let forked = sign_entry(
        &bob(),
        2,
        &Entry {
            prev: Some(Prev {
                digest: [9; 32],
                seq: None,
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/b"),
                payload: Payload::Inline(Bytes::from_static(b"two")),
            }),
        },
    );
    let a = r.admit(&forked);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::Chain));
    assert!(has_alert(&a, |al| matches!(
        al,
        Alert::Equivocation { seq: 1, .. }
    )));
    assert_eq!(a.effects.suspect, vec![bob().key]);
    assert_eq!(r.value("/b"), None);
    assert!(r.store.contains(&forked.name()), "kept as evidence");
}

#[tokio::test]
async fn an_owners_removal_binds_what_it_holds_and_the_cut_survives_a_restart() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let mut b = Chain::new(&bob());
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    r.applied(&p1);
    r.applied(&p2);
    let ops = r.log.remove_ops(&n("/bob"));
    assert_eq!(ops, vec![remove(1, vec![p2.entry_ref()])]);
    r.members(members(None, ops)).await;
    r.flusher.flush().await.unwrap();

    let image = r.crash();
    for mut again in [r, open_on(&image, &me)] {
        let a = again.admit(&p3);
        assert!(
            matches!(
                a.outcome,
                Outcome::Refused(Refusal::OutsideCut(Cut { keeps_to: 2, .. }))
            ),
            "{:?}",
            a.outcome
        );
        assert_eq!(again.value("/p2").as_deref(), Some("2"));
    }
}

#[tokio::test]
async fn a_withdrawn_entry_is_taken_back_only_when_offered_again_and_verified() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let p1 = Chain::new(&bob()).put("/a", "one");
    r.applied(&p1);
    let fx = r.log.withdraw(
        &bob().name,
        1,
        Refusal::Untrusted {
            why: "its key was revoked".into(),
        },
    );
    assert!(
        fx.changes
            .iter()
            .any(|c| matches!(c, Change::Withdrawn { .. }))
    );
    assert_eq!(r.value("/a"), None);
    // A change of the members does not bring it back: only the judge can say
    // its key verifies again.
    r.applied(&owner.members(members(None, vec![add(2, "/carol", Role::Writer)])));
    assert_eq!(r.value("/a"), None);
    assert_eq!(r.admit(&p1).outcome, Outcome::Duplicate);
    assert_eq!(r.value("/a").as_deref(), Some("one"));
}

/// Counts the reads of markers a store answers.
struct Counting {
    inner: Arc<CrashStore>,
    markers: std::sync::atomic::AtomicUsize,
}

impl Counting {
    fn marker(&self, name: &Name) -> bool {
        name.has_prefix(&verified_key(&Name::root()))
    }
}

impl DataStore for Counting {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        if self.marker(name) {
            self.markers
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.get(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        let found = self.inner.scan_under(prefix, limit);
        if self.marker(prefix) {
            self.markers
                .fetch_add(found.len(), std::sync::atomic::Ordering::SeqCst);
        }
        found
    }
    fn remove(&self, name: &Name) {
        self.inner.remove(name);
    }
    fn apply(&self, ops: Vec<ndn_sync::StoreOp>) {
        self.inner.apply(ops);
    }
    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }
}

#[tokio::test]
async fn a_cold_open_reads_one_marker_per_device_not_one_per_entry() {
    let me = carol();
    let mut r = rig(&me);
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    for i in 0..300 {
        r.applied(&b.put(&format!("/p{}", i % 7), &i.to_string()));
    }
    r.flusher.flush().await.unwrap();
    let counting = Arc::new(Counting {
        inner: r.crash(),
        markers: Default::default(),
    });
    let raw = Arc::clone(&counting) as Arc<dyn DataStore>;
    let log = Log::open(
        Params {
            space: space(),
            device: me.name.clone(),
            person: me.person.clone(),
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            block: BLOCK,
        },
        Arc::clone(&raw),
        Stage::new(raw),
        Flusher::spawn(Arc::clone(&counting) as Arc<dyn DataStore>),
    )
    .unwrap();
    assert_eq!(log.held_prefix(&bob().name), 300);
    let reads = counting.markers.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        reads <= 4,
        "{reads} markers read for 2 devices and 300 entries"
    );
}

#[tokio::test]
async fn a_members_entry_that_only_removes_a_reader_is_a_membership_change() {
    // Another owner device's entry leaves the epoch in force for a reader
    // who is gone: the host must hear it, so the owner devices can repair.
    let mut r = rig(&laptop());
    let mut owner = Chain::new(&phone());
    r.applied(&owner.members(members(Some(false), vec![add(1, "/bob", Role::Reader)])));
    r.applied(&owner.entry(
        Body::Epoch(EpochBody {
            key_check: [1; 32],
            audience: vec![n("/alice"), n("/bob")],
        }),
        vec![],
    ));
    let a = r.applied(&owner.members(members(None, vec![remove(1, vec![])])));
    assert!(a.effects.membership);
    assert!(a.effects.changes.iter().any(|c| matches!(
        c,
        Change::Members(m) if m.readers == Readers::Persons(vec![n("/alice")])
    )));
    assert!(!r.log.fold().complete(), "an epoch is owed");
}

/// A device whose name lies under the owner's but whose key a sub-namespace
/// context vouches for: `/alice/kid` of the person `/alice/kid`.
fn kid() -> Dev {
    dev("/alice/kid", "/alice/kid", 5)
}

#[tokio::test]
async fn a_writer_device_under_the_owners_name_but_of_another_person_cannot_carry_members_or_epoch_entries()
 {
    let mut owner = Chain::new(&phone());
    let create = owner.members(members(
        Some(true),
        vec![add(1, "/alice/kid", Role::Writer)],
    ));
    let mut k = Chain::new(&kid());
    let grant = k.members(members(None, vec![add(2, "/carol", Role::Writer)]));
    let epoch = k.entry(
        Body::Epoch(EpochBody {
            key_check: [3; 32],
            audience: vec![n("/alice")],
        }),
        vec![],
    );
    let all = [&create, &grant, &epoch];
    let nothing_carried = |r: &Rig| {
        assert!(r.log.fold().is_writer(&n("/alice/kid")), "it is a writer");
        assert!(
            !r.log.fold().is_writer(&n("/carol")),
            "its Members entry did not apply"
        );
        assert!(
            r.log.fold().epochs().is_empty(),
            "its Epoch entry did not apply"
        );
        for p in [&grant, &epoch] {
            assert!(
                !r.store
                    .contains(&structural_key(&space(), &p.dev.name, p.seq))
            );
        }
    };
    for order in [[0, 1, 2], [1, 2, 0], [2, 0, 1]] {
        let mut r = rig(&carol());
        for i in order {
            let a = r.admit(all[i]);
            if i != 0 {
                assert_eq!(a.outcome, Outcome::Refused(Refusal::NotMember), "{order:?}");
            }
        }
        nothing_carried(&r);
    }

    // Held in the store, it is judged the same at a restart and at a re-check
    // that another Members entry of the owner starts.
    let mut r = rig(&carol());
    for p in all {
        r.admit(p);
    }
    r.flusher.flush().await.unwrap();
    let mut again = open_on(&r.crash(), &carol());
    nothing_carried(&again);
    again.applied(&owner.members(members(None, vec![remove(1, vec![])])));
    assert!(!again.log.fold().is_writer(&n("/carol")));
    assert!(again.log.fold().epochs().is_empty());
}

#[tokio::test]
async fn a_device_of_another_person_under_the_owners_name_does_not_sign_members_or_epoch_entries() {
    let mut r = rig(&kid());
    let nothing = members(Some(true), vec![]);
    assert!(matches!(
        r.log.sign_members(nothing, NOW),
        Err(HeapError::NotOwner { .. })
    ));
    assert!(matches!(
        r.log.sign_epoch(vec![n("/alice")], NOW),
        Err(HeapError::NotOwner { .. })
    ));
}

#[tokio::test]
async fn an_old_image_adopts_what_the_previous_run_could_have_signed_and_resumes_above_the_rest() {
    // d12 at unit level: the image's R is BLOCK; peers hold seq 1..=12 of
    // this device. What this run's own extension covers (9..=16) is not what
    // an earlier run signed.
    let me = laptop();
    let mut source = rig(&me);
    source.members(members(Some(true), vec![])).await;
    for i in 0..11 {
        source.put("/a", &i.to_string()).await;
    }
    let packet = |seq: u64| {
        let wire = source
            .store
            .get(&log_name(&me.name, &space(), seq))
            .unwrap();
        Packet {
            dev: me.clone(),
            seq,
            digest: signed_digest(&wire),
            wire,
        }
    };
    let image = Arc::new(CrashStore::new());
    write_reserve(
        &*image,
        &space(),
        ReserveRecord {
            r: BLOCK,
            clean: false,
        },
    );
    let mut old = open_on(&image, &me);
    old.flusher.flush().await.unwrap();
    for seq in 1..=12 {
        let a = old.admit(&packet(seq));
        if seq <= BLOCK {
            assert_eq!(a.outcome, Outcome::Applied, "seq {seq}");
        } else {
            assert_eq!(a.outcome, Outcome::Evidence, "seq {seq}");
            assert!(has_alert(&a, |al| matches!(
                al,
                Alert::RolledBack { reserved, seen } if *reserved == BLOCK && *seen == seq
            )));
        }
    }
    assert_eq!(old.log.head(), 12);
    assert_eq!(old.log.next_seq(), 13, "above everything a peer holds");
    let s = old.members(members(None, vec![])).await;
    assert_eq!(s.id.seq, 13);
    assert!(s.effects.alerts.iter().any(|a| matches!(
        a,
        Alert::GapSigned {
            after: 8,
            resumed: 13
        }
    )));
}
