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
use ndn_sync::{DataStore, MemoryStore};
use proptest::prelude::*;

use super::*;
use crate::error::{Cut, NextStep, Refusal, Timestamp};
use crate::reserve::Flusher;
use crate::revocation::Suspicion;
use crate::seal::{self, Keys};
use crate::store::{self, Kind, Marker, ReserveRecord, write_reserve};
use crate::test_kit::{CrashStore, n};
use crate::trust::TipCut;
use crate::wire::{
    self, Body, Entry, EntryRef, EpochBody, EpochId, MembersBody, Op, Payload, Prev, PutBody, Role,
    SealedBody, log_name, signed_digest,
};

/// What the tests inspect of a log.
impl Log {
    /// Whether at least one entry of `device` is held in this space (any seq,
    /// whatever became of it); a notice alone does not count.
    fn holds(&self, device: &Name) -> bool {
        self.devices
            .get(device)
            .is_some_and(|d| d.held.max().is_some())
    }

    /// The seqs `device`'s entries declared absent (gap statements).
    fn voids(&self, device: &Name) -> Vec<(u64, u64)> {
        self.devices
            .get(device)
            .map_or_else(Vec::new, |d| d.voids().to_vec())
    }
}

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
    /// What the judge says of the device's standing (`Verified::owner_capable`).
    owner_capable: bool,
    signer: Arc<Ed25519Signer>,
}

fn dev(name: &str, person: &str, seed: u8) -> Dev {
    let key = n(&format!("{name}/KEY/k1"));
    Dev {
        name: n(name),
        key: key.clone(),
        person: n(person),
        owner_capable: true,
        signer: Arc::new(Ed25519Signer::from_seed(&[seed; 32], key)),
    }
}

/// A device of its person that holds none of the owner's powers: a `guest`
/// or a `node` of the role layout.
fn not_owner_device(mut d: Dev) -> Dev {
    d.owner_capable = false;
    d
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
        owner_capable: d.owner_capable,
        tip: None,
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
    flusher: Arc<Flusher>,
    suspicion: Arc<Suspicion>,
}

fn open_on(store: &Arc<CrashStore>, me: &Dev) -> Rig {
    let raw = Arc::clone(store) as Arc<dyn DataStore>;
    let suspicion = Suspicion::open(Arc::clone(&raw));
    let flusher = Flusher::spawn(Arc::clone(&raw));
    let log = Log::open(
        Params {
            space: space(),
            device: me.name.clone(),
            person: me.person.clone(),
            owner_capable: me.owner_capable,
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            suspicion: Arc::clone(&suspicion),
            block: BLOCK,
        },
        raw,
        Arc::clone(&flusher),
    )
    .unwrap();
    Rig {
        log,
        store: Arc::clone(store),
        flusher,
        suspicion,
    }
}

fn rig(me: &Dev) -> Rig {
    open_on(&Arc::new(CrashStore::new()), me)
}

/// What a test sees of one entry offered to the log.
struct Admitted {
    outcome: Outcome,
    effects: Effects,
}

/// What a test sees of one own entry signed.
struct Signed {
    id: EntryId,
    effects: Effects,
}

impl Rig {
    fn admit(&mut self, p: &Packet) -> Admitted {
        let data = Data::decode(p.wire.clone()).unwrap();
        let (outcome, effects) = self
            .log
            .admit(&p.wire, &data, &verified(&p.dev), NOW, false);
        Admitted { outcome, effects }
    }

    fn applied(&mut self, p: &Packet) -> Admitted {
        let a = self.admit(p);
        assert_eq!(a.outcome, Outcome::Applied, "{:?}", a.effects.alerts);
        a
    }

    /// An own write, waiting for the reservation's flush as the node does.
    async fn signed(
        &mut self,
        mut write: impl FnMut(&mut Log) -> Result<Step, HeapError>,
    ) -> Signed {
        loop {
            match write(&mut self.log).unwrap() {
                Step::Done(id, effects) => return Signed { id, effects },
                Step::Wait(ticket) => self.flusher.wait_durable(ticket).await.unwrap(),
            }
        }
    }

    async fn put(&mut self, path: &str, bytes: &str) -> Signed {
        let payload = Payload::Inline(Bytes::from(bytes.to_owned()));
        self.signed(|log| log.put(&n(path), payload.clone(), vec![], NOW))
            .await
    }

    async fn members(&mut self, body: MembersBody) -> Signed {
        self.signed(|log| log.sign_members(body.clone(), NOW)).await
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
    assert!(a.effects.wants.iter().any(|w| {
        w.device == p2.dev.name && w.first == 1 && w.digest == Some(Pin::Signed(p1.digest))
    }));
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

/// Every order of `0..n`.
fn orders(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![vec![]];
    }
    let mut all = Vec::new();
    for rest in orders(n - 1) {
        for at in 0..=rest.len() {
            let mut order = rest.clone();
            order.insert(at, n - 1);
            all.push(order);
        }
    }
    all
}

#[tokio::test]
async fn other_bytes_below_the_tip_never_keep_the_honest_chain_out_in_any_arrival_order() {
    // r5/q2: the cut names p3; a copy of Bob's key signed other bytes at
    // seq 2, below the tip. Whatever comes first, the chain from the tip
    // is what is kept: p1, p2 and p3 are read, the copy's bytes are not.
    let mut owner = Chain::new(&phone());
    let mut b = Chain::new(&bob());
    let created = creation(&mut owner);
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
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
    let cut = owner.members(members(None, vec![remove(1, vec![p3.entry_ref()])]));
    let all = [created, cut, p1, p2, p3, other];
    let mut failures = Vec::new();
    for order in orders(all.len()) {
        let mut r = rig(&carol());
        // The fetch asks again for what the log still wants, in the order
        // of its passes: every packet is offered again, in rounds, as
        // long as an offer changes what is read; a duplicate changes
        // nothing.
        let mut last = None;
        for _round in 0..6 {
            for &i in &order {
                r.admit(&all[i]);
            }
            let now = [r.value("/p1"), r.value("/p2"), r.value("/p3")];
            if last.as_ref() == Some(&now) {
                break;
            }
            last = Some(now);
        }
        let read = [r.value("/p1"), r.value("/p2"), r.value("/p3")];
        let want = [
            Some("1".to_owned()),
            Some("2".to_owned()),
            Some("3".to_owned()),
        ];
        if read != want {
            failures.push((order, read));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of 720 orders read other than the chain from the tip; the first: {:?}",
        failures.len(),
        failures.first()
    );
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
    assert_eq!(r.suspicion.since(&bob().key), Some(Timestamp(NOW)));
    assert_eq!(
        r.store.get(&Kind::EQUIVOCAL.of(&first.name())),
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
    assert!(a.effects.alerts.is_empty());
    // p2 chains to the signed digest: the relayed copy satisfies it.
    r.applied(&p2);
    assert_eq!(r.value("/a").as_deref(), Some("two"));
    assert!(r.suspicion.since(&bob().key).is_none());
    // The marker records the signed digest, not the wire's.
    let m = Marker::decode(&r.store.get(&Kind::VERIFIED.of(&p1.name())).unwrap()).unwrap();
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
        r.store.contains(&Kind::VERIFIED.of(&junk.name())),
        "a marker records it"
    );
    assert!(
        r.store
            .contains(&Kind::STATUS.seq(&space(), &bob().name, 2))
    );
    let walked = Kept::compute(
        &*r.store,
        &bob().name,
        &space(),
        vec![store::Link {
            seq: 2,
            digest: junk.digest,
        }],
    );
    assert!(walked.frontier.is_empty(), "{walked:?}");
    assert_eq!(r.log.held_prefix(&bob().name), 2);
    assert!(
        r.log.missing().iter().all(|w| w.device != bob().name),
        "it is not fetched again"
    );
    // Offered again it is a duplicate, never decoded again.
    assert_eq!(r.admit(&junk).outcome, Outcome::Duplicate);
}

/// A marker at `seq` of `bob` in the space: its digest is `[seq; 32]`, its
/// previous entry `prev_seq` (digest `[prev_seq; 32]`, zero from 0).
fn mark(store: &dyn DataStore, seq: u64, prev_seq: u64) {
    let digest = |s: u64| if s == 0 { [0; 32] } else { [s as u8; 32] };
    store.insert(
        Kind::VERIFIED.of(&log_name(&bob().name, &space(), seq)),
        Marker {
            signed_digest: digest(seq),
            key_digest: [7; 32],
            prev: digest(prev_seq),
            prev_seq,
            at: 1,
        }
        .encode(),
    );
}

fn tip(seq: u64) -> store::Link {
    store::Link {
        seq,
        digest: [seq as u8; 32],
    }
}

fn walk(store: &dyn DataStore, tip: store::Link) -> Kept {
    Kept::compute(store, &bob().name, &space(), vec![tip])
}

#[test]
fn a_cut_walk_reads_markers_only_and_follows_a_declared_gap() {
    // No entry is stored anywhere: only markers. 1 <- 2 <- 3, then the
    // device lost 4 and 5 and signed 6 over 3 (a gap statement).
    let store = MemoryStore::new();
    mark(&store, 1, 0);
    mark(&store, 2, 1);
    mark(&store, 3, 2);
    mark(&store, 6, 3);
    let walked = walk(&store, tip(6));
    assert_eq!(walked.ranges.to_vec(), vec![(1, 3), (6, 6)]);
    assert!(
        walked.frontier.is_empty(),
        "the chain reaches its first entry"
    );
}

#[test]
fn a_cut_walk_names_the_missing_link_the_diverging_one_and_ends_at_the_corrupt_one() {
    let store = MemoryStore::new();
    mark(&store, 1, 0);
    mark(&store, 3, 2);
    mark(&store, 4, 3);
    let walked = walk(&store, tip(4));
    assert_eq!(walked.ranges.to_vec(), vec![(3, 4)]);
    assert_eq!(walked.frontier, vec![tip(2)], "the entry to fetch next");

    // The tip's digest is not the marker's: another packet at that seq.
    let other = store::Link {
        seq: 4,
        digest: [0xee; 32],
    };
    let walked = walk(&store, other);
    assert!(walked.ranges.to_vec().is_empty());
    assert_eq!(walked.frontier, vec![other], "the bytes the chain names");

    // A marker whose previous seq is not below its own would loop for ever.
    mark(&store, 8, 8);
    let walked = walk(&store, tip(8));
    assert!(walked.frontier.is_empty() && walked.ranges.to_vec().is_empty());

    // A marker that does not decode is a corrupt link, not a missing one.
    store.insert(
        Kind::VERIFIED.of(&log_name(&bob().name, &space(), 9)),
        Bytes::from_static(&[0; 5]),
    );
    let walked = walk(&store, tip(9));
    assert!(walked.frontier.is_empty() && walked.ranges.to_vec().is_empty());
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
    assert!(r.suspicion.since(&phone().key).is_some());
    // Both are facts of the space: the fold lists both Adds whichever came
    // first.
    assert!(r.log.fold.is_writer(&n("/bob")));
    assert!(r.log.fold.is_writer(&n("/carol")));
}

#[tokio::test]
async fn a_members_entry_from_a_device_outside_the_owner_namespace_is_refused() {
    let mut r = rig(&carol());
    let forged =
        Chain::new(&bob()).members(members(Some(true), vec![add(1, "/bob", Role::Writer)]));
    let a = r.admit(&forged);
    assert_eq!(a.outcome, Outcome::Refused(Refusal::NotMember));
    assert!(!r.log.fold.is_writer(&n("/bob")));
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
        prop_assert!(!r.log.fold.is_writer(&n("/bob")));
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

/// A second epoch of the owner's phone, for the owner alone: Carol, a reader, is outside its
/// audience.
fn owner_only_epoch(s: &Sealed) -> Sealed {
    let epoch = EpochId {
        creator: phone().name,
        seq: 3,
    };
    let key = [8u8; 32];
    let epoch_entry = sign_entry(
        &phone(),
        3,
        &Entry {
            prev: Some(Prev {
                digest: s.epoch_entry.digest,
                seq: None,
            }),
            after: vec![],
            body: Body::Epoch(EpochBody {
                key_check: seal::key_check(&ContentKey::from_bytes(key), &space(), &epoch),
                audience: vec![n("/alice")],
            }),
        },
    );
    Sealed {
        key,
        epoch,
        created: s.created.clone(),
        epoch_entry,
    }
}

#[tokio::test]
async fn a_reader_awaits_the_key_of_its_closed_entry_whatever_epoch_leaves_it_out() {
    let s = sealed_space();
    let outgrown = owner_only_epoch(&s);
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    r.applied(&outgrown.epoch_entry);
    assert_eq!(
        r.admit(&sealed_put(&s, "/secret", "hush")).outcome,
        Outcome::Closed
    );
    // The key Carol lacks and may be granted opens what she holds closed; the key of the epoch
    // that leaves her out opens nothing she holds.
    assert_eq!(r.log.closed_epochs(), [s.epoch.clone()].into());
    assert!(
        r.log.awaits_keys(),
        "Carol is in the audience of the epoch her closed entry is sealed in"
    );
}

#[tokio::test]
async fn a_reader_left_out_of_the_epoch_of_its_closed_entry_does_not_await_its_key() {
    let s = sealed_space();
    let outgrown = owner_only_epoch(&s);
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    r.applied(&outgrown.epoch_entry);
    assert_eq!(
        r.admit(&sealed_put(&outgrown, "/secret", "hush")).outcome,
        Outcome::Closed
    );
    assert_eq!(r.log.closed_epochs(), [outgrown.epoch.clone()].into());
    assert!(
        !r.log.awaits_keys(),
        "Carol is outside the audience of the epoch her closed entry is sealed in"
    );
}

#[tokio::test]
async fn a_reader_awaits_the_epoch_entry_of_a_closed_entry_it_does_not_hold_yet() {
    let s = sealed_space();
    let mut r = rig(&carol());
    r.applied(&s.created);
    assert_eq!(
        r.admit(&sealed_put(&s, "/secret", "hush")).outcome,
        Outcome::Closed
    );
    assert!(
        r.log.awaits_keys(),
        "the epoch's audience is unknown until its entry arrives"
    );
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
        vec![a.id.clone()],
        "it supersedes the head it saw"
    );
    assert_eq!(r.value("/a").as_deref(), Some("two"));
    let marker = Marker::decode(
        &r.store
            .get(&Kind::VERIFIED.of(&log_name(&me.name, &space(), 3)))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(marker.signed_digest, b.id.digest);
    assert_eq!(
        store::read_head(&*r.store, &space()).unwrap().unwrap().seq,
        3
    );
    assert!(
        r.store
            .contains(&Kind::STRUCTURAL.seq(&space(), &me.name, 1))
    );
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
    let s = r.signed(|log| log.sign_epoch(vec![n("/alice")], NOW)).await;
    let epoch = EpochId {
        creator: me.name.clone(),
        seq: s.id.seq,
    };
    assert!(
        r.store
            .contains(&Kind::EPOCH.seq(&space(), &me.name, s.id.seq))
    );
    assert_eq!(r.log.fold.in_force(), Some(epoch));
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
    assert!(again.log.fold.is_writer(&n("/bob")));
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
    r.log.reservation.close_clean(head).await.unwrap();
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
async fn a_devices_own_head_after_restart_comes_from_its_ledger_even_if_an_entry_does_not_decode() {
    let me = laptop();
    let mut first = rig(&me);
    // The entry at seq 5 verifies and is not an entry (stored, recorded as
    // unreadable); seq 3 is a real one.
    let three = sign_raw(&me, 3, b"anything");
    let five = sign_raw(&me, 5, b"torn");
    first.admit(&three);
    first.admit(&five);
    first.flusher.flush().await.unwrap();

    let mut r = open_on(&first.crash(), &me);
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
    // The first run reserved BLOCK: the entry resumes above it, over a gap
    // statement that chains to the highest own entry held (5).
    assert_eq!(
        entry.prev,
        Some(Prev {
            digest: signed_digest(&five.wire),
            seq: Some(5)
        })
    );
    assert_eq!(s.id.seq, BLOCK + 1);
}

#[tokio::test]
async fn a_device_that_cannot_read_its_own_ledger_does_not_open_the_space() {
    let me = laptop();
    let store = Arc::new(CrashStore::new());
    store.insert(
        Kind::LEDGER.device(&space(), &me.name),
        Bytes::from_static(b"\xff"),
    );
    let raw = Arc::clone(&store) as Arc<dyn DataStore>;
    let opened = Log::open(
        Params {
            space: space(),
            device: me.name.clone(),
            person: me.person.clone(),
            owner_capable: me.owner_capable,
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            suspicion: Suspicion::open(Arc::clone(&raw)),
            block: BLOCK,
        },
        Arc::clone(&raw),
        Flusher::spawn(raw),
    );
    let why = opened
        .err()
        .expect("an unreadable ledger is not taken for an empty one");
    assert!(
        why.to_string().contains("ledger record"),
        "the refusal says what cannot be read: {why}"
    );
}

#[tokio::test]
async fn an_own_entry_above_r_durable_that_chains_to_nothing_held_raises_rolledback_and_waits() {
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
    // A copy of this device's key signed seq 500, over an entry this device
    // does not hold.
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
    assert_eq!(a.outcome, Outcome::Waiting);
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::RolledBack { reserved, seen: 500 } if *reserved == durable)
    ));
    assert_eq!(r.value("/stolen"), None);
    assert!(r.log.next_seq() > 500, "resumes above it");
    assert!(
        r.store.contains(&copy.name()),
        "held: it waits for what it chains to, and is applied only then"
    );
}

#[tokio::test]
async fn an_unbacked_counter_does_not_raise_the_head() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    let head = r.log.head();
    let fx = r.log.note_own_counter(9_999);
    assert!(fx.alerts.contains(&Alert::UnbackedCounter {
        device: me.name.clone(),
        seen: 9_999
    }));
    assert_eq!(r.log.head(), head);
    let next = r.put("/a", "x").await;
    assert_eq!(next.id.seq, head + 1);
}

#[tokio::test]
async fn an_own_counter_above_the_reservation_wants_only_what_was_reserved() {
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
    r.log.note_own_counter(9_999);
    let wanted: Vec<(u64, u64)> = r
        .log
        .missing()
        .into_iter()
        .filter(|w| w.device == me.name)
        .map(|w| (w.first, w.last))
        .collect();
    assert_eq!(
        wanted,
        vec![(1, BLOCK)],
        "an unsigned counter is believed as far as this device could have signed"
    );
    assert_eq!(r.log.high(&me.name), BLOCK);
}

#[tokio::test]
async fn only_a_device_an_admitted_entry_vouches_for_is_a_peer() {
    let mut r = rig(&carol());
    assert!(!r.log.has_peers());
    assert_eq!(
        r.admit(&Chain::new(&bob()).put("/a", "1")).outcome,
        Outcome::Refused(Refusal::NotMember)
    );
    assert!(!r.log.has_peers(), "a refused entry vouches for nothing");
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    assert!(r.log.has_peers());
}

#[tokio::test]
async fn a_strangers_refused_entries_are_stored_once_and_alert_once() {
    let mut r = rig(&carol());
    let mut stranger = Chain::new(&bob());
    let packets: Vec<Packet> = (1..=5)
        .map(|i| stranger.put("/a", &i.to_string()))
        .collect();
    let mut alerts = 0;
    for p in &packets[2..] {
        let data = Data::decode(p.wire.clone()).unwrap();
        let (outcome, fx) = r.log.admit(&p.wire, &data, &verified(&p.dev), NOW, true);
        assert_eq!(outcome, Outcome::Refused(Refusal::NotMember));
        alerts += fx
            .alerts
            .iter()
            .filter(|al| matches!(al, Alert::Refused { .. }))
            .count();
    }
    let stored = packets
        .iter()
        .filter(|p| r.store.contains(&p.name()))
        .count();
    assert_eq!(
        stored, 1,
        "one refused entry per stranger, not one per counter"
    );
    assert_eq!(alerts, 1, "and one alert");
    assert!(
        r.log.missing().iter().all(|w| w.device != bob().name),
        "the holes below a stranger's entry are not wanted"
    );
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
    assert!(lost.log.reservation.durable_r() >= 3);
    // 3 chains to 2, which is not held: it is held, waiting, and not applied.
    let a = lost.admit(&p3);
    assert_eq!(a.outcome, Outcome::Waiting);
    assert_eq!(lost.value("/a"), None);
    // 1 is the device's first entry; 2 chains to it, and 3, which waited,
    // is applied with it.
    for p in [&p1, &p2] {
        assert_eq!(lost.admit(p).outcome, Outcome::Applied);
    }
    assert_eq!(lost.admit(&p3).outcome, Outcome::Duplicate);
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
async fn what_is_wanted_is_the_holes_below_the_highest_entry_held_and_shrinks_only_by_holding() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let ps: Vec<Packet> = (1..=3).map(|i| b.put("/a", &i.to_string())).collect();
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
    // The hole below the entry held is real; nothing above it is wanted
    // until an entry there is held (a counter is unsigned, `Log::high`).
    assert_eq!(wanted(&r), vec![(2, 2)]);
    assert_eq!(r.log.high(&bob().name), 3);
    assert_eq!(r.log.held_prefix(&bob().name), 1);
    r.applied(&ps[1]);
    assert!(wanted(&r).is_empty());
    assert_eq!(r.log.held_prefix(&bob().name), 3);
}

fn id_of(p: &Packet) -> EntryId {
    EntryId {
        device: p.dev.name.clone(),
        seq: p.seq,
        digest: p.digest,
    }
}

/// `Log::applied` says the entry is in the folded state: held as those bytes, admitted, and its
/// writer's log chained below it (every seq under it held or declared void) in a space whose
/// creation is known. An entry whose predecessor is missing is held and shown, but a caller that
/// asks "may I build on it" (c1: the phone held the owner's first write, not the creation, and
/// could not write) is answered no until the chain below it is whole.
#[tokio::test]
async fn an_entry_is_applied_only_once_the_log_below_it_is_held_or_declared_void_and_the_creation_is_known()
 {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    let creation = creation(&mut owner);
    let first = Chain::new(&laptop()).put("/a", "one");
    let mut b = Chain::new(&bob());
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    // The owner's laptop's first entry, its log whole, before the creation: judged provisionally
    // (a plain write is taken until the creation says whether the space seals), not yet applied.
    r.applied(&first);
    assert!(
        !r.log.applied(&id_of(&first)),
        "the creation is not held: a plain write is not yet judged by it"
    );
    r.applied(&creation);
    assert!(r.log.applied(&id_of(&creation)));
    assert!(r.log.applied(&id_of(&first)), "the creation is known");

    // Bob's tip alone: held and shown, its chain below it missing.
    r.applied(&p3);
    assert_eq!(r.value("/p3").as_deref(), Some("3"));
    assert!(!r.log.applied(&id_of(&p3)), "seqs 1 and 2 are not held");
    r.applied(&p2);
    assert!(!r.log.applied(&id_of(&p3)), "seq 1 is not held");
    assert!(!r.log.applied(&id_of(&p2)));
    r.applied(&p1);
    for p in [&p1, &p2, &p3] {
        assert!(r.log.applied(&id_of(p)), "seq {} is chained now", p.seq);
    }
}

/// A gap an entry declares is not a hole: the entry above it is applied without it.
#[tokio::test]
async fn an_entry_above_a_declared_gap_is_applied_without_the_seqs_the_gap_declares_absent() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let p1 = b.put("/p1", "1");
    let _lost = b.put("/lost", "2");
    let p3 = b.entry_after_gap(
        Body::Put(PutBody {
            path: n("/p3"),
            payload: Payload::Inline(Bytes::from_static(b"3")),
        }),
        1,
        p1.digest,
    );
    r.applied(&p3);
    assert!(!r.log.applied(&id_of(&p3)), "seq 1 is missing");
    r.applied(&p1);
    assert!(r.log.applied(&id_of(&p3)), "seq 2 is declared absent");
}

/// A device the fold lets write writes while the owner's log has a hole below an entry it holds:
/// a put never waits on other devices (p1), and an entry in the hole that removes the device
/// binds what it signs after the cut it names, as a removal that has not reached it yet does
/// (o1).
#[tokio::test]
async fn a_device_the_fold_lets_write_writes_while_the_owners_log_has_a_hole() {
    let mut r = rig(&bob());
    let mut owner = Chain::new(&phone());
    let create = creation(&mut owner);
    let more = owner.members(members(None, vec![add(2, "/carol", Role::Writer)]));
    let tip = owner.members(members(None, vec![add(3, "/dave", Role::Reader)]));
    r.applied(&create);
    r.applied(&tip);
    assert!(r.log.applied(&id_of(&create)));
    assert!(
        !r.log.applied(&id_of(&tip)),
        "seq 2 of the owner's log is missing"
    );
    assert_eq!(
        r.log.judge_own().unwrap(),
        None,
        "bob is a writer, hole or not"
    );
    r.applied(&more);
    assert_eq!(r.log.judge_own().unwrap(), None);
}

/// A device the fold refuses does not know it is refused while the owner's log has a hole below an
/// entry it holds (o3: a member held the creation and the epoch, not the entries that made the
/// readers, and was told it was a writer outside the audience, for good): the answer is to ask
/// again until the hole is filled.
#[tokio::test]
async fn a_device_the_fold_refuses_is_told_to_wait_while_the_owners_log_has_a_hole() {
    let mut r = rig(&bob());
    let mut owner = Chain::new(&phone());
    let create = owner.members(members(Some(true), vec![add(1, "/carol", Role::Writer)]));
    let adds_bob = owner.members(members(None, vec![add(2, "/bob", Role::Writer)]));
    let tip = owner.members(members(None, vec![add(3, "/dave", Role::Reader)]));
    r.applied(&create);
    r.applied(&tip);
    assert!(
        matches!(r.log.judge_own(), Err(HeapError::NotReady { .. })),
        "seq 2 of the owner's log is missing: {:?}",
        r.log.judge_own()
    );
    r.applied(&adds_bob);
    assert_eq!(r.log.judge_own().unwrap(), None);
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
    assert!(r.suspicion.since(&bob().key).is_some());
    assert_eq!(r.value("/b"), None);
    assert!(r.store.contains(&forked.name()), "kept as evidence");
}

/// A removed writer's entries are judged by the cut alone, which settles a fork: it is not
/// refused as one. The evidence that the key signed two chains is still told, once, as an
/// equivocation, so the host sees a copied key even when the cut is what decides.
#[tokio::test]
async fn a_removed_writers_fork_below_the_tip_is_told_and_not_refused_as_a_chain_fork() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let mut b = Chain::new(&bob());
    let (p1, _p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    // The same first entry, then another second one: a fork below the tip.
    let mut other = Chain::new(&bob());
    assert_eq!(other.put("/p1", "1").digest, p1.digest);
    let forked = other.put("/p2", "other");
    r.applied(&p1);
    r.applied(&p3);
    let ops = r.log.remove_ops(&n("/bob"));
    assert_eq!(ops, vec![remove(1, vec![p3.entry_ref()])]);
    r.members(members(None, ops)).await;

    let a = r.admit(&forked);
    assert!(
        has_alert(&a, |al| matches!(
            al,
            Alert::Equivocation { device, seq: 2 } if *device == bob().name
        )),
        "{:?}",
        a.effects.alerts
    );
    assert_ne!(
        a.outcome,
        Outcome::Refused(Refusal::Chain),
        "the cut decides what a removed writer's fork is"
    );
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

/// The cut is computed again from the markers at open (nothing of it is
/// stored), so a chain that was not whole when the device stopped is found
/// again with the same exact wants, and walks on as its links arrive.
#[tokio::test]
async fn a_cut_whose_chain_is_not_whole_is_walked_again_after_a_restart() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let mut b = Chain::new(&bob());
    let (p1, p2, p3) = (b.put("/p1", "1"), b.put("/p2", "2"), b.put("/p3", "3"));
    r.applied(&p3);
    let ops = r.log.remove_ops(&n("/bob"));
    assert_eq!(ops, vec![remove(1, vec![p3.entry_ref()])]);
    r.members(members(None, ops)).await;
    r.flusher.flush().await.unwrap();

    let image = r.crash();
    let want = |p: &Packet| Want {
        device: bob().name,
        first: p.seq,
        last: p.seq,
        digest: Some(Pin::Signed(p.digest)),
    };
    for mut again in [r, open_on(&image, &me)] {
        assert!(again.log.missing().contains(&want(&p2)));
        again.applied(&p2);
        assert!(again.log.missing().contains(&want(&p1)));
        assert!(!again.log.missing().contains(&want(&p2)));
        again.applied(&p1);
        assert!(again.log.missing().iter().all(|w| w.digest.is_none()));
        assert_eq!(again.value("/p1").as_deref(), Some("1"));
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

#[tokio::test]
async fn an_entry_withdrawn_for_a_cause_that_may_pass_is_taken_back_when_it_verifies_again() {
    // Review L3: the judge's `BadSignature` for a missing certificate or a
    // failing key store is not final; stored as final, no later copy could
    // re-assess it.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let p1 = Chain::new(&bob()).put("/a", "one");
    r.applied(&p1);
    r.log.withdraw(&bob().name, 1, Refusal::BadSignature);
    assert_eq!(r.value("/a"), None);
    assert_eq!(r.admit(&p1).outcome, Outcome::Duplicate);
    assert_eq!(r.value("/a").as_deref(), Some("one"));
}

#[tokio::test]
async fn an_entry_that_names_another_writers_entry_wrongly_or_at_another_path_hides_nothing() {
    // Review H2: a writer cannot hide what another writer writes by naming
    // it in `after`, with a digest it does not have or from another path.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let wrong = EntryRef {
        device: bob().name,
        seq: 1,
        digest: [9; 32],
    };
    r.applied(&owner.put_after("/a", "owner", vec![wrong]));
    let mut b = Chain::new(&bob());
    let p1 = b.put("/a", "bob");
    r.applied(&p1);
    let heads = |r: &Rig, path: &str| -> Vec<EntryRef> {
        r.log
            .register
            .heads_of(&n(path))
            .iter()
            .map(|h| h.entry.clone())
            .collect()
    };
    assert!(
        heads(&r, "/a").contains(&p1.entry_ref()),
        "bob's entry is a head"
    );
    // The right digest, from an entry at another path.
    r.applied(&owner.put_after("/c", "elsewhere", vec![p1.entry_ref()]));
    assert!(
        heads(&r, "/a").contains(&p1.entry_ref()),
        "still a head at /a"
    );
    assert_eq!(heads(&r, "/c").len(), 1);
    // Withdrawing the entries that named it leaves it as it was.
    r.log.withdraw(&phone().name, 2, Refusal::NotMember);
    r.log.withdraw(&phone().name, 3, Refusal::NotMember);
    assert_eq!(heads(&r, "/a"), vec![p1.entry_ref()]);
}

/// Counts the reads of markers a store answers.
struct Counting {
    inner: Arc<CrashStore>,
    markers: std::sync::atomic::AtomicUsize,
}

impl Counting {
    fn marker(&self, name: &Name) -> bool {
        name.has_prefix(&Kind::VERIFIED.of(&Name::root()))
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
            owner_capable: me.owner_capable,
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            suspicion: Suspicion::open(Arc::clone(&raw)),
            block: BLOCK,
        },
        Arc::clone(&raw),
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
    assert!(!r.log.fold.complete(), "an epoch is owed");
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
        assert!(r.log.fold.is_writer(&n("/alice/kid")), "it is a writer");
        assert!(
            !r.log.fold.is_writer(&n("/carol")),
            "its Members entry did not apply"
        );
        assert!(
            r.log.fold.epochs().is_empty(),
            "its Epoch entry did not apply"
        );
        for p in [&grant, &epoch] {
            assert!(
                !r.store
                    .contains(&Kind::STRUCTURAL.seq(&space(), &p.dev.name, p.seq))
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
    assert!(!again.log.fold.is_writer(&n("/carol")));
    assert!(again.log.fold.epochs().is_empty());
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
async fn an_old_image_applies_every_own_entry_that_chains_and_resumes_above_them() {
    // d12 at unit level (review M2): the image's R is BLOCK; peers hold seq
    // 1..=12 of this device. What this run's own extension covers (9..=16)
    // is not what an earlier run signed: the entries above BLOCK raise
    // `RolledBack` and are applied all the same, as every peer applied them,
    // so this device and its peers agree on the value.
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
    // The entries above BLOCK come out of order: one that does not chain yet
    // is held, waiting; it is applied when its predecessor is, and nothing
    // asks for it again.
    let early = old.admit(&packet(11));
    assert_eq!(early.outcome, Outcome::Waiting);
    assert!(has_alert(&early, |al| matches!(
        al,
        Alert::RolledBack { reserved, seen: 11 } if *reserved == BLOCK
    )));
    assert!(old.log.next_seq() > 11, "never signs over a seq it saw");
    for seq in (1..=12).filter(|s| *s != 11) {
        let a = old.admit(&packet(seq));
        assert_eq!(a.outcome, Outcome::Applied, "seq {seq}");
        assert_eq!(
            has_alert(&a, |al| matches!(
                al,
                Alert::RolledBack { reserved, seen } if *reserved == BLOCK && *seen == seq
            )),
            seq > BLOCK,
            "seq {seq}"
        );
    }
    assert_eq!(old.admit(&packet(11)).outcome, Outcome::Duplicate);
    assert_eq!(old.log.head(), 12);
    assert_eq!(
        old.value("/a"),
        Some("10".into()),
        "the value the peers hold"
    );
    assert_eq!(old.log.next_seq(), 13, "above everything a peer holds");
    let s = old.members(members(None, vec![])).await;
    assert_eq!(s.id.seq, 13);
    assert!(
        !s.effects
            .alerts
            .iter()
            .any(|a| matches!(a, Alert::GapSigned { .. })),
        "what chains is held: no gap to state"
    );
}

#[tokio::test]
async fn a_refused_entry_does_not_vouch_for_its_device_and_an_applied_or_closed_one_does() {
    let dave = dev("/dave/phone", "/dave", 6);
    let erin = dev("/erin/phone", "/erin", 7);
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    // A stranger under a trusted namespace: refused, held, no voucher.
    let refused = r.admit(&Chain::new(&dave).put("/a", "x"));
    assert_eq!(refused.outcome, Outcome::Refused(Refusal::NotMember));
    // Bytes that verify and do not decode.
    assert_eq!(
        r.admit(&sign_raw(&erin, 1, b"\xff\xfejunk")).outcome,
        Outcome::Unreadable
    );
    for d in [&dave, &erin] {
        assert!(r.log.holds(&d.name), "held");
        assert!(!r.log.vouches(&d.name), "{} is not vouched for", d.name);
    }
    assert!(!r.log.vouches(&bob().name), "nothing of Bob's is held");
    r.applied(&Chain::new(&bob()).put("/a", "one"));
    assert!(r.log.vouches(&bob().name));
    r.flusher.flush().await.unwrap();
    let again = open_on(&r.crash(), &carol());
    assert!(again.log.vouches(&bob().name) && again.log.vouches(&phone().name));
    assert!(!again.log.vouches(&dave.name) && !again.log.vouches(&erin.name));

    // Held closed (sealed, no key yet) is admitted: it vouches.
    let s = sealed_space();
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    assert_eq!(
        r.admit(&sealed_put(&s, "/secret", "hush")).outcome,
        Outcome::Closed
    );
    assert!(r.log.vouches(&bob().name));
}

#[tokio::test]
async fn a_member_signing_the_largest_seq_does_not_panic_the_log() {
    // Review L8: seq arithmetic on a seq the signer chose.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let one = b.put("/a", "one");
    let top = sign_entry(
        &bob(),
        u64::MAX,
        &Entry {
            prev: Some(Prev {
                digest: one.digest,
                seq: Some(1),
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from_static(b"top")),
            }),
        },
    );
    // The top first, then lower ones: the ranges held end at u64::MAX.
    r.applied(&top);
    r.applied(&one);
    r.applied(&b.put("/b", "two"));
    assert!(r.log.holds(&bob().name));
}

#[tokio::test]
async fn a_device_that_sees_its_own_entry_at_the_largest_seq_signs_no_more() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![])).await;
    let top = sign_entry(
        &me,
        u64::MAX,
        &Entry {
            prev: Some(Prev {
                digest: [0; 32],
                seq: Some(0),
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from_static(b"top")),
            }),
        },
    );
    r.applied(&top);
    let put = r.log.put(
        &n("/a"),
        Payload::Inline(Bytes::from_static(b"more")),
        vec![],
        NOW,
    );
    assert!(
        matches!(put, Err(HeapError::Local { .. })),
        "no seq is left above one that is held, and none is signed over: {:?}",
        put.map(|_| ())
    );
}

#[tokio::test]
async fn a_removal_binds_the_highest_applied_entry_never_a_refused_fork_above_it() {
    // Review L4: the tip is what the owner holds and applied.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let (p1, p2) = (b.put("/a", "1"), b.put("/a", "2"));
    r.applied(&p1);
    r.applied(&p2);
    // Bob's key signed another entry at seq 3 that names bytes other than p2
    // at seq 2: held, refused, never applied.
    let fork = sign_entry(
        &bob(),
        3,
        &Entry {
            prev: Some(Prev {
                digest: [9; 32],
                seq: None,
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from_static(b"fork")),
            }),
        },
    );
    assert_eq!(r.admit(&fork).outcome, Outcome::Refused(Refusal::Chain));
    assert!(r.log.holds(&bob().name));
    assert_eq!(r.log.removal_tips(&n("/bob")), vec![p2.entry_ref()]);
}

#[tokio::test]
async fn only_the_writer_remove_of_a_removal_carries_tips() {
    // Review L4: the fold ignores the tips of a reader Add's Remove.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    r.applied(&owner.members(members(None, vec![add(2, "/bob", Role::Reader)])));
    let p1 = Chain::new(&bob()).put("/a", "1");
    r.applied(&p1);
    let ops = r.log.remove_ops(&n("/bob"));
    assert_eq!(ops.len(), 2, "one per standing Add");
    for op in ops {
        let Op::Remove { id, tips } = op else {
            panic!("a removal is made of Removes")
        };
        match id[0] {
            1 => assert_eq!(tips, vec![p1.entry_ref()], "the writer Add"),
            2 => assert!(tips.is_empty(), "the reader Add"),
            other => panic!("an Add nobody made: {other}"),
        }
    }
}

#[tokio::test]
async fn a_removal_of_a_person_with_many_devices_fits_entries_and_loses_no_tip() {
    // Review L4: past about 25 devices the Remove outgrew an entry (and
    // beyond 64 its tips were cut off silently).
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let long = "x".repeat(70);
    let mut want = std::collections::BTreeSet::new();
    for i in 0..70u8 {
        let d = dev(&format!("/bob/{long}{i}"), "/bob", 10 + i);
        let p = Chain::new(&d).put("/a", "x");
        r.applied(&p);
        want.insert(p.entry_ref());
    }
    let mut got = std::collections::BTreeSet::new();
    let batches = pack_ops(r.log.remove_ops(&n("/bob")));
    assert!(batches.len() > 1, "the removal does not fit one entry");
    for batch in batches {
        for op in &batch {
            if let Op::Remove { tips, .. } = op {
                got.extend(tips.iter().cloned());
            }
        }
        let entry = Entry {
            prev: Some(Prev {
                digest: [1; 32],
                seq: Some(u64::MAX),
            }),
            after: vec![],
            body: Body::Members(MembersBody {
                create: None,
                ops: batch,
            }),
        };
        entry.encode().expect("each batch fits an entry");
    }
    assert_eq!(got, want, "every device's tip is bound");
}

/// A packet of `dev` at `seq` that states a gap: its `PREV` names `prev` at
/// `prev_seq`.
fn gap_entry(dev: &Dev, seq: u64, prev: [u8; 32], prev_seq: u64, bytes: &str) -> Packet {
    sign_entry(
        dev,
        seq,
        &Entry {
            prev: Some(Prev {
                digest: prev,
                seq: Some(prev_seq),
            }),
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from(bytes.to_owned())),
            }),
        },
    )
}

#[tokio::test]
async fn a_refused_entrys_gap_statement_declares_nothing_absent() {
    // Review L5: voids come from entries that were admitted.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    r.applied(&b.put("/a", "1"));
    r.applied(&b.put("/a", "2"));
    // A fork: it names other bytes than the entry held at seq 2, and says
    // seqs 3..=99 are absent.
    let fork = gap_entry(&bob(), 100, [9; 32], 2, "fork");
    assert_eq!(r.admit(&fork).outcome, Outcome::Refused(Refusal::Chain));
    assert_eq!(
        r.log.voids(&bob().name),
        vec![],
        "nothing was declared void"
    );
}

#[tokio::test]
async fn the_gap_statement_of_an_entry_found_equivocal_is_retracted() {
    // Review L5: a writer whose fork came first must not make a reader skip
    // its real entries for good.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut b = Chain::new(&bob());
    let mut last = None;
    for i in 0..10 {
        let p = b.put("/a", &i.to_string());
        r.applied(&p);
        last = Some(p);
    }
    let last = last.unwrap();
    let first = gap_entry(&bob(), 100, last.digest, 10, "one");
    r.applied(&first);
    assert_eq!(r.log.voids(&bob().name), vec![(11, 99)]);
    let second = gap_entry(&bob(), 100, last.digest, 10, "two");
    assert_eq!(r.admit(&second).outcome, Outcome::Evidence);
    assert_eq!(
        r.log.voids(&bob().name),
        vec![],
        "what an equivocating writer said is absent is not taken as said"
    );
    let wants = r.log.missing();
    assert!(
        wants
            .iter()
            .any(|w| w.device == bob().name && (w.first, w.last) == (11, 99)),
        "its entries below the equivocal one are asked for again: {wants:?}"
    );
}

#[tokio::test]
async fn an_entry_that_does_not_decode_keeps_the_link_it_states() {
    // Review L6: a cut walking through it must find a real prev.
    use ndn_tlv::TlvWriter;
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut content = TlvWriter::new();
    content.write_nested(wire::tlv::ENTRY, |w| {
        w.write_tlv(wire::tlv::KIND, &[7]); // no such kind: the body fails
        w.write_tlv(wire::tlv::PREV, &[7; 32]);
        w.write_tlv(wire::tlv::PREV_SEQ, &[3]);
        w.write_tlv(wire::tlv::INLINE, b"x");
    });
    let p = sign_raw(&bob(), 5, &content.finish());
    assert_eq!(r.admit(&p).outcome, Outcome::Unreadable);
    let marker = Marker::decode(&r.store.get(&Kind::VERIFIED.of(&p.name())).unwrap()).unwrap();
    assert_eq!((marker.prev, marker.prev_seq), ([7; 32], 3));
}

#[tokio::test]
async fn a_member_cannot_make_the_ledger_grow_without_bound_by_fragmenting_its_runs() {
    // Review L9: the ledger record is rewritten with every entry, so what a
    // device keeps of one writer's runs is capped.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let (mut prev, mut prev_seq) = ([0; 32], 0);
    for k in 1..=chain::RANGES_MAX as u64 {
        let p = gap_entry(&bob(), 2 * k, prev, prev_seq, "x");
        r.applied(&p);
        (prev, prev_seq) = (p.digest, 2 * k);
    }
    let one_more = gap_entry(
        &bob(),
        2 * chain::RANGES_MAX as u64 + 2,
        prev,
        prev_seq,
        "x",
    );
    assert_eq!(
        r.admit(&one_more).outcome,
        Outcome::Refused(Refusal::Fragmented)
    );
    assert!(
        r.store.get(&one_more.name()).is_none(),
        "an entry that is refused for it is not stored"
    );
    // An entry that extends the last run starts no fragment.
    let top = 2 * chain::RANGES_MAX as u64;
    r.applied(&gap_entry(&bob(), top + 1, prev, top, "x"));
}

/// A cut that re-admits an entry by its name and digest has it wanted by the bytes it names,
/// the implicit digest of the packet, until a packet with those bytes is held; other bytes at
/// the name do not satisfy it.
#[tokio::test]
async fn an_entry_a_cut_readmits_is_wanted_by_its_implicit_digest_until_held() {
    let me = laptop();
    let mut r = rig(&me);
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let mut b = Chain::new(&bob());
    let p1 = b.put("/p1", "1");
    let named = implicit_digest(&p1.wire);
    let want = |digest: [u8; 32]| Want {
        device: bob().name,
        first: 1,
        last: 1,
        digest: Some(Pin::Implicit(digest)),
    };
    assert_eq!(
        r.log.cut_wants(&[], &[(bob().name, 1, named)], &[]),
        vec![want(named)]
    );
    r.applied(&p1);
    assert_eq!(r.log.cut_wants(&[], &[(bob().name, 1, named)], &[]), vec![]);
    assert_eq!(
        r.log.cut_wants(&[], &[(bob().name, 1, [7; 32])], &[]),
        vec![want([7; 32])],
        "other bytes at the name are not the ones the cut names"
    );
}

/// The thief's bytes were taken first and the honest ones kept as evidence beside them. A cut
/// that names the honest bytes wants them (they are not the entry held at the name); once the
/// thief's are refused, the honest bytes take the name and the thief's stay as evidence, and
/// nothing is told again as an equivocation.
#[tokio::test]
async fn the_second_packet_kept_as_evidence_takes_the_name_when_the_first_is_refused() {
    let mut r = rig(&laptop());
    r.members(members(Some(true), vec![add(1, "/bob", Role::Writer)]))
        .await;
    let thief = Chain::new(&bob()).put("/a", "stolen");
    let honest = Chain::new(&bob()).put("/a", "mine");
    r.applied(&thief);
    assert_eq!(r.admit(&honest).outcome, Outcome::Evidence);
    let named = implicit_digest(&honest.wire);
    let want = Want {
        device: bob().name,
        first: 1,
        last: 1,
        digest: Some(Pin::Implicit(named)),
    };
    assert_eq!(
        r.log.cut_wants(&[], &[(bob().name, 1, named)], &[]),
        vec![want],
        "the honest bytes kept as evidence are not the entry held at the name"
    );

    // The revocation that refuses the thief's bytes lifts the suspicion of the key.
    r.suspicion.lift(&bob().key);
    let cut = Refusal::OutsideCut(Cut {
        device: bob().name,
        keeps_to: 0,
    });
    r.log.withdraw(&bob().name, 1, cut);
    assert_eq!(r.value("/a"), None, "the thief's entry is withdrawn");
    let data = Data::decode(honest.wire.clone()).unwrap();
    let (outcome, fx) = r.log.promote(&honest.wire, &data, &verified(&bob()), NOW);
    assert_eq!(outcome, Outcome::Applied);
    assert_eq!(r.value("/a").as_deref(), Some("mine"));
    assert!(
        !fx.alerts
            .iter()
            .any(|a| matches!(a, Alert::Equivocation { .. })),
        "told when the second packet arrived, not again: {:?}",
        fx.alerts
    );
    assert_eq!(
        r.store.get(&Kind::EQUIVOCAL.of(&honest.name())),
        Some(thief.wire.clone()),
        "the refused bytes are the evidence now"
    );
    assert_eq!(r.log.cut_wants(&[], &[(bob().name, 1, named)], &[]), vec![]);
}

// -- The owner's devices: only an `admin` or `member` device holds the owner's powers (§9.9) --

fn guest() -> Dev {
    not_owner_device(dev("/alice/guest/bob", "/alice", 5))
}
fn relay() -> Dev {
    not_owner_device(dev("/alice/node/vps", "/alice", 6))
}
fn tablet() -> Dev {
    dev("/alice/member/tablet", "/alice", 7)
}

/// A guest or node device of the owner signs no Members and no Epoch entry, and nothing it
/// writes counts as the owner's implicit write; a member device of the owner still does both.
#[tokio::test]
async fn a_guest_or_node_device_of_the_owner_holds_none_of_the_owners_powers() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mallory = n("/mallory");

    let m = Chain::new(&guest()).members(members(None, vec![add(9, "/mallory", Role::Writer)]));
    assert_eq!(
        r.admit(&m).outcome,
        Outcome::Refused(Refusal::NotOwnerDevice)
    );
    assert!(
        !r.log.fold.is_writer(&mallory),
        "the guest's Members entry is not applied"
    );

    let e = EpochId {
        creator: relay().name,
        seq: 1,
    };
    let epoch = Chain::new(&relay()).entry(
        Body::Epoch(EpochBody {
            key_check: seal::key_check(&ContentKey::generate(), &space(), &e),
            audience: vec![n("/alice")],
        }),
        vec![],
    );
    assert_eq!(
        r.admit(&epoch).outcome,
        Outcome::Refused(Refusal::NotOwnerDevice)
    );
    assert_eq!(
        r.log.fold.in_force(),
        None,
        "the node's Epoch entry is not applied"
    );

    let other_guest = not_owner_device(dev("/alice/guest/carl", "/alice", 8));
    let put = Chain::new(&other_guest).put("/diary", "as the owner");
    assert_eq!(
        r.admit(&put).outcome,
        Outcome::Refused(Refusal::NotOwnerDevice),
        "a guest device has no implicit owner write"
    );
    assert_eq!(r.value("/diary"), None);

    // A member device of the owner still carries both.
    let mut t = Chain::new(&tablet());
    r.applied(&t.members(members(None, vec![add(8, "/dave", Role::Writer)])));
    assert!(r.log.fold.is_writer(&n("/dave")));
    r.applied(&t.put("/diary", "from the tablet"));
    assert_eq!(r.value("/diary").as_deref(), Some("from the tablet"));
}

/// What a device's entries mean follows its standing: a Members entry applied while its
/// signer stood as a member device is withdrawn when the judge says the device is none, and
/// returns when it says it is again.
#[tokio::test]
async fn a_change_of_a_devices_standing_judges_what_it_signed_again() {
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let mut t = Chain::new(&tablet());
    r.applied(&t.members(members(None, vec![add(8, "/dave", Role::Writer)])));
    assert!(r.log.fold.is_writer(&n("/dave")));

    let later = t.put("/x", "1");
    let data = Data::decode(later.wire.clone()).unwrap();
    let demoted = Verified {
        owner_capable: false,
        ..verified(&tablet())
    };
    let (outcome, _) = r.log.admit(&later.wire, &data, &demoted, NOW, false);
    assert_eq!(outcome, Outcome::Refused(Refusal::NotOwnerDevice));
    assert!(
        !r.log.fold.is_writer(&n("/dave")),
        "the Members entry the device signed as a member device is withdrawn"
    );

    let again = t.put("/y", "2");
    let data = Data::decode(again.wire.clone()).unwrap();
    r.log
        .admit(&again.wire, &data, &verified(&tablet()), NOW, false);
    assert!(
        r.log.fold.is_writer(&n("/dave")),
        "and returns with the standing"
    );
}

/// This device's own standing decides whether it signs the owner's entries; the standing is
/// kept across a restart.
#[tokio::test]
async fn a_guest_device_signs_no_members_or_epoch_entry_and_remembers_it() {
    let g = guest();
    let mut r = rig(&g);
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    assert!(matches!(
        r.log.owner_only(),
        Err(HeapError::NotOwner { .. })
    ));
    assert!(matches!(
        r.log
            .sign_members(members(None, vec![add(9, "/mallory", Role::Writer)]), NOW),
        Err(HeapError::NotOwner { .. })
    ));
    assert!(matches!(
        r.log.put(
            &n("/diary"),
            Payload::Inline(Bytes::from_static(b"x")),
            vec![],
            NOW
        ),
        Err(HeapError::NotAllowed { .. })
    ));

    // Another device of the owner's, a member one, is held as one across a restart; the
    // guest's standing is held as none.
    let mut t = Chain::new(&tablet());
    r.applied(&t.put("/ok", "1"));
    let guest_put = Chain::new(&relay()).put("/no", "1");
    r.admit(&guest_put);
    r.flusher.flush().await.unwrap();
    let reopened = open_on(&r.crash(), &g);
    let standing = |r: &Rig, d: &Dev| r.log.devices.get(&d.name).map(|dev| dev.owner_capable);
    assert_eq!(standing(&reopened, &tablet()), Some(true));
    assert_eq!(standing(&reopened, &relay()), Some(false));
}

/// A writer seals one entry in an epoch no owner device made, to make every reader wait for a
/// key that can never come: it is refused outright, so nothing is held closed and reads go on.
/// An epoch of a device that may be an owner device, whose Epoch entry has not arrived, is still
/// waited for.
#[tokio::test]
async fn an_entry_sealed_in_an_epoch_no_owner_device_made_is_refused_not_held_closed() {
    let s = sealed_space();
    let sealed_in = |epoch: EpochId| {
        let name = log_name(&bob().name, &space(), 1);
        let plain = wire::encode_sealed_plain(&PutBody {
            path: n("/x"),
            payload: Payload::Inline(Bytes::from_static(b"v")),
        })
        .unwrap();
        let sealed = seal::seal_payload(&ContentKey::from_bytes(s.key), &name, &plain);
        sign_entry(
            &bob(),
            1,
            &Entry {
                prev: None,
                after: vec![],
                body: Body::Sealed(SealedBody { epoch, sealed }),
            },
        )
    };
    let epoch = |creator: &str| EpochId {
        creator: n(creator),
        seq: 1 << 40,
    };

    // Not an owner device by name.
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    let a = r.admit(&sealed_in(epoch("/eve/phone")));
    assert_eq!(a.outcome, Outcome::Refused(Refusal::NotOwnerEpoch));
    assert!(
        !r.log.has_closed(),
        "nothing waits for a key that cannot come"
    );
    assert!(r.log.get(&n("/x")).is_ok(), "reads go on");

    // A device of the owner's namespace this log holds as no owner device.
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    let guest_entry = Chain::new(&guest()).put("/g", "1");
    assert_eq!(
        r.admit(&guest_entry).outcome,
        Outcome::Refused(Refusal::NotOwnerDevice)
    );
    let a = r.admit(&sealed_in(epoch("/alice/guest/bob")));
    assert_eq!(a.outcome, Outcome::Refused(Refusal::NotOwnerEpoch));
    assert!(!r.log.has_closed());

    // An owner device not heard of yet: its Epoch entry may be on its way.
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    let a = r.admit(&sealed_in(epoch("/alice/laptop")));
    assert_eq!(a.outcome, Outcome::Closed);
    assert!(r.log.has_closed());
}

/// The epochs the closed entries are sealed in are read once and kept, and what moves an entry
/// to or from closed makes the next read see it.
#[tokio::test]
async fn the_epochs_of_closed_entries_are_kept_until_an_entry_moves_to_or_from_closed() {
    let s = sealed_space();
    let mut r = rig(&carol());
    r.applied(&s.created);
    r.applied(&s.epoch_entry);
    assert!(r.log.closed_epochs().is_empty());
    assert_eq!(r.admit(&sealed_put(&s, "/a", "1")).outcome, Outcome::Closed);
    assert_eq!(
        r.log.closed_epochs(),
        BTreeSet::from([s.epoch.clone()]),
        "a closed entry's epoch is seen at once, the earlier empty read notwithstanding"
    );
    r.log
        .key_arrived(s.epoch.clone(), ContentKey::from_bytes(s.key));
    assert!(
        r.log.closed_epochs().is_empty(),
        "the entry opened: no epoch is waited for"
    );
}

// -- A revocation cut that names a tip (spec §9.5) --------------------------------------------

/// What the judge tells the log of Bob's key when its revocation's cut names `tip` for this log.
fn tipped(tip: &Packet, readmitted: Vec<(u64, [u8; 32])>) -> Verified {
    Verified {
        tip: Some(TipCut {
            tip: store::Link {
                seq: tip.seq,
                digest: tip.digest,
            },
            readmitted,
        }),
        ..verified(&tip.dev)
    }
}

/// The status record of a held entry: `None` for an applied one.
fn status_of(r: &Rig, p: &Packet) -> Option<Status> {
    let at = Kind::STATUS.seq(&space(), &p.dev.name, p.seq);
    r.store
        .get(&at)
        .map(|record| Status::decode(&record, &p.dev.name).expect("a status record"))
}

fn outside_the_tip() -> Option<Status> {
    Some(Status::Refused(Refusal::OutsideCut(Cut {
        device: bob().name,
        keeps_to: 0,
    })))
}

impl Rig {
    fn admit_as(&mut self, p: &Packet, v: &Verified) -> Admitted {
        let data = Data::decode(p.wire.clone()).unwrap();
        let (outcome, effects) = self.log.admit(&p.wire, &data, v, NOW, false);
        Admitted { outcome, effects }
    }
}

/// Bob's chain `1 <- 2 <- 4 <- 5` with an entry `3` of his key beside it: `3` names `2` as `4`
/// does, so it is on no chain from the tip `5`; `4` states the gap over `3`.
struct Forked {
    p1: Packet,
    p2: Packet,
    fork: Packet,
    p4: Packet,
    tip: Packet,
}

fn forked() -> Forked {
    let mut b = Chain::new(&bob());
    let p1 = b.put("/a", "one");
    let p2 = b.put("/b", "two");
    let fork = b.put("/fork", "off the chain");
    let p4 = b.entry_after_gap(
        Body::Put(PutBody {
            path: n("/c"),
            payload: Payload::Inline(Bytes::from_static(b"three")),
        }),
        2,
        p2.digest,
    );
    let tip = b.put("/d", "four");
    assert_eq!((p4.seq, tip.seq), (4, 5));
    Forked {
        p1,
        p2,
        fork,
        p4,
        tip,
    }
}

fn pinned(p: &Packet) -> Want {
    Want {
        device: bob().name,
        first: p.seq,
        last: p.seq,
        digest: Some(Pin::Signed(p.digest)),
    }
}

/// Under a cut that names a tip, the validator accepts Bob's key below the tip by name, and the
/// log keeps an entry only if it is a chain ancestor of the tip, the very bytes the chain names:
/// one off the chain waits while the chain below the tip is not whole (never applied meanwhile)
/// and is refused once the chain has passed it.
#[tokio::test]
async fn an_entry_of_a_tip_cut_key_is_kept_only_if_it_is_a_chain_ancestor_of_the_tip() {
    let f = forked();
    let v = tipped(&f.tip, vec![]);
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));

    // The chain below the tip is not whole: what lies below waits, applied by nobody.
    assert_eq!(r.admit_as(&f.fork, &v).outcome, Outcome::Waiting);
    assert_eq!(r.admit_as(&f.p1, &v).outcome, Outcome::Waiting);
    assert_eq!(r.value("/fork"), None);
    assert_eq!(
        r.value("/a"),
        None,
        "an ancestor waits too until its chain is whole"
    );

    // The tip is the entry the cut names: kept, and what it chains to is wanted by the exact
    // bytes the chain names.
    let a = r.admit_as(&f.tip, &v);
    assert_eq!(a.outcome, Outcome::Applied);
    assert!(
        a.effects.wants.contains(&pinned(&f.p4)),
        "{:?}",
        a.effects.wants
    );
    assert_eq!(status_of(&r, &f.fork), Some(Status::Waiting));

    // Seq 4 is an ancestor and its link names seq 2: seq 3 cannot be an ancestor now, for the
    // chain has passed it.
    let a = r.admit_as(&f.p4, &v);
    assert_eq!(a.outcome, Outcome::Applied);
    assert!(
        a.effects.wants.contains(&pinned(&f.p2)),
        "{:?}",
        a.effects.wants
    );
    assert_eq!(status_of(&r, &f.fork), outside_the_tip());
    assert_eq!(r.value("/fork"), None);

    // The rest of the chain arrives; the ancestor that waited is applied.
    assert_eq!(r.admit_as(&f.p2, &v).outcome, Outcome::Applied);
    assert_eq!(status_of(&r, &f.p1), None);
    for (path, value) in [
        ("/a", "one"),
        ("/b", "two"),
        ("/c", "three"),
        ("/d", "four"),
    ] {
        assert_eq!(r.value(path).as_deref(), Some(value), "{path}");
    }

    // With the chain whole, an entry off it is refused as it arrives, naming the tip.
    let mut late = rig(&carol());
    let mut owner = Chain::new(&phone());
    late.applied(&creation(&mut owner));
    for p in [&f.tip, &f.p4, &f.p2, &f.p1] {
        assert_eq!(late.admit_as(p, &v).outcome, Outcome::Applied);
    }
    let a = late.admit_as(&f.fork, &v);
    assert!(
        matches!(
            a.outcome,
            Outcome::Refused(Refusal::OutsideCut(Cut { keeps_to: 5, .. }))
        ),
        "{:?}",
        a.outcome
    );
    assert!(has_alert(
        &a,
        |al| matches!(al, Alert::OutsideCut { id } if id.seq == 3)
    ));
    assert_eq!(late.value("/fork"), None);
}

/// The entry at the tip's number is only the bytes the cut names: other bytes signed at that seq
/// are refused, and the bytes it names take the name when they arrive, the others staying as
/// evidence. The log says nothing of what lies above the tip: the validator judged it.
#[tokio::test]
async fn other_bytes_at_the_tip_are_refused_and_the_named_bytes_take_the_name() {
    let f = forked();
    let v = tipped(&f.tip, vec![]);
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let other = gap_entry(&bob(), 5, f.p4.digest, 4, "other bytes at the tip");
    let a = r.admit_as(&other, &v);
    assert!(
        matches!(
            a.outcome,
            Outcome::Refused(Refusal::OutsideCut(Cut { keeps_to: 5, .. }))
        ),
        "{:?}",
        a.outcome
    );

    let a = r.admit_as(&f.tip, &v);
    assert_eq!(a.outcome, Outcome::Applied, "{:?}", a.effects.alerts);
    assert_eq!(r.value("/d").as_deref(), Some("four"));
    assert!(r.store.get(&Kind::EQUIVOCAL.of(&f.tip.name())).is_some());

    // Above the tip: not the chain's to judge (the validator refused it, or a range of the same
    // cut accepts it). A log that holds the chain applies it.
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    for p in [&f.tip, &f.p4, &f.p2, &f.p1] {
        assert_eq!(r.admit_as(p, &v).outcome, Outcome::Applied);
    }
    let mut b = Chain::new(&bob());
    b.seq = 5;
    b.last = Some(f.tip.digest);
    let above = b.put("/e", "five");
    assert_eq!(above.seq, 6);
    assert_eq!(r.admit_as(&above, &v).outcome, Outcome::Applied);
}

/// An entry the owner re-admits by its exact name stays kept though it is off the chain of the
/// tip: the cut lists the entries a tip leaves out for the owner to bring back one by one.
#[tokio::test]
async fn an_entry_a_tip_cut_readmits_by_name_is_kept_off_the_chain() {
    let f = forked();
    let readmitted = vec![(f.fork.seq, wire::implicit_digest(&f.fork.wire))];
    let v = tipped(&f.tip, readmitted);
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    for p in [&f.tip, &f.p4, &f.p2, &f.p1] {
        assert_eq!(r.admit_as(p, &v).outcome, Outcome::Applied);
    }
    assert_eq!(r.admit_as(&f.fork, &v).outcome, Outcome::Applied);
    assert_eq!(r.value("/fork").as_deref(), Some("off the chain"));
}

/// A cut that names a tip, adopted after the entries were taken, withdraws the held entries off
/// the tip's chain and keeps the ancestors; once the cut names no tip, what was refused for it
/// is judged again when it is offered.
#[tokio::test]
async fn a_tip_adopted_after_the_entries_withdraws_those_off_the_chain() {
    let f = forked();
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    for p in [&f.p1, &f.p2, &f.fork, &f.p4, &f.tip] {
        r.applied(p);
    }
    assert_eq!(r.value("/fork").as_deref(), Some("off the chain"));

    let tip = TipCut {
        tip: store::Link {
            seq: f.tip.seq,
            digest: f.tip.digest,
        },
        readmitted: vec![],
    };
    let fx = r.log.cut_tips(vec![(bob().key, Some(tip))]);
    assert!(
        fx.changes.iter().any(|c| matches!(
            c,
            Change::Withdrawn { id, why: Refusal::OutsideCut(Cut { keeps_to: 5, .. }) } if id.seq == 3
        )),
        "{:?}",
        fx.changes
    );
    assert_eq!(r.value("/fork"), None);
    assert_eq!(status_of(&r, &f.fork), outside_the_tip());
    for (path, value) in [
        ("/a", "one"),
        ("/b", "two"),
        ("/c", "three"),
        ("/d", "four"),
    ] {
        assert_eq!(r.value(path).as_deref(), Some(value), "{path}");
    }

    r.log.cut_tips(vec![(bob().key, None)]);
    let a = r.admit(&f.fork);
    assert_eq!(a.outcome, Outcome::Duplicate);
    assert_eq!(r.value("/fork").as_deref(), Some("off the chain"));
}

/// A cut's tip is wanted by the signed-region digest it names until an entry with that digest is
/// held, whatever counter the group shows: a device that holds nothing of the key asks for it,
/// and then for what the tip chains to.
#[tokio::test]
async fn the_tip_a_cut_names_is_wanted_by_its_signed_digest_until_held() {
    let f = forked();
    let mut r = rig(&carol());
    let mut owner = Chain::new(&phone());
    r.applied(&creation(&mut owner));
    let tips = [(bob().name, f.tip.seq, f.tip.digest)];
    assert_eq!(r.log.cut_wants(&[], &[], &tips), vec![pinned(&f.tip)]);
    let v = tipped(&f.tip, vec![]);
    assert_eq!(r.admit_as(&f.tip, &v).outcome, Outcome::Applied);
    assert_eq!(r.log.cut_wants(&[], &[], &tips), vec![], "held");
    assert!(
        r.log.missing().contains(&pinned(&f.p4)),
        "what the tip chains to is wanted by the walk, as a removal cut's chain is"
    );
}
