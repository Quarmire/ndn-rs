//! Device-wide events (spec §21): equivocation of any two entries of a key at one seq (a members
//! record against a version included), withdrawals and cuts told with no watcher, delivery at
//! least once across a restart and acknowledgement, and floods bounded without losing the first
//! of each kind per subject. Revocation is in the `tests` module of `device.rs`, beside the
//! harness that adopts trust contexts.

use futures::StreamExt;
use ndn_security::TrustSchema;
use ndn_sync::store::BackendStore;
use ndn_sync::{MemoryStore, StoreOp};

use super::durability_tests::Engine;

use super::test_kit::{
    Made, Unconnected, budget, give, id, key, log_share, made, n, plan, version,
};
use super::*;
use crate::events::{
    Cursor, DeviceEvent, EntryKind, EventDetail, EventId, EventKind, EventSubject, Meaning,
    WithdrawnBy,
};
use crate::layer::Share;

/// A members record of `c` at `revision`, as the device holds the record in force now, listing
/// `writers` and cutting `cuts`.
fn record(
    dev: &Device,
    c: &Name,
    revision: u64,
    writers: &[&str],
    cuts: Vec<CutBody>,
) -> MembersBody {
    let first = dev.inner.st.lock().colls[c].members.clone().unwrap();
    MembersBody {
        collection: c.clone(),
        folder: false,
        revision,
        rule: Rule::Log,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: Vec::new(),
        cuts,
        epoch: None,
        key_check: None,
        since: None,
        parent: Some(first.as_parent()),
    }
}

fn removing_bob(dev: &Device, c: &Name) -> MembersBody {
    record(
        dev,
        c,
        2,
        &["/alice", "/carol"],
        vec![CutBody {
            of: n("/bob"),
            accept: Accepted::new(),
        }],
    )
}

fn of_kind(dev: &Device, kind: EventKind) -> Vec<DeviceEvent> {
    dev.pending_events()
        .into_iter()
        .filter(|e| e.kind() == kind)
        .collect()
}

/// A device on `store` as `/alice/laptop` with the trust contexts of Alice, Bob and Carol, which
/// can be started again on the same store.
async fn on(
    keys: &Arc<SecurityManager>,
    store: &Arc<dyn DataStore>,
    tune: impl FnOnce(Config) -> Config,
) -> Device {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
    }
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n("/alice/laptop"),
        Arc::clone(keys),
        validator,
        Arc::clone(store),
        tune(Config {
            first_look: Duration::from_millis(20),
            ..Config::new()
        }),
    )
    .await
    .unwrap()
}

/// A device on a store of its own, owning `plan()` and `budget()` as log collections.
async fn started(
    tune: impl FnOnce(Config) -> Config,
) -> (Device, Arc<SecurityManager>, Arc<dyn DataStore>) {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n("/alice/laptop/KEY/1")).unwrap();
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let dev = on(&keys, &store, tune).await;
    for c in [plan(), budget()] {
        dev.share(&c, log_share()).await.unwrap();
    }
    (dev, keys, store)
}

/// How many records the store keeps for events.
fn kept(store: &Arc<dyn DataStore>) -> usize {
    store.scan_under(&n("/localhost/ndn-data/events"), 0).len()
}

#[tokio::test]
async fn a_members_record_and_a_version_at_one_seq_are_an_event_in_either_order() {
    for record_first in [false, true] {
        let (dev, ..) = started(|c| c).await;
        // The owner's key signed a version of the plan and, at the same seq, a members record of
        // the budget: two entries of one key at one seq.
        let v = version("/alice/phone", &plan(), 5, &[], None);
        let m = made(
            "/alice/phone",
            &budget(),
            5,
            Record::Members(record(
                &dev,
                &budget(),
                2,
                &["/alice", "/bob", "/carol"],
                Vec::new(),
            )),
        );
        let order = match record_first {
            true => [&m, &v],
            false => [&v, &m],
        };
        give(&dev, order[0]);
        assert!(
            of_kind(&dev, EventKind::Equivocation).is_empty(),
            "one entry at a seq is no event"
        );
        give(&dev, order[1]);
        let events = of_kind(&dev, EventKind::Equivocation);
        assert_eq!(
            events.len(),
            1,
            "record first: {record_first}: a members record and a version at seq 5 of one key \
             are an equivocation, told on the device; pending: {:?}",
            dev.pending_events()
        );
        let e = &events[0];
        let EventDetail::Equivocation {
            writer,
            seq,
            first,
            second,
        } = &e.detail
        else {
            panic!("{e:?}")
        };
        assert_eq!((writer, *seq), (&key("/alice/phone"), 5));
        assert_eq!(
            (&first.name, &second.name),
            (&order[0].name, &order[1].name)
        );
        let kind = |x: &Made| match x.record {
            Record::Version(_) => Some(EntryKind::Version),
            _ => Some(EntryKind::Members),
        };
        assert_eq!(
            (first.kind, second.kind),
            (kind(order[0]), kind(order[1])),
            "the kinds of both entries are known"
        );
        assert_eq!(
            (first.digest, second.digest),
            (
                Some(wire::implicit_digest(&order[0].packet)),
                Some(wire::implicit_digest(&order[1].packet))
            ),
            "the digests of the packets this device verified"
        );
        assert_eq!(e.subject(), EventSubject::Writer(key("/alice/phone")));
        assert_eq!(e.meaning(), Meaning::BothKept);
        assert_eq!(e.next_step(), crate::NextStep::UseOwnerDevice);
        assert!(e.why().contains("two different entries"), "{}", e.why());
        assert_eq!((e.count, e.last.as_ref()), (1, None));
        // Evidence only: names and digests, never what the entries say.
        assert!(!format!("{e:?}").contains("/alice/phone 5"), "{e:?}");
        dev.shutdown();
    }
}

#[tokio::test]
async fn a_members_record_under_the_name_of_a_held_version_is_an_event_in_either_order() {
    for record_first in [false, true] {
        let (dev, ..) = started(|c| c).await;
        // One log entry name, two packets of different kinds: the owner's key signed a version
        // of the plan and a members record of the plan at one seq.
        let v = version("/alice/phone", &plan(), 5, &[], None);
        let m = made(
            "/alice/phone",
            &plan(),
            5,
            Record::Members(record(
                &dev,
                &plan(),
                2,
                &["/alice", "/bob", "/carol"],
                Vec::new(),
            )),
        );
        assert_eq!(v.name, m.name);
        let order = match record_first {
            true => [&m, &v],
            false => [&v, &m],
        };
        give(&dev, order[0]);
        give(&dev, order[1]);
        let events = of_kind(&dev, EventKind::Equivocation);
        assert_eq!(
            events.len(),
            1,
            "record first: {record_first}: two packets of different kinds under one name are \
             an equivocation, told on the device; pending: {:?}",
            dev.pending_events()
        );
        let EventDetail::Equivocation {
            writer,
            seq,
            first,
            second,
        } = &events[0].detail
        else {
            panic!("{:?}", events[0])
        };
        assert_eq!((writer, *seq), (&key("/alice/phone"), 5));
        assert_eq!((&first.name, &second.name), (&v.name, &v.name));
        let kind = |x: &Made| match x.record {
            Record::Version(_) => Some(EntryKind::Version),
            _ => Some(EntryKind::Members),
        };
        assert_eq!((first.kind, second.kind), (kind(order[0]), kind(order[1])));
        assert_eq!(
            (first.digest, second.digest),
            (
                Some(wire::implicit_digest(&order[0].packet)),
                Some(wire::implicit_digest(&order[1].packet))
            )
        );
        // The same packet again is no new evidence.
        give(&dev, order[1]);
        assert_eq!(of_kind(&dev, EventKind::Equivocation)[0].count, 1);
        dev.shutdown();
    }
}

/// `m` again with another signature value over the same signed region (name through
/// `SignatureInfo`): what a flipped ECDSA `S`, or a fresh randomized ECDSA signature of the same
/// content, gives. Its implicit digest differs; what the key signed does not.
fn resigned(m: &Made, sig: u8) -> Made {
    let packet = DataBuilder::new(m.name.clone(), &wire::encode_record(&m.record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&m.key),
        move |_| Bytes::from(vec![sig; 64]),
    );
    assert_ne!(
        packet, m.packet,
        "another signature value is another packet"
    );
    Made {
        packet,
        name: m.name.clone(),
        key: m.key.clone(),
        record: m.record.clone(),
    }
}

#[tokio::test]
async fn another_signature_value_over_the_same_signed_region_is_not_an_equivocation() {
    // A version, a members record the owner stores, and one it does not store (Bob is no device
    // of the plan's namespace): each is held, and then arrives again with another signature.
    let probes = |dev: &Device| {
        [
            version("/alice/phone", &plan(), 5, &[], None),
            made(
                "/alice/phone",
                &plan(),
                6,
                Record::Members(record(
                    dev,
                    &plan(),
                    2,
                    &["/alice", "/bob", "/carol"],
                    Vec::new(),
                )),
            ),
            made(
                "/bob/laptop",
                &plan(),
                7,
                Record::Members(record(dev, &plan(), 2, &["/alice", "/bob"], Vec::new())),
            ),
        ]
    };
    let (dev, ..) = started(|c| c).await;
    let mut changes = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    for first in probes(&dev) {
        give(&dev, &first);
        let copy = resigned(&first, 7);
        give(&dev, &copy);
        give(&dev, &resigned(&first, 9));
    }
    assert!(
        of_kind(&dev, EventKind::Equivocation).is_empty(),
        "the same signed region under another signature value is the same signed object, not \
         two things one key signed; pending: {:?}",
        dev.pending_events()
    );
    assert!(
        dev.inner.st.lock().twins.is_empty(),
        "no second packet is kept as evidence of what the key never signed twice"
    );
    let seen = super::test_kit::drain(&mut changes).await;
    assert!(
        !seen
            .iter()
            .any(|c| matches!(c, Change::Equivocation { .. })),
        "a watcher is not told of an equivocation either: {seen:?}"
    );
    // Two different contents at one name still are.
    let (dev2, ..) = started(|c| c).await;
    let first = version("/alice/phone", &plan(), 5, &[], None);
    let mut body = match &first.record {
        Record::Version(body) => body.clone(),
        other => panic!("{other:?}"),
    };
    body.fields = Content::new().with("t", "another");
    let other = made("/alice/phone", &plan(), 5, Record::Version(body));
    give(&dev2, &first);
    give(&dev2, &other);
    assert_eq!(
        of_kind(&dev2, EventKind::Equivocation).len(),
        1,
        "two different contents signed at one name are equivocation; pending: {:?}",
        dev2.pending_events()
    );
    dev.shutdown();
    dev2.shutdown();
}

#[tokio::test]
async fn a_withdrawal_is_an_event_with_no_watcher_and_later_ones_coalesce() {
    let (dev, ..) = started(|c| c).await;
    let bobs: Vec<Made> = (1..=3)
        .map(|s| version("/bob/laptop", &plan(), s, &[], None))
        .collect();
    for m in &bobs {
        give(&dev, m);
    }
    assert!(of_kind(&dev, EventKind::Withdrawal).is_empty());
    // The owner's phone removes Bob from the plan, accepting nothing of his: all three are
    // withdrawn. No one watches the plan.
    give(
        &dev,
        &made(
            "/alice/phone",
            &plan(),
            1,
            Record::Members(removing_bob(&dev, &plan())),
        ),
    );
    let events = of_kind(&dev, EventKind::Withdrawal);
    assert_eq!(
        events.len(),
        1,
        "three withdrawals of one key are one event; pending: {:?}",
        dev.pending_events()
    );
    let e = &events[0];
    let EventDetail::Withdrawal {
        writer,
        collection,
        entry,
        by,
    } = &e.detail
    else {
        panic!("{e:?}")
    };
    assert_eq!(writer, &key("/bob/laptop"));
    assert_eq!(collection.as_ref(), Some(&plan()));
    assert_eq!(
        entry.name, bobs[0].name,
        "the first withdrawn is the evidence kept"
    );
    assert_eq!(entry.kind, Some(EntryKind::Version));
    assert!(
        matches!(by, WithdrawnBy::Cut { of, signer } if *of == n("/bob") && *signer == key("/alice/phone")),
        "{by:?}"
    );
    assert_eq!(e.count, 3);
    assert!(
        matches!(&e.last, Some(EventDetail::Withdrawal { entry, .. }) if entry.name == bobs[2].name),
        "the last occurrence is referenced: {:?}",
        e.last
    );
    assert_eq!(e.meaning(), Meaning::Withdrawn);
    assert_eq!(e.next_step(), crate::NextStep::AskOwner);
    dev.shutdown();
}

#[tokio::test]
async fn a_cut_is_an_event_even_when_nothing_is_withdrawn_but_not_one_this_device_signed() {
    let (dev, ..) = started(|c| c).await;
    give(
        &dev,
        &made(
            "/alice/phone",
            &plan(),
            1,
            Record::Members(removing_bob(&dev, &plan())),
        ),
    );
    let cuts = of_kind(&dev, EventKind::Cut);
    assert_eq!(
        cuts.len(),
        1,
        "the owner's phone removed Bob: told on this device though no one watches and nothing \
         of Bob's was held; pending: {:?}",
        dev.pending_events()
    );
    let EventDetail::Cut {
        subject,
        folder,
        of,
        signer,
        record,
        revision,
        kept,
    } = &cuts[0].detail
    else {
        panic!("{:?}", cuts[0])
    };
    assert_eq!((subject, *folder, of), (&plan(), false, &n("/bob")));
    assert_eq!(signer, &key("/alice/phone"));
    assert_eq!(
        record,
        &log_name(&n("/alice/phone"), Some(&plan()), 1),
        "the record, by its log entry name"
    );
    assert_eq!((*revision, *kept), (2, 0));
    assert_eq!(cuts[0].subject(), EventSubject::Writer(n("/bob")));
    assert_eq!(cuts[0].meaning(), Meaning::WriterCut);
    assert!(of_kind(&dev, EventKind::Withdrawal).is_empty());
    // This device's own removal is its host's gesture: not reported to it.
    let before = dev.pending_events().len();
    dev.share(
        &budget(),
        Share {
            rule: Rule::Log,
            writers: vec![n("/alice"), n("/carol")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        dev.pending_events().len(),
        before,
        "a cut this device signed is not told to it: {:?}",
        dev.pending_events()
    );
    dev.shutdown();
}

/// Two entries of `device` at `seq`, in the plan and in the budget.
fn twins(device: &str, seq: u64) -> [Made; 2] {
    [
        version(device, &plan(), seq, &[], None),
        version(device, &budget(), seq, &[], None),
    ]
}

#[tokio::test]
async fn an_event_not_acknowledged_comes_again_after_a_restart_and_one_acknowledged_does_not() {
    let (dev, keys, store) = started(|c| c).await;
    for m in twins("/alice/phone", 5) {
        give(&dev, &m);
    }
    let [event] = <[DeviceEvent; 1]>::try_from(dev.pending_events())
        .unwrap_or_else(|p| panic!("one event for the equivocation, pending: {p:?}"));
    // Delivered on the stream, never acknowledged.
    let mut stream = dev.events(Cursor::default());
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("the stream delivers it")
        .unwrap();
    assert_eq!(first, event);
    dev.shutdown();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("the stream ends when the device stops")
            .is_none()
    );
    drop(dev);

    let dev = on(&keys, &store, |c| c).await;
    assert_eq!(
        dev.pending_events(),
        vec![event.clone()],
        "not acknowledged: delivered again after the restart, once, with the same id and cursor"
    );
    let mut stream = dev.events(Cursor::default());
    let again = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("the stream delivers it again")
        .unwrap();
    assert_eq!(again.id, event.id);
    // From its cursor on, nothing: the host has it.
    let mut after = dev.events(event.cursor);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), after.next())
            .await
            .is_err(),
        "an event at or below the cursor is not delivered"
    );

    // An id this device never had is refused with a reason, nothing changed.
    let unseen = EventId([9; 16]);
    let refused = dev.acknowledge(&[event.id, unseen]).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::BadRequest { why, .. } if why.contains(&unseen.to_string())),
        "{refused:?}"
    );
    assert_eq!(refused.next(), crate::NextStep::FixRequest);
    assert_eq!(dev.pending_events(), vec![event.clone()]);

    dev.acknowledge(&[event.id]).await.unwrap();
    assert!(dev.pending_events().is_empty());
    dev.acknowledge(&[event.id])
        .await
        .expect("acknowledging again is accepted: idempotent by id");
    dev.shutdown();
    drop(dev);

    let dev = on(&keys, &store, |c| c).await;
    assert!(
        dev.pending_events().is_empty(),
        "acknowledged: not delivered again, though the store replays both entries: {:?}",
        dev.pending_events()
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_flood_is_bounded_and_the_first_event_of_each_kind_and_subject_survives() {
    let (dev, _keys, store) = started(|c| Config {
        events_unacked: 10,
        ..c
    })
    .await;
    // A withdrawal and a cut first: Bob removed from the plan.
    give(&dev, &version("/bob/laptop", &plan(), 1, &[], None));
    give(
        &dev,
        &made(
            "/alice/phone",
            &plan(),
            1,
            Record::Members(removing_bob(&dev, &plan())),
        ),
    );
    let early: Vec<EventId> = dev.pending_events().iter().map(|e| e.id).collect();
    assert_eq!(early.len(), 2, "{:?}", dev.pending_events());

    // Twenty keys each sign two entries at one seq: twenty subjects.
    for i in 0..20 {
        for m in twins(&format!("/carol/dev{i}"), 7) {
            give(&dev, &m);
        }
    }
    let pending = dev.pending_events();
    assert!(
        early.iter().all(|id| pending.iter().any(|e| e.id == *id)),
        "a flood of other subjects never evicts what was kept: {pending:?}"
    );
    let eq = of_kind(&dev, EventKind::Equivocation);
    assert_eq!(
        eq.len(),
        2,
        "a kind keeps at most a fifth of the cap of 10: {eq:?}"
    );
    for (i, e) in eq.iter().enumerate() {
        assert_eq!(
            e.subject(),
            EventSubject::Writer(key(&format!("/carol/dev{i}"))),
            "the first of the subjects are the ones kept, the later ones are not"
        );
    }
    let overflow = of_kind(&dev, EventKind::Overflow);
    assert_eq!(
        overflow.len(),
        1,
        "a single overflow notice, never silent: {pending:?}"
    );
    assert!(
        matches!(&overflow[0].detail, EventDetail::Overflow { dropped } if *dropped == vec![(EventKind::Equivocation, 18)]),
        "the 18 subjects not kept are counted by kind: {:?}",
        overflow[0]
    );
    assert_eq!(overflow[0].meaning(), Meaning::ReportsDropped);
    assert_eq!(
        pending.len(),
        5,
        "4 kept and the overflow notice: {pending:?}"
    );

    // One subject's flood is one event: coalesced, the first evidence kept, the last referenced.
    let first = eq[0].clone();
    let records = kept(&store);
    for seq in 8..60 {
        for m in twins("/carol/dev0", seq) {
            give(&dev, &m);
        }
    }
    let now = of_kind(&dev, EventKind::Equivocation);
    assert_eq!(now.len(), 2);
    assert_eq!(now[0].id, first.id);
    assert_eq!(now[0].detail, first.detail, "the first evidence stays");
    assert_eq!(now[0].count, 1 + 52);
    assert!(
        matches!(
            &now[0].last,
            Some(EventDetail::Equivocation { seq: 59, .. })
        ),
        "{:?}",
        now[0].last
    );
    assert_eq!(dev.pending_events().len(), 5);
    assert_eq!(
        kept(&store),
        records,
        "what the store keeps for events does not grow with the flood"
    );

    // Acknowledging the overflow notice makes it new again: a later drop is a new notice.
    dev.acknowledge(&[overflow[0].id]).await.unwrap();
    assert!(of_kind(&dev, EventKind::Overflow).is_empty());
    for m in twins("/carol/dev30", 7) {
        give(&dev, &m);
    }
    let again = of_kind(&dev, EventKind::Overflow);
    assert_eq!(again.len(), 1);
    assert_ne!(again[0].id, overflow[0].id);
    assert!(
        matches!(&again[0].detail, EventDetail::Overflow { dropped } if *dropped == vec![(EventKind::Equivocation, 1)])
    );
    // The evidence stays re-derivable from the entries held: a watch lists the equivocations.
    let mut changes = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    let seen = super::test_kit::drain(&mut changes).await;
    assert!(
        seen.iter().any(|c| matches!(c, Change::Equivocation { first, .. } if first.id() == &id("/carol/dev19", 7))),
        "an equivocation whose event was not kept is still listed by a watch"
    );
    dev.shutdown();
}

// ---- what a stop leaves between a cause and its event (spec §21.6) ---------------------------

/// What an [`EventGate`] does to the writes made through it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Gate {
    /// Everything goes through; a batch whole.
    Open,
    /// Writes under the events' namespace are dropped, the rest go through: the store as a stop
    /// just before the events were written leaves it.
    Drop,
    /// The process aborts at the first write of an event of the kind, after what was made before
    /// it in its batch was written: a stop on a store whose batches are not atomic.
    AbortAt(EventKind),
    /// The process aborts before any of the batch that holds an event of the kind is written: a
    /// stop on a store whose batches are atomic.
    AbortBatchAt(EventKind),
}

/// A store that can be made to stop between a cause and its event, as a kill does: it forwards
/// every call to the store under it, as its [`Gate`] says.
pub(super) struct EventGate {
    inner: Arc<dyn DataStore>,
    gate: Mutex<Gate>,
    /// The names of what each batch handed over held, once [`Self::keep_batches`] was called.
    batches: Mutex<Option<Vec<Vec<Name>>>>,
}

fn events_namespace() -> Name {
    n("/localhost/ndn-data/events")
}

/// The kind of the event that `wire` is, if `name` is the name of a stored event.
fn event_written(name: &Name, wire: &Bytes) -> Option<EventKind> {
    let events = events_namespace();
    if !name.has_prefix(&events) {
        return None;
    }
    match &name.components()[events.len()..] {
        [dir, at] if dir.value[..] == *b"e" => {
            let at = <[u8; 8]>::try_from(&at.value[..]).ok()?;
            crate::events::decode_event(Cursor(u64::from_be_bytes(at)), wire.clone())
                .ok()
                .map(|e| e.kind())
        }
        _ => None,
    }
}

fn op_name(op: &StoreOp) -> &Name {
    match op {
        StoreOp::Insert(name, _) | StoreOp::Remove(name) => name,
    }
}

impl EventGate {
    pub(super) fn over(inner: Arc<dyn DataStore>, gate: Gate) -> Arc<EventGate> {
        Arc::new(EventGate {
            inner,
            gate: Mutex::new(gate),
            batches: Mutex::new(None),
        })
    }

    pub(super) fn set(&self, gate: Gate) {
        *self.gate.lock() = gate;
    }

    fn keep_batches(&self) {
        *self.batches.lock() = Some(Vec::new());
    }

    fn batches(&self) -> Vec<Vec<Name>> {
        self.batches.lock().clone().unwrap_or_default()
    }

    /// Whether the write of `name` (with `wire`) is made at all; aborts the process where the
    /// gate says so.
    fn admits(&self, name: &Name, wire: Option<&Bytes>) -> bool {
        match *self.gate.lock() {
            Gate::Open => true,
            Gate::Drop => !name.has_prefix(&events_namespace()),
            Gate::AbortAt(kind) | Gate::AbortBatchAt(kind) => {
                if wire.is_some_and(|w| event_written(name, w) == Some(kind)) {
                    std::process::abort();
                }
                true
            }
        }
    }
}

impl DataStore for EventGate {
    fn insert(&self, name: Name, wire: Bytes) {
        if self.admits(&name, Some(&wire)) {
            self.inner.insert(name, wire);
        }
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn contains(&self, name: &Name) -> bool {
        self.inner.contains(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        if self.admits(name, None) {
            self.inner.remove(name);
        }
    }
    fn apply(&self, ops: Vec<StoreOp>) {
        if let Some(kept) = self.batches.lock().as_mut() {
            kept.push(ops.iter().map(|op| op_name(op).clone()).collect());
        }
        let gate = *self.gate.lock();
        match gate {
            Gate::Open => self.inner.apply(ops),
            Gate::Drop => self.inner.apply(
                ops.into_iter()
                    .filter(|op| !op_name(op).has_prefix(&events_namespace()))
                    .collect(),
            ),
            Gate::AbortBatchAt(kind) => {
                let held = ops.iter().any(|op| {
                    matches!(op, StoreOp::Insert(name, wire) if event_written(name, wire) == Some(kind))
                });
                if held {
                    std::process::abort();
                }
                self.inner.apply(ops);
            }
            // One by one, so that a stop in the middle leaves a prefix of the batch.
            Gate::AbortAt(_) => {
                for op in ops {
                    match op {
                        StoreOp::Insert(name, wire) => self.insert(name, wire),
                        StoreOp::Remove(name) => self.remove(&name),
                    }
                }
            }
        }
    }
    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn sync_is_immediate(&self) -> bool {
        self.inner.sync_is_immediate()
    }
}

/// Alice's laptop on `store`, its key the same in every run.
async fn laptop_on(store: &Arc<dyn DataStore>, tune: impl FnOnce(Config) -> Config) -> Device {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(n("/alice/laptop/KEY/1"), &[7; 32])
        .unwrap();
    on(&keys, store, tune).await
}

/// Alice's laptop on `store`, owning the plan and the budget.
async fn laptop_sharing(store: &Arc<dyn DataStore>, tune: impl FnOnce(Config) -> Config) -> Device {
    let dev = laptop_on(store, tune).await;
    for c in [plan(), budget()] {
        dev.share(&c, log_share()).await.unwrap();
    }
    dev
}

/// The record of Alice's phone that removes Bob from the plan.
fn phone_removes_bob(dev: &Device) -> Made {
    made(
        "/alice/phone",
        &plan(),
        1,
        Record::Members(removing_bob(dev, &plan())),
    )
}

/// Tell the device's events to a test the way the host sees them: the ids, in cursor order.
fn ids_of(dev: &Device) -> Vec<EventId> {
    dev.pending_events().iter().map(|e| e.id).collect()
}

/// Alice's laptop on `store`, its keyring also holding `contexts` (of other namespaces).
async fn laptop_also_holding(
    store: &Arc<dyn DataStore>,
    contexts: Vec<Arc<SignedTrustContext>>,
) -> Device {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
    }
    for ctx in contexts {
        validator.adopt_context(ctx).unwrap();
    }
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(n("/alice/laptop/KEY/1"), &[7; 32])
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n("/alice/laptop"),
        keys,
        validator,
        Arc::clone(store),
        Config::new(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn the_first_context_of_a_namespace_held_at_start_reports_no_revocation_of_its_own() {
    let dave = |version: u64, revoked: &[&str]| {
        let mut ctx = SignedTrustContext::hierarchical(n("/dave")).with_version(version);
        for r in revoked {
            ctx = ctx.with_revocation(n(r));
        }
        Arc::new(ctx)
    };
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let dev = laptop_on(&store, |c| c).await;
    dev.shutdown();
    drop(dev);
    // The host adopted a context of a namespace this device held none of, while it was off: its
    // revocation is no news, as a first context adopted while it ran is none.
    let dev = laptop_also_holding(&store, vec![dave(1, &["/dave/phone/KEY/1"])]).await;
    assert!(
        dev.pending_events().is_empty(),
        "the first context of /dave reports none of its own: {:?}",
        dev.pending_events()
    );
    dev.shutdown();
    drop(dev);
    // A later one that revokes one more reports that one, and not the first again.
    let dev = laptop_also_holding(
        &store,
        vec![dave(2, &["/dave/phone/KEY/1", "/dave/tab/KEY/1"])],
    )
    .await;
    let revoked: Vec<_> = of_kind(&dev, EventKind::Revocation)
        .into_iter()
        .map(|e| e.detail)
        .collect();
    assert_eq!(
        revoked,
        vec![EventDetail::Revocation {
            namespace: n("/dave"),
            revoked: n("/dave/tab/KEY/1"),
            version: 2,
        }],
        "a context adopted while the device was off, revoking one name more than the one it \
         held: that one is reported, at the next start"
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_cut_whose_record_is_held_and_whose_event_was_never_written_is_reported_after_a_restart()
{
    let backing: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let gate = EventGate::over(Arc::clone(&backing), Gate::Open);
    let store: Arc<dyn DataStore> = gate.clone();
    let dev = laptop_sharing(&store, |c| c).await;
    // The stop comes after the record was stored and before the event was.
    gate.set(Gate::Drop);
    let record = phone_removes_bob(&dev);
    give(&dev, &record);
    let told = of_kind(&dev, EventKind::Cut);
    assert_eq!(
        told.len(),
        1,
        "told while it ran: {:?}",
        dev.pending_events()
    );
    assert!(
        backing.get(&record.name).is_some(),
        "the record is stored: this is the state a kill leaves"
    );
    dev.shutdown();
    drop(dev);
    gate.set(Gate::Open);

    let dev = laptop_on(&store, |c| c).await;
    let cuts = of_kind(&dev, EventKind::Cut);
    assert_eq!(
        cuts.len(),
        1,
        "the record is held and no event was written for it: the restart reports the cut; \
         pending: {:?}",
        dev.pending_events()
    );
    assert_eq!(cuts[0].id, told[0].id, "the same evidence, the same id");
    assert_eq!(
        (cuts[0].count, cuts[0].subject()),
        (1, EventSubject::Writer(n("/bob")))
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_cut_event_is_not_reported_again_after_acknowledgement_whether_or_not_its_tombstone_is_kept()
 {
    for tombstones in [1024, 0] {
        let backing: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let gate = EventGate::over(Arc::clone(&backing), Gate::Open);
        let store: Arc<dyn DataStore> = gate.clone();
        let dev = laptop_sharing(&store, |c| Config {
            events_acked: tombstones,
            ..c
        })
        .await;
        give(&dev, &phone_removes_bob(&dev));
        let told = ids_of(&dev);
        assert_eq!(told.len(), 1);
        dev.shutdown();
        drop(dev);

        // Reported before the stop: once after the restart, not twice.
        let dev = laptop_on(&store, |c| Config {
            events_acked: tombstones,
            ..c
        })
        .await;
        assert_eq!(
            ids_of(&dev),
            told,
            "tombstones {tombstones}: an event reported before the stop is not derived again"
        );
        dev.acknowledge(&told).await.unwrap();
        dev.shutdown();
        drop(dev);

        let dev = laptop_on(&store, |c| Config {
            events_acked: tombstones,
            ..c
        })
        .await;
        assert!(
            dev.pending_events().is_empty(),
            "tombstones {tombstones}: acknowledged, and the record is held at every start: \
             not reported again: {:?}",
            dev.pending_events()
        );
        dev.shutdown();
    }
}

#[tokio::test]
async fn a_store_with_no_ledger_reports_what_it_holds_as_no_news_and_keeps_a_ledger_from_then_on() {
    let backing: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let gate = EventGate::over(Arc::clone(&backing), Gate::Open);
    let store: Arc<dyn DataStore> = gate.clone();
    let dev = laptop_sharing(&store, |c| c).await;
    gate.set(Gate::Drop);
    give(&dev, &phone_removes_bob(&dev));
    dev.shutdown();
    drop(dev);
    gate.set(Gate::Open);
    // An earlier revision's store has no ledger: what it holds is the baseline.
    for (name, _) in backing.scan_under(&events_namespace(), 0) {
        backing.remove(&name);
    }
    let dev = laptop_on(&store, |c| c).await;
    assert!(
        dev.pending_events().is_empty(),
        "a store with no ledger: the cut it holds is no news: {:?}",
        dev.pending_events()
    );
    dev.shutdown();
    drop(dev);
    let dev = laptop_on(&store, |c| c).await;
    assert!(
        dev.pending_events().is_empty(),
        "the baseline was entered in the ledger: {:?}",
        dev.pending_events()
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_members_record_and_the_events_of_its_cuts_reach_the_store_in_one_batch() {
    let backing: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let gate = EventGate::over(Arc::clone(&backing), Gate::Open);
    let store: Arc<dyn DataStore> = gate.clone();
    let dev = laptop_sharing(&store, |c| c).await;
    gate.keep_batches();
    let record = phone_removes_bob(&dev);
    give(&dev, &record);
    let batches = gate.batches();
    let batch = batches
        .iter()
        .find(|b| b.contains(&record.name))
        .unwrap_or_else(|| panic!("the record is written in a batch: {batches:?}"));
    assert!(
        batch.iter().any(|n| n.has_prefix(&n_events_e())),
        "the record of a cut and its event are one batch, so a store with atomic batches never \
         holds the record without it: {batch:?}"
    );
    assert!(
        batch.iter().any(|n| n.has_prefix(&n_events_l())),
        "and the ledger entry of the cut is in it: {batch:?}"
    );
    dev.shutdown();
}

fn n_events_e() -> Name {
    events_namespace().append("e")
}

fn n_events_l() -> Name {
    events_namespace().append("l")
}

// ---- the same, with a real process killed between them ---------------------------------------

/// The environment variable that makes the children of the kill cases run:
/// `<engine>|<directory>|<scenario>`.
pub(super) const KILL_ROLE: &str = "NDN_DATA_EVENTS_KILL";

pub(super) fn open_engine(engine: Engine, dir: &std::path::Path) -> Arc<dyn DataStore> {
    let live = engine.live(dir);
    match engine {
        Engine::Fjall => Arc::new(BackendStore::open_fjall(&live).unwrap()),
        Engine::Redb => Arc::new(BackendStore::open_redb(&live).unwrap()),
    }
}

/// The engine, directory and scenario a child was started for.
pub(super) fn role() -> Option<(Engine, std::path::PathBuf, String)> {
    let role = std::env::var(KILL_ROLE).ok()?;
    let mut parts = role.splitn(3, '|');
    let engine = match parts.next()? {
        "fjall" => Engine::Fjall,
        "redb" => Engine::Redb,
        other => panic!("{KILL_ROLE} names engine {other:?}; it is fjall or redb"),
    };
    let dir = std::path::PathBuf::from(parts.next()?);
    Some((engine, dir, parts.next()?.to_string()))
}

/// Run the test `path` (ignored: a child of a kill case) in a process of its own, for the
/// scenario `scenario` on `engine` in `dir`; how it ended. A child that does not end in two
/// minutes is killed and fails the case.
pub(super) fn run_child(
    path: &str,
    engine: Engine,
    dir: &std::path::Path,
    scenario: &str,
) -> std::process::ExitStatus {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            path,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            KILL_ROLE,
            format!("{}|{}|{scenario}", engine.label(), dir.display()),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let began = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if began.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            panic!(
                "the {} child of {path} ({scenario}) did not end in 120 s",
                engine.label()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One run of Alice's laptop in a process of its own, which a cut record's event ends
/// ([`Gate`]). Nothing when no case started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a child process of the kill cases; it runs only when they start it"]
async fn events_cut_kill_child() {
    let Some((engine, dir, scenario)) = role() else {
        return;
    };
    let gate = EventGate::over(open_engine(engine, &dir), Gate::Open);
    let store: Arc<dyn DataStore> = gate.clone();
    let dev = laptop_sharing(&store, |c| c).await;
    match scenario.as_str() {
        // The record is stored, and the process dies as its event is written.
        "cut" => gate.set(Gate::AbortAt(EventKind::Cut)),
        // The same, on a store whose batch is atomic: the record dies with its event.
        "cut-atomic" => gate.set(Gate::AbortBatchAt(EventKind::Cut)),
        // The event is written, and the process dies after it.
        "cut-reported" => {}
        other => panic!("{KILL_ROLE} names scenario {other:?}"),
    }
    give(&dev, &phone_removes_bob(&dev));
    if scenario == "cut-reported" {
        std::process::abort();
    }
    // Not reached: the gate stops the process in `give`.
    std::process::exit(0);
}

fn a_kill_around_the_event_of_a_cut_loses_none_and_repeats_none(engine: Engine) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let child = "device::events_tests::events_cut_kill_child";
    let record = log_name(&n("/alice/phone"), Some(&plan()), 1);

    // (a) Killed between the record stored and its event written: the event is there after the
    // restart, once; acknowledged, it does not come again, though no tombstone is kept.
    let dir = tempfile::tempdir().unwrap();
    let status = run_child(child, engine, dir.path(), "cut");
    assert!(
        !status.success(),
        "{}: the child was to be killed: {status:?}",
        engine.label()
    );
    rt.block_on(async {
        let store = open_engine(engine, dir.path());
        assert!(
            store.get(&record).is_some(),
            "{}: the record was stored before the kill",
            engine.label()
        );
        let tune = |c: Config| Config {
            events_acked: 0,
            ..c
        };
        let dev = laptop_on(&store, tune).await;
        let cuts = of_kind(&dev, EventKind::Cut);
        assert_eq!(
            cuts.len(),
            1,
            "{}: killed between a members record and the event of its cut: the cut is reported \
             after the restart; pending: {:?}",
            engine.label(),
            dev.pending_events()
        );
        let EventDetail::Cut {
            subject,
            of,
            signer,
            record: named,
            revision,
            ..
        } = &cuts[0].detail
        else {
            panic!("{:?}", cuts[0])
        };
        assert_eq!(
            (subject, of, signer, named, *revision),
            (&plan(), &n("/bob"), &key("/alice/phone"), &record, 2)
        );
        dev.acknowledge(&[cuts[0].id]).await.unwrap();
        dev.shutdown();
        drop(dev);
        let dev = laptop_on(&store, tune).await;
        assert!(
            dev.pending_events().is_empty(),
            "{}: acknowledged: not reported again at the next start: {:?}",
            engine.label(),
            dev.pending_events()
        );
        dev.shutdown();
    });

    // (d) Killed after the event was written: the cut is reported once, not twice.
    let dir = tempfile::tempdir().unwrap();
    let status = run_child(child, engine, dir.path(), "cut-reported");
    assert!(!status.success(), "{}: {status:?}", engine.label());
    rt.block_on(async {
        let store = open_engine(engine, dir.path());
        let dev = laptop_on(&store, |c| c).await;
        let cuts = of_kind(&dev, EventKind::Cut);
        assert_eq!(
            (
                cuts.len(),
                cuts.first().map(|e| e.count),
                dev.pending_events().len()
            ),
            (1, Some(1), 1),
            "{}: reported before the kill: once after the restart, not twice: {:?}",
            engine.label(),
            dev.pending_events()
        );
        dev.shutdown();
    });

    // A store whose batches are atomic holds the record and its event, or neither.
    let dir = tempfile::tempdir().unwrap();
    let status = run_child(child, engine, dir.path(), "cut-atomic");
    assert!(!status.success(), "{}: {status:?}", engine.label());
    rt.block_on(async {
        let store = open_engine(engine, dir.path());
        assert!(
            store.get(&record).is_none(),
            "{}: killed with the batch of the record and its event not yet written: the record is \
             not there without its event",
            engine.label()
        );
        let dev = laptop_on(&store, |c| c).await;
        assert!(
            dev.pending_events().is_empty(),
            "{:?}",
            dev.pending_events()
        );
        dev.shutdown();
    });
}

#[test]
fn a_kill_around_the_event_of_a_cut_loses_none_and_repeats_none_on_fjall() {
    a_kill_around_the_event_of_a_cut_loses_none_and_repeats_none(Engine::Fjall);
}

#[test]
fn a_kill_around_the_event_of_a_cut_loses_none_and_repeats_none_on_redb() {
    a_kill_around_the_event_of_a_cut_loses_none_and_repeats_none(Engine::Redb);
}

// ---- the quota of the book (spec §21.5) --------------------------------------------------------

fn entry_of(device: &str, digest: Option<[u8; 32]>) -> crate::events::EntryRef {
    crate::events::EntryRef {
        name: log_name(&n(device), Some(&plan()), 1),
        kind: Some(EntryKind::Version),
        digest,
    }
}

#[test]
fn a_flood_of_two_kinds_under_one_namespace_cannot_hide_a_cut_or_a_revocation() {
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let clock: Clock = Arc::new(|| Timestamp(1));
    let mut book = book_over(store, clock);
    // A collaborator who is her own authority mints keys without end under her own namespace.
    for i in 0..400 {
        let dev = format!("/carol/dev{i}");
        book.report(EventDetail::Equivocation {
            writer: key(&dev),
            seq: 1,
            first: entry_of(&dev, Some([1; 32])),
            second: entry_of(&dev, Some([2; 32])),
        });
        book.report(EventDetail::Withdrawal {
            writer: key(&dev),
            collection: Some(plan()),
            entry: entry_of(&dev, Some([1; 32])),
            by: WithdrawnBy::Cut {
                of: n("/carol"),
                signer: key("/alice/phone"),
            },
        });
    }
    // Honest events after it.
    book.report(EventDetail::Cut {
        subject: plan(),
        folder: false,
        of: n("/bob"),
        signer: key("/alice/phone"),
        record: log_name(&n("/alice/phone"), Some(&plan()), 1),
        revision: 2,
        kept: 0,
    });
    book.report(EventDetail::Revocation {
        namespace: n("/bob"),
        revoked: key("/bob/lost"),
        version: 2,
    });
    let pending = book.pending();
    let named = |k: EventKind| pending.iter().filter(|e| e.kind() == k).count();
    for k in [EventKind::Cut, EventKind::Revocation] {
        assert_eq!(
            named(k),
            1,
            "a later {k} event is named, not only counted in the overflow notice, whatever two \
             other kinds flooded; pending: {} events",
            pending.len()
        );
    }
    let carol = named(EventKind::Equivocation) + named(EventKind::Withdrawal);
    assert!(
        carol <= 64,
        "one namespace keeps at most a quarter of the cap: {carol}"
    );
    let dropped = pending.iter().find_map(|e| match &e.detail {
        EventDetail::Overflow { dropped } => Some(dropped.clone()),
        _ => None,
    });
    assert!(
        dropped.is_some_and(|d| d
            .iter()
            .all(|(k, _)| matches!(k, EventKind::Equivocation | EventKind::Withdrawal))),
        "only the flooded kinds are counted as not kept"
    );
}

/// A book of the default caps over `store`.
fn book_over(store: Arc<dyn DataStore>, clock: Clock) -> super::events::Book {
    super::events::Book::load(
        store,
        clock,
        256,
        1024,
        Arc::new(|name: &Name| {
            Name::from_components(
                name.components()
                    .iter()
                    .take(1)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        }),
    )
}
