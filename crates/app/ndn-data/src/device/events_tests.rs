//! Device-wide events (spec §21): equivocation of any two entries of a key at one seq (a members
//! record against a version included), withdrawals and cuts told with no watcher, delivery at
//! least once across a restart and acknowledgement, and floods bounded without losing the first
//! of each kind per subject. Revocation is in the `tests` module of `device.rs`, beside the
//! harness that adopts trust contexts.

use futures::StreamExt;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

use super::group_tests::{
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
    let seen = super::group_tests::drain(&mut changes).await;
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
        events_unacked: 4,
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
        "a kind keeps at most half of the cap of 4: {eq:?}"
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
    let seen = super::group_tests::drain(&mut changes).await;
    assert!(
        seen.iter().any(|c| matches!(c, Change::Equivocation { first, .. } if first.id() == &id("/carol/dev19", 7))),
        "an equivocation whose event was not kept is still listed by a watch"
    );
    dev.shutdown();
}
