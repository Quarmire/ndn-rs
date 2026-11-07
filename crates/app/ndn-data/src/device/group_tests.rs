//! Groups of versions (spec §5.5), counted all or none: by readers against
//! crafted packets, and by `put_group`.

use super::*;
use crate::layer::Share;
use ndn_app::AppError;
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

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn plan() -> Name {
    n("/alice/32=data/trip/plan")
}

fn budget() -> Name {
    n("/alice/32=data/trip/budget")
}

fn key(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

fn id(device: &str, seq: u64) -> VersionId {
    VersionId {
        writer: Writer::new(key(device)),
        seq: Seq(seq),
    }
}

fn log_share() -> Share {
    Share {
        rule: Rule::Log,
        writers: vec![n("/alice"), n("/bob"), n("/carol")],
        readers: Vec::new(),
    }
}

/// `/alice/laptop` on a forwarder that delivers nothing, owning `plan()`
/// and `budget()` as log collections Alice, Bob and Carol write.
async fn device() -> Device {
    device_with(MergeRules::standard(), log_share()).await
}

/// `/alice/laptop`, knowing `rules`, owning `plan()` and `budget()` shared
/// as `share` says.
async fn device_with(rules: MergeRules, share: Share) -> Device {
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        assert!(validator.adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns)))));
    }
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    let dev = Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        store,
        Config {
            rules,
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .unwrap();
    for c in [plan(), budget()] {
        dev.share(&c, share.clone()).await.unwrap();
    }
    dev
}

/// A log entry as fetched: its name, packet, signing key and record.
struct Made {
    name: Name,
    packet: Bytes,
    key: Name,
    record: Record,
}

/// Entry `seq` of `device` about `c` carrying `record`, signed (unchecked)
/// by the device's key.
fn made(device: &str, c: &Name, seq: u64, record: Record) -> Made {
    let name = log_name(&n(device), Some(c), seq);
    let key = key(device);
    let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&key),
        |_| Bytes::from_static(&[0; 64]),
    );
    Made {
        name,
        packet,
        key,
        record,
    }
}

/// Version `seq` of `device` in `c`, naming `parents`, of `group`.
fn version(
    device: &str,
    c: &Name,
    seq: u64,
    parents: &[(&str, u64)],
    group: Option<Group>,
) -> Made {
    let body = VersionBody {
        collection: c.clone(),
        parents: parents.iter().map(|(d, s)| id(d, *s)).collect(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group,
        fields: Content::new().with("t", format!("{device} {seq}")),
        op: Bytes::new(),
        sealed: None,
        chunks: None,
        block: None,
    };
    made(device, c, seq, Record::Version(body))
}

fn give(dev: &Device, m: &Made) {
    let mut st = dev.inner.st.lock();
    dev.inner.take(
        &mut st,
        m.name.clone(),
        m.packet.clone(),
        Writer::new(m.key.clone()),
        m.record.clone(),
        false,
    );
}

/// Whether `id` counts in `c` here: applied.
fn counts(dev: &Device, c: &Name, id: &VersionId) -> bool {
    let st = dev.inner.st.lock();
    st.colls[c].at().contains(id) && st.colls[c].versions.contains_key(id)
}

fn refusal(dev: &Device, name: &Name) -> Option<Refusal> {
    dev.inner.st.lock().refused.get(name).cloned()
}

fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// Every change the watch has delivered so far.
async fn drain(changes: &mut Changes) -> Vec<Change> {
    use futures::StreamExt;
    let mut out = Vec::new();
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(100), changes.next()).await
    {
        out.push(change);
    }
    out
}

const PAIR: Group = Group { id: 10, count: 2 };

#[tokio::test]
async fn a_group_counts_all_or_none_in_either_arrival_order() {
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    let b = version("/bob/laptop", &budget(), 11, &[], Some(PAIR));
    for order in [[&a, &b], [&b, &a]] {
        let dev = device().await;
        let mut changes = dev
            .watch(&n("/alice/32=data/trip"), &Frontier::new())
            .await
            .unwrap();
        give(&dev, order[0]);
        let (first, first_c) = match order[0].name == a.name {
            true => (id("/bob/laptop", 10), plan()),
            false => (id("/bob/laptop", 11), budget()),
        };
        assert!(!counts(&dev, &first_c, &first), "half a group never counts");
        let seen = drain(&mut changes).await;
        assert!(
            !seen
                .iter()
                .any(|c| matches!(c, Change::Version(v) if v.id == first)),
            "nor is it shown"
        );
        assert!(
            seen.iter()
                .any(|c| matches!(c, Change::NotCounted { id, .. } if *id == first))
        );
        // A later version naming the waiting member waits too.
        let after = version(
            "/carol/laptop",
            &first_c,
            5,
            &[("/bob/laptop", first.seq.0)],
            None,
        );
        give(&dev, &after);
        assert!(!counts(&dev, &first_c, &id("/carol/laptop", 5)));
        give(&dev, order[1]);
        assert!(counts(&dev, &plan(), &id("/bob/laptop", 10)));
        assert!(counts(&dev, &budget(), &id("/bob/laptop", 11)));
        assert!(counts(&dev, &first_c, &id("/carol/laptop", 5)));
        let seen = drain(&mut changes).await;
        assert!(
            seen.iter()
                .any(|c| matches!(c, Change::Counted { id } if *id == first))
        );
        dev.shutdown();
    }
}

#[tokio::test]
async fn a_cut_refusing_one_member_withdraws_the_whole_group_and_spares_others_work() {
    let dev = device().await;
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    let b = version("/bob/laptop", &budget(), 11, &[], Some(PAIR));
    // Carol writes over Bob's member of the plan.
    let over = version("/carol/laptop", &plan(), 5, &[("/bob/laptop", 10)], None);
    for m in [&a, &b, &over] {
        give(&dev, m);
    }
    assert!(counts(&dev, &plan(), &id("/bob/laptop", 10)));
    assert!(counts(&dev, &plan(), &id("/carol/laptop", 5)));
    let mut changes = dev
        .watch(&n("/alice/32=data/trip"), &Frontier::new())
        .await
        .unwrap();
    drain(&mut changes).await;
    // The owner's phone removes Bob from the budget, accepting nothing of
    // his there: his member of the budget is refused.
    let first = dev.inner.st.lock().colls[&budget()]
        .members
        .clone()
        .unwrap();
    let removes = MembersBody {
        collection: budget(),
        folder: false,
        revision: 2,
        rule: Rule::Log,
        writers: vec![n("/alice"), n("/carol")],
        readers: Vec::new(),
        cuts: vec![CutBody {
            of: n("/bob"),
            accept: Accepted::new(),
        }],
        epoch: None,
        key_check: None,
        since: None,
        parent: Some(first.as_parent()),
    };
    give(
        &dev,
        &made("/alice/phone", &budget(), 1, Record::Members(removes)),
    );
    assert!(matches!(
        refusal(&dev, &b.name),
        Some(Refusal::OutsideCut(_))
    ));
    assert!(
        matches!(refusal(&dev, &a.name), Some(Refusal::Group { member, .. }) if member == b.name),
        "the plan's member is refused for its group: {:?}",
        refusal(&dev, &a.name)
    );
    assert!(!counts(&dev, &plan(), &id("/bob/laptop", 10)));
    assert!(
        counts(&dev, &plan(), &id("/carol/laptop", 5)),
        "a version by another writer over a withdrawn member stays counted"
    );
    let seen = drain(&mut changes).await;
    assert!(seen.iter().any(|c| matches!(
        c,
        Change::Withdrawn { id, why: Refusal::Group { .. } } if *id == id_of(&a)
    )));
    assert!(matches!(
        dev.get(&a.name).await,
        Err(DataError::Refused {
            why: Refusal::Group { .. },
            ..
        })
    ));
    dev.shutdown();
}

/// Version `seq` of `device` in merge collection `c`, naming `parents`, of
/// `group`, carrying `op`.
fn op_version(
    device: &str,
    c: &Name,
    seq: u64,
    parents: &[(&str, u64)],
    group: Option<Group>,
    op: Bytes,
) -> Made {
    let Record::Version(mut body) = version(device, c, seq, parents, group).record else {
        unreachable!("a version")
    };
    body.fields = Content::new();
    body.op = op;
    made(device, c, seq, Record::Version(body))
}

#[tokio::test]
async fn an_edit_made_over_a_withdrawn_member_by_its_digest_stays_counted() {
    use super::merge_tests::{RULE, edit, rules};
    let dev = device_with(
        rules(),
        Share {
            rule: Rule::Merge { function: n(RULE) },
            ..log_share()
        },
    )
    .await;
    let a = op_version("/bob/laptop", &plan(), 10, &[], Some(PAIR), edit(None, "a"));
    let b = op_version(
        "/bob/laptop",
        &budget(),
        11,
        &[],
        Some(PAIR),
        edit(None, "b"),
    );
    // Carol's edit names Bob's member of the plan as its basis, by digest.
    let basis = wire::implicit_digest(&a.packet);
    let over = op_version(
        "/carol/laptop",
        &plan(),
        5,
        &[("/bob/laptop", 10)],
        None,
        edit(Some(basis), "c"),
    );
    for m in [&a, &b, &over] {
        give(&dev, m);
    }
    assert!(counts(&dev, &plan(), &id("/carol/laptop", 5)));
    let first = dev.inner.st.lock().colls[&budget()]
        .members
        .clone()
        .unwrap();
    let removes = MembersBody {
        collection: budget(),
        folder: false,
        revision: 2,
        rule: Rule::Merge { function: n(RULE) },
        writers: vec![n("/alice"), n("/carol")],
        readers: Vec::new(),
        cuts: vec![CutBody {
            of: n("/bob"),
            accept: Accepted::new(),
        }],
        epoch: None,
        key_check: None,
        since: None,
        parent: Some(first.as_parent()),
    };
    give(
        &dev,
        &made("/alice/phone", &budget(), 1, Record::Members(removes)),
    );
    assert!(!counts(&dev, &plan(), &id("/bob/laptop", 10)), "withdrawn");
    assert!(
        counts(&dev, &plan(), &id("/carol/laptop", 5)),
        "an edit made over a withdrawn member stays counted: its basis is what it was made over"
    );
    dev.shutdown();
}

fn id_of(m: &Made) -> VersionId {
    VersionId {
        writer: Writer::new(m.key.clone()),
        seq: Seq(parse_log_name(&m.name).unwrap().seq),
    }
}

#[tokio::test]
async fn a_malformed_group_is_refused_on_every_member_whatever_the_order() {
    let other = n("/alice/32=data/home/list");
    let cases: Vec<(&str, Vec<Made>)> = vec![
        (
            "members in collections of different folders",
            vec![
                version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
                version("/bob/laptop", &other, 11, &[], Some(PAIR)),
            ],
        ),
        (
            "members disagreeing on the count",
            vec![
                version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
                version(
                    "/bob/laptop",
                    &budget(),
                    11,
                    &[],
                    Some(Group { id: 10, count: 3 }),
                ),
            ],
        ),
        (
            "a member's seq outside the group",
            vec![
                version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
                version("/bob/laptop", &budget(), 12, &[], Some(PAIR)),
            ],
        ),
    ];
    for (what, members) in cases {
        for reverse in [false, true] {
            let dev = device().await;
            dev.share(&other, log_share()).await.unwrap();
            let mut order: Vec<&Made> = members.iter().collect();
            if reverse {
                order.reverse();
            }
            for m in &order {
                give(&dev, m);
            }
            for m in &members {
                assert!(
                    matches!(refusal(&dev, &m.name), Some(Refusal::Group { .. })),
                    "{what}: {} refused, not {:?}",
                    m.name,
                    refusal(&dev, &m.name)
                );
            }
            // Its writer's later version does not wait for it.
            let later = version("/bob/laptop", &plan(), 13, &[("/bob/laptop", 10)], None);
            give(&dev, &later);
            assert!(counts(&dev, &plan(), &id("/bob/laptop", 13)), "{what}");
            dev.shutdown();
        }
    }
}

#[tokio::test]
async fn a_concurrent_narrowing_of_one_members_collection_leaves_the_verdict() {
    let dev = device().await;
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    let b = version("/bob/laptop", &budget(), 11, &[], Some(PAIR));
    give(&dev, &a);
    let key = (Writer::new(key("/bob/laptop")), 10);
    let before = dev.inner.st.lock().verdict(&key);
    // The phone narrows the budget's writers, removing Carol, who wrote
    // nothing: Bob's member is as admitted as before.
    let first = dev.inner.st.lock().colls[&budget()]
        .members
        .clone()
        .unwrap();
    let narrows = MembersBody {
        collection: budget(),
        folder: false,
        revision: 2,
        rule: Rule::Log,
        writers: vec![n("/alice"), n("/bob")],
        readers: Vec::new(),
        cuts: vec![CutBody {
            of: n("/carol"),
            accept: Accepted::new(),
        }],
        epoch: None,
        key_check: None,
        since: None,
        parent: Some(first.as_parent()),
    };
    give(
        &dev,
        &made("/alice/phone", &budget(), 1, Record::Members(narrows)),
    );
    assert_eq!(dev.inner.st.lock().verdict(&key), before);
    give(&dev, &b);
    assert!(counts(&dev, &plan(), &id("/bob/laptop", 10)));
    assert!(counts(&dev, &budget(), &id("/bob/laptop", 11)));
    dev.shutdown();
}

/// Bob's version `seq` of merge collection `c`, sealed under `key` in its
/// epoch, naming `parents`, of `group`, carrying a Yjs update of his.
fn sealed_edit(
    c: &Name,
    (epoch, ck): &(Epoch, ContentKey),
    seq: u64,
    parents: &[(&str, u64)],
    group: Option<Group>,
) -> Made {
    let bob = Writer::new(key("/bob/laptop"));
    let op = crate::merge::Yrs::new()
        .start(&bob)
        .edit(&Content::new().with(format!("f{seq}"), "v"))
        .unwrap();
    let name = log_name(&n("/bob/laptop"), Some(c), seq);
    let body = VersionBody {
        collection: c.clone(),
        parents: parents.iter().map(|(d, s)| id(d, *s)).collect(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal {
            any_of: vec![Audience::Person(n("/alice")), Audience::Person(n("/bob"))],
        },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group,
        fields: Content::new(),
        op: Bytes::new(),
        sealed: Some(SealedBody {
            epoch: epoch.clone(),
            ciphertext: seal::seal_payload(ck, &name, &Content::new(), &op),
        }),
        chunks: None,
        block: None,
    };
    made("/bob/laptop", c, seq, Record::Version(body))
}

#[tokio::test]
async fn a_sealed_merge_group_counts_all_or_none_in_any_order() {
    let board = |x: &str| n(&format!("/alice/32=data/board/{x}"));
    let share = |readers: &[&str]| Share {
        rule: Rule::Merge {
            function: n("/merge/yrs"),
        },
        writers: vec![n("/alice"), n("/bob")],
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
    };
    let orders: [[usize; 5]; 4] = [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [3, 0, 1, 2, 4],
        [4, 2, 1, 0, 3],
    ];
    for order in orders {
        let dev = device().await;
        for x in ["a", "b", "c"] {
            dev.share(&board(x), share(&["/alice", "/bob"]))
                .await
                .unwrap();
        }
        dev.share(&board("b"), share(&["/alice"])).await.unwrap();
        let key_of = |c: &Name| {
            let st = dev.inner.st.lock();
            let e = st.colls[c].members.as_ref().unwrap().epoch.clone().unwrap();
            let k = st.keys.key(c, &e).unwrap();
            (e, k)
        };
        let (ka, kc) = (key_of(&board("a")), key_of(&board("c")));
        let g = Group { id: 12, count: 2 };
        let versions = [
            sealed_edit(&board("a"), &ka, 9, &[], None),
            sealed_edit(&board("c"), &kc, 11, &[], None),
            sealed_edit(&board("a"), &ka, 12, &[("/bob/laptop", 9)], Some(g)),
            sealed_edit(&board("c"), &kc, 13, &[("/bob/laptop", 11)], Some(g)),
            sealed_edit(&board("a"), &ka, 14, &[("/bob/laptop", 12)], None),
        ];
        for i in order {
            give(&dev, &versions[i]);
            let (a, c) = (
                counts(&dev, &board("a"), &id("/bob/laptop", 12)),
                counts(&dev, &board("c"), &id("/bob/laptop", 13)),
            );
            assert_eq!(a, c, "{order:?}: after {i}, all or none");
        }
        assert!(
            counts(&dev, &board("a"), &id("/bob/laptop", 12)),
            "{order:?}"
        );
        assert!(
            counts(&dev, &board("a"), &id("/bob/laptop", 14)),
            "{order:?}"
        );
        dev.shutdown();
    }
}

/// A `put_group` the device refuses: what is wrong, the items, the options.
type Case = (&'static str, Vec<(Name, Edit)>, PutOptions);

#[tokio::test]
async fn put_group_writes_all_or_nothing() {
    let dev = device().await;
    let notes = n("/alice/32=data/trip/notes");
    let fields = |t: &str| Edit::Fields(Content::new().with("t", t.to_owned()));
    let written = |dev: &Device| {
        let st = dev.inner.st.lock();
        (st.head, st.held.len())
    };
    let before = written(&dev);
    let refused: Vec<Case> = vec![
        ("no items", Vec::new(), options()),
        (
            "a collection twice",
            vec![(plan(), fields("a")), (plan(), fields("b"))],
            options(),
        ),
        (
            "collections of different folders",
            vec![
                (plan(), fields("a")),
                (n("/alice/32=data/home/list"), fields("b")),
            ],
            options(),
        ),
        (
            "batch set",
            vec![(plan(), fields("a")), (budget(), fields("b"))],
            PutOptions {
                batch: Some(Duration::from_secs(1)),
                ..options()
            },
        ),
        (
            "an operation into a log collection",
            vec![
                (plan(), fields("a")),
                (budget(), Edit::Op(Bytes::from_static(b"x"))),
            ],
            options(),
        ),
        (
            // Collections of this namespace with no record: merged by
            // `/merge/yrs`, whose check refuses what is no Yjs update.
            "an operation its rule refuses",
            vec![
                (notes.clone(), fields("a")),
                (
                    n("/alice/32=data/trip/journal"),
                    Edit::Op(Bytes::from_static(b"x")),
                ),
            ],
            options(),
        ),
    ];
    for (what, items, options) in refused {
        let got = dev.put_group(items, options).await;
        assert!(got.is_err(), "{what}: {got:?}");
        assert_eq!(written(&dev), before, "{what}: nothing written");
    }
    // Readers that differ: one collection narrowed to Alice.
    dev.share(
        &budget(),
        Share {
            readers: vec![Audience::Person(n("/alice"))],
            ..log_share()
        },
    )
    .await
    .unwrap();
    let before = written(&dev);
    let got = dev
        .put_group(
            vec![(plan(), fields("a")), (budget(), fields("b"))],
            options(),
        )
        .await;
    assert!(matches!(got, Err(DataError::BadRequest { .. })), "{got:?}");
    assert_eq!(written(&dev), before, "readers differ: nothing written");
    // Alike, a group is written at consecutive seqs and counted at once —
    // in fresh collections too, their records signed first.
    for items in [
        vec![
            (plan(), fields("a")),
            (n("/alice/32=data/trip/log"), fields("b")),
        ],
        vec![
            (notes.clone(), fields("n")),
            (n("/alice/32=data/trip/journal"), fields("j")),
        ],
    ] {
        if items[0].0 == plan() {
            dev.share(&items[1].0, log_share()).await.unwrap();
        }
        let names: Vec<Name> = items.iter().map(|(c, _)| c.clone()).collect();
        let ids = dev.put_group(items, options()).await.unwrap();
        assert_eq!(ids[1].seq.0, ids[0].seq.0 + 1);
        let st = dev.inner.st.lock();
        for (c, id) in names.iter().zip(&ids) {
            let v = &st.colls[c].versions[id].version;
            assert_eq!(
                v.group,
                Some(Group {
                    id: ids[0].seq.0,
                    count: 2
                })
            );
            assert!(st.colls[c].at().contains(id), "counted at once");
        }
    }
    dev.shutdown();
}
