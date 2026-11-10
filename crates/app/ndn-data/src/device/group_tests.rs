//! Groups of versions (spec §5.5), counted all or none: by readers against
//! crafted packets, and by `put_group`.

use super::*;
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A forwarder that never delivers anything: the test hands the device the
/// packets it would have fetched.
pub(super) struct Unconnected;

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

pub(super) fn n(s: &str) -> Name {
    s.parse().unwrap()
}

pub(super) fn plan() -> Name {
    n("/alice/32=data/trip/plan")
}

pub(super) fn budget() -> Name {
    n("/alice/32=data/trip/budget")
}

pub(super) fn key(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

pub(super) fn id(device: &str, seq: u64) -> VersionId {
    VersionId {
        writer: Writer::new(key(device)),
        seq: Seq(seq),
    }
}

pub(super) fn log_share() -> Share {
    Share {
        rule: Rule::Log,
        writers: vec![n("/alice"), n("/bob"), n("/carol")],
        readers: Vec::new(),
    }
}

/// `/alice/laptop` on a forwarder that delivers nothing, owning `plan()`
/// and `budget()` as log collections Alice, Bob and Carol write.
pub(super) async fn device() -> Device {
    device_with(MergeRules::standard(), log_share()).await
}

/// `/alice/laptop`, knowing `rules`, owning `plan()` and `budget()` shared
/// as `share` says.
pub(super) async fn device_with(rules: MergeRules, share: Share) -> Device {
    device_tuned(share, |c| Config { rules, ..c }).await
}

/// `/alice/laptop`, its configuration as `tune` makes it, owning `plan()`
/// and `budget()` shared as `share` says.
pub(super) async fn device_tuned(share: Share, tune: impl FnOnce(Config) -> Config) -> Device {
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
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
        tune(Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        }),
    )
    .await
    .unwrap();
    for c in [plan(), budget()] {
        dev.share(&c, share.clone()).await.unwrap();
    }
    dev
}

/// A log entry as fetched: its name, packet, signing key and record.
pub(super) struct Made {
    pub(super) name: Name,
    pub(super) packet: Bytes,
    pub(super) key: Name,
    pub(super) record: Record,
}

/// Entry `seq` of `device` about `c` carrying `record`, signed (unchecked)
/// by the device's key.
pub(super) fn made(device: &str, c: &Name, seq: u64, record: Record) -> Made {
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

/// A parent: the version `m` and the implicit digest of its packet.
fn tip(m: &Made) -> (VersionId, Option<[u8; 32]>) {
    let seq = parse_log_name(&m.name).expect("a log entry").seq;
    let id = VersionId {
        writer: Writer::new(m.key.clone()),
        seq: Seq(seq),
    };
    (id, Some(wire::implicit_digest(&m.packet)))
}

/// Version `seq` of `device` in `c`, naming `parents`, of `group`.
pub(super) fn version(
    device: &str,
    c: &Name,
    seq: u64,
    parents: &[(&str, u64)],
    group: Option<Group>,
) -> Made {
    let body = VersionBody {
        collection: c.clone(),
        parents: parents.iter().map(|(d, s)| (id(d, *s), None)).collect(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group,
        rule: None,
        fields: Content::new().with("t", format!("{device} {seq}")),
        op: Bytes::new(),
        sealed: None,
        chunks: None,
        block: None,
    };
    made(device, c, seq, Record::Version(body))
}

pub(super) fn give(dev: &Device, m: &Made) {
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
pub(super) fn counts(dev: &Device, c: &Name, id: &VersionId) -> bool {
    let st = dev.inner.st.lock();
    st.colls[c].at().contains(id) && st.colls[c].versions.contains_key(id)
}

pub(super) fn refusal(dev: &Device, name: &Name) -> Option<Refusal> {
    dev.inner.st.lock().refused.get(name).cloned()
}

pub(super) fn options() -> PutOptions {
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
pub(super) async fn drain(changes: &mut Changes) -> Vec<Change> {
    use futures::StreamExt;
    let mut out = Vec::new();
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(100), changes.next()).await
    {
        out.push(change);
    }
    out
}

pub(super) const PAIR: Group = Group { id: 10, count: 2 };

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
                .any(|c| matches!(c, Change::Counted { collection, id } if *id == first && *collection == first_c))
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
        Change::Withdrawn { collection, id, why: Refusal::Group { .. } } if *id == id_of(&a) && *collection == plan()
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

/// Version `seq` of `device` in merge collection `c` (under the merge
/// tests' rule), naming `parents`, of `group`, carrying `op`.
fn op_version(
    device: &str,
    c: &Name,
    seq: u64,
    parents: &[&Made],
    group: Option<Group>,
    op: Bytes,
) -> Made {
    let Record::Version(mut body) = version(device, c, seq, &[], group).record else {
        unreachable!("a version")
    };
    body.parents = parents.iter().map(|m| tip(m)).collect();
    body.rule = Some(n(super::merge_tests::RULE));
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
        &[&a],
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

/// The state of merge collection `c` at `dev`.
async fn state_of(dev: &Device, c: &Name) -> State {
    match dev.get(c).await.unwrap().got {
        Got::State(s) => s,
        other => panic!("not a state: {other:?}"),
    }
}

/// Why `s` holds `id` without counting it, if it does.
fn why_not<'s>(s: &'s State, id: &VersionId) -> Option<&'s NotCounted> {
    s.not_counted
        .iter()
        .find(|(v, _)| v == id)
        .map(|(_, why)| why)
}

/// A group counts only while every member counts (spec §5.5): a member its
/// rule does not count holds every other member back — applied, not
/// counted with a reason naming that member and carrying its rule's reason,
/// out of the value — and once it counts, the whole group counts.
#[tokio::test]
async fn a_member_its_rule_does_not_count_holds_its_whole_group_back() {
    use super::merge_tests::{RULE, edit, hold, notes, pair, rules};
    let dev = device_with(
        rules(),
        Share {
            rule: Rule::Merge { function: n(RULE) },
            ..log_share()
        },
    )
    .await;
    let mut changes = dev
        .watch(&n("/alice/32=data/trip"), &Frontier::new())
        .await
        .unwrap();
    let held = op_version("/bob/laptop", &plan(), 10, &[], Some(PAIR), hold("w"));
    let other = op_version(
        "/bob/laptop",
        &budget(),
        11,
        &[],
        Some(PAIR),
        edit(None, "b"),
    );
    give(&dev, &held);
    give(&dev, &other);
    let (held_id, other_id) = (id_of(&held), id_of(&other));
    let (plan_state, budget_state) = (
        state_of(&dev, &plan()).await,
        state_of(&dev, &budget()).await,
    );
    let own = why_not(&plan_state, &held_id).expect("its rule does not count it");
    let waits = why_not(&budget_state, &other_id).expect("held back by its group");
    assert!(
        matches!(own, NotCounted::Excluded(_)) && matches!(waits, NotCounted::Excluded(_)),
        "a rule's exclusion, and the group held back by it, are exclusions: {own:?} {waits:?}"
    );
    let (own, waits) = (own.to_string(), waits.to_string());
    assert!(
        waits.contains(&held.name.to_string()) && waits.contains(&own),
        "the reason names the member it waits on, with that member's reason: {waits:?}"
    );
    assert!(budget_state.at.contains(&other_id), "applied");
    assert!(!notes(&budget_state).contains(&"b".to_owned()), "not shown");
    let seen = drain(&mut changes).await;
    assert!(seen.iter().any(
        |c| matches!(c, Change::NotCounted { id, why, .. } if *id == other_id && *why == NotCounted::Excluded(waits.clone()))
    ));
    assert!(
        !seen
            .iter()
            .any(|c| matches!(c, Change::Counted { id, .. } if *id == other_id)),
        "never told counted while held back"
    );
    // The held member's pair arrives: it counts, and so does its group.
    let p = op_version("/carol/laptop", &plan(), 5, &[], None, pair("w"));
    give(&dev, &p);
    let (plan_state, budget_state) = (
        state_of(&dev, &plan()).await,
        state_of(&dev, &budget()).await,
    );
    assert!(plan_state.not_counted.is_empty() && budget_state.not_counted.is_empty());
    assert!(notes(&plan_state).contains(&"w".to_owned()));
    assert!(notes(&budget_state).contains(&"b".to_owned()));
    let seen = drain(&mut changes).await;
    for id in [&held_id, &other_id] {
        assert!(
            seen.iter()
                .any(|c| matches!(c, Change::Counted { id: v, .. } if v == id)),
            "{id:?} told counted: {seen:?}"
        );
    }
    dev.shutdown();
}

/// A group member still arriving is the layer's own wait ([`NotCounted::Waits`]):
/// it ends, and `Counted` follows; a rule's exclusion is [`NotCounted::Excluded`]
/// and does not end by waiting. A version whose reason moves from one to the
/// other is told again.
#[tokio::test]
async fn a_group_member_still_arriving_waits_and_a_rule_exclusion_is_excluded() {
    use super::merge_tests::{RULE, edit, hold, notes, pair, rules};
    let dev = device_with(
        rules(),
        Share {
            rule: Rule::Merge { function: n(RULE) },
            ..log_share()
        },
    )
    .await;
    let mut changes = dev
        .watch(&n("/alice/32=data/trip"), &Frontier::new())
        .await
        .unwrap();
    // One member of a pair, its partner still arriving.
    let first = op_version("/bob/laptop", &plan(), 10, &[], Some(PAIR), edit(None, "a"));
    give(&dev, &first);
    let first_id = id_of(&first);
    let seen = drain(&mut changes).await;
    let told = seen.iter().find_map(|c| match c {
        Change::NotCounted { id, why, .. } if *id == first_id => Some(why.clone()),
        _ => None,
    });
    assert_eq!(
        told,
        Some(NotCounted::Waits("group incomplete: 1 of 2".into())),
        "a group still arriving is a wait: {seen:?}"
    );
    assert_eq!(told.unwrap().to_string(), "group incomplete: 1 of 2");
    // The partner arrives, and the wait ends: counted.
    let second = op_version(
        "/bob/laptop",
        &budget(),
        11,
        &[],
        Some(PAIR),
        edit(None, "b"),
    );
    give(&dev, &second);
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter()
            .any(|c| matches!(c, Change::Counted { id, .. } if *id == first_id)),
        "the wait that ends is told counted: {seen:?}"
    );
    assert!(state_of(&dev, &plan()).await.not_counted.is_empty());
    // A rule's exclusion, alone in no group: an exclusion, in the change and
    // in the state.
    let held = op_version("/carol/laptop", &plan(), 5, &[], None, hold("w"));
    give(&dev, &held);
    let held_id = id_of(&held);
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter().any(|c| matches!(
            c,
            Change::NotCounted { id, why: NotCounted::Excluded(_), .. } if *id == held_id
        )),
        "a rule's exclusion is excluded: {seen:?}"
    );
    let state = state_of(&dev, &plan()).await;
    assert!(matches!(
        why_not(&state, &held_id),
        Some(NotCounted::Excluded(_))
    ));
    assert!(!notes(&state).contains(&"w".to_owned()));
    // Its pair arrives: counted.
    let p = op_version("/bob/laptop", &plan(), 12, &[], None, pair("w"));
    give(&dev, &p);
    assert!(state_of(&dev, &plan()).await.not_counted.is_empty());
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
    parents: &[&Made],
    group: Option<Group>,
) -> Made {
    let bob = Writer::new(key("/bob/laptop"));
    let op = crate::merge::Yrs::new()
        .start(c, &bob)
        .edit(&Content::new().with(format!("f{seq}"), "v"))
        .unwrap();
    let name = log_name(&n("/bob/laptop"), Some(c), seq);
    let body = VersionBody {
        collection: c.clone(),
        parents: parents.iter().map(|m| tip(m)).collect(),
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
        rule: Some(n("/merge/yrs")),
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
        let v9 = sealed_edit(&board("a"), &ka, 9, &[], None);
        let v11 = sealed_edit(&board("c"), &kc, 11, &[], None);
        let v12 = sealed_edit(&board("a"), &ka, 12, &[&v9], Some(g));
        let v13 = sealed_edit(&board("c"), &kc, 13, &[&v11], Some(g));
        let v14 = sealed_edit(&board("a"), &ka, 14, &[&v12], None);
        let versions = [v9, v11, v12, v13, v14];
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

/// The collections of Alice's board folder, merged by `/merge/yrs`, which
/// Alice and Bob write (and Carol too, with `carol`).
fn board(x: &str) -> Name {
    n(&format!("/alice/32=data/board/{x}"))
}

fn board_share(carol: bool) -> Share {
    let mut writers = vec![n("/alice"), n("/bob")];
    if carol {
        writers.push(n("/carol"));
    }
    Share {
        rule: Rule::Merge {
            function: n("/merge/yrs"),
        },
        writers,
        readers: Vec::new(),
    }
}

/// A Yjs update by `device`, the first of its in `c`, setting field `t` to
/// text that makes the update exactly `len` octets.
fn yrs_op(c: &Name, device: &str, len: usize) -> Bytes {
    let w = Writer::new(key(device));
    let make = |text: usize| {
        crate::merge::Yrs::new()
            .start(c, &w)
            .edit(&Content::new().with("t", "p".repeat(text)))
            .unwrap()
    };
    let mut text = len;
    for _ in 0..8 {
        let op = make(text);
        if op.len() == len {
            return op;
        }
        text = (text + len).checked_sub(op.len()).expect("a shorter text");
    }
    panic!("no update of {len} octets");
}

/// Bob's version `seq` of `c` under `/merge/yrs`, of `group`, carrying `op`:
/// in pieces, returned with it, when its payload is over `INLINE_MAX`.
fn yrs_version(c: &Name, seq: u64, group: Group, op: Bytes) -> (Made, Vec<pieces::Piece>) {
    let name = log_name(&n("/bob/laptop"), Some(c), seq);
    let mut body = VersionBody {
        collection: c.clone(),
        parents: Parents::new(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group: Some(group),
        rule: Some(n("/merge/yrs")),
        fields: Content::new(),
        op: Bytes::new(),
        sealed: None,
        chunks: None,
        block: None,
    };
    let payload = wire::encode_payload(&Content::new(), &op);
    let pieces = if payload.len() > wire::INLINE_MAX {
        let (pieces, chunks) = pieces::split(&name, &payload);
        body.chunks = Some(chunks);
        pieces
    } else {
        body.op = op;
        Vec::new()
    };
    (made("/bob/laptop", c, seq, Record::Version(body)), pieces)
}

/// How many of `ids`, members of `c` in order, count here.
fn counted(dev: &Device, cs: &[Name], ids: &[VersionId]) -> usize {
    cs.iter()
        .zip(ids)
        .filter(|(c, id)| counts(dev, c, id))
        .count()
}

/// ndf's report (REPLY-13 §8): a group whose member's operation travels in
/// pieces never counted on a device that did not have that member open — the
/// member, pending and unopened, was judged missing though every piece was
/// held, so its group stayed incomplete and nothing opened it.
#[tokio::test]
async fn a_group_whose_member_travels_in_pieces_counts_whole() {
    let cs = [board("a"), board("b"), board("c")];
    let g = Group { id: 10, count: 3 };
    let (a, _) = yrs_version(&cs[0], 10, g, yrs_op(&cs[0], "/bob/laptop", 64));
    let (b, pieces) = yrs_version(&cs[1], 11, g, yrs_op(&cs[1], "/bob/laptop", 37_847));
    let (c, _) = yrs_version(&cs[2], 12, g, yrs_op(&cs[2], "/bob/laptop", 64));
    assert!(
        !pieces.is_empty(),
        "the 37,847-octet member travels in pieces"
    );
    let ids = [10, 11, 12].map(|s| id("/bob/laptop", s));
    let dev = device().await;
    for x in &cs {
        dev.share(x, board_share(false)).await.unwrap();
    }
    for m in [&a, &b, &c] {
        give(&dev, m);
    }
    assert_eq!(
        counted(&dev, &cs, &ids),
        0,
        "its pieces not held: none counts"
    );
    for p in &pieces {
        dev.inner.store.insert(p.name.clone(), p.wire.clone());
    }
    dev.inner.st.lock().pieces_arrived(&cs[1], &b.name);
    assert_eq!(
        counted(&dev, &cs, &ids),
        3,
        "every piece held: the group counts whole"
    );
    dev.shutdown();
}

/// The writer's own device, after a members record makes it read each
/// collection again (its applied operation in pieces let go from memory),
/// still counts all three.
#[tokio::test]
async fn the_writer_counts_its_group_with_a_member_in_pieces_after_a_rebuild() {
    let cs = [board("a"), board("b"), board("c")];
    let dev = device().await;
    for x in &cs {
        dev.share(x, board_share(false)).await.unwrap();
    }
    let items = vec![
        (cs[0].clone(), Edit::Op(yrs_op(&cs[0], "/alice/laptop", 64))),
        (
            cs[1].clone(),
            Edit::Op(yrs_op(&cs[1], "/alice/laptop", 37_847)),
        ),
        (cs[2].clone(), Edit::Op(yrs_op(&cs[2], "/alice/laptop", 64))),
    ];
    let ids = dev.put_group(items, options()).await.unwrap();
    assert!(
        dev.inner.st.lock().colls[&cs[1]].versions[&ids[1]]
            .chunks
            .is_some(),
        "the 37,847-octet member travels in pieces"
    );
    assert_eq!(counted(&dev, &cs, &ids), 3, "counted at once");
    for x in &cs {
        dev.share(x, board_share(true)).await.unwrap();
    }
    assert_eq!(
        counted(&dev, &cs, &ids),
        3,
        "read again under a new members record, the group still counts whole"
    );
    dev.shutdown();
}
