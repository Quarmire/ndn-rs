//! Admission across a key's one log (spec §4, §5.5, §6.1, §8): a seq is
//! one entry in every collection, a folder cut keeps each seq in the
//! collection it was held in, and a group is judged from what every reader
//! can tell alike — its own signed versions, the audiences of the epochs
//! they are sealed in, and keeps that never expire.

use super::group_tests::{
    Made, PAIR, Unconnected, budget, counts, device, drain, give, id, key, log_share, made, n,
    options, plan, refusal, version,
};
use super::*;
use crate::layer::Share;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A device named `device`, on a forwarder that delivers nothing, holding
/// the trust contexts of Alice, Bob and Carol, owning nothing.
async fn reader(device: &str) -> Device {
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        assert!(validator.adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns)))));
    }
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        store,
        Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// The newest entry of `owner`'s log, about `c`, as a reader fetches it.
fn newest(owner: &Device, c: &Name) -> Made {
    let seq = owner.inner.st.lock().head;
    let name = log_name(owner.name(), Some(c), seq);
    let packet = owner.inner.store.get(&name).expect("written and stored");
    let content = Data::decode(packet.clone())
        .unwrap()
        .content()
        .unwrap()
        .clone();
    Made {
        name,
        packet,
        key: key(&owner.name().to_string()),
        record: wire::decode_record(content).unwrap(),
    }
}

fn outside_cut(why: Option<Refusal>) -> bool {
    matches!(why, Some(Refusal::OutsideCut(_)))
}

fn group_refused(why: Option<Refusal>) -> bool {
    matches!(why, Some(Refusal::Group { .. }))
}

/// SubstrateReview H1, exploit 1 (a regression of SealReview CUT-BYP-01):
/// Bob, removed from a folder whose cut kept his seq 1 in one collection
/// and seq 2 in another, signs seqs 1 and 2 again in other collections
/// under the folder — new names, so no same-name equivocation. A cut by
/// seq alone would admit them everywhere; it keeps each seq only in the
/// collection it was held in, at the owner and at a reader that has the
/// folder record off the wire.
#[tokio::test]
async fn a_removed_writer_signing_a_kept_seq_again_in_another_collection_is_refused_everywhere() {
    let owner = device().await;
    let other = reader("/carol/phone").await;
    let f = n("/alice/32=data/docs");
    let [c1, c2, c3] = ["plan", "notes", "later"].map(|x| f.clone().append(x));
    let share = |writers: &[&str]| Share {
        rule: Rule::Log,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: Vec::new(),
    };
    owner
        .share_folder(&f, share(&["/alice", "/bob"]))
        .await
        .unwrap();
    let kept = [
        version("/bob/phone", &c1, 1, &[], None),
        version("/bob/phone", &c2, 2, &[], None),
    ];
    for m in &kept {
        give(&owner, m);
    }
    owner.share_folder(&f, share(&["/alice"])).await.unwrap();
    give(&other, &newest(&owner, &f));
    for m in &kept {
        give(&other, m);
    }
    for dev in [&owner, &other] {
        for (m, c) in kept.iter().zip([&c1, &c2]) {
            assert_eq!(refusal(dev, &m.name), None, "what the cut kept stays");
            assert!(counts(
                dev,
                c,
                &id("/bob/phone", parse_log_name(&m.name).unwrap().seq)
            ));
        }
        for (c, seq) in [(&c3, 1), (&c2, 1), (&c1, 2), (&c3, 2)] {
            let again = version("/bob/phone", c, seq, &[], None);
            give(dev, &again);
            assert!(
                outside_cut(refusal(dev, &again.name)),
                "seq {seq} signed again in {c}: {:?}",
                refusal(dev, &again.name)
            );
            assert!(!counts(dev, c, &id("/bob/phone", seq)));
        }
    }
    owner.shutdown();
    other.shutdown();
}

/// SubstrateReview H1, exploit 2: Bob signs two entries at seq 10, in two
/// collections, both members of group (10, 2), and seq 11 in a third. The
/// group is malformed — its writer equivocated at one of its seqs — and
/// every reader reaches that verdict, whatever order the three arrive in:
/// none counts, each is refused for its group, and the equivocation is
/// reported. A non-group entry at a member's seq does the same.
#[tokio::test]
async fn a_group_whose_writer_signed_two_entries_at_one_of_its_seqs_is_refused_in_any_order() {
    let days = n("/alice/32=data/trip/days");
    let twice = [
        version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
        version("/bob/laptop", &budget(), 10, &[], Some(PAIR)),
        version("/bob/laptop", &days, 11, &[], Some(PAIR)),
    ];
    let beside = [
        version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
        version("/bob/laptop", &budget(), 11, &[], Some(PAIR)),
        version("/bob/laptop", &days, 10, &[], None),
    ];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for (what, entries) in [("two members", &twice), ("a member and a version", &beside)] {
        for order in orders {
            let dev = device().await;
            dev.share(&days, log_share()).await.unwrap();
            let mut changes = dev
                .watch(&n("/alice/32=data/trip"), &Frontier::new())
                .await
                .unwrap();
            for i in order {
                give(&dev, &entries[i]);
            }
            for m in entries.iter().filter(|m| match &m.record {
                Record::Version(b) => b.group.is_some(),
                _ => false,
            }) {
                let Record::Version(b) = &m.record else {
                    unreachable!()
                };
                assert!(
                    group_refused(refusal(&dev, &m.name)),
                    "{what} {order:?}: {} refused for its group, not {:?}",
                    m.name,
                    refusal(&dev, &m.name)
                );
                let seq = parse_log_name(&m.name).unwrap().seq;
                assert!(
                    !counts(&dev, &b.collection, &id("/bob/laptop", seq)),
                    "{what} {order:?}"
                );
            }
            let seen = drain(&mut changes).await;
            assert!(
                seen.iter()
                    .any(|c| matches!(c, Change::Equivocation { .. })),
                "{what} {order:?}: the equivocation is reported"
            );
            // Bob's later version naming the plan's member does not wait.
            let later = version("/bob/laptop", &plan(), 12, &[("/bob/laptop", 10)], None);
            give(&dev, &later);
            assert!(
                counts(&dev, &plan(), &id("/bob/laptop", 12)),
                "{what} {order:?}"
            );
            dev.shutdown();
        }
    }
}

/// Bob's log version `seq` of `c`, sealed in `epoch` under `ck`, declaring
/// `seal`, of `group`.
fn sealed(
    c: &Name,
    (epoch, ck): &(Epoch, ContentKey),
    seq: u64,
    seal: &[&str],
    group: Option<Group>,
) -> Made {
    let name = log_name(&n("/bob/laptop"), Some(c), seq);
    let fields = Content::new().with("t", format!("bob {seq}"));
    let Record::Version(body) = version("/bob/laptop", c, seq, &[], group).record else {
        unreachable!("a version")
    };
    let body = VersionBody {
        seal: Seal {
            any_of: seal.iter().map(|r| Audience::Person(n(r))).collect(),
        },
        fields: Content::new(),
        sealed: Some(SealedBody {
            epoch: epoch.clone(),
            ciphertext: seal::seal_payload(ck, &name, &fields, &[]),
        }),
        ..body
    };
    made("/bob/laptop", c, seq, Record::Version(body))
}

/// SubstrateReview H3: Bob declares the seal {Alice, Carol} on both members
/// of a group, yet seals one in a collection's epoch only Alice reads.
/// Alice opens both and Carol only one: judged by the declared seals
/// alone, Alice would count the group and Carol never could. Judged by the
/// audiences of the epochs the members are sealed in, neither counts it
/// while an epoch leaves out a reader the group declares — and both do
/// once the owner adds Carol to that epoch.
#[tokio::test]
async fn a_group_sealed_for_fewer_readers_than_it_declares_counts_nowhere_until_they_read() {
    let owner = device().await;
    let carol = reader("/carol/phone").await;
    let [a, b] = ["a", "b"].map(|x| n(&format!("/alice/32=data/trip/{x}")));
    let share = |readers: &[&str]| Share {
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
        ..log_share()
    };
    owner.share(&a, share(&["/alice", "/carol"])).await.unwrap();
    give(&carol, &newest(&owner, &a));
    owner.share(&b, share(&["/alice"])).await.unwrap();
    give(&carol, &newest(&owner, &b));
    let key_of = |c: &Name| {
        let st = owner.inner.st.lock();
        let e = st.colls[c].members.as_ref().unwrap().epoch.clone().unwrap();
        let k = st.keys.key(c, &e).unwrap();
        (e, k)
    };
    let (ka, kb) = (key_of(&a), key_of(&b));
    let declared = ["/alice", "/carol"];
    let members = [
        sealed(&a, &ka, 10, &declared, Some(PAIR)),
        sealed(&b, &kb, 11, &declared, Some(PAIR)),
    ];
    let grant = |c: &Name, e: &Epoch| {
        let st = owner.inner.st.lock();
        owner
            .inner
            .grant_key(&st, c, e, &n("/carol/phone"), &n("/carol"))
    };
    let key = grant(&a, &ka.0).expect("Carol reads a");
    assert!(carol.inner.st.lock().take_key(&a, &ka.0, key));
    assert!(grant(&b, &kb.0).is_none(), "Carol does not read b");
    for m in &members {
        give(&owner, m);
        give(&carol, m);
    }
    let counted = |dev: &Device| {
        (
            counts(dev, &a, &id("/bob/laptop", 10)),
            counts(dev, &b, &id("/bob/laptop", 11)),
        )
    };
    assert_eq!(
        counted(&owner),
        (false, false),
        "Alice opens both, and waits"
    );
    assert_eq!(counted(&carol), (false, false));
    // The owner adds Carol to b: its epoch is kept, and now reads as declared.
    owner.share(&b, share(&["/alice", "/carol"])).await.unwrap();
    assert_eq!(
        owner.inner.st.lock().colls[&b]
            .members
            .as_ref()
            .unwrap()
            .epoch,
        Some(kb.0.clone())
    );
    give(&carol, &newest(&owner, &b));
    let key = grant(&b, &kb.0).expect("Carol reads b now");
    assert!(carol.inner.st.lock().take_key(&b, &kb.0, key));
    assert_eq!(counted(&owner), (true, true));
    assert_eq!(counted(&carol), (true, true));
    owner.shutdown();
    carol.shutdown();
}

/// SubstrateReview M1: a group member kept for the last `n` versions, or
/// until a date, would count as present once expired — but only at the
/// readers that held it before it went; a reader that started later never
/// learns it existed. A group's versions are therefore kept until pruned:
/// `put_group` refuses another keep and writes nothing, and a reader
/// refuses a group whose member carries one, so a reader that held it
/// counts the group no more than a late reader that never did.
#[tokio::test]
async fn a_group_member_that_may_expire_counts_at_no_reader_and_is_never_written() {
    let dev = device().await;
    let fields = |t: &str| Edit::Fields(Content::new().with("t", t.to_owned()));
    for keep in [Keep::LastN(1), Keep::Until(Timestamp(u64::MAX / 2))] {
        let head = dev.inner.st.lock().head;
        let got = dev
            .put_group(
                vec![(plan(), fields("a")), (budget(), fields("b"))],
                PutOptions { keep, ..options() },
            )
            .await;
        assert!(
            matches!(got, Err(DataError::BadRequest { .. })),
            "{keep:?}: {got:?}"
        );
        assert_eq!(got.unwrap_err().next(), crate::NextStep::FixRequest);
        assert_eq!(dev.inner.st.lock().head, head, "{keep:?}: nothing written");
    }
    dev.shutdown();
    let kept = |seq: u64, keep: Keep, c: &Name, group: Option<Group>| {
        let Record::Version(body) = version("/bob/laptop", c, seq, &[], group).record else {
            unreachable!("a version")
        };
        made(
            "/bob/laptop",
            c,
            seq,
            Record::Version(VersionBody { keep, ..body }),
        )
    };
    let a = kept(10, Keep::Forever, &plan(), Some(PAIR));
    let b = kept(11, Keep::LastN(1), &budget(), Some(PAIR));
    let newer = kept(12, Keep::LastN(1), &budget(), None);
    // An early reader holds both members, then the newer version that ends
    // the member's last 1; a late reader never held the member.
    let early = device().await;
    for m in [&a, &b, &newer] {
        give(&early, m);
    }
    let late = device().await;
    for m in [&a, &newer] {
        give(&late, m);
    }
    for (who, dev) in [("early", &early), ("late", &late)] {
        assert!(!counts(dev, &plan(), &id("/bob/laptop", 10)), "{who}");
    }
    assert!(group_refused(refusal(&early, &a.name)));
    early.shutdown();
    late.shutdown();
}

/// FixReview 1: a group is judged from what every reader of its folder
/// holds alike. An entry its writer signed at a member's seq outside the
/// folder — which only readers of that other collection fetch — or one kept
/// to expire — which leaves the writer's listing, so a later reader never
/// learns of it — is no evidence against the group: it counts at every
/// reader, whichever of them each holds.
#[tokio::test]
async fn a_second_entry_no_reader_of_the_folder_holds_alike_leaves_the_group_alone() {
    let elsewhere = n("/alice/32=data/home/list");
    let days = n("/alice/32=data/trip/days");
    let members = [
        version("/bob/laptop", &plan(), 10, &[], Some(PAIR)),
        version("/bob/laptop", &budget(), 11, &[], Some(PAIR)),
    ];
    let Record::Version(body) = version("/bob/laptop", &days, 10, &[], None).record else {
        unreachable!("a version")
    };
    let expiring = made(
        "/bob/laptop",
        &days,
        10,
        Record::Version(VersionBody {
            keep: Keep::LastN(1),
            ..body
        }),
    );
    for (what, partner) in [
        (
            "outside the folder",
            version("/bob/laptop", &elsewhere, 10, &[], None),
        ),
        ("kept to expire", expiring),
    ] {
        let dev = device().await;
        dev.share(&elsewhere, log_share()).await.unwrap();
        dev.share(&days, log_share()).await.unwrap();
        for m in members.iter().chain([&partner]) {
            give(&dev, m);
        }
        assert!(
            counts(&dev, &plan(), &id("/bob/laptop", 10))
                && counts(&dev, &budget(), &id("/bob/laptop", 11)),
            "{what}: {:?}",
            refusal(&dev, &members[0].name)
        );
        dev.shutdown();
    }
}

/// FixReview 2: what a group needs is taken from the epochs its members
/// are sealed in, never from the seal its writer declares. Bob declares
/// only Alice on both members, seals one in an epoch Alice and Carol read
/// and the other in one only Alice reads: Carol could open one member and
/// never the other, so no reader counts the group until both epochs admit
/// Carol. A group with a sealed and an unsealed member is malformed.
#[tokio::test]
async fn a_group_declaring_a_smaller_seal_than_its_epochs_counts_nowhere_until_they_agree() {
    let owner = device().await;
    let [a, b] = ["a", "b"].map(|x| n(&format!("/alice/32=data/trip/{x}")));
    let share = |readers: &[&str]| Share {
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
        ..log_share()
    };
    owner.share(&a, share(&["/alice", "/carol"])).await.unwrap();
    owner.share(&b, share(&["/alice"])).await.unwrap();
    let key_of = |c: &Name| {
        let st = owner.inner.st.lock();
        let e = st.colls[c].members.as_ref().unwrap().epoch.clone().unwrap();
        let k = st.keys.key(c, &e).unwrap();
        (e, k)
    };
    let (ka, kb) = (key_of(&a), key_of(&b));
    for m in [
        sealed(&a, &ka, 10, &["/alice"], Some(PAIR)),
        sealed(&b, &kb, 11, &["/alice"], Some(PAIR)),
    ] {
        give(&owner, &m);
    }
    let counted = || {
        (
            counts(&owner, &a, &id("/bob/laptop", 10)),
            counts(&owner, &b, &id("/bob/laptop", 11)),
        )
    };
    assert_eq!(counted(), (false, false), "b's epoch leaves out Carol");
    owner.share(&b, share(&["/alice", "/carol"])).await.unwrap();
    assert_eq!(counted(), (true, true), "both epochs admit Alice and Carol");
    // A sealed member and an unsealed one, declaring one seal.
    let g = Group { id: 20, count: 2 };
    let unsealed = {
        let Record::Version(body) = version("/bob/laptop", &plan(), 21, &[], Some(g)).record else {
            unreachable!("a version")
        };
        let body = VersionBody {
            seal: Seal {
                any_of: vec![Audience::Person(n("/alice"))],
            },
            ..body
        };
        made("/bob/laptop", &plan(), 21, Record::Version(body))
    };
    let mixed = [sealed(&a, &ka, 20, &["/alice"], Some(g)), unsealed];
    for m in &mixed {
        give(&owner, m);
    }
    for m in &mixed {
        assert!(
            group_refused(refusal(&owner, &m.name)),
            "{} refused for its group, not {:?}",
            m.name,
            refusal(&owner, &m.name)
        );
    }
    owner.shutdown();
}

/// A node of Bob's of `c`, at `head`, listing `entries` and, of a folder,
/// `children` with Bob's head in each.
fn node(c: &Name, head: u64, entries: Vec<(u64, u64)>, children: &[(&str, u64)]) -> NodeBody {
    NodeBody {
        subject: c.clone(),
        writer: key("/bob/laptop"),
        head,
        page: None,
        entries,
        members: Vec::new(),
        expiry: Vec::new(),
        branches: wire::Branches::Children(
            children
                .iter()
                .map(|(x, head)| wire::ChildRef {
                    component: n(&format!("/{x}")).components()[0].clone(),
                    head: *head,
                    digest: [0; 32],
                })
                .collect(),
        ),
    }
}

/// FixReview 3: a late reader that never saw a group's member — it expired
/// at its writer's before the reader started — reaches the early readers'
/// verdict, refused, from its writer's signed nodes: the folder's node and
/// those of each of its collections reach the member's seq and list it
/// nowhere. While a collection's node that reaches it is not held, the
/// group only waits.
#[tokio::test]
async fn a_member_no_node_of_its_folder_lists_refuses_its_group_at_a_late_reader() {
    let late = device().await;
    let trip = n("/alice/32=data/trip");
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    let later = version("/bob/laptop", &plan(), 12, &[("/bob/laptop", 10)], None);
    give(&late, &a);
    give(&late, &later);
    let bob = Writer::new(key("/bob/laptop"));
    let judge = |nodes: &[NodeBody]| {
        let mut st = late.inner.st.lock();
        st.colls.entry(trip.clone()).or_default();
        for b in nodes {
            st.listing(&b.subject, &bob, b);
        }
        st.apply_ready(&plan(), &BTreeSet::new());
    };
    judge(&[
        node(&trip, 12, Vec::new(), &[("plan", 12), ("budget", 11)]),
        node(&plan(), 12, vec![(10, 10), (12, 12)], &[]),
    ]);
    assert_eq!(
        refusal(&late, &a.name),
        None,
        "the budget's node is not held: the member may be there"
    );
    judge(&[node(&budget(), 11, Vec::new(), &[])]);
    assert!(
        group_refused(refusal(&late, &a.name)),
        "{:?}",
        refusal(&late, &a.name)
    );
    assert!(!counts(&late, &plan(), &id("/bob/laptop", 10)));
    assert!(
        counts(&late, &plan(), &id("/bob/laptop", 12)),
        "the writer's later version no longer waits for the refused member"
    );
    late.shutdown();
}

/// The same through pages: the writer's node of the folder lists pages
/// instead of children. While the page reaching the member's seq is not
/// held the group waits; once it is, and no node it leads to lists the
/// seq, the group is refused.
#[tokio::test]
async fn a_member_no_page_of_its_folder_leads_to_refuses_its_group_at_a_late_reader() {
    let late = device().await;
    let trip = n("/alice/32=data/trip");
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    give(&late, &a);
    let bob = Writer::new(key("/bob/laptop"));
    let judge = |nodes: &[NodeBody]| {
        let mut st = late.inner.st.lock();
        st.colls.entry(trip.clone()).or_default();
        for b in nodes {
            st.listing(&b.subject, &bob, b);
        }
        st.apply_ready(&plan(), &BTreeSet::new());
    };
    let paged = NodeBody {
        branches: wire::Branches::Pages(vec![wire::PageRef {
            bucket: 3,
            head: 12,
            digest: [0; 32],
        }]),
        ..node(&trip, 12, Vec::new(), &[])
    };
    judge(&[
        paged,
        node(&plan(), 12, vec![(10, 10), (12, 12)], &[]),
        node(&budget(), 11, Vec::new(), &[]),
    ]);
    assert_eq!(
        refusal(&late, &a.name),
        None,
        "the page is not held: the member may be under it"
    );
    let page = NodeBody {
        page: Some(Bytes::from_static(&[3])),
        ..node(&trip, 12, Vec::new(), &[("plan", 12), ("budget", 11)])
    };
    judge(&[page]);
    assert!(
        group_refused(refusal(&late, &a.name)),
        "{:?}",
        refusal(&late, &a.name)
    );
    late.shutdown();
}
