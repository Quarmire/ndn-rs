//! One watch of a folder (spec §15): every collection under it, those
//! created after the watch began included, every kind of change, each tagged
//! with its collection, and no version twice.

use super::group_tests::{
    PAIR, budget, device, device_tuned, drain, give, id, log_share, n, plan, version,
};
use super::*;
use crate::layer::{Share, ShareChange, Sharing};

fn trip() -> Name {
    n("/alice/32=data/trip")
}

fn later() -> Name {
    n("/alice/32=data/trip/later")
}

/// How many times `changes` deliver version `id`.
fn delivered(changes: &[Change], id: &VersionId) -> usize {
    changes
        .iter()
        .filter(|c| matches!(c, Change::Version(v) if v.id == *id))
        .count()
}

#[tokio::test]
async fn a_folder_watch_reports_every_kind_for_a_collection_created_after_it_began() {
    let dev = device().await;
    dev.share_folder(&trip(), log_share().into()).await.unwrap();
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    assert!(
        drain(&mut changes)
            .await
            .iter()
            .all(|c| c.collection().has_prefix(&trip()))
    );

    // A collection nobody wrote before the watch began: its first version
    // comes on the same stream, tagged with it.
    let first = version("/bob/laptop", &later(), 20, &[], None);
    give(&dev, &first);
    let seen = drain(&mut changes).await;
    let v = seen
        .iter()
        .find(|c| matches!(c, Change::Version(v) if v.id == id("/bob/laptop", 20)))
        .expect("the new collection's version is delivered");
    assert_eq!(v.collection(), &later());

    // A group member of the new collection waits for its other member:
    // reported not counted, then counted, each tagged with its collection.
    let a = version("/carol/laptop", &later(), 10, &[], Some(PAIR));
    let b = version("/carol/laptop", &plan(), 11, &[], Some(PAIR));
    give(&dev, &a);
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter()
            .any(|c| matches!(c, Change::NotCounted { collection, id: i, .. }
            if *collection == later() && *i == id("/carol/laptop", 10))),
        "{seen:?}"
    );
    give(&dev, &b);
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter()
            .any(|c| matches!(c, Change::Counted { collection, id: i }
            if *collection == later() && *i == id("/carol/laptop", 10))),
        "{seen:?}"
    );
    assert_eq!(delivered(&seen, &id("/carol/laptop", 10)), 1);
    assert_eq!(delivered(&seen, &id("/carol/laptop", 11)), 1);

    // Bob signs a second entry at seq 20, in another collection under the
    // folder: told once for each collection, tagged with each.
    let second = version("/bob/laptop", &budget(), 20, &[], None);
    give(&dev, &second);
    let seen = drain(&mut changes).await;
    let mut told: Vec<Name> = seen
        .iter()
        .filter(|c| matches!(c, Change::Equivocation { .. }))
        .map(|c| c.collection().clone())
        .collect();
    let mut want = vec![budget(), later()];
    told.sort();
    want.sort();
    assert_eq!(told, want, "{seen:?}");
    for c in &seen {
        assert!(c.collection().has_prefix(&trip()), "{c:?}");
    }
    dev.shutdown();
}

#[tokio::test]
async fn a_watch_lists_a_member_waiting_for_its_group_as_not_counted() {
    let dev = device().await;
    let a = version("/bob/laptop", &plan(), 10, &[], Some(PAIR));
    give(&dev, &a);
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter().any(
            |c| matches!(c, Change::NotCounted { collection, id: i, why: NotCounted::Waits(why) }
            if *collection == plan() && *i == id("/bob/laptop", 10) && why.starts_with("group incomplete"))
        ),
        "the listing shows a held version not counted, with why: {seen:?}"
    );
    assert_eq!(
        delivered(&seen, &id("/bob/laptop", 10)),
        0,
        "nor is it shown"
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_version_waiting_when_the_watch_begins_is_delivered_once_when_it_applies() {
    let dev = device().await;
    let three = version("/bob/laptop", &plan(), 3, &[("/bob/laptop", 2)], None);
    give(&dev, &three);
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    let mut seen = drain(&mut changes).await;
    assert_eq!(
        delivered(&seen, &id("/bob/laptop", 3)),
        0,
        "not applied, so not listed: {seen:?}"
    );
    give(&dev, &version("/bob/laptop", &plan(), 2, &[], None));
    seen.extend(drain(&mut changes).await);
    assert_eq!(delivered(&seen, &id("/bob/laptop", 2)), 1, "{seen:?}");
    assert_eq!(delivered(&seen, &id("/bob/laptop", 3)), 1, "{seen:?}");
    dev.shutdown();
}

/// Version `seq` of `device` in `c` saying `text`.
fn saying(device: &str, c: &Name, seq: u64, text: &str) -> super::group_tests::Made {
    let body = VersionBody {
        collection: c.clone(),
        parents: Parents::default(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group: None,
        rule: None,
        fields: Content::new().with("t", text.to_owned()),
        op: Bytes::new(),
        sealed: None,
        chunks: None,
        block: None,
    };
    super::group_tests::made(device, c, seq, Record::Version(body))
}

#[tokio::test]
async fn an_equivocation_across_folders_shows_a_watcher_nothing_of_the_other_folder() {
    let dev = device().await;
    let list = n("/alice/32=data/home/list");
    dev.share(&list, log_share()).await.unwrap();
    // Bob's version in another folder, then a second entry of his at the
    // same seq in the watched folder.
    give(
        &dev,
        &saying("/bob/laptop", &list, 20, "the home folder's secret"),
    );
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    drain(&mut changes).await;
    give(&dev, &saying("/bob/laptop", &plan(), 20, "the trip's plan"));
    let seen = drain(&mut changes).await;
    let (first, second) = seen
        .iter()
        .find_map(|c| match c {
            Change::Equivocation { first, second, .. } => Some((first, second)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the equivocation is reported: {seen:?}"));
    assert!(
        matches!(first, Equivocal::Elsewhere { id: i, .. } if *i == id("/bob/laptop", 20)),
        "the other folder's version by name and id only: {first:?}"
    );
    assert!(
        matches!(second, Equivocal::Here(v) if v.collection == plan()),
        "the watched folder's own version whole: {second:?}"
    );
    for c in &seen {
        assert!(
            !format!("{c:?}").contains("the home folder's secret"),
            "a watcher of the trip folder sees nothing of the home folder's content: {c:?}"
        );
    }
    dev.shutdown();
}

#[tokio::test]
async fn a_watcher_that_falls_behind_is_told_it_lagged_never_queued_without_bound() {
    let queue = 3;
    let dev = device_tuned(log_share(), |c| Config {
        watch_queue: queue,
        ..c
    })
    .await;
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    // Its listing (the records in force) was queued beside the queue.
    let listed = drain(&mut changes).await.len();
    // Many more changes than the queue holds, none read meanwhile.
    for seq in 1..=20 {
        give(&dev, &version("/bob/laptop", &plan(), seq, &[], None));
    }
    let seen = drain(&mut changes).await;
    assert!(
        seen.len() <= queue + 1 + listed,
        "what a watcher leaves unread is bounded: {seen:?}"
    );
    assert!(
        matches!(seen.last(), Some(Change::Lagged { collection }) if *collection == trip()),
        "the gap is told, after everything delivered before it: {seen:?}"
    );
    // Read empty, the watcher is told what comes next again.
    give(&dev, &version("/bob/laptop", &plan(), 21, &[], None));
    let seen = drain(&mut changes).await;
    assert_eq!(delivered(&seen, &id("/bob/laptop", 21)), 1, "{seen:?}");
    // Watching anew from what it holds lists what it missed.
    let mut again = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    let listed = drain(&mut again).await;
    for seq in 1..=21 {
        assert_eq!(delivered(&listed, &id("/bob/laptop", seq)), 1, "{listed:?}");
    }
    dev.shutdown();
}

#[tokio::test]
async fn an_outside_writer_makes_a_follower_track_only_as_many_collections_as_its_policy_says() {
    let dev = device_tuned(log_share(), |c| Config {
        writer_collections: 2,
        ..c
    })
    .await;
    dev.share_folder(&trip(), log_share().into()).await.unwrap();
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    drain(&mut changes).await;
    let new = |i: u64| n(&format!("/alice/32=data/trip/new{i}"));
    for i in 0..3 {
        give(&dev, &version("/bob/laptop", &new(i), 30 + i, &[], None));
    }
    let seen = drain(&mut changes).await;
    for i in 0..2 {
        assert_eq!(delivered(&seen, &id("/bob/laptop", 30 + i)), 1, "{seen:?}");
    }
    assert_eq!(
        delivered(&seen, &id("/bob/laptop", 32)),
        0,
        "past the policy, the writer's new collection is not followed: {seen:?}"
    );
    let bob = Writer::new(super::group_tests::key("/bob/laptop"));
    let why = seen
        .iter()
        .find_map(|c| match c {
            Change::Untracked {
                collection,
                writer,
                why,
            } if *collection == new(2) && *writer == bob => Some(why.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("the refusal is told: {seen:?}"));
    assert!(
        why.contains(&bob.key().to_string()),
        "it names the writer: {why}"
    );
    // The namespace's own devices and collections shared with a record of
    // their own are not counted.
    give(&dev, &version("/alice/phone", &new(3), 1, &[], None));
    give(&dev, &version("/bob/laptop", &budget(), 40, &[], None));
    let seen = drain(&mut changes).await;
    assert_eq!(delivered(&seen, &id("/alice/phone", 1)), 1, "{seen:?}");
    assert_eq!(delivered(&seen, &id("/bob/laptop", 40)), 1, "{seen:?}");
    // Followed by its own name, the refused collection is read.
    let mut by_name = dev.watch(&new(2), &Frontier::new()).await.unwrap();
    give(&dev, &version("/bob/laptop", &new(2), 32, &[], None));
    let seen = drain(&mut by_name).await;
    assert_eq!(delivered(&seen, &id("/bob/laptop", 32)), 1, "{seen:?}");
    dev.shutdown();
}

#[tokio::test]
async fn records_made_again_unchanged_tell_a_watch_no_members_change() {
    let dev = device().await;
    dev.share_folder(&trip(), log_share().into()).await.unwrap();
    let mut folder = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    let mut own = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    drain(&mut folder).await;
    drain(&mut own).await;
    let members = async || {
        (
            dev.members(&trip()).await.unwrap(),
            dev.members(&plan()).await.unwrap(),
        )
    };
    let before = members().await;
    // The records in force made again from the same records held, as after
    // a trust context refused a record that was not in force.
    {
        let mut st = dev.inner.st.lock();
        for c in [trip(), plan()] {
            dev.inner.rebuild_members(&mut st, &c, &Refusal::NotMember);
        }
    }
    let seen: Vec<Change> = [drain(&mut folder).await, drain(&mut own).await].concat();
    assert!(
        !seen.iter().any(|c| matches!(c, Change::Members { .. })),
        "nothing in force changed, so nothing is told: {seen:?}"
    );
    assert_eq!(members().await, before);
    dev.shutdown();
}

#[tokio::test]
async fn a_version_comes_to_a_host_with_its_packets_digest_on_every_path() {
    let dev = device().await;
    let mut changes = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    drain(&mut changes).await;
    let first = saying("/bob/laptop", &plan(), 20, "first");
    let digest = wire::implicit_digest(&first.packet);
    give(&dev, &first);
    // Told on the watch, listed to a new one, read by its name: its
    // digest, and no operation under the log rule.
    let seen = drain(&mut changes).await;
    assert!(
        seen.iter().any(|c| matches!(c, Change::Version(v)
            if v.id == id("/bob/laptop", 20) && v.digest == digest && v.op.is_none())),
        "{seen:?}"
    );
    let mut again = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    let listed = drain(&mut again).await;
    assert!(
        listed.iter().any(|c| matches!(c, Change::Version(v)
            if v.id == id("/bob/laptop", 20) && v.digest == digest)),
        "{listed:?}"
    );
    match dev.get(&first.name).await.unwrap().got {
        Got::Version(v) => assert_eq!((v.digest, v.op), (digest, None)),
        other => panic!("not a version: {other:?}"),
    }
    // A second packet at its name: both told whole, each with its own.
    let second = saying("/bob/laptop", &plan(), 20, "second");
    give(&dev, &second);
    let seen = drain(&mut changes).await;
    let digests = seen.iter().find_map(|c| match c {
        Change::Equivocation {
            first: Equivocal::Here(a),
            second: Equivocal::Here(b),
            ..
        } => Some((a.digest, b.digest)),
        _ => None,
    });
    assert_eq!(
        digests,
        Some((digest, wire::implicit_digest(&second.packet))),
        "{seen:?}"
    );
    dev.shutdown();
}

/// The `Change::Members` told for `name` among `seen`, newest last.
fn told_members<'c>(seen: &'c [Change], name: &Name) -> Vec<&'c Share> {
    seen.iter()
        .filter_map(|c| match c {
            Change::Members { collection, share } if collection == name => Some(share),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_folder_watch_is_told_its_members_and_a_change_keeps_whom_it_does_not_name() {
    let dev = device().await;
    let writers = |w: &[&str]| Share {
        rule: Rule::Log,
        writers: w.iter().map(|x| n(x)).collect(),
        readers: Vec::new(),
    };
    let change = |add: &[&str], remove: &[&str]| -> Sharing {
        ShareChange {
            add_writers: add.iter().map(|x| n(x)).collect(),
            remove_writers: remove.iter().map(|x| n(x)).collect(),
            ..ShareChange::default()
        }
        .into()
    };
    // Nothing held: why, and nothing to change.
    let none = dev.members(&trip()).await;
    assert!(matches!(none, Err(DataError::NotReady { .. })), "{none:?}");
    let none = dev.share_folder(&trip(), change(&["/bob"], &[])).await;
    assert!(matches!(none, Err(DataError::NotReady { .. })), "{none:?}");

    dev.share_folder(&trip(), writers(&["/alice"]).into())
        .await
        .unwrap();
    let mut changes = dev.watch(&trip(), &Frontier::new()).await.unwrap();
    let mut plan_watch = dev.watch(&plan(), &Frontier::new()).await.unwrap();
    let listed = drain(&mut changes).await;
    assert!(
        matches!(listed.first(), Some(Change::Members { collection, share })
            if *collection == trip() && *share == writers(&["/alice"])),
        "the listing starts with the record in force: {listed:?}"
    );
    assert_eq!(dev.members(&trip()).await.unwrap(), writers(&["/alice"]));
    drain(&mut plan_watch).await;

    // Bob added by a change (as an introduction's admission adds him),
    // Carol added, then let go by a change naming her alone: Bob stays.
    dev.share_folder(&trip(), change(&["/bob"], &[]))
        .await
        .unwrap();
    dev.share_folder(&trip(), change(&["/carol"], &[]))
        .await
        .unwrap();
    dev.share_folder(&trip(), change(&[], &["/carol"]))
        .await
        .unwrap();
    let seen = drain(&mut changes).await;
    assert_eq!(
        told_members(&seen, &trip()),
        [
            &writers(&["/alice", "/bob"]),
            &writers(&["/alice", "/bob", "/carol"]),
            &writers(&["/alice", "/bob"]),
        ],
        "{seen:?}"
    );
    assert_eq!(
        dev.members(&trip()).await.unwrap(),
        writers(&["/alice", "/bob"])
    );
    // A collection under the folder, on its own watch: its record in force,
    // the folder's narrowing included.
    let seen = drain(&mut plan_watch).await;
    let in_force = dev.members(&plan()).await.unwrap();
    assert_eq!(
        told_members(&seen, &plan()).last(),
        Some(&&in_force),
        "{seen:?}"
    );

    // A change that changes nothing signs nothing.
    let head = dev.inner.st.lock().head;
    dev.share_folder(&trip(), change(&["/bob/laptop"], &["/carol"]))
        .await
        .unwrap();
    assert_eq!(dev.inner.st.lock().head, head);
    // Refused, nothing signed: a writer covered but not listed, and a
    // change leaving no writer.
    for refused in [
        change(&[], &["/bob/laptop"]),
        change(&[], &["/alice", "/bob"]),
    ] {
        let r = dev.share_folder(&trip(), refused).await;
        assert!(matches!(r, Err(DataError::BadRequest { .. })), "{r:?}");
    }
    assert_eq!(dev.inner.st.lock().head, head);
    dev.shutdown();
}
