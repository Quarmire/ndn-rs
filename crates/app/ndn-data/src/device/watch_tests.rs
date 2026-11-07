//! One watch of a folder (spec §15): every collection under it, those
//! created after the watch began included, every kind of change, each tagged
//! with its collection, and no version twice.

use super::group_tests::{PAIR, budget, device, drain, give, id, log_share, n, plan, version};
use super::*;

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
    dev.share_folder(&trip(), log_share()).await.unwrap();
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
            |c| matches!(c, Change::NotCounted { collection, id: i, why }
            if *collection == plan() && *i == id("/bob/laptop", 10) && !why.is_empty())
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
