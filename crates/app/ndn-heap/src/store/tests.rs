//! The store layer's invariants: batches reach the engine as one write, the
//! records round trip, keys never collide,
//! and a chain walk reads markers only.

use super::*;
use crate::test_kit::{Held, n};
use crate::wire::log_name;
use ndn_sync::MemoryStore;

fn bytes(s: &'static str) -> Bytes {
    Bytes::from_static(s.as_bytes())
}

fn device() -> Name {
    n("/alice/laptop")
}

fn space() -> Name {
    n("/alice/32=data/notes")
}

#[test]
fn batches_reach_the_store_as_one_apply() {
    let store = Arc::new(Held::default());
    let batch = Batch::new(Arc::clone(&store) as Arc<dyn DataStore>);
    batch.insert(n("/a"), bytes("1"));
    batch.apply(vec![
        StoreOp::Insert(n("/b"), bytes("2")),
        StoreOp::Remove(n("/a")),
    ]);
    batch.remove(&n("/gone"));
    batch.insert(n("/c"), bytes("3"));
    assert_eq!(
        store.batches(),
        0,
        "nothing reaches the store before the commit"
    );
    assert!(
        store.get(&n("/b")).is_none(),
        "no part of a put reaches the store before all of it does"
    );
    batch.commit();
    assert_eq!(store.batches(), 1, "everything the batch kept is one apply");
    assert!(store.get(&n("/a")).is_none(), "the order made is kept");
    assert!(store.get(&n("/b")).is_some() && store.get(&n("/c")).is_some());

    batch.commit();
    assert_eq!(store.batches(), 1, "a commit of nothing applies nothing");
}

#[test]
fn a_read_through_a_batch_answers_as_the_store_would_with_the_batch_applied() {
    let store = Arc::new(Held::default());
    store.insert(n("/p/old"), bytes("old"));
    store.insert(n("/p/replaced"), bytes("before"));
    store.insert(n("/q/other"), bytes("other"));
    let batch = Batch::new(Arc::clone(&store) as Arc<dyn DataStore>);

    batch.insert(n("/p/new"), bytes("new"));
    batch.insert(n("/p/replaced"), bytes("after"));
    batch.remove(&n("/p/old"));

    let under: Vec<(String, Bytes)> = batch
        .scan_under(&n("/p"), 0)
        .into_iter()
        .map(|(name, wire)| (name.to_string(), wire))
        .collect();
    assert_eq!(
        under,
        vec![
            ("/p/new".to_owned(), bytes("new")),
            ("/p/replaced".to_owned(), bytes("after")),
        ]
    );
    assert_eq!(
        batch.scan_under(&n("/p"), 1).len(),
        1,
        "the limit counts what stands, not what the store held"
    );
    assert_eq!(batch.find_under(&n("/p")), Some(bytes("new")));
    assert_eq!(batch.get(&n("/p/old")), None);
    assert!(!batch.contains(&n("/p/old")) && batch.contains(&n("/p/new")));
    assert_eq!(
        store.get(&n("/p/replaced")),
        Some(bytes("before")),
        "a read is not a point to hand a part of a put to the store"
    );
    batch.commit();
    assert_eq!(store.get(&n("/p/replaced")), Some(bytes("after")));
}

#[test]
fn a_batch_is_its_owners_alone() {
    let store = Arc::new(MemoryStore::new());
    let mine = Batch::new(Arc::clone(&store) as Arc<dyn DataStore>);
    let theirs = Batch::new(Arc::clone(&store) as Arc<dyn DataStore>);
    mine.insert(n("/mine"), bytes("1"));
    theirs.insert(n("/theirs"), bytes("2"));
    theirs.commit();
    assert!(
        store.get(&n("/theirs")).is_some(),
        "another batch commits whole"
    );
    assert!(store.get(&n("/mine")).is_none());
    assert!(
        mine.get(&n("/theirs")).is_some(),
        "a read through a batch sees the store"
    );
    assert!(theirs.get(&n("/mine")).is_none(), "and no other's batch");
    mine.commit();
    assert!(store.get(&n("/mine")).is_some());
}

#[test]
fn the_markers_round_trip() {
    let marker = Marker {
        signed_digest: [1; 32],
        key_digest: [2; 32],
        prev: [3; 32],
        prev_seq: 0x0102_0304_0506_0708,
        at: u64::MAX - 1,
    };
    let wire = marker.encode();
    assert_eq!(wire.len(), 112);
    assert_eq!(&wire[..32], &[1; 32]);
    assert_eq!(&wire[96..104], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(Marker::decode(&wire), Some(marker));
    assert_eq!(Marker::decode(&wire[..111]), None);
    assert_eq!(
        Marker::decode(&[&wire[..], &[0][..]].concat()),
        None,
        "a marker of another length is not read as one"
    );

    let head = Link {
        seq: 77,
        digest: [9; 32],
    };
    let wire = head.encode();
    assert_eq!(wire.len(), 40);
    assert_eq!(&wire[..8], &77u64.to_be_bytes());
    assert_eq!(Link::decode(&wire), Some(head));
    assert_eq!(Link::decode(&wire[..39]), None);

    for record in [
        ReserveRecord { r: 0, clean: false },
        ReserveRecord {
            r: 1024,
            clean: true,
        },
        ReserveRecord {
            r: u64::MAX,
            clean: false,
        },
    ] {
        let wire = record.encode();
        assert_eq!(wire.len(), 9);
        assert_eq!(ReserveRecord::decode(&wire), Some(record));
    }
    assert_eq!(
        ReserveRecord::decode(&[0, 0, 0, 0, 0, 0, 0, 8, 2]),
        None,
        "a clean flag that is neither 0 nor 1 is refused, not read as clean"
    );
    assert_eq!(ReserveRecord::decode(&[0; 8]), None);
}

#[test]
fn a_corrupt_record_is_an_error_naming_its_key_never_an_absent_one() {
    let store = MemoryStore::new();
    assert_eq!(read_reserve(&store, &space()), Ok(None));
    assert_eq!(read_head(&store, &space()), Ok(None));
    store.insert(Kind::RESERVE.of(&space()), Bytes::from_static(&[1, 2, 3]));
    store.insert(Kind::HEAD.of(&space()), Bytes::from_static(&[1, 2, 3]));
    let err = read_reserve(&store, &space()).unwrap_err();
    assert_eq!(err.key, Kind::RESERVE.of(&space()));
    assert!(
        err.to_string().contains("reserve"),
        "the refusal says which record: {err}"
    );
    assert!(read_head(&store, &space()).is_err());

    write_reserve(&store, &space(), ReserveRecord { r: 5, clean: true });
    assert_eq!(
        read_reserve(&store, &space()),
        Ok(Some(ReserveRecord { r: 5, clean: true }))
    );
}

#[test]
fn keys_live_under_the_local_prefix_and_never_confuse_a_space_with_one_that_extends_it() {
    let (s, deeper) = (space(), n("/alice/32=data/notes/y"));
    let entry = log_name(&device(), &s, 4);
    let local = n("/localhost/ndn-heap");
    for key in [
        Kind::VERIFIED.of(&entry),
        Kind::HEAD.of(&s),
        Kind::RESERVE.of(&s),
        Kind::SPACE.of(&s),
        Kind::STRUCTURAL.seq(&s, &device(), 1),
        heads_key(&s, b"path"),
        supers_key(&s, &device(), 1, &[0; 32]),
        Kind::EPOCH.seq(&s, &device(), 1),
        Kind::EQUIVOCAL.of(&entry),
        Kind::SUSPECTED.of(&n("/alice/laptop/KEY/1")),
        Kind::SCOPED.of(&n("/alice")),
        Kind::STATUS.seq(&s, &device(), 1),
        Kind::LEDGER.device(&s, &device()),
    ] {
        assert!(key.has_prefix(&local), "{key} is not under {local}");
    }
    let mut kinds: Vec<Name> = [
        Kind::VERIFIED.of(&entry),
        Kind::HEAD.of(&s),
        Kind::RESERVE.of(&s),
        Kind::SPACE.of(&s),
        Kind::EQUIVOCAL.of(&entry),
    ]
    .into();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 5, "every kind has its own key");

    // A space is a prefix of the spaces that extend it: what a scan of one
    // space's keys must never return from another's.
    let mine = Kind::STRUCTURAL.listing(&s);
    assert!(Kind::STRUCTURAL.seq(&s, &device(), 5).has_prefix(&mine));
    assert!(
        !Kind::STRUCTURAL
            .seq(&deeper, &device(), 5)
            .has_prefix(&mine)
    );
    assert!(!heads_key(&deeper, b"path").has_prefix(&Kind::HEADS.listing(&s)));
    assert!(
        !Kind::EPOCH
            .seq(&deeper, &device(), 5)
            .has_prefix(&Kind::EPOCH.listing(&s))
    );

    // The seq orders numerically, and the key parses back.
    let keys: Vec<Name> = [1, 2, 255, 256, 70_000]
        .into_iter()
        .map(|seq| Kind::STRUCTURAL.seq(&s, &device(), seq))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "{keys:?}");
    assert_eq!(
        Kind::STRUCTURAL.parse_seq(&s, &keys[3]),
        Some((device(), 256)),
        "start replays the structural entries by what the key says"
    );
    assert_eq!(Kind::STRUCTURAL.parse_seq(&deeper, &keys[3]), None);
    assert_eq!(Kind::STRUCTURAL.parse_seq(&s, &Kind::HEAD.of(&s)), None);
    assert_eq!(Kind::STRUCTURAL.parse_device(&s, &keys[3]), None);
    let ledger = Kind::LEDGER.device(&s, &device());
    assert_eq!(Kind::LEDGER.parse_device(&s, &ledger), Some(device()));
    assert_eq!(Kind::LEDGER.parse_seq(&s, &ledger), None);

    assert_ne!(heads_key(&s, b"a"), heads_key(&s, b"b"));
    assert_eq!(heads_key(&s, b"a"), heads_key(&s, b"a"));
}

#[test]
fn a_kind_lists_its_names_with_their_values_and_no_other_kinds() {
    let store = MemoryStore::new();
    let other = n("/bob/32=data/x");
    store.insert(Kind::SPACE.of(&space()), bytes("1"));
    store.insert(Kind::SPACE.of(&other), bytes("2"));
    store.insert(Kind::HEAD.of(&space()), bytes("3"));
    let listed: std::collections::BTreeMap<Name, Bytes> =
        Kind::SPACE.named(&store).into_iter().collect();
    assert_eq!(
        listed,
        [(space(), bytes("1")), (other, bytes("2"))]
            .into_iter()
            .collect()
    );
}
