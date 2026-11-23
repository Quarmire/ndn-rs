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
    let stage = Stage::new(Arc::clone(&store) as Arc<dyn DataStore>);
    {
        let _batch = stage.batch();
        stage.insert(n("/a"), bytes("1"));
        stage.apply(vec![
            StoreOp::Insert(n("/b"), bytes("2")),
            StoreOp::Remove(n("/a")),
        ]);
        {
            let _inner = stage.batch();
            stage.remove(&n("/gone"));
            stage.insert(n("/c"), bytes("3"));
        }
        assert_eq!(
            store.batches(),
            0,
            "an inner batch joins the outer: nothing reaches the store before the outer ends"
        );
        assert!(
            store.get(&n("/b")).is_none(),
            "no part of a put reaches the store before all of it does"
        );
    }
    assert_eq!(store.batches(), 1, "everything the batch kept is one apply");
    assert!(store.get(&n("/a")).is_none(), "the order made is kept");
    assert!(store.get(&n("/b")).is_some() && store.get(&n("/c")).is_some());

    stage.insert(n("/d"), bytes("4"));
    assert!(
        store.get(&n("/d")).is_some(),
        "a write with no batch open goes straight through"
    );
}

#[test]
fn a_read_by_prefix_inside_a_batch_answers_as_the_store_would_with_the_batch_applied() {
    let store = Arc::new(Held::default());
    store.insert(n("/p/old"), bytes("old"));
    store.insert(n("/p/replaced"), bytes("before"));
    store.insert(n("/q/other"), bytes("other"));
    let stage = Stage::new(Arc::clone(&store) as Arc<dyn DataStore>);

    let batch = stage.batch();
    stage.insert(n("/p/new"), bytes("new"));
    stage.insert(n("/p/replaced"), bytes("after"));
    stage.remove(&n("/p/old"));

    let under: Vec<(String, Bytes)> = stage
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
        stage.scan_under(&n("/p"), 1).len(),
        1,
        "the limit counts what stands, not what the store held"
    );
    assert_eq!(stage.find_under(&n("/p")), Some(bytes("new")));
    assert_eq!(stage.get(&n("/p/old")), None);
    assert!(!stage.contains(&n("/p/old")) && stage.contains(&n("/p/new")));
    assert_eq!(
        store.get(&n("/p/replaced")),
        Some(bytes("before")),
        "a read is not a point to hand a part of a put to the store"
    );
    drop(batch);
    assert_eq!(store.get(&n("/p/replaced")), Some(bytes("after")));
}

#[test]
fn another_threads_writes_do_not_join_an_open_batch() {
    let store = Arc::new(MemoryStore::new());
    let stage = Stage::new(Arc::clone(&store) as Arc<dyn DataStore>);
    let batch = stage.batch();
    stage.insert(n("/mine"), bytes("1"));
    {
        let stage = Arc::clone(&stage);
        std::thread::spawn(move || {
            let _theirs = stage.batch();
            stage.insert(n("/theirs"), bytes("2"));
        })
        .join()
        .unwrap();
    }
    assert!(
        store.get(&n("/theirs")).is_some(),
        "a thread whose batch could not open writes through"
    );
    assert!(store.get(&n("/mine")).is_none());
    drop(batch);
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

    let head = Head {
        seq: 77,
        digest: [9; 32],
    };
    let wire = head.encode();
    assert_eq!(wire.len(), 40);
    assert_eq!(&wire[..8], &77u64.to_be_bytes());
    assert_eq!(Head::decode(&wire), Some(head));
    assert_eq!(Head::decode(&wire[..39]), None);

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
    store.insert(reserve_key(&space()), Bytes::from_static(&[1, 2, 3]));
    store.insert(head_key(&space()), Bytes::from_static(&[1, 2, 3]));
    let err = read_reserve(&store, &space()).unwrap_err();
    assert_eq!(err.key, reserve_key(&space()));
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
        verified_key(&entry),
        head_key(&s),
        reserve_key(&s),
        space_key(&s),
        structural_key(&s, &device(), 1),
        heads_key(&s, b"path"),
        supers_key(&s, &device(), 1, &[0; 32]),
        epoch_key(&s, &device(), 1),
        equivocal_key(&entry),
        suspected_key(&n("/alice/laptop/KEY/1")),
        scoped_key(&n("/alice")),
    ] {
        assert!(key.has_prefix(&local), "{key} is not under {local}");
    }
    let mut kinds: Vec<Name> = [
        verified_key(&entry),
        head_key(&s),
        reserve_key(&s),
        space_key(&s),
        equivocal_key(&entry),
    ]
    .into();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 5, "every kind has its own key");

    // A space is a prefix of the spaces that extend it: what a scan of one
    // space's keys must never return from another's.
    let mine = structural_prefix(&s);
    assert!(structural_key(&s, &device(), 5).has_prefix(&mine));
    assert!(!structural_key(&deeper, &device(), 5).has_prefix(&mine));
    assert!(!heads_key(&deeper, b"path").has_prefix(&heads_prefix(&s)));
    assert!(!epoch_key(&deeper, &device(), 5).has_prefix(&epoch_prefix(&s)));

    // The seq orders numerically, and the key parses back.
    let keys: Vec<Name> = [1, 2, 255, 256, 70_000]
        .into_iter()
        .map(|seq| structural_key(&s, &device(), seq))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "{keys:?}");
    assert_eq!(
        parse_structural_key(&s, &keys[3]),
        Some((device(), 256)),
        "start replays the structural entries by what the key says"
    );
    assert_eq!(parse_structural_key(&deeper, &keys[3]), None);
    assert_eq!(parse_structural_key(&s, &head_key(&s)), None);

    assert_ne!(heads_key(&s, b"a"), heads_key(&s, b"b"));
    assert_eq!(heads_key(&s, b"a"), heads_key(&s, b"a"));
}

/// A marker at `seq` of `device` in the space: its digest is `[seq; 32]`,
/// its previous entry `prev_seq` (digest `[prev_seq; 32]`, zero from 0).
fn mark(store: &dyn DataStore, seq: u64, prev_seq: u64) {
    let digest = |s: u64| if s == 0 { [0; 32] } else { [s as u8; 32] };
    store.insert(
        verified_key(&log_name(&device(), &space(), seq)),
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

fn tip(seq: u64) -> Link {
    Link {
        seq,
        digest: [seq as u8; 32],
    }
}

#[test]
fn a_chain_walk_reads_markers_only_and_follows_a_declared_gap() {
    // No entry is stored anywhere: only markers. 1 <- 2 <- 3, then the
    // device lost 4 and 5 and signed 6 over 3 (a gap statement).
    let store = MemoryStore::new();
    mark(&store, 1, 0);
    mark(&store, 2, 1);
    mark(&store, 3, 2);
    mark(&store, 6, 3);
    let walk = walk_chain(&store, &device(), &space(), tip(6));
    assert_eq!(walk.links, vec![tip(6), tip(3), tip(2), tip(1)]);
    assert_eq!(walk.end, ChainEnd::Genesis);
    assert!(walk.is_complete());
}

#[test]
fn a_chain_walk_names_the_missing_link_the_diverging_one_and_the_corrupt_one() {
    let store = MemoryStore::new();
    mark(&store, 1, 0);
    mark(&store, 3, 2);
    mark(&store, 4, 3);
    let walk = walk_chain(&store, &device(), &space(), tip(4));
    assert_eq!(walk.links, vec![tip(4), tip(3)]);
    assert_eq!(
        walk.end,
        ChainEnd::Missing { seq: 2 },
        "the seq to fetch next"
    );
    assert!(!walk.is_complete());

    // The tip's digest is not the marker's: another packet at that seq.
    let walk = walk_chain(
        &store,
        &device(),
        &space(),
        Link {
            seq: 4,
            digest: [0xee; 32],
        },
    );
    assert!(walk.links.is_empty());
    assert_eq!(
        walk.end,
        ChainEnd::Diverges {
            seq: 4,
            expected: [0xee; 32],
            found: [4; 32]
        }
    );

    // A marker whose previous seq is not below its own would loop for ever.
    mark(&store, 8, 8);
    let walk = walk_chain(&store, &device(), &space(), tip(8));
    assert_eq!(walk.end, ChainEnd::Corrupt { seq: 8 });

    // A marker that does not decode is a corrupt link, not a missing one.
    store.insert(
        verified_key(&log_name(&device(), &space(), 9)),
        Bytes::from_static(&[0; 5]),
    );
    let walk = walk_chain(&store, &device(), &space(), tip(9));
    assert_eq!(walk.end, ChainEnd::Corrupt { seq: 9 });
}
