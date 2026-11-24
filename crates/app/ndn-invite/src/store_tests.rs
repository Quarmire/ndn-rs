//! The keys of the state the exchange keeps (`store.rs`) and the durable
//! writes over them.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::{DataStore, MemoryStore, StoreOp};

use crate::store::{
    accepted_key, apply_durable, closed_key, flush, grant_key, grant_listing, hint_key, key_key,
    list, mirror_key, mirror_listing, offer_key, offer_listing, parse_grant_key, parse_mirror_key,
    parse_offer_key, put_durable, remove_durable, root, tries_asker_key, tries_key, used_key,
    using_key,
};
use crate::wire::{OFFER_ID_LEN, OfferId};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn id(tag: u8) -> OfferId {
    [tag; OFFER_ID_LEN]
}

/// A store that counts the flushes asked of it and records whether the write
/// was in it when the flush came.
struct Counting {
    inner: MemoryStore,
    syncs: AtomicUsize,
    watch: Name,
    held_at_sync: AtomicBool,
}

impl Counting {
    fn new(watch: Name) -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryStore::new(),
            syncs: AtomicUsize::new(0),
            watch,
            held_at_sync: AtomicBool::new(false),
        })
    }
}

impl DataStore for Counting {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.inner.remove(name);
    }
    fn apply(&self, ops: Vec<StoreOp>) {
        self.inner.apply(ops);
    }
    fn sync(&self) -> std::io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        self.held_at_sync
            .store(self.inner.get(&self.watch).is_some(), Ordering::SeqCst);
        Ok(())
    }
}

/// Every key sits under `/localhost/ndn-invite/`, a prefix no device serves,
/// in the shape the contract lists: the kind, then the id (one generic component
/// of 16 octets), then for the asker's counter its key's digest.
#[test]
fn every_key_is_under_the_invite_prefix_in_its_shape() {
    assert_eq!(root(), n("/localhost/ndn-invite"));
    let space = n("/alice/32=data/notes");
    let digest = [9u8; 32];
    for (key, kind, tail) in [
        (offer_key(&id(1)), "offer", vec![16]),
        (key_key(&id(1)), "key", vec![16]),
        (tries_key(&id(1)), "tries", vec![16]),
        (tries_asker_key(&id(1), &digest), "tries", vec![16, 32]),
        (using_key(&id(1)), "using", vec![16]),
        (accepted_key(&id(1)), "accepted", vec![16]),
        (closed_key(&id(1)), "closed", vec![16]),
        (used_key(&id(1)), "used", vec![16]),
        (hint_key(&id(1)), "hint", vec![16]),
        (grant_key(&id(1)), "grant", vec![16]),
        (mirror_key(&space, &digest), "mirror", vec![]),
    ] {
        assert!(key.has_prefix(&root()), "{key}");
        let comps = key.components();
        assert_eq!(&comps[root().len()].value[..], kind.as_bytes(), "{key}");
        assert_eq!(
            comps[root().len()].typ,
            8,
            "the kind is a generic component"
        );
        if !tail.is_empty() {
            let lens: Vec<usize> = comps[root().len() + 1..]
                .iter()
                .map(|c| c.value.len())
                .collect();
            assert_eq!(lens, tail, "{key}");
        }
    }
}

/// No two kinds share a key, no two ids do, and the asker's counter lies under
/// its offer's counter and no other's.
#[test]
fn keys_of_different_kinds_and_ids_never_meet() {
    let builders: [fn(&OfferId) -> Name; 9] = [
        offer_key,
        key_key,
        tries_key,
        using_key,
        accepted_key,
        closed_key,
        used_key,
        hint_key,
        grant_key,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for build in builders {
        for tag in [1u8, 2] {
            assert!(seen.insert(build(&id(tag))), "a key is shared");
        }
    }
    assert!(tries_asker_key(&id(1), &[3; 32]).has_prefix(&tries_key(&id(1))));
    assert!(!tries_asker_key(&id(1), &[3; 32]).has_prefix(&tries_key(&id(2))));
    assert_ne!(
        tries_asker_key(&id(1), &[3; 32]),
        tries_asker_key(&id(1), &[4; 32])
    );
    // `used` and `using` are two kinds, not one a prefix of the other.
    assert!(!using_key(&id(1)).has_prefix(&used_key(&id(1))));
    assert!(!used_key(&id(1)).has_prefix(&using_key(&id(1))));
}

/// A key names its id back, and only a key of its kind does.
#[test]
fn keys_parse_back() {
    let (a, b) = (id(7), n("/alice/32=data/notes"));
    assert_eq!(parse_offer_key(&offer_key(&a)), Some(a));
    assert_eq!(parse_offer_key(&grant_key(&a)), None);
    assert_eq!(parse_offer_key(&offer_key(&a).append("more")), None);
    assert_eq!(
        parse_offer_key(&root().append("offer").append([1u8; 15])),
        None
    );
    assert_eq!(parse_grant_key(&grant_key(&a)), Some(a));
    assert_eq!(parse_grant_key(&offer_key(&a)), None);
    assert_eq!(
        parse_mirror_key(&b, &mirror_key(&b, &[1; 32])),
        Some([1; 32])
    );
    assert_eq!(
        parse_mirror_key(&n("/alice/32=data/other"), &mirror_key(&b, &[1; 32])),
        None
    );
}

/// A space is a prefix of the spaces that extend it: spelled as components,
/// a listing of one space's keys would list another's. Each is one component
/// holding its `Name` TLV, so a listing holds exactly its own.
#[test]
fn a_space_listing_holds_that_space_and_no_space_that_extends_it() {
    let (short, long) = (n("/alice/32=data/notes"), n("/alice/32=data/notes/old"));
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    assert!(mirror_key(&short, &k1).has_prefix(&mirror_listing(&short)));
    assert!(mirror_key(&short, &k2).has_prefix(&mirror_listing(&short)));
    assert!(!mirror_key(&long, &k1).has_prefix(&mirror_listing(&short)));
    assert!(mirror_key(&long, &k1).has_prefix(&mirror_listing(&long)));
    assert!(grant_key(&id(1)).has_prefix(&grant_listing()));
    assert!(offer_key(&id(1)).has_prefix(&offer_listing()));
    assert!(!offer_key(&id(1)).has_prefix(&grant_listing()));
}

/// A durable write is in the store, and a flush was asked for after it was and
/// returned before the write did.
#[tokio::test]
async fn a_durable_write_is_flushed_after_it_lands() {
    let key = offer_key(&id(1));
    let counting = Counting::new(key.clone());
    let store: Arc<dyn DataStore> = counting.clone();
    put_durable(&store, key.clone(), Bytes::from_static(b"note"))
        .await
        .unwrap();
    assert_eq!(store.get(&key), Some(Bytes::from_static(b"note")));
    assert_eq!(counting.syncs.load(Ordering::SeqCst), 1);
    assert!(
        counting.held_at_sync.load(Ordering::SeqCst),
        "flushed before it landed"
    );

    remove_durable(&store, &key).await.unwrap();
    assert_eq!(store.get(&key), None);
    assert_eq!(counting.syncs.load(Ordering::SeqCst), 2);

    // A batch is handed over whole and flushed once.
    let (a, b) = (used_key(&id(1)), accepted_key(&id(1)));
    apply_durable(
        &store,
        vec![
            StoreOp::Insert(a.clone(), Bytes::from_static(b"1")),
            StoreOp::Insert(b.clone(), Bytes::from_static(b"2")),
        ],
    )
    .await
    .unwrap();
    assert_eq!(store.get(&a), Some(Bytes::from_static(b"1")));
    assert_eq!(store.get(&b), Some(Bytes::from_static(b"2")));
    assert_eq!(counting.syncs.load(Ordering::SeqCst), 3);

    flush(&store).await.unwrap();
    assert_eq!(counting.syncs.load(Ordering::SeqCst), 4);
}

/// A store that cannot flush says so, with what to do; nothing is reported as
/// durable.
#[tokio::test]
async fn a_failed_flush_is_an_error_that_says_what_to_do() {
    struct Failing(MemoryStore);
    impl DataStore for Failing {
        fn insert(&self, name: Name, wire: Bytes) {
            self.0.insert(name, wire);
        }
        fn get(&self, name: &Name) -> Option<Bytes> {
            self.0.get(name)
        }
        fn remove(&self, name: &Name) {
            self.0.remove(name);
        }
        fn sync(&self) -> std::io::Result<()> {
            Err(std::io::Error::other("no space left"))
        }
    }
    let store: Arc<dyn DataStore> = Arc::new(Failing(MemoryStore::new()));
    let err = put_durable(&store, offer_key(&id(1)), Bytes::from_static(b"x"))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("no space left") && text.contains("fix this device"),
        "{text}"
    );
}

/// A listing returns what is under it, in name order, with the key and value.
#[test]
fn a_listing_returns_the_notes_under_a_prefix_in_order() {
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    store.insert(grant_key(&id(2)), Bytes::from_static(b"two"));
    store.insert(grant_key(&id(1)), Bytes::from_static(b"one"));
    store.insert(offer_key(&id(1)), Bytes::from_static(b"offer"));
    let got = list(&*store, &grant_listing());
    assert_eq!(
        got,
        vec![
            (grant_key(&id(1)), Bytes::from_static(b"one")),
            (grant_key(&id(2)), Bytes::from_static(b"two")),
        ]
    );
}
