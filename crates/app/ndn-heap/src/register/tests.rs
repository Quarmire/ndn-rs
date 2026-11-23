//! The register's invariants: the state is a function of the set of applied
//! entries, never of the order they arrived in, and no value is held.
//!
//! A [`Replica`] plays the log's part: it keeps the store's `heads/` and
//! `supers/` records the register's writes make, answers the register's
//! lookups from them, and knows which entries are applied.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::StoreOp;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

use super::*;
use crate::store::{heads_prefix, supers_key};
use crate::test_kit::n;

/// An entry as the log hands it over.
#[derive(Clone, Debug)]
struct Ent {
    id: EntryRef,
    write: Write,
    after: Vec<EntryRef>,
}

fn space() -> Name {
    n("/alice/32=data/notes")
}

/// The entry `seq` of device `/p<person>/d<device>` over `path`, digest
/// `digest` in every octet, superseding `after`.
fn ent(
    person: u8,
    device: u8,
    seq: u64,
    digest: u8,
    path: &str,
    bytes: &str,
    after: &[&Ent],
) -> Ent {
    Ent {
        id: EntryRef {
            device: n(&format!("/p{person}/d{device}")),
            seq,
            digest: [digest; 32],
        },
        write: Write {
            path: n(path),
            person: n(&format!("/p{person}")),
            removal: bytes.is_empty(),
            size: bytes.len() as u64,
        },
        after: after.iter().map(|e| e.id.clone()).collect(),
    }
}

/// A replica: one register, the store records it asked to be written, and
/// the entries the log has applied.
struct Replica {
    reg: Register,
    store: BTreeMap<Name, Bytes>,
    applied: BTreeMap<EntryRef, Write>,
}

impl Replica {
    fn new() -> Replica {
        Replica {
            reg: Register::new(space()),
            store: BTreeMap::new(),
            applied: BTreeMap::new(),
        }
    }

    fn run(&mut self, effects: Effects) -> Vec<ValueChange> {
        for op in effects.writes {
            match op {
                StoreOp::Insert(name, wire) => {
                    self.store.insert(name, wire);
                }
                StoreOp::Remove(name) => {
                    self.store.remove(&name);
                }
            }
        }
        effects.changes
    }

    /// The log's `supers/` lookup over this replica's store.
    fn lookup(store: &BTreeMap<Name, Bytes>) -> impl Fn(&EntryRef) -> Vec<EntryRef> + '_ {
        |x| {
            store
                .get(&supers_key(&space(), &x.device, x.seq))
                .map(|b| decode_refs(b).expect("the register's own record decodes"))
                .unwrap_or_default()
        }
    }

    fn take(&mut self, e: &Ent) -> Vec<ValueChange> {
        self.applied.insert(e.id.clone(), e.write.clone());
        let fx = self
            .reg
            .apply(&e.id, &e.write, &e.after, &Self::lookup(&self.store));
        self.run(fx)
    }

    fn refuse(&mut self, e: &Ent) -> Vec<ValueChange> {
        self.applied.remove(&e.id);
        let applied = &self.applied;
        let fx = self
            .reg
            .withdraw(&e.id, &e.after, &Self::lookup(&self.store), &|x| {
                applied.get(x).cloned()
            });
        self.run(fx)
    }

    fn take_all<'a>(&mut self, es: impl IntoIterator<Item = &'a Ent>) {
        for e in es {
            self.take(e);
        }
    }

    /// The winner of `path`: its entry, or `None` for no value (nothing
    /// written, or a removal).
    fn value(&self, path: &str) -> Option<EntryRef> {
        self.reg.value(&n(path)).map(|h| h.entry.clone())
    }

    /// Every path's heads, as the register holds them.
    fn heads(&self) -> BTreeMap<Name, BTreeSet<EntryRef>> {
        self.reg
            .paths_with_heads()
            .map(|(p, hs)| (p.clone(), hs.iter().map(|h| h.entry.clone()).collect()))
            .collect()
    }

    /// Every path's heads, as the store's `heads/` records say.
    fn persisted(&self) -> BTreeMap<Name, BTreeSet<EntryRef>> {
        let prefix = heads_prefix(&space());
        let records = self
            .store
            .iter()
            .filter(|(k, _)| k.has_prefix(&prefix))
            .map(|(k, v)| (k.clone(), v.clone()));
        let restored = Register::restore(space(), records, &|x| self.applied.get(x).cloned())
            .expect("the register's own records restore");
        assert!(
            restored.missing.is_empty(),
            "every persisted head is applied"
        );
        let by_restore: BTreeMap<_, BTreeSet<_>> = restored
            .register
            .paths_with_heads()
            .map(|(p, hs)| (p.clone(), hs.iter().map(|h| h.entry.clone()).collect()))
            .collect();
        assert_eq!(
            winners(&restored.register),
            winners(&self.reg),
            "a restored register answers as the live one"
        );
        by_restore
    }
}

/// The heads of every path by the definition: the applied entries no applied
/// entry's `after` names.
fn expected_heads(applied: &[&Ent]) -> BTreeMap<Name, BTreeSet<EntryRef>> {
    let named: BTreeSet<&EntryRef> = applied.iter().flat_map(|e| &e.after).collect();
    let mut out: BTreeMap<Name, BTreeSet<EntryRef>> = BTreeMap::new();
    for e in applied.iter().filter(|e| !named.contains(&e.id)) {
        out.entry(e.write.path.clone())
            .or_default()
            .insert(e.id.clone());
    }
    out
}

/// The winner of `path` by the definition: the head with the highest
/// digest, then device, then seq.
fn expected_winner(heads: &BTreeSet<EntryRef>) -> Option<&EntryRef> {
    heads
        .iter()
        .max_by_key(|h| (h.digest, h.device.clone(), h.seq))
}

// -- Ported from ndf's `newest.rs` -------------------------------------------------

#[test]
fn a_version_over_another_replaces_it_whatever_the_digests() {
    let a1 = ent(1, 1, 1, 200, "/f", "old", &[]);
    let a2 = ent(1, 1, 2, 1, "/f", "new", &[&a1]);
    let mut r = Replica::new();
    assert_eq!(r.value("/f"), None, "nothing written reads as nothing");
    r.take(&a1);
    let changes = r.take(&a2);
    assert_eq!(r.value("/f"), Some(a2.id.clone()));
    assert_eq!(
        r.reg.heads_of(&n("/f")).len(),
        1,
        "the superseded entry is no head"
    );
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].was.as_ref().map(|h| &h.entry), Some(&a1.id));
    assert_eq!(changes[0].now.as_ref().map(|h| &h.entry), Some(&a2.id));
}

#[test]
fn concurrent_versions_give_one_winner_in_any_order() {
    let a = ent(1, 1, 1, 5, "/f", "from a", &[]);
    let b = ent(2, 1, 1, 9, "/f", "from b", &[]);
    let (mut s, mut t) = (Replica::new(), Replica::new());
    s.take_all([&a, &b]);
    t.take_all([&b, &a]);
    assert_eq!(s.value("/f"), Some(b.id.clone()));
    assert_eq!(s.value("/f"), t.value("/f"));
    assert_eq!(s.heads(), t.heads());
    // A version made over both settles it, whatever its digest.
    let merged = ent(1, 1, 2, 0, "/f", "merged", &[&a, &b]);
    let changes = s.take(&merged);
    assert_eq!(s.value("/f"), Some(merged.id.clone()));
    assert_eq!(s.reg.heads_of(&n("/f")).len(), 1);
    assert_eq!(changes.len(), 1);
}

#[test]
fn an_empty_version_is_a_removal() {
    let a1 = ent(1, 1, 1, 1, "/f", "x", &[]);
    let a2 = ent(1, 1, 2, 2, "/f", "", &[&a1]);
    let mut r = Replica::new();
    r.take(&a1);
    r.take(&a2);
    assert_eq!(r.value("/f"), None, "a removal is not a value");
    let winner = r.reg.winner(&n("/f")).expect("the removal still decides");
    assert!(winner.removal);
    assert_eq!(winner.entry, a2.id);
    assert_eq!(r.reg.values().count(), 0, "the first listing omits it");
}

// -- Plan 3.10 ------------------------------------------------------------------------

#[test]
fn two_offline_writers_converge_on_the_highest_digest() {
    // Each writes twice while the other is away.
    let a1 = ent(1, 1, 1, 10, "/f", "a1", &[]);
    let a2 = ent(1, 1, 2, 3, "/f", "a2", &[&a1]);
    let b1 = ent(2, 1, 1, 4, "/f", "b1", &[]);
    let b2 = ent(2, 1, 2, 7, "/f", "b2", &[&b1]);
    let (mut a, mut b) = (Replica::new(), Replica::new());
    a.take_all([&a1, &a2]);
    b.take_all([&b1, &b2]);
    assert_eq!(a.value("/f"), Some(a2.id.clone()));
    assert_eq!(b.value("/f"), Some(b2.id.clone()));
    // They meet: each applies what the other wrote, in the order it was made.
    a.take_all([&b1, &b2]);
    b.take_all([&a1, &a2]);
    assert_eq!(
        a.value("/f"),
        Some(b2.id.clone()),
        "the highest digest wins"
    );
    assert_eq!(a.value("/f"), b.value("/f"));
    assert_eq!(a.heads(), b.heads());
    assert_eq!(a.reg.heads_of(&n("/f")).len(), 2);
    // The next put names both heads and ends the fork.
    let after = a.reg.after_for_put(&n("/f"));
    assert_eq!(after.len(), 2);
    let c = Ent {
        id: EntryRef {
            device: n("/p1/d1"),
            seq: 3,
            digest: [0; 32],
        },
        write: Write {
            path: n("/f"),
            person: n("/p1"),
            removal: false,
            size: 1,
        },
        after,
    };
    a.take(&c);
    b.take(&c);
    assert_eq!(a.value("/f"), Some(c.id.clone()));
    assert_eq!(a.heads(), b.heads());
    assert_eq!(a.reg.heads_of(&n("/f")).len(), 1);
}

#[test]
fn a_removal_is_the_newest_until_someone_puts_again() {
    let put = ent(1, 1, 1, 9, "/f", "x", &[]);
    let gone = ent(1, 1, 2, 1, "/f", "", &[&put]);
    let again = ent(2, 1, 1, 0, "/f", "y", &[&gone]);
    let mut r = Replica::new();
    r.take(&put);
    assert_eq!(r.value("/f"), Some(put.id.clone()));
    let changes = r.take(&gone);
    assert_eq!(r.value("/f"), None);
    assert!(
        changes[0].now.as_ref().is_some_and(|h| h.removal),
        "watch sends Removed"
    );
    // A put that never saw the removal does not undo it when its digest is
    // lower, and does when it is higher: the order is the digest's.
    let blind_low = ent(2, 1, 1, 0, "/f", "z", &[]);
    r.take(&blind_low);
    assert_eq!(r.value("/f"), None, "the removal's digest is higher");
    let blind_high = ent(3, 1, 1, 200, "/f", "w", &[]);
    r.take(&blind_high);
    assert_eq!(r.value("/f"), Some(blind_high.id.clone()));
    // Someone who saw the removal puts again, whatever the digest.
    let mut s = Replica::new();
    s.take_all([&put, &gone]);
    s.take(&again);
    assert_eq!(s.value("/f"), Some(again.id.clone()));
    assert_eq!(s.reg.heads_of(&n("/f")).len(), 1);
}

#[test]
fn more_than_eight_concurrent_heads_converge() {
    // Twelve writers put at once, none having seen another.
    let writers: Vec<Ent> = (1..=12)
        .map(|i| ent(i, 1, 1, i * 10, "/f", "v", &[]))
        .collect();
    let (mut forward, mut backward) = (Replica::new(), Replica::new());
    forward.take_all(&writers);
    backward.take_all(writers.iter().rev());
    assert_eq!(forward.reg.heads_of(&n("/f")).len(), 12);
    assert_eq!(forward.heads(), backward.heads());
    // A put lists eight: the eight highest digests.
    let after = forward.reg.after_for_put(&n("/f"));
    assert_eq!(after.len(), AFTER_MAX);
    let mut digests: Vec<u8> = after.iter().map(|r| r.digest[0]).collect();
    digests.sort_unstable();
    assert_eq!(digests, (5..=12).map(|i| i * 10).collect::<Vec<u8>>());
    assert_eq!(
        after,
        backward.reg.after_for_put(&n("/f")),
        "every replica lists the same eight"
    );
    // The other four remain heads beside the new entry; every replica agrees.
    let put = ent(1, 1, 2, 1, "/f", "next", &[]);
    let put = Ent {
        after: after.clone(),
        ..put
    };
    forward.take(&put);
    backward.take(&put);
    assert_eq!(forward.reg.heads_of(&n("/f")).len(), 5);
    assert_eq!(forward.heads(), backward.heads());
    assert_eq!(forward.value("/f"), backward.value("/f"));
    assert_eq!(
        forward.value("/f").map(|r| r.digest[0]),
        Some(40),
        "the highest remaining head wins"
    );
    // The next put names five and ends the fork.
    let rest = forward.reg.after_for_put(&n("/f"));
    assert_eq!(rest.len(), 5);
}

#[test]
fn withdrawing_a_head_restores_the_entry_it_superseded() {
    let a = ent(1, 1, 1, 5, "/f", "a", &[]);
    let b = ent(1, 1, 2, 9, "/f", "b", &[&a]);
    let mut r = Replica::new();
    r.take_all([&a, &b]);
    let changes = r.refuse(&b);
    assert_eq!(
        r.value("/f"),
        Some(a.id.clone()),
        "its place is taken by what it superseded"
    );
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].was.as_ref().map(|h| &h.entry), Some(&b.id));
    assert_eq!(changes[0].now.as_ref().map(|h| &h.entry), Some(&a.id));
    assert_eq!(r.heads(), r.persisted());
    // A superseded entry still named by another applied entry stays hidden.
    let c = ent(2, 1, 1, 1, "/f", "c", &[&a]);
    r.take(&c);
    let d = ent(2, 1, 2, 2, "/f", "d", &[&c]);
    r.take(&d);
    r.refuse(&d);
    assert_eq!(r.value("/f"), Some(c.id.clone()));
    assert_eq!(r.reg.heads_of(&n("/f")).len(), 1, "a is still named by c");
    // The last head withdrawn with nothing under it leaves the path empty.
    let mut s = Replica::new();
    s.take(&a);
    let changes = s.refuse(&a);
    assert_eq!(s.value("/f"), None);
    assert!(changes[0].now.is_none());
    assert!(
        s.store
            .keys()
            .all(|k| !k.has_prefix(&heads_prefix(&space())))
    );
}

#[test]
fn a_withdrawn_namer_gives_a_late_arriving_superseded_entry_its_place_back() {
    let x = ent(1, 1, 1, 5, "/f", "x", &[]);
    let namer = ent(2, 1, 1, 1, "/f", "n", &[&x]);
    // The namer arrives first: x, which it supersedes, is not yet held.
    let mut r = Replica::new();
    r.take(&namer);
    r.take(&x);
    assert_eq!(
        r.heads()[&n("/f")],
        BTreeSet::from([namer.id.clone()]),
        "a late x is not a head"
    );
    assert_eq!(r.value("/f"), Some(namer.id.clone()));
    // The namer is refused before x arrives: x then takes its place.
    let mut s = Replica::new();
    s.take(&namer);
    s.refuse(&namer);
    assert_eq!(s.value("/f"), None);
    let changes = s.take(&x);
    assert_eq!(s.value("/f"), Some(x.id.clone()));
    assert_eq!(changes.len(), 1);
    // The namer refused after x arrived (x is held back under it) restores x.
    r.refuse(&namer);
    assert_eq!(r.value("/f"), Some(x.id.clone()));
    assert_eq!(r.heads(), s.heads());
    assert_eq!(r.heads(), r.persisted());
}

#[test]
fn memory_is_o_heads_not_o_entries() {
    let mut r = Replica::new();
    let mut last: Option<Ent> = None;
    for seq in 1..=10_000u64 {
        let e = Ent {
            id: EntryRef {
                device: n("/p1/d1"),
                seq,
                digest: Sha256::digest(seq.to_be_bytes()).into(),
            },
            write: Write {
                path: n("/f"),
                person: n("/p1"),
                removal: false,
                size: 3,
            },
            after: last.iter().map(|l| l.id.clone()).collect(),
        };
        r.take(&e);
        last = Some(e);
    }
    assert_eq!(r.reg.head_count(), 1);
    assert_eq!(r.reg.heads_of(&n("/f")).len(), 1);
    assert_eq!(r.value("/f"), last.map(|l| l.id));
    assert_eq!(
        r.store
            .keys()
            .filter(|k| k.has_prefix(&heads_prefix(&space())))
            .count(),
        1,
        "one record per path"
    );
}

#[test]
fn a_value_is_never_held_in_the_register() {
    // Compiles only while a head is exactly a reference, a person, whether it
    // removes, and a size: a field of bytes added to it breaks this pattern.
    let head = Head {
        entry: EntryRef {
            device: n("/p1/d1"),
            seq: 1,
            digest: [1; 32],
        },
        person: n("/p1"),
        removal: false,
        size: 4,
    };
    let Head {
        entry: _,
        person: _,
        removal: _,
        size: _,
    } = head.clone();
    // The item a reader gets is built from a head and bytes the log read.
    let item = head.item(&n("/f"), Bytes::from_static(b"data"));
    assert_eq!(item.bytes, Bytes::from_static(b"data"));
    assert_eq!(item.by, n("/p1"));
    assert_eq!(item.writer, n("/p1/d1"));
    assert_eq!(item.id, EntryId::from(&head.entry));
    assert_eq!(item.as_of, None);
}

#[test]
fn a_duplicate_changes_nothing_and_writes_nothing() {
    let a = ent(1, 1, 1, 5, "/f", "a", &[]);
    let b = ent(1, 1, 2, 9, "/f", "b", &[&a]);
    let mut r = Replica::new();
    r.take_all([&a, &b]);
    let before = (r.heads(), r.store.clone());
    for e in [&a, &b, &a] {
        let fx = r
            .reg
            .apply(&e.id, &e.write, &e.after, &Replica::lookup(&r.store));
        assert!(
            fx.writes.is_empty() && fx.changes.is_empty(),
            "{:?} again",
            e.id
        );
    }
    assert_eq!((r.heads(), r.store.clone()), before);
}

#[test]
fn a_persisted_head_whose_entry_is_gone_is_reported_not_dropped_silently() {
    let a = ent(1, 1, 1, 5, "/f", "a", &[]);
    let mut r = Replica::new();
    r.take(&a);
    let prefix = heads_prefix(&space());
    let records: Vec<_> = r
        .store
        .iter()
        .filter(|(k, _)| k.has_prefix(&prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let restored = Register::restore(space(), records.clone(), &|_| None).expect("well formed");
    assert_eq!(restored.missing, vec![a.id.clone()]);
    assert_eq!(restored.register.head_count(), 0);
    // A record that is not the register's is refused, not skipped.
    let (key, mut value) = records.into_iter().next().expect("one record");
    let mut bad = value.to_vec();
    bad.truncate(bad.len() - 1);
    value = Bytes::from(bad);
    assert!(Register::restore(space(), vec![(key, value)], &|_| None).is_err());
    let moved = (
        n("/localhost/ndn-heap/heads/elsewhere"),
        r.store.values().next().cloned().unwrap(),
    );
    assert!(Register::restore(space(), vec![moved], &|_| None).is_err());
}

#[test]
fn an_item_converts_from_a_reference_and_back() {
    let r = EntryRef {
        device: n("/p1/d1"),
        seq: 7,
        digest: [3; 32],
    };
    let id = EntryId::from(&r);
    assert_eq!(
        (id.device.clone(), id.seq, id.digest),
        (r.device.clone(), 7, [3; 32])
    );
    assert_eq!(EntryRef::from(&id), r);
}

// -- Arrival order ---------------------------------------------------------------------

/// A generated history: `entries[i]` supersedes some of the entries before it.
#[derive(Clone, Debug)]
struct Shape {
    path: u8,
    removal: bool,
    person: u8,
    digest: u8,
    after: Vec<usize>,
}

fn shapes() -> impl Strategy<Value = Vec<Shape>> {
    prop::collection::vec(
        (
            0u8..3,
            any::<bool>(),
            0u8..3,
            0u8..6,
            prop::collection::vec(any::<usize>(), 0..4),
        ),
        1..14,
    )
    .prop_map(|v| {
        v.into_iter()
            .enumerate()
            .map(|(i, (path, removal, person, digest, picks))| {
                let mut after: Vec<usize> = if i == 0 {
                    Vec::new()
                } else {
                    picks.into_iter().map(|p| p % i).collect()
                };
                after.sort_unstable();
                after.dedup();
                Shape {
                    path,
                    removal,
                    person,
                    digest,
                    after,
                }
            })
            .collect()
    })
}

/// The entries of a history: each its own device, so no two are the same
/// entry whatever the digests (small digests force ties).
fn build(shapes: &[Shape]) -> Vec<Ent> {
    let mut out: Vec<Ent> = Vec::new();
    for (i, s) in shapes.iter().enumerate() {
        let after: Vec<&Ent> = s.after.iter().map(|&j| &out[j]).collect();
        let bytes = if s.removal { "" } else { "v" };
        let e = ent(
            s.person,
            i as u8,
            1,
            s.digest,
            &format!("/path{}", s.path),
            bytes,
            &after,
        );
        out.push(e);
    }
    out
}

/// Every index once in a random order, with repeats inserted at random
/// points (a duplicate may come before, between or after other deliveries).
fn deliveries(len: usize) -> impl Strategy<Value = Vec<usize>> {
    (
        Just((0..len).collect::<Vec<_>>()).prop_shuffle(),
        prop::collection::vec((0..len, any::<usize>()), 0..len + 3),
    )
        .prop_map(|(mut order, dups)| {
            for (entry, at) in dups {
                order.insert(at % (order.len() + 1), entry);
            }
            order
        })
}

/// The winning entry of every path that has heads.
fn winners(reg: &Register) -> BTreeMap<Name, EntryRef> {
    reg.paths_with_heads()
        .map(|(p, hs)| (p.clone(), hs[0].entry.clone()))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn register_state_is_independent_of_arrival_order(
        shapes in shapes(),
        order_a in deliveries(14),
        order_b in deliveries(14),
    ) {
        let entries = build(&shapes);
        let deliver = |order: &[usize]| {
            let mut r = Replica::new();
            for &i in order.iter().filter(|&&i| i < entries.len()) {
                r.take(&entries[i]);
            }
            r
        };
        let (a, b) = (deliver(&order_a), deliver(&order_b));
        let all: Vec<&Ent> = entries.iter().collect();
        let expected = expected_heads(&all);
        prop_assert_eq!(&a.heads(), &expected);
        prop_assert_eq!(&b.heads(), &expected);
        for (path, heads) in &expected {
            let winner = expected_winner(heads);
            prop_assert_eq!(a.reg.winner(path).map(|h| &h.entry), winner);
            prop_assert_eq!(b.reg.winner(path).map(|h| &h.entry), winner);
            prop_assert_eq!(a.reg.after_for_put(path), b.reg.after_for_put(path));
            prop_assert!(a.reg.after_for_put(path).len() <= AFTER_MAX);
        }
        prop_assert_eq!(a.persisted(), expected.clone());
        prop_assert_eq!(b.persisted(), expected);
    }

    #[test]
    fn withdrawal_leaves_what_never_applying_would_have_left(
        shapes in shapes(),
        order in deliveries(14),
        refused in prop::collection::vec(any::<bool>(), 14),
        refusals in Just((0..14).collect::<Vec<usize>>()).prop_shuffle(),
        after_order in deliveries(14),
    ) {
        let entries = build(&shapes);
        let refused: BTreeSet<usize> = (0..entries.len()).filter(|&i| refused[i]).collect();
        // Everything arrives, then the refused entries leave in some order.
        let mut a = Replica::new();
        for &i in order.iter().filter(|&&i| i < entries.len()) {
            a.take(&entries[i]);
        }
        for &i in refusals.iter().filter(|i| refused.contains(i)) {
            a.refuse(&entries[i]);
        }
        // The same replica had never heard of them.
        let mut b = Replica::new();
        for &i in after_order.iter().filter(|&&i| i < entries.len() && !refused.contains(&i)) {
            b.take(&entries[i]);
        }
        let kept: Vec<&Ent> = (0..entries.len()).filter(|i| !refused.contains(i)).map(|i| &entries[i]).collect();
        let expected = expected_heads(&kept);
        prop_assert_eq!(&a.heads(), &expected);
        prop_assert_eq!(&b.heads(), &expected);
        prop_assert_eq!(a.persisted(), expected);
        prop_assert_eq!(winners(&a.reg), winners(&b.reg));
    }
}
