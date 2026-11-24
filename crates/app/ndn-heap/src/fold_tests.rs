//! Invariants of the membership fold: every query is a function of the
//! facts, never of the order they arrived in.

use std::collections::BTreeSet;
use std::str::FromStr;

use ndn_foundation_types::Name;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use super::*;
use crate::wire::{EntryRef, EpochBody, EpochId, MembersBody, Op, Role};

const PERSONS: u8 = 4;
const DEVICES: u8 = 3;
const EPOCH_CREATORS: u8 = 2;
const EPOCH_SEQS: u64 = 3;

fn name(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn owner() -> Name {
    name("/o")
}

fn person(i: u8) -> Name {
    name(&format!("/p/{i}"))
}

fn id(i: u8) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[0] = i;
    a
}

fn carrier(device: u8, seq: u64, digest: u8) -> EntryRef {
    EntryRef {
        device: name(&format!("/o/d{device}")),
        seq,
        digest: [digest; 32],
    }
}

fn eid(creator: u8, seq: u64) -> EpochId {
    EpochId {
        creator: name(&format!("/o/d{creator}")),
        seq,
    }
}

fn add(i: u8, who: Name, role: Role) -> Op {
    Op::Add {
        id: id(i),
        who,
        role,
        epoch: None,
    }
}

fn reader_in(i: u8, who: Name, epoch: EpochId) -> Op {
    Op::Add {
        id: id(i),
        who,
        role: Role::Reader,
        epoch: Some(epoch),
    }
}

fn remove(i: u8, tips: Vec<EntryRef>) -> Op {
    Op::Remove { id: id(i), tips }
}

fn members(ops: Vec<Op>) -> MembersBody {
    MembersBody { create: None, ops }
}

fn epoch_body(audience: Vec<Name>) -> EpochBody {
    EpochBody {
        key_check: [7; 32],
        audience,
    }
}

fn names(v: &[Name]) -> Vec<Name> {
    v.to_vec()
}

/// The `after` of an Epoch entry that replaces `epochs`.
fn refs(epochs: &[EpochId]) -> Vec<EntryRef> {
    epochs
        .iter()
        .map(|e| EntryRef {
            device: e.creator.clone(),
            seq: e.seq,
            digest: [0; 32],
        })
        .collect()
}

// ---- the property test ----------------------------------------------------

#[derive(Clone, Debug)]
enum Event {
    Members(EntryRef, MembersBody),
    Epoch(EpochId, EpochBody, Vec<EpochId>),
}

fn apply(fold: &mut Fold, event: &Event) {
    match event {
        Event::Members(carrier, body) => fold.apply_members(carrier, body),
        Event::Epoch(id, body, replaces) => fold.apply_epoch(id.clone(), body, &refs(replaces)),
    }
}

/// Everything the rest of the crate may ask of a fold.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    writers: Vec<Name>,
    readers: Readers,
    anyone: Option<bool>,
    epochs: Vec<EpochId>,
    tips: Vec<(Name, Vec<EntryRef>)>,
    audiences: Vec<(EpochId, BTreeSet<Name>)>,
    holders: Vec<(EpochId, BTreeSet<Name>)>,
    epoch_tips: Vec<EpochId>,
    in_force: Option<EpochId>,
    complete: bool,
    removed_writers: Vec<(Name, Vec<EntryRef>)>,
}

fn snapshot(f: &Fold) -> Snapshot {
    let mut who: Vec<Name> = (0..PERSONS).map(person).collect();
    who.push(owner());
    let mut pool = Vec::new();
    for c in 0..EPOCH_CREATORS {
        for s in 1..=EPOCH_SEQS {
            pool.push(eid(c, s));
        }
    }
    Snapshot {
        writers: f.writers(),
        readers: f.readers(),
        anyone: f.create(),
        epochs: f.epochs(),
        tips: who.iter().map(|p| (p.clone(), f.removal_tips(p))).collect(),
        audiences: pool.iter().map(|e| (e.clone(), f.audience(e))).collect(),
        holders: pool.iter().map(|e| (e.clone(), f.holders(e))).collect(),
        epoch_tips: f.epoch_tips(),
        in_force: f.in_force(),
        complete: f.complete(),
        removed_writers: f.removed_writers(),
    }
}

fn arb_who() -> impl Strategy<Value = Name> {
    // `PERSONS` is the owner: an Add naming the owner is allowed and ignored by removals.
    (0..=PERSONS).prop_map(|p| if p == PERSONS { owner() } else { person(p) })
}

fn arb_epoch_id() -> impl Strategy<Value = EpochId> {
    (0..EPOCH_CREATORS, 1..=EPOCH_SEQS).prop_map(|(c, s)| eid(c, s))
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            0u8..6,
            arb_who(),
            any::<bool>(),
            proptest::option::of(arb_epoch_id())
        )
            .prop_map(|(i, who, writer, epoch)| Op::Add {
                id: id(i),
                who,
                role: if writer { Role::Writer } else { Role::Reader },
                epoch,
            }),
        (0u8..6, vec(0..DEVICES, 0..3)).prop_map(|(i, tips)| Op::Remove {
            id: id(i),
            tips: tips
                .into_iter()
                .map(|d| carrier(d, u64::from(d) + 1, 200))
                .collect(),
        }),
    ]
}

/// What an entry carries, before it is given a carrier.
#[derive(Clone, Debug)]
enum Content {
    Members(Option<bool>, Vec<Op>),
    Epoch(EpochId, Vec<Name>, Vec<EpochId>),
}

fn arb_content() -> impl Strategy<Value = Content> {
    prop_oneof![
        3 => (
            proptest::option::weighted(0.1, any::<bool>()),
            vec(arb_op(), 0..4)
        )
            .prop_map(|(create, ops)| Content::Members(create, ops)),
        1 => (arb_epoch_id(), vec(arb_who(), 0..5), vec(arb_epoch_id(), 0..3))
            .prop_map(|(e, audience, replaces)| Content::Epoch(e, audience, replaces)),
    ]
}

/// A history (each entry once, carriers distinct) and the same entries
/// arriving in a random order with random duplicates.
fn arb_history() -> impl Strategy<Value = (Vec<Event>, Vec<Event>)> {
    (vec(arb_content(), 1..12), vec(any::<Index>(), 0..6)).prop_flat_map(|(contents, dups)| {
        let events: Vec<Event> = contents
            .into_iter()
            .enumerate()
            .map(|(n, c)| match c {
                Content::Members(create, ops) => Event::Members(
                    carrier((n % usize::from(DEVICES)) as u8, n as u64 + 1, n as u8 + 1),
                    MembersBody { create, ops },
                ),
                Content::Epoch(e, audience, replaces) => {
                    Event::Epoch(e, epoch_body(audience), replaces)
                }
            })
            .collect();
        let mut all = events.clone();
        for d in dups {
            all.push(events[d.index(events.len())].clone());
        }
        (Just(events), Just(all).prop_shuffle())
    })
}

fn fold_of(events: &[Event]) -> Fold {
    let mut f = Fold::new(owner());
    for e in events {
        apply(&mut f, e);
    }
    f
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn fold_state_is_independent_of_arrival_order((events, shuffled) in arb_history()) {
        let canonical = snapshot(&fold_of(&events));
        prop_assert_eq!(&canonical, &snapshot(&fold_of(&shuffled)));
        // Applying everything twice changes nothing.
        let mut twice = fold_of(&shuffled);
        for e in &shuffled {
            apply(&mut twice, e);
        }
        prop_assert_eq!(&canonical, &snapshot(&twice));
    }

    #[test]
    fn withdrawing_a_members_entry_equals_never_having_seen_it(
        (events, shuffled) in arb_history(),
        pick in any::<Index>(),
    ) {
        let carriers: Vec<&EntryRef> = events
            .iter()
            .filter_map(|e| match e { Event::Members(c, _) => Some(c), Event::Epoch(..) => None })
            .collect();
        prop_assume!(!carriers.is_empty());
        let gone = carriers[pick.index(carriers.len())].clone();
        let without: Vec<Event> = events
            .iter()
            .filter(|e| !matches!(e, Event::Members(c, _) if *c == gone))
            .cloned()
            .collect();
        let mut f = fold_of(&shuffled);
        prop_assert!(f.withdraw_members(&gone));
        prop_assert_eq!(snapshot(&fold_of(&without)), snapshot(&f));
        prop_assert!(!f.withdraw_members(&gone));
    }

    #[test]
    fn withdrawing_an_epoch_equals_never_having_seen_it(
        (events, shuffled) in arb_history(),
        pick in any::<Index>(),
    ) {
        let ids: Vec<&EpochId> = events
            .iter()
            .filter_map(|e| match e { Event::Epoch(id, ..) => Some(id), Event::Members(..) => None })
            .collect();
        prop_assume!(!ids.is_empty());
        let gone = ids[pick.index(ids.len())].clone();
        let without: Vec<Event> = events
            .iter()
            .filter(|e| !matches!(e, Event::Epoch(id, ..) if *id == gone))
            .cloned()
            .collect();
        let mut f = fold_of(&shuffled);
        prop_assert!(f.withdraw_epoch(&gone));
        prop_assert_eq!(snapshot(&fold_of(&without)), snapshot(&f));
        prop_assert!(!f.withdraw_epoch(&gone));
    }

    /// An epoch's key is held by everyone it was ever given to, so only an
    /// epoch no removed reader holds may stay in force.
    #[test]
    fn holders_never_shrink_and_bound_the_epoch_in_force((events, _) in arb_history()) {
        let f = fold_of(&events);
        let readers: BTreeSet<Name> = match f.readers() {
            Readers::Persons(p) => p.into_iter().collect(),
            Readers::Anyone => BTreeSet::new(),
        };
        for c in 0..EPOCH_CREATORS {
            for s in 1..=EPOCH_SEQS {
                let e = eid(c, s);
                prop_assert!(f.audience(&e).is_subset(&f.holders(&e)));
            }
        }
        if let Some(e) = f.in_force() {
            prop_assert!(f.holders(&e).is_subset(&readers));
            prop_assert!(f.epoch_tips().contains(&e), "no replaced epoch is in force");
            prop_assert_eq!(f.complete(), f.holders(&e) == readers);
        }
        // No Remove, and no withdrawal of a Remove, ever takes a holder away.
        let kept: Vec<Event> = events
            .iter()
            .map(|e| match e {
                Event::Members(c, b) => Event::Members(
                    c.clone(),
                    MembersBody {
                        create: b.create,
                        ops: b.ops.iter().filter(|o| matches!(o, Op::Add { .. })).cloned().collect(),
                    },
                ),
                other => other.clone(),
            })
            .collect();
        let bare = fold_of(&kept);
        for c in 0..EPOCH_CREATORS {
            for s in 1..=EPOCH_SEQS {
                let e = eid(c, s);
                prop_assert_eq!(f.holders(&e), bare.holders(&e));
            }
        }
    }
}

// ---- the rules ------------------------------------------------------------

#[test]
fn removal_beats_an_add_of_the_same_id() {
    let adds = members(vec![add(1, person(0), Role::Writer)]);
    let removes = members(vec![remove(1, vec![])]);
    let (c1, c2) = (carrier(0, 1, 1), carrier(0, 2, 2));
    for add_first in [true, false] {
        let mut f = Fold::new(owner());
        if add_first {
            f.apply_members(&c1, &adds);
            f.apply_members(&c2, &removes);
        } else {
            f.apply_members(&c2, &removes);
            f.apply_members(&c1, &adds);
        }
        assert!(!f.is_writer(&person(0)));
        assert_eq!(f.writers(), vec![owner()]);
    }
}

#[test]
fn a_fresh_id_readmits() {
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![add(1, person(0), Role::Writer)]),
    );
    f.apply_members(&carrier(0, 2, 2), &members(vec![remove(1, vec![])]));
    assert!(!f.is_writer(&person(0)));
    // The same id can never come back; another id is a new admission.
    f.apply_members(
        &carrier(0, 3, 3),
        &members(vec![add(1, person(0), Role::Writer)]),
    );
    assert!(!f.is_writer(&person(0)));
    f.apply_members(
        &carrier(0, 4, 4),
        &members(vec![add(2, person(0), Role::Writer)]),
    );
    assert!(f.is_writer(&person(0)));
    assert_eq!(f.writers(), vec![owner(), person(0)]);
}

#[test]
fn the_owner_cannot_be_removed() {
    let tip = carrier(1, 5, 9);
    // Removal before the Add is known, and after it.
    for remove_first in [true, false] {
        let mut f = Fold::new(owner());
        let a = members(vec![
            add(1, owner(), Role::Writer),
            add(2, owner(), Role::Reader),
        ]);
        let r = members(vec![
            remove(1, vec![tip.clone()]),
            remove(2, vec![tip.clone()]),
        ]);
        if remove_first {
            f.apply_members(&carrier(0, 2, 2), &r);
            f.apply_members(&carrier(0, 1, 1), &a);
        } else {
            f.apply_members(&carrier(0, 1, 1), &a);
            f.apply_members(&carrier(0, 2, 2), &r);
        }
        assert!(f.is_writer(&owner()));
        assert_eq!(f.writers(), vec![owner()]);
        assert_eq!(f.readers(), Readers::Persons(vec![owner()]));
        assert!(f.removal_tips(&owner()).is_empty());
    }
    // Even with no Add at all, the owner writes and reads.
    let f = Fold::new(owner());
    assert!(f.is_writer(&owner()));
    assert!(f.is_reader(&owner()));
}

#[test]
fn the_owner_reads_unless_the_space_is_public() {
    let mut f = Fold::new(owner());
    assert_eq!(f.readers(), Readers::Persons(vec![owner()]));
    f.apply_members(
        &carrier(0, 1, 1),
        &MembersBody {
            create: Some(true),
            ops: vec![],
        },
    );
    assert_eq!(f.readers(), Readers::Anyone);
    assert!(f.is_reader(&person(3)));
    // A public space needs no epoch.
    assert_eq!(f.in_force(), None);
    assert!(f.complete());
}

#[test]
fn duplicate_add_ids_keep_the_lowest_carrier_digest() {
    let low = members(vec![add(1, person(0), Role::Writer)]);
    let high = members(vec![add(1, person(1), Role::Writer)]);
    let (c_low, c_high) = (carrier(1, 1, 3), carrier(0, 1, 8));
    for low_first in [true, false] {
        let mut f = Fold::new(owner());
        if low_first {
            f.apply_members(&c_low, &low);
            f.apply_members(&c_high, &high);
        } else {
            f.apply_members(&c_high, &high);
            f.apply_members(&c_low, &low);
        }
        assert!(f.is_writer(&person(0)));
        assert!(!f.is_writer(&person(1)));
        // The removal names the id, so it takes the winning Add whichever it is.
        f.apply_members(&carrier(0, 2, 9), &members(vec![remove(1, vec![])]));
        assert_eq!(f.writers(), vec![owner()]);
    }
}

#[test]
fn the_create_of_the_lowest_carrier_digest_wins() {
    let public = MembersBody {
        create: Some(true),
        ops: vec![],
    };
    let private = MembersBody {
        create: Some(false),
        ops: vec![],
    };
    for private_first in [true, false] {
        let mut f = Fold::new(owner());
        if private_first {
            f.apply_members(&carrier(0, 1, 2), &private);
            f.apply_members(&carrier(1, 1, 5), &public);
        } else {
            f.apply_members(&carrier(1, 1, 5), &public);
            f.apply_members(&carrier(0, 1, 2), &private);
        }
        assert_eq!(f.create(), Some(false));
        assert_eq!(f.readers(), Readers::Persons(vec![owner()]));
    }
}

#[test]
fn removal_tips_are_the_union_over_every_removed_writer_add_of_that_person() {
    let (t1, t2, t3) = (carrier(1, 4, 1), carrier(2, 6, 2), carrier(1, 9, 3));
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![
            add(1, person(0), Role::Writer),
            add(2, person(0), Role::Writer),
            add(3, person(1), Role::Writer),
            add(4, person(0), Role::Reader),
        ]),
    );
    f.apply_members(
        &carrier(0, 2, 2),
        &members(vec![
            remove(1, vec![t1.clone(), t2.clone()]),
            remove(3, vec![t3.clone()]),
        ]),
    );
    f.apply_members(
        &carrier(1, 1, 3),
        &members(vec![remove(2, vec![t2.clone()])]),
    );
    f.apply_members(
        &carrier(1, 2, 4),
        &members(vec![remove(4, vec![t3.clone()])]),
    );
    let mut want = vec![t1, t2];
    want.sort();
    assert_eq!(f.removal_tips(&person(0)), want);
    assert_eq!(f.removal_tips(&person(1)), vec![t3]);
    assert!(f.removal_tips(&person(2)).is_empty());
}

#[test]
fn removed_writers_lists_each_person_removed_and_not_readmitted() {
    let (t1, t2, t3) = (carrier(1, 4, 1), carrier(2, 6, 2), carrier(1, 9, 3));
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![
            add(1, person(0), Role::Writer),
            add(2, person(0), Role::Writer),
            add(3, person(1), Role::Writer),
            add(4, person(2), Role::Writer),
            add(5, person(3), Role::Reader),
            add(6, owner(), Role::Writer),
        ]),
    );
    f.apply_members(
        &carrier(0, 2, 2),
        &members(vec![
            remove(1, vec![t1.clone()]),
            remove(2, vec![t2.clone()]),
            remove(3, vec![t3.clone()]),
            remove(5, vec![t3.clone()]),
            remove(6, vec![t3.clone()]),
        ]),
    );
    // Person 1 is admitted again under a fresh id; person 0 is not. Persons
    // who were only readers, and the owner, are never listed.
    f.apply_members(
        &carrier(0, 3, 3),
        &members(vec![add(7, person(1), Role::Writer)]),
    );
    let mut tips = vec![t1, t2];
    tips.sort();
    assert_eq!(f.removed_writers(), vec![(person(0), tips.clone())]);
    f.apply_members(&carrier(0, 4, 4), &members(vec![remove(7, vec![])]));
    assert_eq!(
        f.removed_writers(),
        vec![(person(0), tips), (person(1), vec![t3]),]
    );
}

#[test]
fn removal_record_names_the_lowest_entry_that_removed_a_person_listed_no_more() {
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![
            add(1, person(0), Role::Writer),
            add(2, person(0), Role::Reader),
            add(3, person(1), Role::Reader),
            add(4, owner(), Role::Writer),
        ]),
    );
    for who in [person(0), person(1), person(2), owner()] {
        assert_eq!(f.removal_record(&who), None, "{who} was not removed");
    }
    // Two owner devices each remove one of her Adds: while the other stands
    // she is still listed, and once both are gone the entry of the lower
    // rank (signed digest first) is the one named.
    let (late, early) = (carrier(1, 5, 9), carrier(0, 2, 2));
    f.apply_members(&late, &members(vec![remove(2, vec![])]));
    assert_eq!(f.removal_record(&person(0)), None, "still a writer");
    f.apply_members(&early, &members(vec![remove(1, vec![])]));
    assert_eq!(f.removal_record(&person(0)), Some(early.clone()));
    f.apply_members(&carrier(0, 3, 3), &members(vec![remove(3, vec![])]));
    assert_eq!(f.removal_record(&person(1)), Some(carrier(0, 3, 3)));
    // A Remove of the owner's Add is ignored, so the owner has no record.
    f.apply_members(&carrier(0, 4, 4), &members(vec![remove(4, vec![])]));
    assert_eq!(f.removal_record(&owner()), None);
    // Admitted again under a fresh id: listed, so nothing removed her.
    f.apply_members(
        &carrier(0, 6, 6),
        &members(vec![add(5, person(0), Role::Writer)]),
    );
    assert_eq!(f.removal_record(&person(0)), None);
    // Removed again by a third entry: the lowest of the three is named.
    f.apply_members(&carrier(0, 7, 7), &members(vec![remove(5, vec![])]));
    assert_eq!(f.removal_record(&person(0)), Some(early.clone()));
    // The record follows the carriers: an entry withdrawn removes nobody.
    assert!(f.withdraw_members(&early));
    assert_eq!(f.removal_record(&person(0)), None, "her first Add stands again");
}

#[test]
fn in_force_picks_the_greatest_epoch_whose_audience_is_within_readers() {
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![add(1, person(0), Role::Reader)]),
    );
    let (e1, e2, e3) = (eid(0, 1), eid(0, 2), eid(1, 1));
    f.apply_epoch(e1.clone(), &epoch_body(vec![owner()]), &[]);
    assert_eq!(f.in_force(), Some(e1.clone()));
    assert!(!f.complete(), "person 0 reads but is not in the audience");
    f.apply_epoch(e2.clone(), &epoch_body(vec![owner(), person(0)]), &[]);
    assert_eq!(f.in_force(), Some(e2.clone()));
    assert!(f.complete());
    // An epoch naming someone who is no reader is never in force.
    f.apply_epoch(
        e3.clone(),
        &epoch_body(vec![owner(), person(0), person(1)]),
        &[],
    );
    assert_eq!(f.in_force(), Some(e2.clone()));
    // Ordered by creator name first, then seq.
    f.apply_members(
        &carrier(0, 2, 2),
        &members(vec![add(2, person(1), Role::Reader)]),
    );
    assert_eq!(f.in_force(), Some(e3));
    assert!(f.complete());
    // Losing a reader takes the epoch that named them out of force.
    f.apply_members(&carrier(0, 3, 3), &members(vec![remove(2, vec![])]));
    assert_eq!(f.in_force(), Some(e2));
}

#[test]
fn a_removed_reader_leaves_no_epoch_in_force_until_the_owner_repairs() {
    let mut f = Fold::new(owner());
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![add(1, person(0), Role::Reader)]),
    );
    f.apply_epoch(eid(0, 1), &epoch_body(vec![owner(), person(0)]), &[]);
    assert!(f.complete());
    f.apply_members(&carrier(0, 2, 2), &members(vec![remove(1, vec![])]));
    assert_eq!(f.in_force(), None);
    assert!(!f.complete());
    f.apply_epoch(eid(0, 2), &epoch_body(names(&[owner()])), &[]);
    assert_eq!(f.in_force(), Some(eid(0, 2)));
    assert!(f.complete());
}

#[test]
fn audience_adds_the_readers_granted_the_epoch_and_drops_the_removed() {
    let e = eid(0, 1);
    let mut f = Fold::new(owner());
    f.apply_epoch(e.clone(), &epoch_body(vec![owner()]), &[]);
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![
            reader_in(1, person(0), e.clone()),
            reader_in(2, person(1), e.clone()),
            reader_in(3, person(2), eid(1, 1)),
        ]),
    );
    let want: BTreeSet<Name> = [owner(), person(0), person(1)].into_iter().collect();
    assert_eq!(f.audience(&e), want);
    f.apply_members(&carrier(0, 2, 2), &members(vec![remove(2, vec![])]));
    let want: BTreeSet<Name> = [owner(), person(0)].into_iter().collect();
    assert_eq!(f.audience(&e), want);
}

#[test]
fn a_reader_added_to_an_epoch_and_removed_leaves_it_out_of_force() {
    // Alice's epoch names only her; Bob is added to it, then removed: the epoch
    // is again for exactly the readers, but Bob still holds its key.
    let e = eid(0, 1);
    let mut f = Fold::new(owner());
    f.apply_epoch(e.clone(), &epoch_body(vec![owner()]), &[]);
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![reader_in(1, person(0), e.clone())]),
    );
    assert_eq!(f.in_force(), Some(e.clone()));
    assert!(f.complete());
    f.apply_members(&carrier(0, 2, 2), &members(vec![remove(1, vec![])]));
    assert_eq!(
        f.in_force(),
        None,
        "the removed reader holds the epoch's key"
    );
    assert!(!f.complete());
    // The owner's repair is a fresh epoch, which Bob was never admitted to.
    f.apply_epoch(eid(0, 2), &epoch_body(names(&[owner()])), &[]);
    assert_eq!(f.in_force(), Some(eid(0, 2)));
    assert!(f.complete());
}

#[test]
fn holders_keep_every_reader_ever_named_to_an_epoch_and_the_audience_only_the_standing() {
    let e = eid(0, 1);
    let mut f = Fold::new(owner());
    f.apply_epoch(e.clone(), &epoch_body(vec![owner()]), &[]);
    f.apply_members(
        &carrier(0, 1, 1),
        &members(vec![reader_in(1, person(0), e.clone())]),
    );
    f.apply_members(&carrier(0, 2, 2), &members(vec![remove(1, vec![])]));
    let holders: BTreeSet<Name> = [owner(), person(0)].into_iter().collect();
    assert_eq!(f.holders(&e), holders);
    assert_eq!(f.audience(&e), [owner()].into_iter().collect());
}

#[test]
fn an_epoch_a_held_epoch_replaces_is_never_in_force_whatever_their_order() {
    // The creator that sorts last made the old epoch, so by order alone it
    // would beat the rotation the other owner device signed after it.
    let (old, new) = (eid(1, 1), eid(0, 5));
    let mut f = Fold::new(owner());
    f.apply_epoch(old.clone(), &epoch_body(vec![owner()]), &[]);
    assert_eq!(f.in_force(), Some(old.clone()));
    f.apply_epoch(
        new.clone(),
        &epoch_body(vec![owner()]),
        &refs(std::slice::from_ref(&old)),
    );
    assert_eq!(f.in_force(), Some(new.clone()));
    assert_eq!(f.epoch_tips(), vec![new.clone()]);
    assert!(f.complete());
    // The replacing entry withdrawn (its signer's key revoked): never signed.
    assert!(f.withdraw_epoch(&new));
    assert_eq!(f.in_force(), Some(old.clone()));
    assert_eq!(f.epoch_tips(), vec![old]);
}

#[test]
fn equivocating_epoch_bodies_resolve_to_one_regardless_of_order() {
    let e = eid(0, 1);
    let a = EpochBody {
        key_check: [1; 32],
        audience: vec![owner()],
    };
    let b = EpochBody {
        key_check: [2; 32],
        audience: vec![owner(), person(0)],
    };
    let mut ab = Fold::new(owner());
    ab.apply_epoch(e.clone(), &a, &[]);
    ab.apply_epoch(e.clone(), &b, &[]);
    let mut ba = Fold::new(owner());
    ba.apply_epoch(e.clone(), &b, &[]);
    ba.apply_epoch(e.clone(), &a, &[]);
    assert_eq!(ab.epoch_body(&e), ba.epoch_body(&e));
    assert_eq!(ab.audience(&e), ba.audience(&e));
}

#[test]
fn withdrawing_an_epoch_takes_it_out_of_force() {
    let mut f = Fold::new(owner());
    f.apply_epoch(eid(0, 1), &epoch_body(vec![owner()]), &[]);
    f.apply_epoch(eid(0, 2), &epoch_body(vec![owner()]), &[]);
    assert_eq!(f.in_force(), Some(eid(0, 2)));
    assert!(f.withdraw_epoch(&eid(0, 2)));
    assert_eq!(f.in_force(), Some(eid(0, 1)));
    assert!(!f.withdraw_epoch(&eid(0, 2)));
}

/// Two owner devices each remove a reader without seeing the other's removal,
/// then repair by rule 7 (sign an Epoch whose audience is `readers()` whenever
/// `!complete()`): both end with the same, complete, epoch.
#[test]
fn concurrent_removals_leave_a_complete_epoch_after_each_owner_device_repairs() {
    let setup = members(vec![
        add(1, person(0), Role::Reader),
        add(2, person(1), Role::Reader),
        add(3, person(2), Role::Reader),
    ]);
    let everyone = vec![owner(), person(0), person(1), person(2)];
    let (setup_c, rm1_c, rm2_c) = (carrier(0, 1, 1), carrier(0, 2, 5), carrier(1, 1, 6));
    let rm1 = members(vec![remove(2, vec![])]);
    let rm2 = members(vec![remove(3, vec![])]);

    let mut d0 = Fold::new(owner());
    let mut d1 = Fold::new(owner());
    for f in [&mut d0, &mut d1] {
        f.apply_members(&setup_c, &setup);
        f.apply_epoch(eid(0, 1), &epoch_body(everyone.clone()), &[]);
        assert!(f.complete());
    }
    d0.apply_members(&rm1_c, &rm1);
    d1.apply_members(&rm2_c, &rm2);
    // Each device alone can already tell it is incomplete, and repairs.
    let repair = |f: &mut Fold, creator: u8, seq: u64| {
        assert!(!f.complete());
        let Readers::Persons(audience) = f.readers() else {
            panic!("private space")
        };
        let e = eid(creator, seq);
        let body = epoch_body(audience);
        f.apply_epoch(e.clone(), &body, &[]);
        assert!(f.complete());
        (e, body)
    };
    let (e0, b0) = repair(&mut d0, 0, 2);
    let (e1, b1) = repair(&mut d1, 1, 2);
    // They merge: the union of removals leaves neither repair within the readers.
    d0.apply_members(&rm2_c, &rm2);
    d0.apply_epoch(e1.clone(), &b1, &[]);
    d1.apply_members(&rm1_c, &rm1);
    d1.apply_epoch(e0.clone(), &b0, &[]);
    assert_eq!(snapshot(&d0), snapshot(&d1));
    assert!(!d0.complete());
    // Each owner device repairs again against the merged state.
    let (e0, b0) = repair(&mut d0, 0, 3);
    let (e1, b1) = repair(&mut d1, 1, 3);
    d0.apply_epoch(e1.clone(), &b1, &[]);
    d1.apply_epoch(e0, &b0, &[]);
    assert_eq!(snapshot(&d0), snapshot(&d1));
    assert!(d0.complete());
    assert_eq!(d0.in_force(), Some(e1));
    assert_eq!(d0.readers(), Readers::Persons(vec![owner(), person(0)]));
}
