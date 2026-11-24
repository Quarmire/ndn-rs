//! The devices heard in a sync group (spec §7): bounded whatever a Sync
//! Interest names, a device held data vouches for never displaced by a name
//! that Interest carried, a name at counter 0 never kept, and the relays a
//! `32=held` ask goes to only ever vouched for.

use super::*;
use crate::test_kit::n;
use std::collections::BTreeSet;

fn device(i: usize) -> Name {
    n(&format!("/alice/d{i}"))
}

/// A device that vouches for exactly the names in `set`.
fn vouching(set: &BTreeSet<Name>) -> impl Fn(&Name) -> bool + '_ {
    |d| set.contains(d)
}

/// A flood of names (here 1 000, Sync Interests are unsigned) leaves at most
/// [`HEARD_MAX`] devices heard; the devices held data vouches for are all
/// still heard, whatever came after them.
#[test]
fn heard_never_displaces_a_vouched_device() {
    let vouched: BTreeSet<Name> = (0..HEARD_MAX).map(device).collect();
    let mut heard = Heard::default();
    for d in &vouched {
        assert!(
            heard.hear(d.clone(), 1, vouching(&vouched)).kept,
            "{d}: there is room for a device that is vouched for"
        );
    }
    assert_eq!(heard.len(), HEARD_MAX);
    for i in 1000..2000 {
        let fake = device(i);
        let hearing = heard.hear(fake.clone(), 1, vouching(&vouched));
        assert!(
            !hearing.kept,
            "{fake}: with every device heard vouched for, an unvouched name is the one dropped"
        );
        assert_eq!(hearing.dropped, Some(fake), "the name itself, nothing else");
    }
    assert_eq!(heard.len(), HEARD_MAX, "bounded");
    for d in &vouched {
        assert!(heard.contains(d), "{d}: a vouched device was displaced");
    }
}

/// The device heard longest ago that nothing vouches for goes first, and a
/// vouched device older than every one of them stays.
#[test]
fn the_oldest_unvouched_device_is_dropped_first() {
    let vouched: BTreeSet<Name> = [device(0)].into_iter().collect();
    let mut heard = Heard::default();
    for i in 0..HEARD_MAX {
        heard.hear(device(i), 1, vouching(&vouched));
    }
    let hearing = heard.hear(device(5000), 1, vouching(&vouched));
    assert!(hearing.kept);
    assert_eq!(
        hearing.dropped,
        Some(device(1)),
        "device 0 is older but vouched for: the oldest of the others goes"
    );
    assert!(heard.contains(&device(0)) && heard.contains(&device(5000)));
    // Hearing a device again makes it the newest, not a second entry.
    heard.hear(device(2), 1, vouching(&vouched));
    let hearing = heard.hear(device(5001), 1, vouching(&vouched));
    assert_eq!(hearing.dropped, Some(device(3)), "device 2 was heard again");
    assert_eq!(heard.len(), HEARD_MAX);
}

/// A state vector entry at counter 0 names a device with nothing to fetch:
/// it is not heard, takes no room, and displaces no one.
#[test]
fn a_vector_naming_a_device_at_counter_zero_is_ignored() {
    let none = BTreeSet::new();
    let mut heard = Heard::default();
    for i in 0..HEARD_MAX {
        assert!(heard.hear(device(i), 1, vouching(&none)).kept);
    }
    for i in 100..400 {
        let hearing = heard.hear(device(i), 0, vouching(&none));
        assert!(!hearing.kept, "{}: at counter 0, not kept", device(i));
        assert_eq!(hearing.dropped, None, "nobody was displaced for it");
        assert!(!heard.contains(&device(i)));
    }
    assert_eq!(heard.len(), HEARD_MAX);
    assert!(
        (0..HEARD_MAX).all(|i| heard.contains(&device(i))),
        "every device heard at a counter above 0 is still heard"
    );
    // A device already heard that now shows counter 0 stays as it was.
    assert!(!heard.hear(device(3), 0, vouching(&none)).kept);
    assert!(heard.contains(&device(3)));
}

/// One Sync Interest naming 250 devices leaves the list within
/// [`HEARD_MAX`], the one device held data vouches for among them.
#[test]
fn a_sync_interest_naming_many_devices_leaves_the_list_bounded() {
    let laptop = n("/alice/laptop");
    let vouched: BTreeSet<Name> = [laptop.clone()].into_iter().collect();
    let mut heard = Heard::default();
    assert!(heard.hear(laptop.clone(), 3, vouching(&vouched)).kept);
    for i in 0..250 {
        heard.hear(device(i), u64::from(i < 200), vouching(&vouched));
        assert!(heard.len() <= HEARD_MAX, "{} heard", heard.len());
    }
    assert!(heard.contains(&laptop));
    assert!(
        heard.iter().all(|d| *d == laptop || {
            let i: usize = d
                .to_string()
                .trim_start_matches("/alice/d")
                .parse()
                .unwrap();
            i < 200
        }),
        "no name at counter 0 is kept"
    );
}

/// Whom a `32=held` ask goes to: vouched devices only, never this device,
/// the writer, one to skip or one ended; those whose first entries were held
/// before the others' come first; at most [`RELAYS_ASKED`].
#[test]
fn relays_are_vouched_for_ranked_and_bounded() {
    let me = n("/alice/me");
    let writer = n("/alice/writer");
    let mut heard = Heard::default();
    let everyone = |d: &Name| d.to_string().len() > 100;
    for d in [&me, &writer] {
        heard.hear(d.clone(), 1, everyone);
    }
    for i in 0..30 {
        heard.hear(device(i), 1, everyone);
    }
    let unvouched = device(7);
    let ended = device(8);
    let skipped = device(9);
    let first = |d: &Name| *d == device(20) || *d == device(21);
    let standing = |d: &Name| {
        if *d == unvouched || *d == ended {
            None
        } else {
            Some(first(d))
        }
    };
    let asked = heard.relays(&me, &writer, std::slice::from_ref(&skipped), standing);
    assert_eq!(asked.len(), RELAYS_ASKED);
    assert_eq!(
        asked[..2],
        [device(20), device(21)],
        "those held first lead, the rest by name"
    );
    for gone in [&me, &writer, &unvouched, &ended, &skipped] {
        assert!(!asked.contains(gone), "{gone} must not be asked");
    }
    let mut sorted = asked.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), asked.len(), "each device once");
}

/// The holders the host configured come after the relays, never this device, the writer or a
/// relay twice, and never past [`RELAYS_ASKED`] with them: a holder displaces no relay.
#[test]
fn holders_follow_the_relays_within_the_bound_and_never_displace_one() {
    let me = n("/alice/me");
    let writer = n("/alice/writer");
    let holders = vec![
        me.clone(),
        writer.clone(),
        device(1),
        device(50),
        device(51),
    ];
    let few = vec![device(1), device(2)];
    assert_eq!(
        holders_after(&holders, &me, &writer, &few),
        vec![device(50), device(51)],
        "not this device, the writer or a relay already listed"
    );
    let many: Vec<Name> = (0..RELAYS_ASKED - 1).map(device).collect();
    assert_eq!(
        holders_after(&holders, &me, &writer, &many),
        vec![device(50)],
        "the relays and holders together are at most RELAYS_ASKED"
    );
    let full: Vec<Name> = (0..RELAYS_ASKED).map(device).collect();
    assert!(holders_after(&holders, &me, &writer, &full).is_empty());
}

/// An epoch key is asked of its creator first, then of the relays; a creator
/// that is this device is not asked.
#[test]
fn granters_are_the_creator_then_the_relays() {
    let me = n("/alice/me");
    let creator = n("/alice/creator");
    let mut heard = Heard::default();
    for d in [&me, &creator, &device(1), &device(2)] {
        heard.hear(d.clone(), 1, |_| true);
    }
    let all = |_: &Name| Some(false);
    assert_eq!(
        heard.granters(&me, &creator, all),
        vec![creator.clone(), device(1), device(2)],
        "creator first; the creator is not asked twice, this device never"
    );
    assert_eq!(
        heard.granters(&me, &me, all),
        vec![device(1), device(2), creator],
        "this device created the epoch: it asks others only"
    );
}
