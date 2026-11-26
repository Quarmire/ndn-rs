//! The sender's channel table: re-keying, caps, the asker's bucket, what runs out. Time is an
//! `Instant` the case moves by hand: no case reads a clock.

use std::time::Duration;

use ndn_foundation_types::Name;

use super::*;
use crate::wire::EpochId;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn space() -> Name {
    n("/alice/32=data/notes")
}

/// The person of a test device: its first name component (`/bob/phone` is `/bob`'s).
fn person_of(device: &Name) -> Name {
    Name::from_components(device.components()[..1].iter().cloned())
}

fn ask<'a>(device: &'a Name, person: &'a Name, key: &'a Name, wanted: u64) -> Asker<'a> {
    Asker {
        device,
        person,
        key,
        wanted,
        new: false,
        stream: true,
    }
}

fn admit(
    table: &Channels,
    device: &Name,
    key: &Name,
    wanted: u64,
    now: Instant,
) -> Result<Admitted, Cap> {
    table.admit(
        &space(),
        ChannelMode::Latest,
        &ask(device, &person_of(device), key, wanted),
        None,
        (1, 1),
        now,
    )
}

#[test]
fn a_renewal_rekeys_and_an_ask_sooner_or_by_a_holder_of_an_older_key_does_not() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let first = admit(&table, &bob, &bob_key, 3600, t0).unwrap();
    assert_eq!((first.key_epoch, first.rekeyed), (0, false));
    let carol_first = admit(&table, &carol, &carol_key, 3600, t0).unwrap();
    assert_eq!(carol_first.id, first.id, "one channel per space and mode");
    assert_eq!(
        carol_first.key.expose(),
        first.key.expose(),
        "the same key to every receiver"
    );

    // Bob asks again at once: the same key, nothing re-keyed.
    let again = admit(&table, &bob, &bob_key, 3600, t0 + Duration::from_secs(10)).unwrap();
    assert_eq!((again.key_epoch, again.rekeyed), (0, false));

    // At 75 % of an hour, bob renews: a new key epoch, the same channel id.
    let renewed = admit(&table, &bob, &bob_key, 3600, t0 + Duration::from_secs(2700)).unwrap();
    assert_eq!(renewed.id, first.id);
    assert_eq!((renewed.key_epoch, renewed.rekeyed), (1, true));
    assert_ne!(
        renewed.key.expose(),
        first.key.expose(),
        "a re-key is a new key"
    );

    // Carol still holds epoch 0: asking is given the key as it is now, no second re-key.
    let pulled = admit(
        &table,
        &carol,
        &carol_key,
        3600,
        t0 + Duration::from_secs(2701),
    )
    .unwrap();
    assert_eq!((pulled.key_epoch, pulled.rekeyed), (1, false));
    assert_eq!(pulled.key.expose(), renewed.key.expose());
}

#[test]
fn a_dropped_receiver_rekeys_the_channel_at_once_and_a_moved_audience_epoch_does_too() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let id = admit(&table, &bob, &bob_key, 3600, t0).unwrap().id;
    admit(&table, &carol, &carol_key, 3600, t0).unwrap();
    assert_eq!(table.receiver_count(&space(), ChannelMode::Latest), 2);

    // Everyone stands: nothing moves, and the judgement is what the table holds now.
    let done = table.rejudged(&space(), (2, 2), None, t0, |_, _| true);
    assert_eq!(done, Rejudged::default());
    assert_eq!(
        table.judged_at(&space()),
        vec![(ChannelMode::Latest, (2, 2))]
    );

    // Bob no longer stands: dropped, and a new key at once.
    let done = table.rejudged(&space(), (3, 3), None, t0, |device, _| *device != bob);
    assert_eq!(done.dropped, vec![(ChannelMode::Latest, bob.clone())]);
    assert_eq!(done.rekeyed, vec![ChannelMode::Latest]);
    let now = table.current(&space(), ChannelMode::Latest).unwrap();
    assert_eq!((now.id, now.key_epoch), (id, 1));
    assert_eq!(table.receivers(&space()).len(), 1);

    // The audience epoch moved: re-keyed with nobody dropped.
    let epoch = EpochId {
        creator: n("/alice/laptop"),
        seq: 2,
    };
    let done = table.rejudged(&space(), (4, 4), Some(&epoch), t0, |_, _| true);
    assert_eq!(done.dropped, vec![]);
    assert_eq!(done.rekeyed, vec![ChannelMode::Latest]);
    assert_eq!(
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch,
        2
    );
}

#[test]
fn a_sealed_space_with_no_epoch_in_force_moves_no_audience_and_drops_only_who_no_longer_stands() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let old = EpochId {
        creator: n("/alice/laptop"),
        seq: 1,
    };
    for (device, key) in [(&bob, &bob_key), (&carol, &carol_key)] {
        table
            .admit(
                &space(),
                ChannelMode::Latest,
                &ask(device, &person_of(device), key, 3600),
                Some(old.clone()),
                (1, 1),
                t0,
            )
            .unwrap();
    }

    // Bob left the record and the owner's next epoch is not here yet: bob is dropped and the
    // key moves once; carol stands, so she stays, and the channel keeps the epoch it had.
    let done = table.rejudged(&space(), (2, 2), None, t0, |device, _| *device != bob);
    assert_eq!(done.dropped, vec![(ChannelMode::Latest, bob.clone())]);
    assert_eq!(done.rekeyed, vec![ChannelMode::Latest]);
    assert_eq!(table.receiver_count(&space(), ChannelMode::Latest), 1);

    // Judged again with the gap still open and nobody gone: nothing moves.
    let done = table.rejudged(&space(), (3, 3), None, t0, |_, _| true);
    assert_eq!(done, Rejudged::default());

    // The epoch arrives: the audience moved, which re-keys the second time (its own cause).
    let new = EpochId {
        creator: n("/alice/laptop"),
        seq: 2,
    };
    let done = table.rejudged(&space(), (4, 4), Some(&new), t0, |_, _| true);
    assert_eq!((done.dropped.len(), done.rekeyed.len()), (0, 1));
    let key = table.current(&space(), ChannelMode::Latest).unwrap();
    assert_eq!(key.key_epoch, 2);
}

#[test]
fn a_receiver_that_does_not_renew_is_dropped_after_its_lifetime_and_grace_and_the_channel_rekeys() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    admit(&table, &bob, &bob_key, 60, t0).unwrap();
    let (lapsed, ended) = table.expire(t0 + Duration::from_secs(64));
    assert!(
        (lapsed.is_empty(), ended.is_empty()) == (true, true),
        "inside lifetime and grace"
    );
    let (lapsed, ended) = table.expire(t0 + Duration::from_secs(66));
    assert_eq!(lapsed, vec![(space(), ChannelMode::Latest, bob)]);
    assert!(ended.is_empty());
    let epoch = || {
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch
    };
    assert_eq!(epoch(), 0, "the re-key it owes waits for REKEY_MIN");
    let _ = table.expire(t0 + REKEY_MIN);
    assert_eq!(epoch(), 1);
    // A channel nobody holds ends after a default lifetime.
    let (_, ended) = table.expire(t0 + Duration::from_secs(66 + 3600));
    assert_eq!(ended, vec![(space(), ChannelMode::Latest)]);
    assert_eq!(table.count(), 0);
}

/// The asker names its lifetime: a lifetime of 1 s would make the renewal threshold half a
/// second and every ask a re-key, and each re-key makes every other receiver ask again.
#[test]
fn a_receiver_asking_with_a_lifetime_of_one_second_cannot_rekey_twice_in_30_s() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    // Bob holds epoch 0 of the channel.
    let first = admit(&table, &bob, &bob_key, 3600, t0).unwrap();
    assert_eq!(first.key_epoch, 0);
    // Carol asks every 600 ms for 30 s with a lifetime of one second.
    let mut rekeys = 0;
    for i in 1..=50u64 {
        let given = admit(
            &table,
            &carol,
            &carol_key,
            1,
            t0 + Duration::from_millis(600 * i),
        )
        .unwrap();
        rekeys += u32::from(given.rekeyed);
    }
    assert_eq!(
        rekeys, 0,
        "carol re-keyed the channel {rekeys} times in 30 s"
    );
    assert_eq!(
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch,
        0,
        "bob's key epoch is still the channel's"
    );
}

/// What a receiver's renewal or a lapsed lease may do is bounded: one re-key per [`REKEY_MIN`],
/// whatever the receivers' lifetimes and rhythm. A removal re-keys at once, always.
#[test]
fn renewals_and_lapses_rekey_at_most_once_per_rekey_min_and_a_removal_at_once() {
    let table = Channels::default();
    let t0 = Instant::now();
    let epoch = || {
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch
    };
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let at = |s: u64| t0 + Duration::from_secs(s);
    admit(&table, &bob, &bob_key, 3600, t0).unwrap();

    // Carol asks every 31 s with the shortest lifetime (60 s: every ask after the first is a
    // renewal). Nothing re-keys before REKEY_MIN has passed since the channel's key was made.
    let step = 31;
    let mut rekeys = Vec::new();
    let mut s = 0;
    while s <= 2 * REKEY_MIN.as_secs() + 40 {
        let given = admit(&table, &carol, &carol_key, 1, at(s)).unwrap();
        if given.rekeyed {
            rekeys.push(s);
        }
        s += step;
    }
    assert_eq!(
        rekeys.len(),
        2,
        "two re-keys in two REKEY_MIN and a bit, at {rekeys:?}"
    );
    assert!(
        rekeys[0] >= REKEY_MIN.as_secs() && rekeys[1] - rekeys[0] >= REKEY_MIN.as_secs(),
        "each at least REKEY_MIN after the one before: {rekeys:?}"
    );
    assert_eq!(epoch(), 2);

    // Lapsed leases: three receivers vanish one second apart; they are dropped when they lapse,
    // and the channel is re-keyed once, when REKEY_MIN allows.
    let table = Channels::default();
    let epoch = || {
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch
    };
    for (i, who) in ["/a/dev", "/b/dev", "/c/dev"].into_iter().enumerate() {
        admit(
            &table,
            &n(who),
            &n(&format!("{who}/KEY/1")),
            60,
            at(i as u64),
        )
        .unwrap();
    }
    let (lapsed, _) = table.expire(at(70));
    assert_eq!(lapsed.len(), 3);
    assert_eq!(epoch(), 0, "the lapses are owed a re-key, not made at once");
    let _ = table.expire(at(REKEY_MIN.as_secs() - 1));
    assert_eq!(epoch(), 0);
    let _ = table.expire(at(REKEY_MIN.as_secs()));
    assert_eq!(epoch(), 1, "one re-key for the three");
    let _ = table.expire(at(REKEY_MIN.as_secs() + 10));
    assert_eq!(epoch(), 1, "and no second");

    // A removal, a moment after a re-key, re-keys at once.
    admit(&table, &bob, &bob_key, 3600, at(REKEY_MIN.as_secs() + 11)).unwrap();
    let done = table.rejudged(
        &space(),
        (2, 2),
        None,
        at(REKEY_MIN.as_secs() + 12),
        |_, _| false,
    );
    assert_eq!(done.rekeyed, vec![ChannelMode::Latest]);
    assert_eq!(epoch(), 2);
}

#[test]
fn the_lifetime_is_the_asks_clamped_between_a_minute_and_24_hours_and_never_refused() {
    assert_eq!(lifetime_for(0), 3600);
    assert_eq!(lifetime_for(1), 60);
    assert_eq!(lifetime_for(59), 60);
    assert_eq!(lifetime_for(60), 60);
    assert_eq!(lifetime_for(90), 90);
    assert_eq!(lifetime_for(86_400), 86_400);
    assert_eq!(lifetime_for(10_000_000), 86_400);
    let table = Channels::default();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let given = admit(&table, &bob, &bob_key, 10_000_000, Instant::now()).unwrap();
    assert_eq!(given.lifetime, 86_400);
}

#[test]
fn a_sender_keeps_64_channels_and_a_channel_256_receivers() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    for i in 0..CHANNELS_PER_SENDER {
        let s = n(&format!("/alice/32=data/s{i}"));
        table
            .admit(
                &s,
                ChannelMode::Latest,
                &ask(&bob, &person_of(&bob), &bob_key, 0),
                None,
                (1, 1),
                t0,
            )
            .unwrap();
    }
    let over = n("/alice/32=data/over");
    assert_eq!(
        table
            .admit(
                &over,
                ChannelMode::Latest,
                &ask(&bob, &person_of(&bob), &bob_key, 0),
                None,
                (1, 1),
                t0
            )
            .err(),
        Some(Cap::Channels)
    );
    // The same space in another mode is another channel: also over the cap.
    assert_eq!(
        table
            .admit(
                &n("/alice/32=data/s0"),
                ChannelMode::Reliable,
                &ask(&bob, &person_of(&bob), &bob_key, 0),
                None,
                (1, 1),
                t0
            )
            .err(),
        Some(Cap::Channels)
    );
    let table = Channels::default();
    for i in 0..RECEIVERS_PER_CHANNEL {
        let (d, k) = (n(&format!("/p{i}/dev")), n(&format!("/p{i}/dev/KEY/1")));
        admit(&table, &d, &k, 0, t0).unwrap();
    }
    let (d, k) = (n("/late/dev"), n("/late/dev/KEY/1"));
    assert_eq!(admit(&table, &d, &k, 0, t0).err(), Some(Cap::Receivers));
    // A receiver the channel already has is not over the cap by asking again.
    let (d0, k0) = (n("/p0/dev"), n("/p0/dev/KEY/1"));
    assert!(admit(&table, &d0, &k0, 0, t0).is_ok());
}

/// One person's devices are bounded in a channel's places: a member with many device keys cannot
/// fill the channel for the other members. Her extra device is refused by `Cap::Person` (a place
/// is not taken), the devices she has still renew, and every other person still finds a place up
/// to the channel's own cap.
#[test]
fn one_person_cannot_fill_a_channels_receiver_places() {
    let table = Channels::default();
    let t0 = Instant::now();
    for i in 0..RECEIVERS_PER_PERSON {
        let (d, k) = (
            n(&format!("/mallory/d{i}")),
            n(&format!("/mallory/d{i}/KEY/1")),
        );
        admit(&table, &d, &k, 0, t0).unwrap();
    }
    let (extra, extra_key) = (n("/mallory/extra"), n("/mallory/extra/KEY/1"));
    assert_eq!(
        admit(&table, &extra, &extra_key, 0, t0).err(),
        Some(Cap::Person),
        "a person's {}th device took a place of the channel",
        RECEIVERS_PER_PERSON + 1
    );
    assert_eq!(
        table.receiver_count(&space(), ChannelMode::Latest),
        RECEIVERS_PER_PERSON,
        "a refused ask took a place"
    );
    let (d0, k0) = (n("/mallory/d0"), n("/mallory/d0/KEY/1"));
    assert!(
        admit(&table, &d0, &k0, 0, t0).is_ok(),
        "a device she has is not over the cap by asking again"
    );
    for i in 0..RECEIVERS_PER_CHANNEL - RECEIVERS_PER_PERSON {
        let (d, k) = (n(&format!("/p{i}/dev")), n(&format!("/p{i}/dev/KEY/1")));
        assert!(
            admit(&table, &d, &k, 0, t0).is_ok(),
            "person {i} found no place: one person filled the channel"
        );
    }
    let (late, late_key) = (n("/late/dev"), n("/late/dev/KEY/1"));
    assert_eq!(
        admit(&table, &late, &late_key, 0, t0).err(),
        Some(Cap::Receivers)
    );
}

#[test]
fn an_asker_key_has_four_asks_a_second_and_a_burst_of_eight() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, other) = (n("/bob/phone/KEY/1"), n("/carol/tablet/KEY/1"));
    let passed = (0..20).filter(|_| table.throttle(&bob, t0)).count();
    assert_eq!(passed, 8, "a burst of 8");
    assert!(table.throttle(&other, t0), "another key has its own bucket");
    assert!(
        !table.throttle(&bob, t0 + Duration::from_millis(200)),
        "0.8 of a token"
    );
    assert!(
        table.throttle(&bob, t0 + Duration::from_millis(300)),
        "a token after 300 ms"
    );
    assert!(!table.throttle(&bob, t0 + Duration::from_millis(301)));
    let in_a_second = (0..20)
        .filter(|i| {
            table.throttle(
                &bob,
                t0 + Duration::from_secs(10) + Duration::from_millis(i * 10),
            )
        })
        .count();
    assert_eq!(
        in_a_second, 8,
        "a refilled bucket allows the burst again, not more"
    );
}

#[test]
fn a_channel_is_announced_at_start_and_every_30_seconds_while_it_lives() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    assert!(
        table.announce_due(t0).is_empty(),
        "no channel, nothing to announce"
    );
    admit(&table, &bob, &bob_key, 0, t0).unwrap();
    assert_eq!(table.announce_due(t0), vec![space()], "once at the start");
    assert!(table.announce_due(t0 + Duration::from_secs(29)).is_empty());
    assert_eq!(
        table.announce_due(t0 + Duration::from_secs(30)),
        vec![space()]
    );
    table.announced(&space(), t0 + Duration::from_secs(40));
    assert!(table.announce_due(t0 + Duration::from_secs(69)).is_empty());
    assert_eq!(
        table.announce_due(t0 + Duration::from_secs(70)),
        vec![space()]
    );
}

#[test]
fn a_channel_is_rekeyed_before_its_sequence_passes_two_to_the_63() {
    let table = Channels::default();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    admit(&table, &bob, &bob_key, 0, Instant::now()).unwrap();
    assert!(!table.note_seq(&space(), ChannelMode::Latest, 1 << 40));
    assert_eq!(
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch,
        0
    );
    assert!(table.note_seq(&space(), ChannelMode::Latest, 1 << 63));
    assert_eq!(
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch,
        1
    );
    assert!(!table.note_seq(&n("/alice/32=data/none"), ChannelMode::Latest, 1 << 63));
}

#[test]
fn a_session_names_the_next_sequence_and_the_audience_epoch_the_receiver_was_judged_by() {
    let table = Channels::default();
    let (bob, bob_key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let epoch = EpochId {
        creator: n("/alice/laptop"),
        seq: 4,
    };
    let now = Instant::now();
    table
        .admit(
            &space(),
            ChannelMode::Latest,
            &ask(&bob, &person_of(&bob), &bob_key, 0),
            Some(epoch.clone()),
            (1, 1),
            now,
        )
        .unwrap();
    table.note_seq(&space(), ChannelMode::Latest, 77);
    let (carol, carol_key) = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let given = admit(&table, &carol, &carol_key, 0, now).unwrap();
    assert_eq!(given.seq, 77);
    assert_eq!(given.audience, Some(epoch));
}

#[test]
fn a_receiver_that_says_it_holds_no_session_claims_to_be_new_and_is_not_fresh() {
    let table = Channels::default();
    let t0 = Instant::now();
    let (bob, key) = (n("/bob/phone"), n("/bob/phone/KEY/1"));
    let first = admit(&table, &bob, &key, 3600, t0).unwrap();
    assert!(first.fresh && !first.claim, "the first ask: a new device");
    let renewal = admit(&table, &bob, &key, 3600, t0 + Duration::from_secs(1)).unwrap();
    assert!(
        !renewal.fresh && !renewal.claim,
        "an ask that holds its session is a renewal"
    );
    // The receiver let the channel go and asks again: the sender does not know it left, the
    // ask says so.
    let asker = Asker {
        device: &bob,
        person: &person_of(&bob),
        key: &key,
        wanted: 3600,
        new: true,
        stream: true,
    };
    let again = table
        .admit(
            &space(),
            ChannelMode::Latest,
            &asker,
            None,
            (1, 1),
            t0 + Duration::from_secs(2),
        )
        .unwrap();
    assert!(
        !again.fresh && again.claim,
        "a listed device that says ASK_NEW makes a claim, which the sender's limiter judges; \
         only a device that was never a receiver is fresh"
    );
    // A device that was never listed is fresh whatever it says.
    let carol = (n("/carol/tablet"), n("/carol/tablet/KEY/1"));
    let asker = Asker {
        device: &carol.0,
        person: &person_of(&carol.0),
        key: &carol.1,
        wanted: 3600,
        new: true,
        stream: true,
    };
    let joined = table
        .admit(
            &space(),
            ChannelMode::Latest,
            &asker,
            None,
            (1, 1),
            t0 + Duration::from_secs(3),
        )
        .unwrap();
    assert!(joined.fresh && !joined.claim);
    assert_eq!(table.receiver_count(&space(), ChannelMode::Latest), 2);
}
