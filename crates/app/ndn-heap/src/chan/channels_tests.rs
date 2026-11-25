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

fn ask<'a>(device: &'a Name, key: &'a Name, wanted: u64) -> Asker<'a> {
    Asker {
        device,
        key,
        wanted,
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
        &ask(device, key, wanted),
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
                &ask(device, key, 3600),
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
    assert_eq!(
        table
            .current(&space(), ChannelMode::Latest)
            .unwrap()
            .key_epoch,
        1
    );
    // A channel nobody holds ends after a default lifetime.
    let (_, ended) = table.expire(t0 + Duration::from_secs(66 + 3600));
    assert_eq!(ended, vec![(space(), ChannelMode::Latest)]);
    assert_eq!(table.count(), 0);
}

#[test]
fn the_lifetime_is_the_asks_clamped_to_24_hours_and_never_refused() {
    assert_eq!(lifetime_for(0), 3600);
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
                &ask(&bob, &bob_key, 0),
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
                &ask(&bob, &bob_key, 0),
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
                &ask(&bob, &bob_key, 0),
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
            &ask(&bob, &bob_key, 0),
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
