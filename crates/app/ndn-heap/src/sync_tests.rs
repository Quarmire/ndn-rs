//! The network half against a toy log and a scripted network: what is asked
//! of whom, how often and in what order when a notice arrives, what a
//! forged, replayed or invented notice costs, how a restarting device gets
//! its own entries back, how values in pieces and epoch keys are pulled.
//! Time is the runtime's paused clock.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, Node};
use ndn_foundation_types::Name;
use ndn_packet::NackReason;
use ndn_packet::encode::DataBuilder;
use ndn_sync::SyncUpdate;

use super::net_kit::*;
use super::*;
use crate::heard::HEARD_MAX;
use crate::log::Blob;
use crate::pieces;
use crate::register::EntryId;
use crate::test_kit::n;
use crate::wire::{
    EpochId, log_name, parse_grant_name, parse_held_name, parse_log_name, seal_key_name,
    sync_group_of,
};

const LAPTOP: &str = "/alice/laptop";
const PHONE: &str = "/alice/phone";
const TABLET: &str = "/alice/tablet";
const DESKTOP: &str = "/alice/desktop";

/// A device under test over a toy log and a scripted network, joined to the
/// case's space.
struct Rig {
    host: Arc<Toyhost>,
    wire: Arc<Wire>,
    face: Arc<Face>,
    net: Arc<Net>,
    group: Arc<Group>,
}

async fn rig_with(cfg: Config) -> Rig {
    let host = Toyhost::new(LAPTOP);
    let wire = Wire::new();
    let node = Node::from_connection(Arc::clone(&wire) as Arc<dyn Connection>);
    let face = Face::new();
    let net = Net::start(
        Arc::clone(&host) as Arc<dyn Host>,
        cfg,
        node.connection(),
        Arc::clone(&face) as Arc<dyn Connection>,
    );
    let group = net.join(&space(), 0).await.expect("the space is joined");
    Rig {
        host,
        wire,
        face,
        net,
        group,
    }
}

async fn rig() -> Rig {
    rig_with(Config::default()).await
}

/// A notice: `device` says its counter is `high`.
fn notice(device: &str, high: u64) -> SyncUpdate {
    SyncUpdate {
        publisher: device.to_string(),
        name: n(device),
        low_seq: 1,
        high_seq: high,
        mapping: None,
        serving_party: None,
    }
}

/// `(device, seq)` of a direct ask `<device>/32=log/<space>/seq=<n>`.
fn direct(name: &Name) -> Option<(Name, u64)> {
    parse_log_name(name).map(|l| (l.device, l.seq))
}

/// `(holder, device, seq)` of an ask through a relay.
fn relayed(name: &Name) -> Option<(Name, Name, u64)> {
    let (holder, original) = parse_held_name(name)?;
    let l = parse_log_name(&original)?;
    Some((holder, l.device, l.seq))
}

/// What a holder answers a `32=held` ask with: the packet in a DigestSha256
/// wrapper.
fn wrapped(name: &Name, original: Bytes) -> Bytes {
    DataBuilder::new(name.clone(), &original).sign_digest_sha256()
}

async fn pass(secs: u64) {
    tokio::time::sleep(Duration::from_secs(secs)).await;
}

/// D5/§7: one group per space on the node's one driver, the sync face
/// registered once per owner for `<O>/32=sync`; a publication is a Sync
/// Interest in the space's group.
#[tokio::test(start_paused = true)]
async fn groups_register_the_owner_prefix_once_and_publish_announces() {
    let r = rig().await;
    r.net
        .join(&n("/alice/32=data/docs"), 0)
        .await
        .expect("a second space of the same owner");
    r.net
        .join(&n("/bob/32=data/x"), 0)
        .await
        .expect("a space of another owner");
    assert_eq!(
        r.face.registered(),
        vec![n("/alice/32=sync"), n("/bob/32=sync")],
        "`<O>/32=sync` once per owner, whatever the number of its spaces"
    );
    let group = sync_group_of(&space()).unwrap();
    assert_eq!(group, n("/alice/32=sync/notes"));
    r.group.sink().publish(1).await;
    pass(3).await;
    assert!(
        r.face.sent_in(&group) >= 1,
        "a publication reaches the group as a Sync Interest"
    );
}

/// The notice names the entry: one Interest, for exactly that entry, and
/// nothing else is asked.
#[tokio::test(start_paused = true)]
async fn one_new_entry_is_one_fetch() {
    let r = rig().await;
    r.wire.script(|name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) && seq == 1 => Reply::Data(genuine(PHONE, 1)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 1));
    pass(10).await;
    assert_eq!(r.wire.names(), vec![log_name(&n(PHONE), &space(), 1)]);
    assert!(r.host.holds(PHONE, 1));
    assert_eq!(r.host.st.lock().applied, vec![(n(PHONE), 1)]);
}

/// Nothing is held and the notice says 100: the entry it names is asked
/// first and alone, then the rest in a window, each once.
#[tokio::test(start_paused = true)]
async fn a_gap_in_the_notice_is_backfilled_in_a_window() {
    let r = rig_with(Config {
        window: 32,
        ..Config::new()
    })
    .await;
    r.wire.delay(Duration::from_millis(50));
    r.wire.script(|name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) => Reply::Data(genuine(PHONE, seq)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 100));
    pass(30).await;
    let asked = r.wire.names();
    assert_eq!(
        direct(&asked[0]),
        Some((n(PHONE), 100)),
        "the entry the notice names comes first"
    );
    assert_eq!(asked.len(), 100, "each entry once: {}", asked.len());
    assert_eq!(r.host.held_count(PHONE), 100, "every entry arrived");
    assert_eq!(
        r.host.st.lock().probed,
        vec![(n(PHONE), 100)],
        "only the entry the counter names is a probe; the holes below it are the log's wants"
    );
    assert!(
        r.wire.peak() <= 32,
        "at most the window in flight: {}",
        r.wire.peak()
    );
    assert!(
        r.wire.peak() > 8,
        "and the window is used: {}",
        r.wire.peak()
    );
}

/// o4/o3 under loss: 1,200 entries below a counter, over a path whose round trip is over a
/// second (a mean of 1.15 s: the faulty profile's delay and block times) and that loses an
/// Interest or its Data 36 % of the time and forges 3 % of what arrives, are all held within a
/// minute of virtual time (the case's bound is two, over a path with a longer tail). Entries a
/// verified tip proves to exist are owed: a miss costs a short doubling pause, never a minute,
/// and the walk keeps the path full: with the window of 32 asks the same walk took 87 s here.
#[tokio::test(start_paused = true)]
async fn a_long_hole_below_a_held_tip_is_repaired_within_a_minute_over_a_lossy_long_path() {
    let r = rig().await;
    r.wire.delay(Duration::from_millis(1150));
    let tick = std::sync::atomic::AtomicU64::new(0);
    r.wire.script(move |name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) => {
            let mut z = tick
                .fetch_add(0x9E37_79B9_7F4A_7C15, std::sync::atomic::Ordering::Relaxed)
                .wrapping_add(0x9E37_79B9_7F4A_7C15);
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            match (z ^ (z >> 31)) % 1000 {
                0..360 => Reply::Silent,
                360..392 => Reply::Data(forged(PHONE, seq)),
                _ => Reply::Data(genuine(PHONE, seq)),
            }
        }
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 1200));
    let began = tokio::time::Instant::now();
    while r.host.held_count(PHONE) < 1200 && began.elapsed() < Duration::from_secs(600) {
        pass(1).await;
    }
    let took = began.elapsed();
    assert!(
        took <= Duration::from_secs(60),
        "{} of 1200 held after {took:?}",
        r.host.held_count(PHONE)
    );
}

/// An entry that says nothing exists between seq 100 and itself leaves the
/// 999 seqs between unasked.
#[tokio::test(start_paused = true)]
async fn a_void_declared_by_a_gap_statement_is_never_asked() {
    let r = rig().await;
    r.host.hold(PHONE, 100);
    r.host.st.lock().vouched.insert(n(PHONE));
    r.wire.script(|name| match direct(name) {
        Some((d, 1100)) if d == n(PHONE) => Reply::Data(declaring(PHONE, 1100, 100)),
        Some((d, seq)) if d == n(PHONE) => Reply::Data(genuine(PHONE, seq)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 1100));
    pass(30).await;
    assert_eq!(
        r.wire.names(),
        vec![log_name(&n(PHONE), &space(), 1100)],
        "the entry the notice names, and nothing inside its void"
    );
    assert!(r.host.holds(PHONE, 1100));
    assert!(!r.host.holds(PHONE, 500));
}

/// An entry that does not verify is refused and applies nothing; what it was
/// fetched for stays wanted and the next ask goes to another holder.
#[tokio::test(start_paused = true)]
async fn a_forged_entry_fetched_directly_is_refused_and_nothing_is_applied() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), false);
    }
    r.wire.script(|name| {
        if let Some((d, seq)) = direct(name)
            && d == n(PHONE)
        {
            return Reply::Data(forged(PHONE, seq));
        }
        if let Some((holder, d, seq)) = relayed(name)
            && holder == n(TABLET)
            && d == n(PHONE)
        {
            return Reply::Data(wrapped(name, genuine(PHONE, seq)));
        }
        Reply::Nack(NackReason::NoRoute)
    });
    r.group.on_update(notice(TABLET, 1));
    pass(1).await;
    r.group.on_update(notice(PHONE, 5));
    pass(30).await;
    let of_phone: Vec<Name> = r
        .wire
        .names()
        .into_iter()
        .filter(|name| {
            direct(name).is_some_and(|(d, s)| d == n(PHONE) && s == 5)
                || relayed(name).is_some_and(|(_, d, s)| d == n(PHONE) && s == 5)
        })
        .collect();
    assert_eq!(
        direct(&of_phone[0]),
        Some((n(PHONE), 5)),
        "the writer is asked first"
    );
    assert_eq!(
        relayed(&of_phone[1]).map(|(h, _, _)| h),
        Some(n(TABLET)),
        "then a heard member that vouches, through `32=held`"
    );
    let st = r.host.st.lock();
    assert_eq!(
        st.applied.first(),
        Some(&(n(PHONE), 5)),
        "the genuine copy of the entry the notice names applied first, once"
    );
    assert_eq!(
        st.applied.iter().filter(|a| **a == (n(PHONE), 5)).count(),
        1,
        "the forged copy applied nothing"
    );
    assert!(
        st.taken.iter().filter(|t| **t == (n(PHONE), 5)).count() >= 2,
        "the forged copy was handed to the node, and refused"
    );
}

/// With nobody else to ask, a forged answer is asked again after growing
/// pauses, never held, never applied.
#[tokio::test(start_paused = true)]
async fn a_forged_entry_is_asked_again_with_growing_pauses() {
    let r = rig().await;
    r.host.st.lock().vouched.insert(n(PHONE));
    r.wire.script(|name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) => Reply::Data(forged(PHONE, seq)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 2));
    pass(40).await;
    let times: Vec<_> = r
        .wire
        .times()
        .into_iter()
        .filter(|(name, _)| direct(name) == Some((n(PHONE), 2)))
        .map(|(_, t)| t)
        .collect();
    assert!(times.len() >= 4, "asked again: {} asks", times.len());
    let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.windows(2).all(|g| g[1] >= g[0]),
        "the pauses never shrink: {gaps:?}"
    );
    assert!(gaps.last().unwrap() > &gaps[0], "and they grow: {gaps:?}");
    assert!(r.host.st.lock().applied.is_empty());
    assert!(!r.host.holds(PHONE, 2));
}

/// Sync Interests are unsigned: a vector naming 250 devices that hold
/// nothing, 50 of them at counter 0, applies nothing, tells the log nothing
/// of devices nothing vouches for, asks for nothing at counter 0 and for no
/// more devices than are kept heard.
#[tokio::test(start_paused = true)]
async fn a_notice_names_nothing_it_decides() {
    let r = rig().await;
    for i in 0..250 {
        let high = u64::from(i < 200);
        r.group.on_update(notice(&format!("/alice/fake{i}"), high));
    }
    pass(30).await;
    let st = r.host.st.lock();
    assert!(st.applied.is_empty(), "nothing was applied");
    assert!(st.taken.is_empty(), "nothing answered");
    assert!(
        st.counters.is_empty(),
        "the log is told nothing of names no held data vouches for"
    );
    drop(st);
    let asked = r.wire.names();
    assert!(
        asked.iter().all(|name| {
            let (d, _) = direct(name).expect("a direct ask");
            let i: usize = d
                .to_string()
                .trim_start_matches("/alice/fake")
                .parse()
                .unwrap();
            i < 200
        }),
        "no name at counter 0 is asked for"
    );
    let devices: std::collections::BTreeSet<Name> = asked
        .iter()
        .filter_map(|name| direct(name).map(|(d, _)| d))
        .collect();
    assert!(
        devices.len() <= HEARD_MAX,
        "{} devices asked, at most {HEARD_MAX}",
        devices.len()
    );
}

/// o3/o4 under loss: a real counter whose entry the path loses five asks in a row (a path that
/// loses 36 % of the asks does that to one counter in a hundred, and a space has dozens) is
/// held within a minute, not after a pause of a minute per ask: the pause between asks of a
/// counter grows from 4 s once [`FETCH_TRIES`] asks missed, to a minute at most, so a forged
/// counter's steady cost is the same one ask a minute.
#[tokio::test(start_paused = true)]
async fn a_counters_entry_the_path_lost_five_asks_in_a_row_is_held_within_a_minute() {
    let r = rig().await;
    r.host.hold(PHONE, 1);
    r.host.st.lock().vouched.insert(n(PHONE));
    let lost = std::sync::atomic::AtomicUsize::new(0);
    r.wire.script(move |name| match direct(name) {
        Some((d, 2)) if d == n(PHONE) => {
            if lost.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 5 {
                Reply::Silent
            } else {
                Reply::Data(genuine(PHONE, 2))
            }
        }
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 2));
    let began = tokio::time::Instant::now();
    while !r.host.holds(PHONE, 2) && began.elapsed() < Duration::from_secs(300) {
        pass(1).await;
    }
    assert!(
        r.host.holds(PHONE, 2) && began.elapsed() <= Duration::from_secs(60),
        "held: {}, after {:?}",
        r.host.holds(PHONE, 2),
        began.elapsed()
    );
}

/// o3 under loss: a hole the writer alone holds (the eight devices that would answer for it are
/// missing the same entry: they keep asking each other) is asked of the writer every other
/// miss, not once in nine, so two lost asks to the writer cost seconds, not minutes.
#[tokio::test(start_paused = true)]
async fn a_hole_only_the_writer_holds_is_asked_of_the_writer_every_other_miss() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(PHONE));
        for i in 0..8 {
            let relay = n(&format!("/alice/relay{i}"));
            st.vouched.insert(relay.clone());
            st.standing.insert(relay, true);
        }
    }
    for i in 0..8 {
        r.group.on_update(notice(&format!("/alice/relay{i}"), 1));
    }
    let begun = tokio::time::Instant::now();
    r.wire.script(move |name| match direct(name) {
        Some((d, 6)) if d == n(PHONE) => {
            if begun.elapsed() < Duration::from_secs(6) {
                Reply::Silent
            } else {
                Reply::Data(genuine(PHONE, 6))
            }
        }
        Some((d, seq)) if d == n(PHONE) => Reply::Data(genuine(PHONE, seq)),
        _ => Reply::Silent,
    });
    r.group.on_update(notice(PHONE, 10));
    let began = tokio::time::Instant::now();
    while r.host.held_count(PHONE) < 10 && began.elapsed() < Duration::from_secs(300) {
        pass(1).await;
    }
    assert!(
        r.host.held_count(PHONE) == 10 && began.elapsed() <= Duration::from_secs(25),
        "{} of 10 held, after {:?}",
        r.host.held_count(PHONE),
        began.elapsed()
    );
}

/// A Sync Interest is unsigned: a forged counter for a device the log
/// vouches for names an entry and nothing else. It is asked for alone, a
/// bounded number of times; what lies below it is not asked, nothing is
/// wanted of the log, and the log is told nothing (M4).
#[tokio::test(start_paused = true)]
async fn a_forged_counter_for_a_vouched_device_costs_a_bounded_number_of_asks() {
    let r = rig().await;
    r.host.hold(PHONE, 2);
    r.host.st.lock().vouched.insert(n(PHONE));
    r.wire.script(|_| Reply::Silent);
    r.group.on_update(notice(PHONE, 1_000_000));
    pass(200).await;
    let asked: Vec<u64> = r
        .wire
        .names()
        .iter()
        .filter_map(|name| direct(name).map(|(_, s)| s))
        .collect();
    assert!(
        asked.iter().all(|s| *s == 1_000_000),
        "only the entry the counter names is asked for, never what lies below it: {} asks, \
         lowest {:?}",
        asked.len(),
        asked.iter().min()
    );
    assert!(asked.len() <= 40, "{} asks", asked.len());
    assert!(
        r.host.missing(&space()).is_empty(),
        "an unsigned counter leaves nothing wanted, so the heap stays ready"
    );
    assert!(
        r.host.st.lock().counters.is_empty(),
        "the log is told nothing"
    );
}

/// The counter of this device's own name is as unsigned: the entries within
/// what it reserved are fetched back, and above that one probe at the
/// counter and nothing between (M4).
#[tokio::test(start_paused = true)]
async fn a_forged_own_counter_asks_for_the_reserved_range_and_one_probe() {
    let r = rig().await;
    r.host.hold(LAPTOP, 10);
    {
        let mut st = r.host.st.lock();
        st.head = 10;
        st.reserved = 20;
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), true);
    }
    r.wire.script(|_| Reply::Nack(NackReason::NoRoute));
    r.group.on_update(notice(TABLET, 1));
    r.group.on_update(notice(LAPTOP, 1_000_000));
    pass(200).await;
    let own: Vec<u64> = r
        .wire
        .names()
        .iter()
        .filter_map(relayed)
        .filter(|(_, d, _)| *d == n(LAPTOP))
        .map(|(_, _, s)| s)
        .collect();
    assert!(
        own.iter().all(|s| (11..=20).contains(s) || *s == 1_000_000),
        "own entries are asked for within the reservation, and the counter once alone: {:?}",
        own.iter().filter(|s| !(11..=20).contains(*s)).max()
    );
    assert!(own.contains(&1_000_000), "the counter itself is probed");
    // Four asks, then the pause climbs (4, 8, 16, 32 s) to one ask a minute.
    assert!(own.iter().filter(|s| **s == 1_000_000).count() <= 11);
}

/// A removed writer that serves other bytes at the seq its cut keeps does
/// not end the ask: the bytes are not the cut's, so they are not even handed
/// to the log, and the next ask goes to a relay (L2).
#[tokio::test(start_paused = true)]
async fn a_removed_writers_junk_at_its_cut_frontier_moves_the_ask_to_a_relay() {
    let r = rig().await;
    let good = genuine(PHONE, 5);
    {
        let mut st = r.host.st.lock();
        st.exact
            .push((n(PHONE), 5, crate::wire::signed_digest(&good)));
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), true);
    }
    let relayed_good = good.clone();
    r.wire.script(move |name| {
        if direct(name) == Some((n(PHONE), 5)) {
            return Reply::Data(entry(PHONE, 5, b"g-other bytes"));
        }
        match relayed(name) {
            Some((h, d, 5)) if h == n(TABLET) && d == n(PHONE) => {
                Reply::Data(wrapped(name, relayed_good.clone()))
            }
            _ => Reply::Nack(NackReason::NoRoute),
        }
    });
    r.group.on_update(notice(TABLET, 1));
    pass(1).await;
    r.group.nudge();
    pass(30).await;
    assert!(
        r.host.holds(PHONE, 5),
        "the cut's bytes came from the relay after the writer's junk"
    );
    assert_eq!(
        r.host.st.lock().evidence,
        0,
        "the junk never reached the log"
    );
}

/// An answer the log calls a duplicate while it still wants that very entry
/// resolved nothing: it counts as a miss, so the next ask goes to another
/// source (L2).
#[tokio::test(start_paused = true)]
async fn a_duplicate_of_what_is_still_wanted_counts_as_a_miss() {
    let r = rig().await;
    let good = genuine(PHONE, 5);
    {
        let mut st = r.host.st.lock();
        st.exact
            .push((n(PHONE), 5, crate::wire::signed_digest(&good)));
        st.stuck.insert((n(PHONE), 5));
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), true);
    }
    r.wire.script(move |name| {
        if direct(name) == Some((n(PHONE), 5)) {
            return Reply::Data(genuine(PHONE, 5));
        }
        match relayed(name) {
            Some((h, d, 5)) if h == n(TABLET) && d == n(PHONE) => {
                Reply::Data(wrapped(name, genuine(PHONE, 5)))
            }
            _ => Reply::Nack(NackReason::NoRoute),
        }
    });
    r.group.on_update(notice(TABLET, 1));
    pass(1).await;
    r.group.nudge();
    pass(30).await;
    assert!(
        r.wire
            .names()
            .iter()
            .any(|name| relayed(name) == Some((n(TABLET), n(PHONE), 5))),
        "a duplicate of a wanted entry is a miss: the relay was asked"
    );
}

/// A notice that is replayed, stale or lower never makes the reader stop
/// asking for the newer entry it already heard of; what is wanted shrinks
/// only by holding it.
#[tokio::test(start_paused = true)]
async fn a_replayed_stale_notice_never_stops_the_fetch_of_a_newer_entry() {
    let r = rig().await;
    r.host.hold(PHONE, 2);
    r.host.st.lock().vouched.insert(n(PHONE));
    r.wire.script(|_| Reply::Silent);
    r.group.on_update(notice(PHONE, 10));
    pass(5).await;
    r.group.on_update(notice(PHONE, 3));
    r.group.on_update(notice(PHONE, 1));
    pass(5).await;
    assert!(!r.host.holds(PHONE, 10));
    let before = r.wire.count(&log_name(&n(PHONE), &space(), 10));
    assert!(before >= 1);
    r.wire.script(|name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) => Reply::Data(genuine(PHONE, seq)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    pass(80).await;
    assert!(
        r.host.holds(PHONE, 10),
        "the newer entry was still being asked for, and arrived"
    );
    assert_eq!(r.host.held_count(PHONE), 10, "and everything below it");
}

/// A device that held a prefix before it was away asks only for what
/// changed.
#[tokio::test(start_paused = true)]
async fn a_returning_device_fetches_only_what_changed() {
    let r = rig().await;
    r.host.hold(PHONE, 50);
    r.host.st.lock().vouched.insert(n(PHONE));
    r.wire.script(|name| match direct(name) {
        Some((d, seq)) if d == n(PHONE) => Reply::Data(genuine(PHONE, seq)),
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(PHONE, 52));
    pass(10).await;
    let mut asked: Vec<u64> = r
        .wire
        .names()
        .iter()
        .filter_map(|name| direct(name).map(|(_, s)| s))
        .collect();
    assert_eq!(asked[0], 52, "the entry the notice names first");
    asked.sort_unstable();
    assert_eq!(asked, vec![51, 52]);
    assert_eq!(r.host.held_count(PHONE), 52);
}

/// A counter naming this device above its head (a restart's peers hold
/// entries it lost) is fetched from heard members through `32=held`, never
/// from itself, and the log hears the counter.
#[tokio::test(start_paused = true)]
async fn a_notice_naming_this_device_is_fetched_from_relays_never_from_itself() {
    let r = rig().await;
    r.host.hold(LAPTOP, 3);
    r.host.st.lock().head = 3;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), true);
    }
    r.wire.script(|name| match relayed(name) {
        Some((h, d, seq)) if h == n(TABLET) && d == n(LAPTOP) => {
            Reply::Data(wrapped(name, genuine(LAPTOP, seq)))
        }
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(TABLET, 1));
    r.group.on_update(notice(LAPTOP, 5));
    pass(10).await;
    assert!(
        r.host.st.lock().counters.contains(&(n(LAPTOP), 5)),
        "the log hears the own counter"
    );
    assert_eq!(r.host.held_count(LAPTOP), 5, "entries 4 and 5 came back");
    assert_eq!(
        r.wire.count(&n(LAPTOP)),
        0,
        "nothing was asked of this device itself"
    );
}

/// Own entries are fetched back at most four reservation blocks above the
/// head, and the entry the counter names is probed first: once that is held,
/// the holes below it cost 4 × block asks.
#[tokio::test(start_paused = true)]
async fn recovery_fetches_own_entries_at_most_four_blocks_above_the_head() {
    let cfg = Config {
        reserve_block: 100,
        ..Config::default()
    };
    let r = rig_with(cfg).await;
    r.host.hold(LAPTOP, 10);
    r.host.st.lock().head = 10;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), true);
    }
    r.wire.script(|name| match relayed(name) {
        Some((h, d, seq)) if h == n(TABLET) && d == n(LAPTOP) => {
            Reply::Data(wrapped(name, genuine(LAPTOP, seq)))
        }
        _ => Reply::Nack(NackReason::NoRoute),
    });
    r.group.on_update(notice(TABLET, 1));
    r.group.on_update(notice(LAPTOP, 5010));
    let recovered = r.group.recover(Duration::from_secs(1)).await;
    assert!(recovered.heard, "a vector arrived within the wait");
    assert!(
        recovered.complete,
        "everything within the bound was fetched"
    );
    let asked: Vec<u64> = r
        .wire
        .names()
        .iter()
        .filter_map(|name| relayed(name).map(|(_, d, s)| (d, s)))
        .filter(|(d, _)| *d == n(LAPTOP))
        .map(|(_, s)| s)
        .collect();
    let mut within_bound: Vec<u64> = asked.iter().copied().filter(|s| *s != 5010).collect();
    within_bound.sort_unstable();
    assert_eq!(
        asked.iter().filter(|s| **s == 5010).count(),
        1,
        "the counter's own entry is probed once, and held when it answers"
    );
    assert_eq!(within_bound.len(), 400, "{} asks", within_bound.len());
    assert_eq!(
        within_bound.last(),
        Some(&410),
        "once it is held, nothing above head + 4 blocks is asked"
    );
    assert_eq!(within_bound.first(), Some(&11));
    assert_eq!(r.host.held_count(LAPTOP), 411);
}

/// A restart waits up to `settle` for the first group vector, then goes on
/// without one.
#[tokio::test(start_paused = true)]
async fn recovery_waits_settle_for_the_first_vector_and_goes_on_without() {
    let r = rig().await;
    let began = tokio::time::Instant::now();
    let recovered = r.group.recover(Duration::from_secs(1)).await;
    assert!(!recovered.heard, "nobody was heard");
    assert!(recovered.complete, "nothing was owed");
    assert_eq!(began.elapsed(), Duration::from_secs(1));

    let r = rig().await;
    let began = tokio::time::Instant::now();
    let group = Arc::clone(&r.group);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        group.on_update(notice(TABLET, 1));
    });
    let recovered = r.group.recover(Duration::from_secs(1)).await;
    assert!(recovered.heard);
    assert!(
        began.elapsed() < Duration::from_secs(1),
        "the first vector ends the wait: {:?}",
        began.elapsed()
    );
}

/// The Content of an entry's pieces (a value in pieces) is fetched from the
/// writer, proved by digest, and handed over once, whole.
#[tokio::test(start_paused = true)]
async fn a_value_in_pieces_is_assembled_and_handed_over_once() {
    let r = rig().await;
    let entry_name = log_name(&n(PHONE), &space(), 1);
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let cut = pieces::split(&entry_name, &payload).unwrap();
    let id = EntryId {
        device: n(PHONE),
        seq: 1,
        digest: [3; 32],
    };
    r.host.st.lock().blobs_on_take = vec![Blob {
        id: id.clone(),
        size: cut.size,
        root: cut.root,
    }];
    let packets = cut.packets.clone();
    r.wire.script(move |name| {
        if direct(name) == Some((n(PHONE), 1)) {
            return Reply::Data(genuine(PHONE, 1));
        }
        match packets.iter().find(|p| p.name == *name) {
            Some(p) => Reply::Data(p.wire.clone()),
            None => Reply::Nack(NackReason::NoRoute),
        }
    });
    r.group.on_update(notice(PHONE, 1));
    pass(10).await;
    let st = r.host.st.lock();
    assert_eq!(st.assembled, vec![id], "recorded whole once");
    let mut names: Vec<Name> = st.stored.keys().cloned().collect();
    names.sort();
    let mut expected: Vec<Name> = cut.packets.iter().map(|p| p.name.clone()).collect();
    expected.sort();
    assert_eq!(names, expected, "every piece was kept, by name");
    assert!(
        st.keeps >= 1 && st.keeps <= expected.len(),
        "a round of proved pieces is one batch, not one write per piece: {} batches",
        st.keeps
    );
}

/// A space may owe many values in pieces, each up to 64 MiB: only
/// `ASSEMBLIES_MAX` are gathered at once on the node, and every one is
/// gathered in its turn.
#[tokio::test(start_paused = true)]
async fn only_a_few_values_are_gathered_at_once_and_every_one_in_turn() {
    let r = rig().await;
    r.wire.delay(Duration::from_millis(200));
    let mut owed = Vec::new();
    let mut packets = Vec::new();
    for seq in 1..=12u64 {
        let entry_name = log_name(&n(PHONE), &space(), seq);
        let cut = pieces::split(&entry_name, &vec![seq as u8; 1000]).unwrap();
        owed.push(Blob {
            id: EntryId {
                device: n(PHONE),
                seq,
                digest: [seq as u8; 32],
            },
            size: cut.size,
            root: cut.root,
        });
        packets.extend(cut.packets);
    }
    r.host.st.lock().blobs_owed = owed;
    r.wire
        .script(move |name| match packets.iter().find(|p| p.name == *name) {
            Some(p) => Reply::Data(p.wire.clone()),
            None => Reply::Nack(NackReason::NoRoute),
        });
    r.group.on_update(notice(PHONE, 1));
    pass(20).await;
    let st = r.host.st.lock();
    assert_eq!(st.assembled.len(), 12, "every value is gathered in turn");
    assert!(
        r.wire.peak() <= 4,
        "{} pieces were asked at once for 12 values of one piece each: at most 4 values gather at once",
        r.wire.peak()
    );
}

/// A copy of a piece that is not the one its parent lists is never taken;
/// the piece is asked of another holder and the value assembles.
#[tokio::test(start_paused = true)]
async fn a_bad_piece_is_never_taken_and_another_holder_is_asked() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), false);
    }
    let entry_name = log_name(&n(PHONE), &space(), 1);
    let payload: Vec<u8> = (0..9_000u32).map(|i| (i % 13) as u8).collect();
    let cut = pieces::split(&entry_name, &payload).unwrap();
    let id = EntryId {
        device: n(PHONE),
        seq: 1,
        digest: [4; 32],
    };
    r.host.st.lock().blobs_on_take = vec![Blob {
        id: id.clone(),
        size: cut.size,
        root: cut.root,
    }];
    let packets = cut.packets.clone();
    let bad_one = cut.packets[1].name.clone();
    r.wire.script(move |name| {
        if direct(name) == Some((n(PHONE), 1)) {
            return Reply::Data(genuine(PHONE, 1));
        }
        if let Some(p) = packets.iter().find(|p| p.name == *name) {
            if *name == bad_one {
                // Someone else's bytes under the piece's name.
                return Reply::Data(
                    DataBuilder::new(name.clone(), b"not the piece").sign_digest_sha256(),
                );
            }
            return Reply::Data(p.wire.clone());
        }
        if let Some((holder, original)) = parse_held_name(name)
            && holder == n(TABLET)
            && let Some(p) = packets.iter().find(|p| p.name == original)
        {
            return Reply::Data(wrapped(name, p.wire.clone()));
        }
        Reply::Nack(NackReason::NoRoute)
    });
    r.group.on_update(notice(TABLET, 1));
    r.group.on_update(notice(PHONE, 1));
    pass(60).await;
    let st = r.host.st.lock();
    assert_eq!(st.assembled, vec![id], "assembled from the second holder");
    assert_eq!(
        st.stored.get(&cut.packets[1].name),
        Some(&cut.packets[1].wire),
        "the genuine copy is kept, not the bad one"
    );
}

/// An epoch key owed is asked of the epoch's creator, then of the heard
/// members that vouch, in rounds with growing pauses, until a grant arrives.
#[tokio::test(start_paused = true)]
async fn the_grant_pull_walks_creator_then_relays_with_backoff() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        for d in [TABLET, DESKTOP] {
            st.vouched.insert(n(d));
            st.standing.insert(n(d), false);
        }
        st.owed = vec![EpochId {
            creator: n(PHONE),
            seq: 4,
        }];
    }
    // The desktop's asks so far, and when the latest began: an Interest within one lifetime of
    // that is the same ask expressed again (how many times it is depends on the round-trip
    // estimate of that device), a later one is the next ask.
    let answered = Arc::new(parking_lot::Mutex::new((
        0usize,
        None::<tokio::time::Instant>,
    )));
    let counter = Arc::clone(&answered);
    r.wire.script(move |name| {
        let Some((granter, _)) = parse_grant_name(name) else {
            return Reply::Nack(NackReason::NoRoute);
        };
        if granter == n(PHONE) {
            return Reply::Silent;
        }
        if granter == n(TABLET) {
            return Reply::Nack(NackReason::NoRoute);
        }
        // The third round's desktop answers; before, it is silent.
        let mut asked = counter.lock();
        let now = tokio::time::Instant::now();
        if asked
            .1
            .is_none_or(|began| now.duration_since(began) >= Duration::from_secs(2))
        {
            asked.0 += 1;
            asked.1 = Some(now);
        }
        if asked.0 < 3 {
            Reply::Silent
        } else {
            Reply::Data(DataBuilder::new(name.clone(), b"a key, wrapped").sign_digest_sha256())
        }
    });
    r.group.on_update(notice(TABLET, 1));
    r.group.on_update(notice(DESKTOP, 1));
    pass(60).await;
    // An ask the granter left unanswered is expressed again under a fresh nonce within its
    // lifetime: one ask, however many Interests it took.
    let mut asks: Vec<(Name, tokio::time::Instant)> = r
        .wire
        .times()
        .into_iter()
        .filter(|(name, _)| parse_grant_name(name).is_some())
        .collect();
    asks.dedup_by(|again, first| again.0 == first.0);
    let order: Vec<Name> = asks
        .iter()
        .take(3)
        .map(|(name, _)| parse_grant_name(name).unwrap().0)
        .collect();
    assert_eq!(
        order,
        vec![n(PHONE), n(TABLET), n(DESKTOP)],
        "the creator first, then the members that vouch"
    );
    {
        let st = r.host.st.lock();
        assert_eq!(st.arrived.len(), 1, "the key arrived once");
        assert_eq!(st.arrived[0].0.seq, 4);
        assert!(st.owed.is_empty());
    }
    let rounds: Vec<tokio::time::Instant> = asks
        .iter()
        .filter(|(name, _)| parse_grant_name(name).unwrap().0 == n(PHONE))
        .map(|(_, t)| *t)
        .collect();
    assert!(rounds.len() >= 3, "round after round: {}", rounds.len());
    let gaps: Vec<Duration> = rounds.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps[1] > gaps[0], "the pauses grow: {gaps:?}");
    let total = r
        .wire
        .times()
        .iter()
        .filter(|(name, _)| parse_grant_name(name).is_some())
        .count();
    pass(120).await;
    assert_eq!(
        r.wire
            .times()
            .iter()
            .filter(|(name, _)| parse_grant_name(name).is_some())
            .count(),
        total,
        "once the key is held nothing is asked"
    );
    assert!(
        r.wire
            .names()
            .iter()
            .all(|name| match parse_grant_name(name) {
                Some((granter, ask)) => {
                    ask.epoch.creator == n(PHONE)
                        && ask.space == space()
                        && ask.seal_key == seal_key_name(&n(LAPTOP), &[7; 32])
                        && [PHONE, TABLET, DESKTOP].contains(&granter.to_string().as_str())
                }
                None => true,
            }),
        "every ask names this device's seal key, the space and the epoch"
    );
}

/// A granted key the log does not take (it fails the key check of the Epoch
/// entry naming the epoch) ends nothing: the key is still owed and asked
/// for.
#[tokio::test(start_paused = true)]
async fn a_key_that_fails_the_key_check_is_dropped() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        st.vouched.insert(n(TABLET));
        st.standing.insert(n(TABLET), false);
        st.owed = vec![EpochId {
            creator: n(PHONE),
            seq: 4,
        }];
        st.key_matches = false;
    }
    r.wire.script(|name| match parse_grant_name(name) {
        Some((g, _)) if g == n(TABLET) => {
            Reply::Data(DataBuilder::new(name.clone(), b"a wrong key").sign_digest_sha256())
        }
        _ => Reply::Silent,
    });
    r.group.on_update(notice(TABLET, 1));
    pass(20).await;
    let given = r.host.st.lock().arrived.len();
    assert!(
        given >= 2,
        "the wrong key was refused and the ask went on: {given}"
    );
    assert_eq!(r.host.st.lock().owed.len(), 1, "the key is still owed");
    r.host.st.lock().key_matches = true;
    pass(80).await;
    assert!(r.host.st.lock().owed.is_empty(), "the right key ended it");
}

/// A name a Sync Interest carried that nothing vouches for is never asked
/// for a key: the creator and vouched members only.
#[tokio::test(start_paused = true)]
async fn a_name_a_sync_interest_carried_is_never_asked_for_a_key() {
    let r = rig().await;
    {
        let mut st = r.host.st.lock();
        st.owed = vec![EpochId {
            creator: n(PHONE),
            seq: 4,
        }];
    }
    r.wire.script(|_| Reply::Silent);
    for i in 0..20 {
        r.group.on_update(notice(&format!("/alice/ghost{i}"), 3));
    }
    pass(30).await;
    let granters: std::collections::BTreeSet<Name> = r
        .wire
        .names()
        .iter()
        .filter_map(|name| parse_grant_name(name).map(|(g, _)| g))
        .collect();
    assert_eq!(
        granters,
        [n(PHONE)].into_iter().collect(),
        "only the epoch's creator"
    );
}

/// A device that joined a group and heard no one asks the group again, after the capped
/// doubling pauses, not once a group period (half a minute) later: the join announcement, or the
/// reply a peer made to it, may be what the link lost (p1 at `--faulty --fault-seed 1`: the
/// laptop joined the space the phone wrote into, the phone's reply was lost three times in a row,
/// and the first notice came 95 s after the join). The asks are a bounded handful, then the
/// group's period alone.
#[tokio::test(start_paused = true)]
async fn a_group_joined_and_heard_from_no_one_is_announced_again_with_growing_pauses() {
    let r = rig().await;
    let group = sync_group_of(&space()).unwrap();
    pass(1).await;
    let at_1s = r.face.sent_in(&group);
    assert!(
        at_1s >= 3,
        "the join announcement and two more within a second, not {at_1s}"
    );
    pass(8).await;
    let at_9s = r.face.sent_in(&group);
    assert!(
        at_9s >= 5,
        "the pauses grow to seconds but go on while no one is heard, not {at_9s} by 9 s"
    );
    pass(60).await;
    let at_70s = r.face.sent_in(&group);
    assert!(
        at_70s <= 1 + 8 + 3,
        "bounded: the join, eight more, and the group's period, not {at_70s}"
    );
}

/// The asking again ends at the first notice of the group: a peer is heard.
#[tokio::test(start_paused = true)]
async fn a_group_asked_again_stops_when_a_peer_is_heard() {
    let r = rig().await;
    let group = sync_group_of(&space()).unwrap();
    pass(1).await;
    r.group.on_update(notice(PHONE, 1));
    let heard = r.face.sent_in(&group);
    pass(25).await;
    assert_eq!(
        r.face.sent_in(&group),
        heard,
        "no more announcements within a group period once a peer is heard"
    );
}

/// Over a real forwarder and the real SVS driver: a device publishes its
/// counter, the other hears the notice, fetches the entry it names through
/// the forwarder from the writer's server, and takes it: one fetch, one take.
#[tokio::test]
async fn a_published_counter_reaches_a_peer_which_fetches_the_entry_through_the_engine() {
    use crate::test_kit::cluster::Cluster;
    let cluster = Cluster::new(&[LAPTOP, PHONE]).await;
    let (laptop, phone) = (cluster.device(0), cluster.device(1));
    let (on_laptop, on_phone) = (Toyhost::new(LAPTOP), Toyhost::new(PHONE));
    let cfg = Config {
        svs: ndn_sync::SvsConfig::lan(),
        ..Config::default()
    };
    let laptop_net = Net::start(
        Arc::clone(&on_laptop) as Arc<dyn Host>,
        cfg.clone(),
        laptop.node.connection(),
        Arc::clone(&laptop.sync),
    );
    let phone_net = Net::start(
        Arc::clone(&on_phone) as Arc<dyn Host>,
        cfg,
        phone.node.connection(),
        Arc::clone(&phone.sync),
    );
    let _serving = phone
        .node
        .serve(phone.name.clone(), {
            let net = Arc::clone(&phone_net);
            move |interest, responder| crate::serve::answer(Arc::clone(&net), interest, responder)
        })
        .await
        .expect("the phone serves its name");
    laptop_net.join(&space(), 0).await.expect("laptop joins");
    let on_the_phone = phone_net.join(&space(), 0).await.expect("phone joins");
    on_phone
        .st
        .lock()
        .served
        .insert((n(PHONE), 1), genuine(PHONE, 1));
    on_the_phone.sink().publish(1).await;
    let began = std::time::Instant::now();
    while !on_laptop.holds(PHONE, 1) {
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "the entry did not arrive within ten seconds"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        on_laptop.st.lock().taken,
        vec![(n(PHONE), 1)],
        "one fetch, one take"
    );
}

/// The SVS driver is authoritative for this device's own name and merges no
/// remote counter into it, so a peer's counter for it is no notice: after a
/// restart that lost two entries, the peer's vector still names this device
/// at 2, and the half reads that from the observed state and tells the log.
#[tokio::test]
async fn a_peers_counter_for_this_device_is_read_from_the_observed_state() {
    use crate::test_kit::cluster::Cluster;
    let mut cluster = Cluster::new(&[LAPTOP, PHONE]).await;
    let cfg = Config {
        svs: ndn_sync::SvsConfig::lan(),
        ..Config::default()
    };
    let on_phone = Toyhost::new(PHONE);
    let phone_net = Net::start(
        Arc::clone(&on_phone) as Arc<dyn Host>,
        cfg.clone(),
        cluster.device(1).node.connection(),
        Arc::clone(&cluster.device(1).sync),
    );
    phone_net.join(&space(), 0).await.expect("phone joins");
    let before = Toyhost::new(LAPTOP);
    let laptop_net = Net::start(
        Arc::clone(&before) as Arc<dyn Host>,
        cfg.clone(),
        cluster.device(0).node.connection(),
        Arc::clone(&cluster.device(0).sync),
    );
    let group = laptop_net.join(&space(), 0).await.expect("laptop joins");
    group.sink().publish(1).await;
    group.sink().publish(2).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The laptop restarts with nothing of its own.
    laptop_net.shutdown();
    drop(group);
    let again = cluster.restart(0);
    let after = Toyhost::new(LAPTOP);
    let net = Net::start(
        Arc::clone(&after) as Arc<dyn Host>,
        cfg,
        again.node.connection(),
        Arc::clone(&again.sync),
    );
    net.join(&space(), 0).await.expect("laptop joins again");
    let began = std::time::Instant::now();
    while !after.st.lock().counters.contains(&(n(LAPTOP), 2)) {
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "the peer's counter for this device never reached the log: {:?}",
            after.st.lock().counters
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
