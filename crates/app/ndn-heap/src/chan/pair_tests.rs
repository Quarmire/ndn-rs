use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_security::{ContentKey, PairKeys, RecipientKey, wrap_ck_to_pair};

use super::*;
use crate::chan::qframe::QueryHeader;

fn n(parts: &[&str]) -> Name {
    Name::from_components(
        parts
            .iter()
            .map(|p| NameComponent::generic(Bytes::copy_from_slice(p.as_bytes()))),
    )
}

/// The pair keys both ends of one session answer hold.
fn keys() -> (PairKeys, PairKeys) {
    let asker = RecipientKey::generate();
    let ck = ContentKey::generate();
    let (ephemeral, sealed, at_server) =
        wrap_ck_to_pair(&asker.public(), &ck, b"aad", b"ctx").unwrap();
    let (_, at_asker) = asker
        .unwrap_ck_pair(&ephemeral, &sealed, b"aad", b"ctx")
        .unwrap();
    (at_server, at_asker)
}

fn owner(space: &str, device: &str, channel: u64) -> PairOwner {
    PairOwner {
        space: n(&[space]),
        channel,
        key_epoch: 0,
        device: n(&[device]),
        person: n(&["person", device]),
        key: n(&[device, "KEY"]),
        stream: false,
    }
}

fn server_pair(owner: PairOwner, lease: Duration, now: Instant) -> ServerPair {
    let (keys, _) = keys();
    ServerPair::new(
        &keys,
        Aead::Aes256Gcm,
        owner,
        (1, 1),
        Arc::new(AtomicU64::new(1)),
        now + lease,
    )
}

#[test]
fn the_nonce_is_the_epochs_low_octet_three_zeros_and_the_counter() {
    assert_eq!(
        nonce(0x07, 0x0102),
        [0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02]
    );
    assert_eq!(
        nonce(0xff, u64::MAX >> 1),
        [
            0xff, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        ]
    );
}

#[test]
fn the_pair_context_binds_each_of_its_fields_and_is_canonical() {
    let base = pair_context(&n(&["s"]), 7, 3, &n(&["a"]), &n(&["b"]));
    let others = [
        pair_context(&n(&["t"]), 7, 3, &n(&["a"]), &n(&["b"])),
        pair_context(&n(&["s"]), 8, 3, &n(&["a"]), &n(&["b"])),
        pair_context(&n(&["s"]), 7, 4, &n(&["a"]), &n(&["b"])),
        pair_context(&n(&["s"]), 7, 3, &n(&["c"]), &n(&["b"])),
        pair_context(&n(&["s"]), 7, 3, &n(&["a"]), &n(&["c"])),
        // The asker and the server swapped.
        pair_context(&n(&["s"]), 7, 3, &n(&["b"]), &n(&["a"])),
    ];
    for other in &others {
        assert_ne!(&base, other);
    }
    // `/a/b` + `/c` is not `/a` + `/b/c`.
    assert_ne!(
        pair_context(&n(&["s"]), 1, 1, &n(&["a", "b"]), &n(&["c"])),
        pair_context(&n(&["s"]), 1, 1, &n(&["a"]), &n(&["b", "c"]))
    );
}

#[test]
fn a_query_opens_under_the_asker_key_an_answer_under_the_servers_and_not_the_other_way() {
    let (server, asker) = keys();
    let at_server = PairCiphers::new(&server, Aead::Aes256Gcm);
    let at_asker = PairCiphers::new(&asker, Aead::Aes256Gcm);
    let aad = [9u8; 36];
    let sealed = at_asker.seal_query(3, 17, &aad, b"hello");
    assert_eq!(sealed.len(), 5 + TAG_LEN);
    assert_eq!(
        at_server.open_query(3, 17, &aad, &sealed).unwrap(),
        b"hello"
    );
    // Kq does not open an answer, nor Ka a query.
    assert!(at_server.open_answer(3, 17, &aad, &sealed).is_none());
    let answer = at_server.seal_answer(3, 17, &aad[..19], b"yes");
    assert_eq!(
        at_asker.open_answer(3, 17, &aad[..19], &answer).unwrap(),
        b"yes"
    );
    assert!(at_asker.open_query(3, 17, &aad[..19], &answer).is_none());
}

#[test]
fn a_flipped_octet_in_any_header_field_the_counter_the_epoch_or_the_body_fails_the_aead() {
    let (server, asker) = keys();
    let at_server = PairCiphers::new(&server, Aead::Aes256Gcm);
    let at_asker = PairCiphers::new(&asker, Aead::Aes256Gcm);
    let header = QueryHeader {
        route: 0x0102_0304_0506_0708,
        token: 0x1112_1314_1516_1718,
        ttl_ticks: 5,
        pair: [1, 2, 3, 4, 5, 6, 7, 8],
        qseq: 42,
        epoch: 9,
    };
    let aad = header.encode();
    let sealed = at_asker.seal_query(header.epoch, header.qseq, &aad, b"some query octets");
    assert!(
        at_server
            .open_query(header.epoch, header.qseq, &aad, &sealed)
            .is_some()
    );
    // Every octet of the header, one flipped bit at a time.
    for at in 0..aad.len() {
        let mut bad = aad;
        bad[at] ^= 0x01;
        assert!(
            at_server
                .open_query(header.epoch, header.qseq, &bad, &sealed)
                .is_none(),
            "octet {at} of the header is authenticated"
        );
    }
    // The counter and the epoch of the nonce.
    assert!(
        at_server
            .open_query(header.epoch, 43, &aad, &sealed)
            .is_none()
    );
    assert!(
        at_server
            .open_query(10, header.qseq, &aad, &sealed)
            .is_none()
    );
    // Every octet of the body and the tag.
    for at in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[at] ^= 0x80;
        assert!(
            at_server
                .open_query(header.epoch, header.qseq, &aad, &bad)
                .is_none(),
            "octet {at} of the body is authenticated"
        );
    }
    // A cut body.
    assert!(
        at_server
            .open_query(header.epoch, header.qseq, &aad, &sealed[..sealed.len() - 1])
            .is_none()
    );
    assert!(
        at_server
            .open_query(header.epoch, header.qseq, &aad, &[])
            .is_none()
    );
}

#[test]
fn both_aeads_seal_and_open_the_same_way() {
    let (server, asker) = keys();
    for aead in [Aead::Aes256Gcm, Aead::ChaCha20Poly1305] {
        let at_server = PairCiphers::new(&server, aead);
        let at_asker = PairCiphers::new(&asker, aead);
        let sealed = at_asker.seal_query(1, 2, b"aad", b"x");
        assert_eq!(at_server.open_query(1, 2, b"aad", &sealed).unwrap(), b"x");
    }
}

#[test]
fn a_server_pair_marks_a_counter_once_and_checks_before_it_marks() {
    let now = Instant::now();
    let pair = server_pair(owner("s", "dev", 1), Duration::from_secs(60), now);
    assert!(pair.fresh(0));
    assert!(pair.fresh(0), "checking marks nothing");
    assert!(pair.mark(0));
    assert!(!pair.fresh(0), "marked");
    assert!(!pair.mark(0), "the second marker of one counter loses");
    assert!(pair.fresh(1));
    assert!(pair.mark(5000));
    assert!(!pair.fresh(5000 - 4096), "below the window");
    assert!(pair.fresh(5000 - 4095));
    assert!(
        !pair.fresh(5000 + (1 << 24) + 1),
        "a jump no honest asker makes"
    );
    assert!(pair.fresh(5000 + (1 << 24)));
}

#[test]
fn a_busy_is_due_once_a_second() {
    let now = Instant::now();
    let pair = server_pair(owner("s", "dev", 1), Duration::from_secs(60), now);
    assert!(pair.busy_due(now));
    assert!(!pair.busy_due(now + Duration::from_millis(999)));
    assert!(pair.busy_due(now + Duration::from_secs(1)));
}

#[test]
fn a_pair_is_found_by_its_id_on_its_own_channel_until_its_lease_ends() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let pair = pairs
        .install(
            server_pair(owner("s", "a", 7), Duration::from_secs(60), now),
            now,
        )
        .unwrap();
    let id = pair.id();
    assert!(pairs.get(&id, 7, now).is_some());
    assert!(pairs.get(&id, 8, now).is_none(), "another route");
    assert!(pairs.get(&[0; 8], 7, now).is_none(), "another id");
    assert!(pairs.get(&id, 7, now + Duration::from_secs(59)).is_some());
    assert!(pairs.get(&id, 7, now + Duration::from_secs(60)).is_none());
}

#[test]
fn a_replaced_pair_opens_for_the_grace_and_not_after() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let first = pairs
        .install(
            server_pair(owner("s", "a", 7), Duration::from_secs(600), now),
            now,
        )
        .unwrap();
    let second = pairs
        .install(
            server_pair(owner("s", "a", 7), Duration::from_secs(600), now),
            now,
        )
        .unwrap();
    assert_ne!(first.id(), second.id());
    assert!(pairs.get(&first.id(), 7, now).is_some(), "in the grace");
    assert!(pairs.get(&second.id(), 7, now).is_some());
    let later = now + RETIRED_GRACE + Duration::from_millis(1);
    assert!(pairs.get(&first.id(), 7, later).is_none(), "retired");
    assert!(pairs.get(&second.id(), 7, later).is_some());
    pairs.sweep(later);
    assert_eq!(pairs.count(), 1);
    assert!(pairs.has(&n(&["s"]), &n(&["a"])));
}

#[test]
fn dropping_a_device_or_a_space_takes_every_pair_of_it_at_once() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(600);
    let a = pairs
        .install(server_pair(owner("s", "a", 7), lease, now), now)
        .unwrap();
    let b = pairs
        .install(server_pair(owner("s", "b", 7), lease, now), now)
        .unwrap();
    let c = pairs
        .install(server_pair(owner("t", "a", 8), lease, now), now)
        .unwrap();
    pairs.drop_device(&n(&["s"]), &n(&["a"]));
    assert!(pairs.get(&a.id(), 7, now).is_none());
    assert!(pairs.get(&b.id(), 7, now).is_some());
    assert!(
        pairs.get(&c.id(), 8, now).is_some(),
        "the same device in another space"
    );
    pairs.drop_space(&n(&["s"]));
    assert!(pairs.get(&b.id(), 7, now).is_none());
    assert!(pairs.get(&c.id(), 8, now).is_some());
    pairs.drop_all();
    assert_eq!(pairs.count(), 0);
}

#[test]
fn a_rejudging_drops_the_askers_that_do_not_stand_and_restamps_the_rest() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(600);
    let a = pairs
        .install(server_pair(owner("s", "a", 7), lease, now), now)
        .unwrap();
    let b = pairs
        .install(server_pair(owner("s", "b", 7), lease, now), now)
        .unwrap();
    let other = pairs
        .install(server_pair(owner("t", "a", 8), lease, now), now)
        .unwrap();
    let dropped = pairs.rejudge(&n(&["s"]), (2, 2), |o| o.device != n(&["a"]));
    assert_eq!(dropped, vec![n(&["a"])]);
    assert!(pairs.get(&a.id(), 7, now).is_none());
    assert_eq!(pairs.get(&b.id(), 7, now).unwrap().judged_at(), (2, 2));
    assert_eq!(
        other.judged_at(),
        (1, 1),
        "another space is not judged by this move"
    );
    // A pair already judged by the live counters is not judged again.
    let dropped = pairs.rejudge(&n(&["s"]), (2, 2), |_| false);
    assert!(dropped.is_empty());
    assert!(pairs.get(&b.id(), 7, now).is_some());
}

#[test]
fn the_server_table_is_bounded_and_refuses_when_full_of_live_pairs() {
    // Fixed octets and a counter for the id: the bound is the table's, not the agreement's.
    let cheap = |device: &str, id: u64, lease: Duration, now: Instant| {
        let keys = PairKeys {
            query: [1; 32],
            answer: [2; 32],
            id: id.to_be_bytes(),
        };
        ServerPair::new(
            &keys,
            Aead::Aes256Gcm,
            owner("s", device, 7),
            (1, 1),
            Arc::new(AtomicU64::new(1)),
            now + lease,
        )
    };
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(600);
    for i in 0..PAIRS_MAX as u64 {
        pairs
            .install(cheap(&format!("d{i}"), i, lease, now), now)
            .unwrap();
    }
    assert_eq!(pairs.count(), PAIRS_MAX);
    assert_eq!(
        pairs
            .install(cheap("one-more", u64::MAX, lease, now), now)
            .err(),
        Some(Full::Table)
    );
    // Lapsed leases make room.
    let later = now + lease;
    assert!(
        pairs
            .install(cheap("one-more", u64::MAX, lease, later), later)
            .is_ok()
    );
    assert_eq!(pairs.count(), 1);
}

#[test]
fn a_pair_says_it_moved_when_the_trust_generation_or_the_fold_did() {
    let now = Instant::now();
    let (keys, _) = keys();
    let fold = Arc::new(AtomicU64::new(4));
    let pair = ServerPair::new(
        &keys,
        Aead::Aes256Gcm,
        owner("s", "a", 7),
        (9, 4),
        Arc::clone(&fold),
        now + Duration::from_secs(60),
    );
    assert!(!pair.moved(9), "judged by (9, 4) and nothing moved");
    assert!(pair.moved(10), "the trust generation moved");
    fold.store(5, Ordering::SeqCst);
    assert!(
        pair.moved(9),
        "the fold moved: the shared counter is read, not a copy"
    );

    // A rejudgement that keeps her restamps what she is now judged by.
    let pairs = ServerPairs::default();
    let held = pairs.install(pair, now).unwrap();
    let dropped = pairs.rejudge(&n(&["s"]), (9, 5), |_| true);
    assert!(dropped.is_empty());
    assert!(!held.moved(9));
    let dropped = pairs.rejudge(&n(&["s"]), (9, 6), |_| false);
    assert_eq!(dropped, vec![n(&["a"])]);
    assert_eq!(pairs.count(), 0);
}

#[test]
fn an_askers_counter_takes_each_number_once_even_across_threads() {
    let (_, keys) = keys();
    let pair = std::sync::Arc::new(AskPair::new(&keys, Aead::Aes256Gcm, 7, 3, Instant::now()));
    assert_eq!(pair.next_qseq(), Some(0));
    assert_eq!(pair.next_qseq(), Some(1));
    let taken: Vec<Vec<u64>> = (0..8)
        .map(|_| {
            let pair = std::sync::Arc::clone(&pair);
            std::thread::spawn(move || (0..500).filter_map(|_| pair.next_qseq()).collect())
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect();
    let mut all: Vec<u64> = taken.into_iter().flatten().collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 4000, "no number was handed out twice");
    assert_eq!(all[0], 2);
    assert_eq!(pair.epoch(), 3);
}

#[test]
fn an_askers_counter_is_used_up_at_the_limit_and_never_wraps() {
    let (_, keys) = keys();
    let pair = AskPair::new(&keys, Aead::Aes256Gcm, 7, 0, Instant::now());
    pair.next.store(QSEQ_LIMIT - 1, Ordering::Relaxed);
    assert_eq!(pair.next_qseq(), Some(QSEQ_LIMIT - 1));
    assert_eq!(pair.next_qseq(), None);
    assert_eq!(pair.next_qseq(), None);
}

#[test]
fn three_silent_queries_in_a_row_say_the_server_forgot_the_pair_and_an_answer_resets_it() {
    let (_, keys) = keys();
    let t0 = Instant::now();
    let pair = AskPair::new(&keys, Aead::Aes256Gcm, 7, 0, t0);
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    assert!(!pair.silence(at(1)));
    assert!(!pair.silence(at(2)));
    pair.answered(at(3));
    assert!(!pair.silence(at(4)));
    assert!(!pair.silence(at(5)));
    assert!(pair.silence(at(6)));
}

#[test]
fn a_silent_query_sent_before_an_answer_is_no_evidence_the_pair_is_gone() {
    let (_, keys) = keys();
    let t0 = Instant::now();
    let pair = AskPair::new(&keys, Aead::Aes256Gcm, 7, 0, t0);
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    // Five queries in flight; the server answers the fifth (it limited, passed or lost the
    // others): their silence says nothing of the pair, however many there are.
    pair.answered(at(10));
    for sent in 1..=5 {
        assert!(
            !pair.silence(at(sent)),
            "query sent at {sent} ms, answered at 10 ms"
        );
    }
    // A query sent after the answer is evidence again, three in a row.
    assert!(!pair.silence(at(11)));
    assert!(!pair.silence(at(12)));
    assert!(pair.silence(at(13)));
    // And an answer to a query sent later still ends the run.
    pair.answered(at(20));
    assert!(!pair.silence(at(14)), "sent before the answer");
    assert!(!pair.silence(at(21)));
}

#[test]
fn the_asker_keeps_a_pair_per_session_and_lets_idle_and_vanished_ones_go() {
    let pairs = AskPairs::default();
    let now = Instant::now();
    let (_, k1) = keys();
    let (_, k2) = keys();
    let first = pairs.set(1, AskPair::new(&k1, Aead::Aes256Gcm, 1, 0, now));
    pairs.set(2, AskPair::new(&k2, Aead::Aes256Gcm, 2, 0, now));
    assert_eq!(pairs.get(1).unwrap().id(), first.id());
    // A new session of the same channel replaces the pair; a holder of the old one keeps it.
    let (_, k3) = keys();
    let third = pairs.set(1, AskPair::new(&k3, Aead::Aes256Gcm, 1, 1, now));
    assert_ne!(third.id(), first.id());
    assert_eq!(pairs.get(1).unwrap().id(), third.id());
    // Idle.
    pairs.get(2).unwrap().touch(now + Duration::from_secs(50));
    let idle = pairs.idle(now + Duration::from_secs(61), Duration::from_secs(60));
    assert_eq!(idle, vec![1]);
    // Sessions gone.
    pairs.retain_sessions(|id| id == 2);
    assert!(pairs.get(1).is_none());
    assert_eq!(pairs.count(), 1);
    pairs.remove(2);
    assert_eq!(pairs.count(), 0);
}

/// A pair with fixed octets and a counter for the id: for the tests of the table's bounds, which
/// are not about the agreement.
fn numbered(owner: PairOwner, id: u64, lease: Duration, now: Instant) -> ServerPair {
    let keys = PairKeys {
        query: [1; 32],
        answer: [2; 32],
        id: id.to_be_bytes(),
    };
    ServerPair::new(
        &keys,
        Aead::Aes256Gcm,
        owner,
        (1, 1),
        Arc::new(AtomicU64::new(1)),
        now + lease,
    )
}

#[test]
fn a_device_asking_every_250_ms_holds_at_most_two_pairs() {
    // The per-key ask rate lets a device ask four times a second, and the maintenance pass sweeps
    // every 250 ms: the replaced pairs of one device may not pile up behind its current one.
    let pairs = ServerPairs::default();
    let start = Instant::now();
    let lease = Duration::from_secs(3_600);
    for i in 0..80u64 {
        let now = start + Duration::from_millis(250 * i);
        pairs
            .install(numbered(owner("s", "a", 7), i, lease, now), now)
            .unwrap();
        pairs.sweep(now);
        assert!(
            pairs.count() <= 2,
            "after {} asks of one device the table holds {} pairs: one current and one retired \
             is the most",
            i + 1,
            pairs.count()
        );
    }
    // The newest is the device's, and the one before it is the one in grace.
    let now = start + Duration::from_millis(250 * 79);
    assert!(pairs.get(&78u64.to_be_bytes(), 7, now).is_some());
    assert!(pairs.get(&79u64.to_be_bytes(), 7, now).is_some());
    assert!(
        pairs.get(&77u64.to_be_bytes(), 7, now).is_none(),
        "gone at once"
    );
}

#[test]
fn a_retired_pair_of_a_device_is_dropped_at_once_by_its_next_replacement() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(600);
    for i in 0..3u64 {
        pairs
            .install(numbered(owner("s", "a", 7), i, lease, now), now)
            .unwrap();
    }
    assert_eq!(pairs.count(), 2);
    assert!(pairs.get(&0u64.to_be_bytes(), 7, now).is_none());
    assert!(pairs.get(&1u64.to_be_bytes(), 7, now).is_some(), "in grace");
    assert!(pairs.get(&2u64.to_be_bytes(), 7, now).is_some());
    // Another device, and the same device in another space, keep theirs.
    pairs
        .install(numbered(owner("s", "b", 7), 10, lease, now), now)
        .unwrap();
    pairs
        .install(numbered(owner("t", "a", 8), 11, lease, now), now)
        .unwrap();
    pairs
        .install(numbered(owner("s", "a", 7), 3, lease, now), now)
        .unwrap();
    assert_eq!(pairs.count(), 4);
    assert!(pairs.get(&10u64.to_be_bytes(), 7, now).is_some());
    assert!(pairs.get(&11u64.to_be_bytes(), 8, now).is_some());
}

#[test]
fn a_device_with_a_retired_pair_can_replace_it_in_a_full_table() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(600);
    pairs
        .install(numbered(owner("s", "first", 7), u64::MAX, lease, now), now)
        .unwrap();
    pairs
        .install(
            numbered(owner("s", "first", 7), u64::MAX - 1, lease, now),
            now,
        )
        .unwrap();
    for i in 0..(PAIRS_MAX - 2) as u64 {
        pairs
            .install(
                numbered(owner("s", &format!("d{i}"), 7), i, lease, now),
                now,
            )
            .unwrap();
    }
    assert_eq!(pairs.count(), PAIRS_MAX);
    // A third ask of the first device frees the pair it retired and takes its place.
    assert!(
        pairs
            .install(
                numbered(owner("s", "first", 7), u64::MAX - 2, lease, now),
                now
            )
            .is_ok(),
        "the replaced pair makes room for its replacement"
    );
    assert_eq!(pairs.count(), PAIRS_MAX);
    // A new device finds the table full.
    assert_eq!(
        pairs
            .install(numbered(owner("s", "new", 7), 1 << 40, lease, now), now)
            .err(),
        Some(Full::Table)
    );
}

#[test]
fn sweeping_and_rejudging_16384_pairs_is_linear() {
    let pairs = ServerPairs::default();
    let now = Instant::now();
    let lease = Duration::from_secs(3_600);
    for i in 0..PAIRS_MAX as u64 {
        pairs
            .install(
                numbered(owner("s", &format!("d{i}"), 7), i, lease, now),
                now,
            )
            .unwrap();
    }
    assert_eq!(pairs.count(), PAIRS_MAX);
    // A bound that a pass linear in the table meets by a wide margin (tens of milliseconds in a
    // debug build on a loaded machine, a few on an idle one) and one that compares each pair with
    // each other pair (16,384 squared: 700 ms and more in a debug build) does not.
    let bound = Duration::from_millis(400);

    let began = std::time::Instant::now();
    pairs.sweep(now + Duration::from_secs(1));
    let swept = began.elapsed();
    assert_eq!(pairs.count(), PAIRS_MAX, "nothing had lapsed");
    assert!(swept < bound, "sweeping {PAIRS_MAX} pairs took {swept:?}");

    // Every other device stops standing: the judgement is asked once for each pair it concerns,
    // and what it drops is dropped from the table of devices too.
    let asked = std::cell::Cell::new(0usize);
    let began = std::time::Instant::now();
    let dropped = pairs.rejudge(&n(&["s"]), (2, 2), |_| {
        asked.set(asked.get() + 1);
        asked.get() % 2 == 0
    });
    let rejudged = began.elapsed();
    assert_eq!(asked.get(), PAIRS_MAX, "each pair is judged once");
    assert_eq!(dropped.len() + pairs.count(), PAIRS_MAX);
    assert!(!dropped.is_empty() && pairs.count() > 0);
    assert!(
        rejudged < bound,
        "rejudging {PAIRS_MAX} pairs took {rejudged:?}"
    );
}
