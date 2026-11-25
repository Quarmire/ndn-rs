//! The receiver's session store: lifetime and grace, the 75 % renewal, the key before the
//! current one, the once-a-second ask for an unknown key epoch. Time is an `Instant` the case
//! moves by hand: no case reads a clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

use super::*;
use crate::node::tests::world;
use crate::trust::Judge;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn record(id: u64, key_epoch: u32, lifetime: u64) -> SessionRecord {
    SessionRecord {
        id,
        sender: n("/bob/phone"),
        space: n("/alice/32=data/notes"),
        mode: ChannelMode::Latest,
        key_epoch,
        key_id: [0; 8],
        wrap: Bytes::new(),
        aead: Aead::Aes256Gcm,
        carriers: Vec::new(),
        table: Vec::new(),
        ckpt_ms: 20,
        window: None,
        lifetime,
        audience_epoch: None,
        frame_max: 1200,
        seq: 1,
        certs: Vec::new(),
    }
}

struct Fixture {
    judge: Arc<Judge>,
    fold: Arc<AtomicU64>,
    store: RecvSessions,
}

async fn fixture() -> Fixture {
    let dev = world(&["/alice/laptop"]).await.remove(0);
    let (judge, _inbox) = Judge::new(Arc::clone(&dev.validator), Arc::clone(&dev.store), None);
    Fixture {
        judge,
        fold: Arc::new(AtomicU64::new(0)),
        store: RecvSessions::default(),
    }
}

impl Fixture {
    fn session(&self, record: &SessionRecord, key: [u8; 32], now: Instant) -> Arc<RecvSession> {
        let session = Arc::new(RecvSession::new(
            record,
            ChannelKey::from_bytes(key),
            n("/bob/phone/KEY/1"),
            Arc::clone(&self.judge),
            Arc::clone(&self.fold),
            (self.judge.generation(), self.fold.load(Ordering::SeqCst)),
            now,
        ));
        self.store.insert(Arc::clone(&session));
        session
    }
}

fn eq(a: &Option<FrameKey>, b: &ChannelKey, id: u64, epoch: u32) -> bool {
    a.as_ref()
        .is_some_and(|k| k.expose() == b.frame_key(id, epoch).expose())
}

#[tokio::test]
async fn a_session_past_its_lifetime_plus_grace_is_not_used() {
    let f = fixture().await;
    let t0 = Instant::now();
    let key = ChannelKey::from_bytes([1; 32]);
    let s = f.session(&record(7, 0, 10), [1; 32], t0);
    assert!(s.usable(t0));
    assert!(
        eq(
            &s.frame_key(0, t0 + Duration::from_millis(14_900)),
            &key,
            7,
            0
        ),
        "inside lifetime and grace"
    );
    assert!(s.usable(t0 + Duration::from_millis(14_900)));
    // Lifetime 10 s and a grace of 5 s, counted from receipt.
    assert!(!s.usable(t0 + Duration::from_secs(15)));
    assert!(
        s.frame_key(0, t0 + Duration::from_secs(15)).is_none(),
        "no key past the grace"
    );
    // The store drops it with the reason.
    assert_eq!(f.store.lapse(t0 + Duration::from_secs(15)), vec![7]);
    assert!(f.store.get(7).is_none());
    assert_eq!(s.ended(), Some(EndReason::Lapsed));
}

#[tokio::test]
async fn renewal_is_due_at_75_percent_and_a_failed_one_is_tried_again_after_ten_seconds() {
    let f = fixture().await;
    let t0 = Instant::now();
    let s = f.session(&record(7, 0, 100), [1; 32], t0);
    assert!(!s.renewal_due(t0 + Duration::from_millis(74_900)));
    assert!(s.renewal_due(t0 + Duration::from_secs(75)));
    assert_eq!(f.store.due(t0 + Duration::from_secs(75)).len(), 1);
    s.renewal_failed(t0 + Duration::from_secs(75));
    assert!(!s.renewal_due(t0 + Duration::from_secs(84)));
    assert!(s.renewal_due(t0 + Duration::from_secs(85)));
    // The renewal: the same channel, a new key epoch and a new lifetime from receipt.
    s.renewed(
        &record(7, 1, 100),
        ChannelKey::from_bytes([2; 32]),
        n("/bob/phone/KEY/1"),
        (0, 0),
        t0 + Duration::from_secs(85),
    );
    assert_eq!(s.key_epoch(), 1);
    assert!(!s.renewal_due(t0 + Duration::from_secs(85 + 74)));
    assert!(s.renewal_due(t0 + Duration::from_secs(85 + 75)));
}

#[tokio::test]
async fn the_old_key_is_accepted_only_for_the_grace_after_the_new_epoch_was_first_seen() {
    let f = fixture().await;
    let t0 = Instant::now();
    let old = ChannelKey::from_bytes([1; 32]);
    let new = ChannelKey::from_bytes([2; 32]);
    let s = f.session(&record(7, 0, 3600), [1; 32], t0);
    assert!(
        s.frame_key(1, t0).is_none(),
        "an epoch not held opens nothing"
    );

    // A frame under epoch 1 arrives at t1; the answer with its key at t1 + 50 ms.
    let t1 = t0 + Duration::from_secs(100);
    assert!(matches!(
        f.store.unknown_epoch(7, 1, t1),
        Unknown::Ask { .. }
    ));
    s.renewed(
        &record(7, 1, 3600),
        ChannelKey::from_bytes([2; 32]),
        n("/bob/phone/KEY/1"),
        (0, 0),
        t1 + Duration::from_millis(50),
    );
    let seen = |at| (s.frame_key(0, at), s.frame_key(1, at));
    let (o, nw) = seen(t1 + Duration::from_millis(4900));
    assert!(
        eq(&o, &old, 7, 0) && eq(&nw, &new, 7, 1),
        "both keys for the grace: {o:?} {nw:?}"
    );
    let (o, nw) = seen(t1 + Duration::from_millis(5001));
    assert!(
        o.is_none(),
        "the old key is refused 5 s after the new epoch was first seen"
    );
    assert!(eq(&nw, &new, 7, 1));
}

#[tokio::test]
async fn a_renewal_with_no_frame_seen_first_counts_the_grace_from_the_answer() {
    let f = fixture().await;
    let t0 = Instant::now();
    let s = f.session(&record(7, 0, 100), [1; 32], t0);
    let t1 = t0 + Duration::from_secs(75);
    s.renewed(
        &record(7, 1, 100),
        ChannelKey::from_bytes([2; 32]),
        n("/bob/phone/KEY/1"),
        (0, 0),
        t1,
    );
    assert!(s.frame_key(0, t1 + Duration::from_millis(4999)).is_some());
    assert!(s.frame_key(0, t1 + Duration::from_millis(5001)).is_none());
    // The same epoch again changes only the lifetime: the key held stays.
    s.renewed(
        &record(7, 1, 100),
        ChannelKey::from_bytes([9; 32]),
        n("/bob/phone/KEY/1"),
        (0, 0),
        t1 + Duration::from_secs(1),
    );
    assert!(eq(
        &s.frame_key(1, t1 + Duration::from_secs(1)),
        &ChannelKey::from_bytes([2; 32]),
        7,
        1
    ));
}

#[tokio::test]
async fn a_frame_under_an_unknown_key_epoch_asks_the_sender_at_most_once_a_second() {
    let f = fixture().await;
    let t0 = Instant::now();
    f.session(&record(7, 0, 3600), [1; 32], t0);
    assert_eq!(
        f.store.unknown_epoch(8, 1, t0),
        Unknown::NoSession,
        "not this device's channel"
    );
    let ask = Unknown::Ask {
        space: n("/alice/32=data/notes"),
        sender: n("/bob/phone"),
        mode: ChannelMode::Latest,
    };
    assert_eq!(f.store.unknown_epoch(7, 1, t0), ask);
    for ms in [1u64, 500, 999] {
        assert_eq!(
            f.store.unknown_epoch(7, 1, t0 + Duration::from_millis(ms)),
            Unknown::Limited,
            "{ms} ms"
        );
    }
    assert_eq!(
        f.store
            .unknown_epoch(7, 1, t0 + Duration::from_millis(1000)),
        ask
    );
    assert_eq!(
        f.store
            .unknown_epoch(7, 1, t0 + Duration::from_millis(1500)),
        Unknown::Limited
    );
}

#[tokio::test]
async fn a_new_channel_of_the_same_sender_replaces_the_old_one() {
    let f = fixture().await;
    let t0 = Instant::now();
    let old = f.session(&record(7, 0, 3600), [1; 32], t0);
    let new = f.session(&record(9, 0, 3600), [3; 32], t0);
    assert_eq!(old.ended(), Some(EndReason::Replaced));
    assert!(f.store.get(7).is_none());
    assert_eq!(
        f.store
            .find(
                &n("/alice/32=data/notes"),
                &n("/bob/phone"),
                ChannelMode::Latest
            )
            .map(|s| s.id()),
        Some(9)
    );
    assert!(new.ended().is_none());
}

#[tokio::test]
async fn is_current_moves_with_the_fold_version_and_not_with_time() {
    let f = fixture().await;
    let t0 = Instant::now();
    let s = f.session(&record(7, 0, 3600), [1; 32], t0);
    assert!(s.is_current());
    assert!(s.usable(t0 + Duration::from_secs(3000)));
    assert!(s.is_current(), "time moves nothing");
    f.fold.fetch_add(1, Ordering::SeqCst);
    assert!(
        !s.is_current(),
        "the space's fold changed since the sender was judged"
    );
}
