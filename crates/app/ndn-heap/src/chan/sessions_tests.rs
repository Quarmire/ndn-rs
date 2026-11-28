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
        self.store
            .insert(Arc::clone(&session))
            .expect("a fixture session's id is held by nobody else");
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
async fn a_junk_frame_under_a_future_epoch_does_not_shorten_the_old_keys_grace() {
    let f = fixture().await;
    let t0 = Instant::now();
    let old = ChannelKey::from_bytes([1; 32]);
    let new = ChannelKey::from_bytes([2; 32]);
    let s = f.session(&record(7, 0, 3600), [1; 32], t0);
    assert!(
        s.frame_key(1, t0).is_none(),
        "an epoch not held opens nothing"
    );

    // Anyone who can reach the device sends a frame of channel 7 under epoch octet 1 at t1: it
    // is not authenticated (its key is not held), so it says nothing of when the sender
    // re-keyed. The sender's answer with the new key comes 100 s later.
    let t1 = t0 + Duration::from_secs(100);
    assert!(matches!(f.store.unknown_epoch(7, t1), Unknown::Ask { .. }));
    let t2 = t1 + Duration::from_secs(100);
    s.renewed(
        &record(7, 1, 3600),
        ChannelKey::from_bytes([2; 32]),
        n("/bob/phone/KEY/1"),
        (0, 0),
        t2,
    );
    let seen = |at| (s.frame_key(0, at), s.frame_key(1, at));
    let (o, nw) = seen(t2 + Duration::from_millis(4900));
    assert!(
        eq(&o, &old, 7, 0) && eq(&nw, &new, 7, 1),
        "both keys for the grace, counted from the answer: {o:?} {nw:?}"
    );
    let (o, nw) = seen(t2 + Duration::from_millis(5001));
    assert!(o.is_none(), "the old key is refused 5 s after the answer");
    assert!(eq(&nw, &new, 7, 1));
}

/// A hostile writer signs a session of lifetime `2^63`; the maintenance task runs `lapse` and
/// `due`, the frame layer `usable` and `frame_key`, over it: none may panic (a panic in
/// `chan_tick` ends the task for good).
#[tokio::test]
async fn a_session_of_lifetime_2_pow_63_does_not_panic_the_store() {
    let f = fixture().await;
    let t0 = Instant::now();
    for lifetime in [1u64 << 63, u64::MAX - 4, u64::MAX] {
        let s = f.session(&record(7, 0, lifetime), [1; 32], t0);
        let later = t0 + Duration::from_secs(1000);
        assert!(s.usable(later), "a session that long is usable");
        assert!(s.frame_key(0, later).is_some());
        assert!(!s.renewal_due(later), "and is not due its renewal");
        assert!(f.store.lapse(later).is_empty());
        assert!(f.store.due(later).is_empty());
        // A renewal that carries the same lifetime does not panic either.
        s.renewed(
            &record(7, 1, lifetime),
            ChannelKey::from_bytes([2; 32]),
            n("/bob/phone/KEY/1"),
            (0, 0),
            later,
        );
        assert!(s.usable(later));
    }
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
        f.store.unknown_epoch(8, t0),
        Unknown::NoSession,
        "not this device's channel"
    );
    let ask = Unknown::Ask {
        space: n("/alice/32=data/notes"),
        sender: n("/bob/phone"),
        mode: ChannelMode::Latest,
    };
    assert_eq!(f.store.unknown_epoch(7, t0), ask);
    for ms in [1u64, 500, 999] {
        assert_eq!(
            f.store.unknown_epoch(7, t0 + Duration::from_millis(ms)),
            Unknown::Limited,
            "{ms} ms"
        );
    }
    assert_eq!(
        f.store.unknown_epoch(7, t0 + Duration::from_millis(1000)),
        ask
    );
    assert_eq!(
        f.store.unknown_epoch(7, t0 + Duration::from_millis(1500)),
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
async fn a_session_never_overwrites_the_id_another_channel_holds() {
    let f = fixture().await;
    let t0 = Instant::now();
    let bobs = f.session(&record(7, 0, 3600), [1; 32], t0);
    let make = |record: &SessionRecord| {
        Arc::new(RecvSession::new(
            record,
            ChannelKey::from_bytes([9; 32]),
            n("/carol/tablet/KEY/1"),
            Arc::clone(&f.judge),
            Arc::clone(&f.fold),
            (f.judge.generation(), f.fold.load(Ordering::SeqCst)),
            t0,
        ))
    };
    // Another sender, the same space and mode, the same id.
    let carols = SessionRecord {
        sender: n("/carol/tablet"),
        ..record(7, 0, 3600)
    };
    let held = f.store.insert(make(&carols)).expect_err("the id is bob's");
    assert_eq!(
        (held.sender, held.space, held.mode),
        (
            n("/bob/phone"),
            n("/alice/32=data/notes"),
            ChannelMode::Latest
        )
    );
    // The same sender and space in another mode, and another space, are other channels too.
    for other in [
        SessionRecord {
            mode: ChannelMode::Reliable,
            ..record(7, 0, 3600)
        },
        SessionRecord {
            space: n("/alice/32=data/other"),
            ..record(7, 0, 3600)
        },
    ] {
        assert!(f.store.insert(make(&other)).is_err());
    }
    // Nothing changed: bob's session is the one held, not ended, and the generation did not move.
    let generation = f.store.generation();
    assert!(f.store.insert(make(&carols)).is_err());
    assert_eq!(f.store.generation(), generation);
    let kept = f.store.get(7).unwrap();
    assert!(Arc::ptr_eq(&kept, &bobs) && kept.ended().is_none());
    assert_eq!(f.store.all().len(), 1);
    // The channel itself may be put again (the same space, sender and mode).
    f.store
        .insert(make(&record(7, 1, 3600)))
        .expect("the holder of an id may take it again");
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

/// The sender's checkpoint key is decoded when the session takes it, once: a renewal that finds the
/// same 32 octets keeps the decoded key (nothing decoded again), another key replaces it, octets
/// that are not a point are held with no decoded key (nothing verifies under them), and `None`
/// removes it.
#[tokio::test]
async fn the_senders_checkpoint_key_is_decoded_once_and_kept_across_a_renewal() {
    let f = fixture().await;
    let s = f.session(&record(7, 0, 3600), [1; 32], Instant::now());
    assert!(s.signer_key().is_none());
    let alice = ndn_security::Ed25519Signer::from_seed(&[1; 32], n("/bob/phone/KEY/1"));
    let public =
        <[u8; 32]>::try_from(&ndn_security::Signer::public_key(&alice).unwrap()[..]).unwrap();
    s.set_signer_public(Some(public));
    let first = s.signer_key().expect("a key");
    assert!(first.key().is_some(), "a real key decodes");
    s.set_signer_public(Some(public));
    assert!(
        Arc::ptr_eq(&first, &s.signer_key().unwrap()),
        "the same octets at a renewal: the decoded key is kept"
    );
    let other = ndn_security::Ed25519Signer::from_seed(&[2; 32], n("/bob/phone/KEY/1"));
    let other =
        <[u8; 32]>::try_from(&ndn_security::Signer::public_key(&other).unwrap()[..]).unwrap();
    s.set_signer_public(Some(other));
    assert!(!Arc::ptr_eq(&first, &s.signer_key().unwrap()));
    assert_eq!(s.signer_public(), Some(other));
    // Octets that are not a point: found by sweep, held, decoding to nothing.
    let not_a_point = (0..=255u8)
        .map(|n| [n; 32])
        .find(|octets| ndn_security::Ed25519PublicKey::from_bytes(octets).is_none())
        .expect("a 32-octet string that is not a point");
    s.set_signer_public(Some(not_a_point));
    assert!(s.signer_key().expect("held").key().is_none());
    assert_eq!(s.signer_public(), Some(not_a_point));
    s.set_signer_public(None);
    assert!(s.signer_key().is_none());
}
