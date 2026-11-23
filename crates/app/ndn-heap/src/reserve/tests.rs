//! The reservation arithmetic, the flusher and the in-order publisher, over
//! the crash stores of `test_kit`.

use super::*;
use crate::store::{Head, Kind, ReserveRecord, read_reserve, write_head, write_reserve};
use crate::test_kit::{CrashStore, Held, n};
use bytes::Bytes;
use parking_lot::Mutex;
use std::time::Duration;

const BLOCK: u64 = 8;

fn space() -> Name {
    n("/alice/32=data/notes")
}

fn open_on(
    store: &Arc<impl DataStore + 'static>,
    flusher: &Arc<Flusher>,
    adopted: u64,
) -> Reservation {
    Reservation::open(
        Arc::clone(store) as Arc<dyn DataStore>,
        Arc::clone(flusher),
        &space(),
        BLOCK,
        adopted,
    )
    .unwrap()
}

/// Poll `ready` until it holds, for at most 5 s.
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..500 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what} did not happen within 5 s");
}

fn record(store: &dyn DataStore) -> ReserveRecord {
    read_reserve(store, &space()).unwrap().unwrap()
}

#[tokio::test]
async fn never_signs_above_r_durable() {
    // A gate that says Ok for `seq` means the image a power cut leaves holds
    // a reservation covering `seq`.
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    assert_eq!(res.first_seq, 1);
    for seq in 1..=60 {
        res.clear_to_sign(seq).await.unwrap();
        let on_disk = record(&store.crash());
        assert!(
            on_disk.r >= seq,
            "seq {seq} may be signed but a crash leaves R = {}",
            on_disk.r
        );
        assert!(res.durable_r() >= seq);
    }

    // And while the disk stalls, R_durable stays where the last flush put
    // it, whatever R says in memory.
    let store = Arc::new(Held::default());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    let holding = store.hold();
    assert!(
        matches!(res.sign_gate(1), Gate::Wait(_)),
        "the first put waits for the flush at open"
    );
    assert_eq!(res.durable_r(), 0);
    drop(holding);
    res.clear_to_sign(1).await.unwrap();
    assert_eq!(res.durable_r(), BLOCK);

    let holding = store.hold();
    for seq in 2..=BLOCK {
        assert!(
            matches!(res.sign_gate(seq), Gate::Ok),
            "seq {seq} is within R_durable"
        );
    }
    assert_eq!(res.reserved(), 2 * BLOCK, "the extension was written");
    assert!(
        matches!(res.sign_gate(BLOCK + 1), Gate::Wait(_)),
        "R is {} in memory, but the flush covering it has not returned",
        res.reserved()
    );
    assert_eq!(res.durable_r(), BLOCK);
    drop(holding);
    res.clear_to_sign(BLOCK + 1).await.unwrap();
    assert_eq!(res.durable_r(), 2 * BLOCK);
}

#[tokio::test]
async fn extension_is_requested_at_half_a_block() {
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    assert_eq!(
        record(&*store),
        ReserveRecord {
            r: BLOCK,
            clean: false
        },
        "open reserves a block above the resume point"
    );
    res.clear_to_sign(1).await.unwrap();
    for seq in 1..=BLOCK / 2 {
        res.sign_gate(seq);
    }
    assert_eq!(
        record(&*store).r,
        BLOCK,
        "up to R - block/2 nothing is written"
    );

    res.sign_gate(BLOCK / 2 + 1);
    assert_eq!(
        record(&*store),
        ReserveRecord {
            r: 2 * BLOCK,
            clean: false
        },
        "the first seq above R - block/2 writes R + block"
    );
    flusher.flush().await.unwrap();
    assert_eq!(
        record(&store.crash()).r,
        2 * BLOCK,
        "and asks the flusher to make it durable"
    );

    for seq in BLOCK / 2 + 1..=2 * BLOCK - BLOCK / 2 {
        res.sign_gate(seq);
    }
    assert_eq!(record(&*store).r, 2 * BLOCK, "it is written once per block");
    res.sign_gate(2 * BLOCK - BLOCK / 2 + 1);
    assert_eq!(record(&*store).r, 3 * BLOCK);
}

/// The record of a space that holds `head` entries, as the log writes them
/// with each own entry.
fn own_head(store: &dyn DataStore, head: u64) {
    write_head(
        store,
        &space(),
        Head {
            seq: head,
            digest: [head as u8; 32],
        },
    );
}

#[tokio::test]
async fn a_clean_close_marks_clean_and_an_unclean_open_resumes_above_r() {
    // Clean: close writes (head, clean 1); the next open resumes at head + 1
    // with no gap.
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    for seq in 1..=3 {
        res.clear_to_sign(seq).await.unwrap();
    }
    own_head(&*store, 3);
    res.close_clean(3).await.unwrap();
    assert_eq!(
        res.sign_gate(4),
        Gate::Closed,
        "a closed reservation signs nothing"
    );

    let disk = Arc::new(store.crash());
    assert_eq!(record(&*disk), ReserveRecord { r: 3, clean: true });
    let again = open_on(
        &disk,
        &Flusher::spawn(Arc::clone(&disk) as Arc<dyn DataStore>),
        3,
    );
    assert!(again.clean);
    assert_eq!(again.first_seq, 4);

    // Unclean: the process stops with R above the head. The next open
    // resumes above R and says it skipped seqs 4..=8: the signed gap
    // statement names the entry it chains to.
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    for seq in 1..=3 {
        res.clear_to_sign(seq).await.unwrap();
    }
    own_head(&*store, 3);
    flusher.flush().await.unwrap();
    drop(res);

    let disk = Arc::new(store.crash());
    assert_eq!(
        record(&*disk),
        ReserveRecord {
            r: BLOCK,
            clean: false
        }
    );
    let again = open_on(
        &disk,
        &Flusher::spawn(Arc::clone(&disk) as Arc<dyn DataStore>),
        3,
    );
    assert!(!again.clean);
    assert_eq!(again.first_seq, BLOCK + 1, "above R, never at head + 1");
    assert_ne!(again.first_seq, 3 + 1, "seqs lie between head 3 and it");
    assert_eq!(
        record(&*disk),
        ReserveRecord {
            r: 2 * BLOCK,
            clean: false
        },
        "open reserves a block above the resume point before anything is signed"
    );
}

#[tokio::test]
async fn open_is_clean_only_when_the_record_says_so_and_r_is_the_head() {
    /// (reserve record, head record, the head the names show, clean, first
    /// seq, gap).
    type Case = (Option<(u64, bool)>, u64, u64, bool, u64, bool);
    let cases: [Case; 7] = [
        // Nothing stored: a fresh space starts at 1, no hole.
        (None, 0, 0, false, 1, false),
        (Some((5, true)), 5, 5, true, 6, false),
        // The flag says clean but R is not the head: not clean.
        (Some((5, true)), 4, 5, false, 6, false),
        // Unclean with R at the head: resumes just above, no hole.
        (Some((5, false)), 5, 5, false, 6, false),
        // Unclean with R above: a hole.
        (Some((1024, false)), 5, 5, false, 1025, true),
        // The names show an own entry above the head record: never clean,
        // and the resume point is above it.
        (Some((5, true)), 5, 9, false, 10, false),
        (Some((5, false)), 5, 9, false, 10, false),
    ];
    for (reserve, head, adopted, clean, first, gap) in cases {
        let store = Arc::new(CrashStore::new());
        if let Some((r, flag)) = reserve {
            write_reserve(&*store, &space(), ReserveRecord { r, clean: flag });
        }
        if head > 0 {
            own_head(&*store, head);
        }
        let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
        let opened = open_on(&store, &flusher, adopted);
        let why = format!("reserve {reserve:?}, head {head}, names {adopted}");
        assert_eq!(opened.clean, clean, "{why}");
        assert_eq!(opened.first_seq, first, "{why}");
        assert_eq!(opened.first_seq != adopted + 1, gap, "{why}");
        let r = reserve.map_or(0, |(r, _)| r);
        assert_eq!(
            record(&*store),
            ReserveRecord {
                r: r.max(first - 1) + BLOCK,
                clean: false
            },
            "{why}: open writes the next reservation"
        );
    }
}

#[tokio::test]
async fn open_refuses_a_reserve_record_it_cannot_read() {
    let store = Arc::new(CrashStore::new());
    store.insert(Kind::RESERVE.of(&space()), Bytes::from_static(&[1, 2, 3]));
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let err = Reservation::open(
        Arc::clone(&store) as Arc<dyn DataStore>,
        flusher,
        &space(),
        BLOCK,
        0,
    )
    .err()
    .expect("R is unknown: resuming at the head could reuse a seq a peer saw");
    assert_eq!(err.key, Kind::RESERVE.of(&space()));
}

#[tokio::test]
async fn a_failed_flush_is_sticky_and_refuses_signing_past_r_durable_with_the_disks_reason_and_reads_continue()
 {
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, 0);
    res.clear_to_sign(1).await.unwrap();
    assert_eq!(res.durable_r(), BLOCK);

    store.fail_syncs("the disk is full");
    // What R_durable covers is still signed, even as the extension at the
    // half block is written and its flush fails.
    for seq in 2..=BLOCK {
        assert_eq!(
            res.sign_gate(seq),
            Gate::Ok,
            "seq {seq} is within R_durable"
        );
    }
    let why = res.clear_to_sign(BLOCK + 1).await.unwrap_err();
    assert!(
        why.to_string().contains("the disk is full"),
        "the refusal names the disk's reason: {why}"
    );
    assert!(
        why.to_string().contains("disk") && why.to_string().contains("restart"),
        "and says what to do: {why}"
    );
    assert_eq!(res.sign_gate(BLOCK + 1), Gate::Refused(why.clone()));
    assert_eq!(
        res.sign_gate(BLOCK),
        Gate::Ok,
        "nothing signed is retracted"
    );

    // Sticky: the disk comes back, the flusher does not trust it.
    store.heal_syncs();
    assert_eq!(res.sign_gate(BLOCK + 1), Gate::Refused(why.clone()));
    assert!(matches!(flusher.flush().await, Err(FlushError::Disk(_))));
    assert_eq!(
        why,
        FlushError::Disk(flusher.failure().expect("the failure is kept"))
    );

    // Reads go on.
    assert_eq!(
        record(&*store).r,
        2 * BLOCK,
        "the write was accepted, only not made durable"
    );
    assert!(!store.scan_under(&n("/localhost/ndn-heap"), 0).is_empty());
    assert!(store.contains(&Kind::RESERVE.of(&space())));
    assert!(!store.contains(&Kind::HEAD.of(&space())));
}

// -- The flusher --------------------------------------------------------------

#[tokio::test]
async fn flush_covers_every_write_that_returned_before_it_and_waits_for_a_sync() {
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    for i in 0..20 {
        store.insert(n(&format!("/before/{i}")), Bytes::from_static(b"x"));
    }
    flusher.flush().await.unwrap();
    let disk = store.crash();
    assert!((0..20).all(|i| disk.contains(&n(&format!("/before/{i}")))));

    store.insert(n("/after"), Bytes::from_static(b"x"));
    assert!(
        !store.crash().contains(&n("/after")),
        "a flush is not made by writing"
    );
    flusher.flush().await.unwrap();
    assert!(store.crash().contains(&n("/after")));
}

#[tokio::test]
async fn flushes_coalesce() {
    let store = Arc::new(Held::default());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let holding = store.hold();

    store.insert(n("/first"), Bytes::from_static(b"x"));
    let first = flusher.note_write();
    until("the first sync to start", || store.syncs_started() == 1).await;

    // Many writes during the sync: all share the next one.
    let mut last = first;
    for i in 0..50 {
        store.insert(n(&format!("/during/{i}")), Bytes::from_static(b"x"));
        last = flusher.note_write();
    }
    assert!(last > first);
    assert_eq!(store.syncs_started(), 1, "one sync at a time");
    drop(holding);
    flusher.wait_durable(last).await.unwrap();
    assert_eq!(
        store.syncs_started(),
        2,
        "fifty writes during one sync were covered by one more"
    );
    assert!(flusher.durable() >= last);

    // Nothing unsynced: no sync is made.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.syncs_started(), 2);
}

#[tokio::test]
async fn a_stopped_flusher_wakes_its_waiters_with_an_error_not_a_hang() {
    let store = Arc::new(Held::default());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let holding = store.hold();
    let ticket = flusher.note_write();
    let waiting = {
        let flusher = Arc::clone(&flusher);
        tokio::spawn(async move { flusher.wait_durable(ticket).await })
    };
    until("the sync to start", || store.syncs_started() == 1).await;
    flusher.stop();
    let out = tokio::time::timeout(Duration::from_secs(5), waiting).await;
    drop(holding);
    assert!(matches!(out.unwrap().unwrap(), Err(FlushError::Stopped)));
}

// -- The in-order publisher ---------------------------------------------------

/// A sink that notes with each seq the newest ticket a returned flush had
/// covered when the seq was published.
struct Stamped {
    flusher: Arc<Flusher>,
    seen: Mutex<Vec<(u64, Ticket)>>,
}

#[async_trait::async_trait]
impl FlushSink for Stamped {
    async fn publish(&self, seq: u64) {
        self.seen.lock().push((seq, self.flusher.durable()));
    }
}

#[tokio::test]
async fn each_structural_entry_holds_everything_after_it_until_its_own_flush() {
    let store = Arc::new(Held::default());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let sink = Arc::new(Stamped {
        flusher: Arc::clone(&flusher),
        seen: Mutex::new(Vec::new()),
    });
    let publisher = Publisher::spawn(
        Arc::clone(&flusher),
        Arc::clone(&sink) as Arc<dyn FlushSink>,
    );
    let holding = store.hold();
    publisher.submit(1, None);
    store.insert(n("/members/a"), Bytes::from_static(b"a"));
    let first = flusher.note_write();
    publisher.submit(2, Some(first));
    publisher.submit(3, None);
    store.insert(n("/members/b"), Bytes::from_static(b"b"));
    let second = flusher.note_write();
    publisher.submit(4, Some(second));
    publisher.submit(5, None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(holding);
    publisher.drain().await.unwrap();

    let seen = sink.seen.lock().clone();
    let seqs: Vec<u64> = seen.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(seqs, [1, 2, 3, 4, 5], "once each, in seq order");
    for (seq, durable) in seen {
        let gate = match seq {
            2 | 3 => first,
            4 | 5 => second,
            _ => Ticket(0),
        };
        assert!(
            durable >= gate,
            "seq {seq} went out before the flush of the structural entry before it"
        );
    }
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<u64>>,
}

impl Recorder {
    fn seen(&self) -> Vec<u64> {
        self.seen.lock().clone()
    }
}

#[async_trait::async_trait]
impl FlushSink for Recorder {
    async fn publish(&self, seq: u64) {
        self.seen.lock().push(seq);
    }
}

#[tokio::test]
async fn a_structural_entry_is_released_only_after_a_flush_that_covers_it() {
    let store = Arc::new(Held::default());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let sink = Arc::new(Recorder::default());
    let publisher = Publisher::spawn(
        Arc::clone(&flusher),
        Arc::clone(&sink) as Arc<dyn FlushSink>,
    );
    let holding = store.hold();

    // A plain put goes out at once, whatever the disk does.
    publisher.submit(1, None);
    until("seq 1 to be published", || sink.seen() == [1]).await;

    // A Members entry is written; it and what follows it wait for the flush.
    store.insert(n("/members/entry"), Bytes::from_static(b"x"));
    let ticket = flusher.note_write();
    publisher.submit(2, Some(ticket));
    publisher.submit(3, None);
    until("the flush to start", || store.syncs_started() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        sink.seen(),
        [1],
        "a structural entry is not announced before a flush covering it returned, nor is \
         anything after it"
    );
    assert!(
        !publisher.servable(2),
        "a structural entry is not served before its flush"
    );
    assert!(publisher.servable(1) && publisher.servable(3));

    drop(holding);
    publisher.drain().await.unwrap();
    assert_eq!(sink.seen(), [1, 2, 3], "once each, in seq order");
    assert!(flusher.durable() >= ticket);
    assert!(publisher.servable(2), "and is served after it");
}

#[tokio::test]
async fn a_structural_entry_is_never_released_when_its_flush_fails() {
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let sink = Arc::new(Recorder::default());
    let publisher = Publisher::spawn(
        Arc::clone(&flusher),
        Arc::clone(&sink) as Arc<dyn FlushSink>,
    );
    store.fail_syncs("the disk is full");

    store.insert(n("/members/entry"), Bytes::from_static(b"x"));
    publisher.submit(1, Some(flusher.note_write()));
    publisher.submit(2, None);
    let why = publisher.drain().await.unwrap_err();
    assert!(
        matches!(&why, FlushError::Disk(d) if d.to_string().contains("the disk is full")),
        "{why:?}"
    );
    assert_eq!(sink.seen(), Vec::<u64>::new());
}

/// A space left and opened again in one process: the store answers with the
/// `R` the first reservation wrote, which no flush has covered yet. The
/// reopened reservation says Ok only for what the image a power cut leaves
/// covers.
#[tokio::test]
async fn a_reopen_in_the_same_process_trusts_only_an_r_a_flush_covered() {
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let first = open_on(&store, &flusher, 0);
    first.clear_to_sign(1).await.unwrap();
    let holding = store.hold();
    // Past half a block: R + block is written, and the flush is held.
    first.sign_gate(BLOCK / 2 + 1);
    assert_eq!(record(&*store).r, 2 * BLOCK);
    assert_eq!(record(&store.crash()).r, BLOCK, "the disk holds one block");
    drop(first);

    let again = open_on(&store, &flusher, BLOCK / 2 + 1);
    for seq in BLOCK + 1..=2 * BLOCK {
        assert!(
            !matches!(again.sign_gate(seq), Gate::Ok),
            "seq {seq} may be signed, but a power cut leaves R = {}",
            record(&store.crash()).r
        );
    }
    assert_eq!(again.durable_r(), 0);

    drop(holding);
    flusher.flush().await.unwrap();
    assert!(again.durable_r() >= 2 * BLOCK, "a covering flush returned");
    assert!(matches!(again.sign_gate(2 * BLOCK), Gate::Ok));
}

#[tokio::test]
async fn a_head_at_the_largest_seq_does_not_overflow_the_reservation() {
    // Review L8: `max(head, R) + 1` and `R + block` on a seq a peer chose.
    let store = Arc::new(CrashStore::new());
    let flusher = Flusher::spawn(Arc::clone(&store) as Arc<dyn DataStore>);
    let res = open_on(&store, &flusher, u64::MAX);
    assert_eq!(res.first_seq, u64::MAX, "there is no seq above it");
    assert!(matches!(res.sign_gate(u64::MAX), Gate::Ok | Gate::Wait(_)));
}
