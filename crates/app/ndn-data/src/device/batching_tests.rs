//! Per-put store batching (spec §4.2, "Batching"): what a put writes reaches
//! the store as one batch, behind the same barrier as before.
//!
//! The measurement at the end is the harness behind the numbers in the spec
//! and in `handoff-ndf-rs/SHAPES-R5.md`.

use super::durability_tests::{Engine, collection, laptop, percentiles};
use super::test_kit::{Unconnected, n, options};
use super::*;
use crate::layer::Share;
use ndn_security::TrustSchema;
use ndn_sync::store::BackendStore;
use ndn_sync::{MemoryStore, StoreOp};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicUsize;

/// A store that counts how it is written: single writes, and batches.
struct Counting {
    inner: Arc<dyn DataStore>,
    inserts: AtomicU64,
    removes: AtomicU64,
    batches: AtomicU64,
    batched: AtomicU64,
}

/// What a [`Counting`] store was asked so far.
#[derive(Clone, Copy)]
struct Calls {
    /// Single `insert`s and `remove`s.
    singles: u64,
    /// `apply` calls.
    batches: u64,
    /// Changes in them.
    batched: u64,
}

impl Counting {
    fn over(inner: Arc<dyn DataStore>) -> Arc<Counting> {
        Arc::new(Counting {
            inner,
            inserts: AtomicU64::new(0),
            removes: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            batched: AtomicU64::new(0),
        })
    }

    fn calls(&self) -> Calls {
        Calls {
            singles: self.inserts.load(Ordering::SeqCst) + self.removes.load(Ordering::SeqCst),
            batches: self.batches.load(Ordering::SeqCst),
            batched: self.batched.load(Ordering::SeqCst),
        }
    }
}

impl DataStore for Counting {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn contains(&self, name: &Name) -> bool {
        self.inner.contains(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.removes.fetch_add(1, Ordering::SeqCst);
        self.inner.remove(name);
    }
    fn apply(&self, ops: Vec<StoreOp>) {
        self.batches.fetch_add(1, Ordering::SeqCst);
        self.batched.fetch_add(ops.len() as u64, Ordering::SeqCst);
        self.inner.apply(ops);
    }
    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn sync_is_immediate(&self) -> bool {
        self.inner.sync_is_immediate()
    }
}

/// What one operation of a measurement puts.
#[derive(Clone, Copy)]
enum Load {
    /// One `put`.
    Put,
    /// One `put_group` of this many items.
    Group(usize),
}

impl Load {
    fn label(self) -> String {
        match self {
            Load::Put => "put".into(),
            Load::Group(k) => format!("put_group({k})"),
        }
    }

    /// Do operation `i`; the highest seq it wrote.
    async fn run(self, dev: &Device, i: usize) -> u64 {
        let c = collection();
        let content = |i: usize| Content::new().with("k", format!("{i:08}"));
        match self {
            Load::Put => dev.put(&c, content(i), options()).await.unwrap().seq.0,
            Load::Group(k) => {
                let items = (0..k)
                    .map(|j| {
                        (
                            n(&format!("/alice/32=data/grp/c{j}")),
                            Edit::Fields(content(i)),
                        )
                    })
                    .collect();
                let ids = dev.put_group(items, options()).await.unwrap();
                ids.iter().map(|id| id.seq.0).max().unwrap()
            }
        }
    }
}

/// How long `put` and `put_group` take on each engine, how many store calls
/// they make, and how long until what they wrote is published — measured,
/// never asserted. Two loads: one operation at a time, each waiting until
/// published (a flush per operation), and operations back to back (the
/// committer flushes once for all that came during the last flush). Run
/// with `cargo test --release -p ndn-data --lib batching_latency --
/// --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run on purpose"]
async fn batching_latency() {
    let c = collection();
    for engine in [Some(Engine::Fjall), Some(Engine::Redb), None] {
        for (load, ops) in [
            (Load::Put, 2000),
            (Load::Group(10), 400),
            (Load::Group(100), 40),
        ] {
            let dir = tempfile::tempdir().unwrap();
            // `None`: the store's cost is nothing, what a put costs besides it.
            let label = engine.map_or("memory", Engine::label);
            let disk: Arc<dyn DataStore> = match engine {
                Some(Engine::Fjall) => {
                    Arc::new(BackendStore::open_fjall(Engine::Fjall.live(dir.path())).unwrap())
                }
                Some(Engine::Redb) => {
                    Arc::new(BackendStore::open_redb(Engine::Redb.live(dir.path())).unwrap())
                }
                None => Arc::new(MemoryStore::new()),
            };
            let store = Counting::over(disk);
            let dev = laptop(Arc::clone(&store) as Arc<dyn DataStore>).await;
            dev.share(
                &c,
                Share {
                    rule: Rule::Log,
                    writers: vec![n("/alice")],
                    readers: Vec::new(),
                },
            )
            .await
            .unwrap();
            // The first group makes each collection's record.
            let warm = load.run(&dev, 0).await;
            assert!(dev.inner.published(warm).await);

            let (mut put, mut published) = (Vec::new(), Vec::new());
            let before = store.calls();
            for i in 0..ops {
                let t0 = std::time::Instant::now();
                let seq = load.run(&dev, i).await;
                let t1 = std::time::Instant::now();
                assert!(dev.inner.published(seq).await);
                put.push(t1 - t0);
                published.push(t0.elapsed());
            }
            let after = store.calls();
            let (pm, p99) = percentiles(&mut put);
            let (bm, b99) = percentiles(&mut published);
            let per = |a: u64, b: u64| (a - b) as f64 / ops as f64;
            println!(
                "{} {} one at a time: median {pm:.1} µs p99 {p99:.1} µs; to published median \
                 {bm:.1} µs p99 {b99:.1} µs; store calls per op: {} single writes, {} batches of \
                 {} changes in all",
                label,
                load.label(),
                per(after.singles, before.singles),
                per(after.batches, before.batches),
                per(after.batched, before.batched),
            );

            // Back to back: a watcher notes when each seq is published.
            let inner = Arc::clone(&dev.inner);
            let first = inner.st.lock().head + 1;
            let rounds = inner.st.lock().round;
            let last = Arc::new(AtomicU64::new(u64::MAX));
            let stop = Arc::clone(&last);
            let watcher = tokio::spawn(async move {
                let mut at = BTreeMap::new();
                let mut seen = first - 1;
                loop {
                    let notified = inner.committed.notified();
                    let durable = inner.st.lock().durable;
                    let now = std::time::Instant::now();
                    for s in seen + 1..=durable {
                        at.insert(s, now);
                    }
                    seen = seen.max(durable);
                    if seen >= last.load(Ordering::SeqCst) {
                        return at;
                    }
                    notified.await;
                }
            });
            let mut started: Vec<(u64, std::time::Instant)> = Vec::new();
            let mut put = Vec::new();
            for i in 0..ops {
                let t0 = std::time::Instant::now();
                let seq = load.run(&dev, i).await;
                put.push(t0.elapsed());
                started.push((seq, t0));
            }
            stop.store(started.last().unwrap().0, Ordering::SeqCst);
            dev.inner.committed.notify_waiters();
            let at = watcher.await.unwrap();
            let mut published: Vec<Duration> = started.iter().map(|(s, t0)| at[s] - *t0).collect();
            let flushes = dev.inner.st.lock().round - rounds;
            let (pm, p99) = percentiles(&mut put);
            let (bm, b99) = percentiles(&mut published);
            println!(
                "{} {} back to back: median {pm:.1} µs p99 {p99:.1} µs; to published median \
                 {bm:.1} µs p99 {b99:.1} µs; {ops} operations in {flushes} flushes",
                label,
                load.label(),
            );
            dev.shutdown();
        }
    }
}

// ---- a kill in the middle of a put_group, on a real engine -------------------------------------

/// The environment variable that makes [`batch_kill_child`] run:
/// `<engine>|<directory>`.
const KILL_ROLE: &str = "NDN_DATA_BATCH_KILL";

/// Items of a group of the kill case; each entry is several pieces, so that
/// writing a group takes a good part of the time putting it does.
const GROUP: usize = 20;

fn big_group(i: usize) -> Vec<(Name, Edit)> {
    (0..GROUP)
        .map(|j| {
            (
                n(&format!("/alice/32=data/big/c{j}")),
                Edit::Fields(Content::new().with("blob", format!("{i:06}{}", "x".repeat(60_000)))),
            )
        })
        .collect()
}

fn open_engine(engine: Engine, dir: &std::path::Path) -> Arc<dyn DataStore> {
    let live = engine.live(dir);
    match engine {
        Engine::Fjall => Arc::new(BackendStore::open_fjall(&live).unwrap()),
        Engine::Redb => Arc::new(BackendStore::open_redb(&live).unwrap()),
    }
}

/// One run of a device in a process of its own, putting large groups one
/// after the other, each announced before and reported after it returned.
/// Nothing when no case started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a child process of the kill case; it runs only when it starts it"]
async fn batch_kill_child() {
    use std::io::Write;
    let Ok(role) = std::env::var(KILL_ROLE) else {
        return;
    };
    let (engine, dir) = role.split_once('|').expect("<engine>|<directory>");
    let engine = match engine {
        "fjall" => Engine::Fjall,
        "redb" => Engine::Redb,
        other => panic!("{KILL_ROLE} names engine {other:?}; it is fjall or redb"),
    };
    let dev = laptop(open_engine(engine, std::path::Path::new(dir))).await;
    let say = |line: String| {
        println!("{line}");
        std::io::stdout().flush().unwrap();
    };
    for i in 0.. {
        say(format!("start {i}"));
        dev.put_group(big_group(i), options()).await.unwrap();
        say(format!("done {i}"));
    }
}

/// The groups of `store`'s own log: for each group id, how many of its members
/// the store holds and how many it has.
fn groups_held(store: &dyn DataStore) -> BTreeMap<u64, (usize, u32)> {
    let mut groups: BTreeMap<u64, (usize, u32)> = BTreeMap::new();
    for (name, wire) in store.scan_under(&n("/alice/laptop"), 0) {
        let Some(l) = parse_log_name(&name) else {
            continue;
        };
        if l.subject
            .is_none_or(|c| !c.has_prefix(&n("/alice/32=data/big")))
        {
            continue;
        }
        let Some(Record::Version(body)) = Data::decode(wire).ok().and_then(|d| {
            d.content()
                .and_then(|c| wire::decode_record(c.clone()).ok())
        }) else {
            continue;
        };
        if let Some(g) = body.group {
            let held = groups.entry(g.id).or_insert((0, g.count));
            held.0 += 1;
        }
    }
    groups
}

fn a_kill_in_the_middle_of_a_put_group_leaves_all_of_it_or_none(engine: Engine) {
    use std::io::{BufRead, BufReader};
    let mut rng = std::hash::BuildHasher::hash_one(
        &std::collections::hash_map::RandomState::new(),
        engine.label(),
    );
    // A fixed seed would repeat the same cuts: the moment of the kill is the
    // point, so it varies; the case's checks hold at every moment.
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng % 1000) as f64 / 1000.0
    };
    let mut mid_batch = 0;
    for round in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "device::batching_tests::batch_kill_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                KILL_ROLE,
                format!("{}|{}", engine.label(), dir.path().display()),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // How long a group takes, from the second.
        let (mut lines, mut began) = (Vec::new(), None);
        let took = loop {
            let line = rx
                .recv_timeout(Duration::from_secs(120))
                .unwrap_or_else(|e| {
                    let _ = child.kill();
                    panic!("the {} child said nothing for 120 s ({e})", engine.label())
                });
            if line == "start 1" {
                began = Some(std::time::Instant::now());
            }
            if line == "done 1" {
                lines.push(line);
                break began.expect("start 1 came first").elapsed();
            }
            if line.starts_with("start ") || line.starts_with("done ") {
                lines.push(line);
            }
        };
        // A group after them is under way; cut it somewhere inside.
        std::thread::sleep(took.mul_f64(next() * 2.0));
        child.kill().unwrap();
        child.wait().unwrap();
        lines.extend(rx.iter());
        let number = |what: &str| {
            lines
                .iter()
                .filter_map(|l| l.strip_prefix(what)?.parse::<usize>().ok())
                .max()
                .unwrap()
        };
        let (started, done) = (number("start "), number("done "));
        if started > done {
            mid_batch += 1;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = open_engine(engine, dir.path());
            let groups = groups_held(store.as_ref());
            for (id, (held, count)) in &groups {
                assert_eq!(
                    *held,
                    *count as usize,
                    "{} round {round}: of the group at seq {id} ({started} groups started, {done} \
                     reported done) the store holds {held} of {count} versions after kill -9: a \
                     version is there without the rest of its group",
                    engine.label()
                );
            }
            assert!(
                groups.len() > done,
                "{} round {round}: {} groups reported done before kill -9, the store holds {}",
                engine.label(),
                done + 1,
                groups.len()
            );
            // And the device starts on it and goes on, above what the store holds.
            let top = store
                .scan_under(&n("/alice/laptop"), 0)
                .iter()
                .filter_map(|(name, _)| parse_log_name(name).map(|l| l.seq))
                .max()
                .unwrap();
            let dev = laptop(Arc::clone(&store)).await;
            let next = dev
                .put(
                    // (A new run has a recipient key of its own here, so a key the
                    // killed run made for a sealed collection is not one it can open.)
                    &n("/alice/32=data/after"),
                    Content::new().with("k", "after"),
                    options(),
                )
                .await
                .unwrap();
            assert!(
                next.seq.0 > top,
                "the restarted device signed at seq {}, not above the {top} its store holds",
                next.seq.0
            );
            dev.shutdown();
        });
    }
    assert!(
        mid_batch >= 1,
        "{}: none of eight kills landed while a group was being put, so the case shows nothing",
        engine.label()
    );
}

#[test]
fn a_kill_in_the_middle_of_a_put_group_leaves_all_of_it_or_none_on_fjall() {
    a_kill_in_the_middle_of_a_put_group_leaves_all_of_it_or_none(Engine::Fjall);
}

#[test]
fn a_kill_in_the_middle_of_a_put_group_leaves_all_of_it_or_none_on_redb() {
    a_kill_in_the_middle_of_a_put_group_leaves_all_of_it_or_none(Engine::Redb);
}

// ---- what the store is asked ------------------------------------------------------------------

/// One call made on a [`Recording`] store.
#[derive(Clone, Debug)]
enum Call {
    Insert(Name),
    Remove(Name),
    Batch(Vec<StoreOp>),
}

/// A store that keeps what it was asked, in order, and passes it on.
struct Recording {
    inner: Arc<dyn DataStore>,
    log: parking_lot::Mutex<Vec<Call>>,
}

impl Recording {
    fn over(inner: Arc<dyn DataStore>) -> Arc<Recording> {
        Arc::new(Recording {
            inner,
            log: parking_lot::Mutex::new(Vec::new()),
        })
    }

    fn mark(&self) -> usize {
        self.log.lock().len()
    }

    fn since(&self, mark: usize) -> Vec<Call> {
        self.log.lock()[mark..].to_vec()
    }
}

impl DataStore for Recording {
    fn insert(&self, name: Name, wire: Bytes) {
        self.log.lock().push(Call::Insert(name.clone()));
        self.inner.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn contains(&self, name: &Name) -> bool {
        self.inner.contains(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.log.lock().push(Call::Remove(name.clone()));
        self.inner.remove(name);
    }
    fn apply(&self, ops: Vec<StoreOp>) {
        self.log.lock().push(Call::Batch(ops.clone()));
        self.inner.apply(ops);
    }
    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn sync_is_immediate(&self) -> bool {
        self.inner.sync_is_immediate()
    }
}

/// Whether the store name `n` is about the own log entry `entry`: the entry, a
/// piece of it, or one of its markers.
fn about(entry: &Name, n: &Name) -> bool {
    n.has_prefix(entry) || *n == written_name(entry) || *n == verified_name(entry)
}

/// The one batch of `calls` that stores `entry`; every write about `entry`
/// is in it, and none was made on its own.
fn the_batch<'a>(calls: &'a [Call], entry: &Name) -> &'a [StoreOp] {
    let singles: Vec<&Call> = calls
        .iter()
        .filter(|c| match c {
            Call::Insert(n) | Call::Remove(n) => about(entry, n),
            Call::Batch(_) => false,
        })
        .collect();
    assert!(
        singles.is_empty(),
        "the writes about {entry} were made one by one ({singles:?}), not as one batch"
    );
    let holding: Vec<&Vec<StoreOp>> = calls
        .iter()
        .filter_map(|c| match c {
            Call::Batch(ops)
                if ops
                    .iter()
                    .any(|op| matches!(op, StoreOp::Insert(n, _) if n == entry)) =>
            {
                Some(ops)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        holding.len(),
        1,
        "{entry} was stored by {} batches, not one: {calls:?}",
        holding.len()
    );
    holding[0]
}

/// Where `ops` stores `name`.
fn at(ops: &[StoreOp], name: &Name) -> usize {
    ops.iter()
        .position(|op| matches!(op, StoreOp::Insert(n, _) if n == name))
        .unwrap_or_else(|| panic!("the batch does not store {name}"))
}

async fn shared_log(dev: &Device) {
    dev.share(
        &collection(),
        Share {
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: Vec::new(),
        },
    )
    .await
    .unwrap();
    dev.inner.flushed().await;
}

/// An entry too large for one packet: it travels in pieces.
fn large() -> Content {
    Content::new().with("blob", "x".repeat(3 * wire::INLINE_MAX))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_reaches_the_store_as_one_batch_markers_first_the_entry_last() {
    let store = Recording::over(Arc::new(MemoryStore::new()));
    let dev = laptop(Arc::clone(&store) as Arc<dyn DataStore>).await;
    shared_log(&dev).await;
    let c = collection();

    let mark = store.mark();
    let id = dev
        .put(&c, Content::new().with("text", "one"), options())
        .await
        .unwrap();
    let entry = log_name(dev.name(), Some(&c), id.seq.0);
    let calls = store.since(mark);
    let ops = the_batch(&calls, &entry);
    let last = at(ops, &entry);
    assert!(
        at(ops, &written_name(&entry)) < last && at(ops, &verified_name(&entry)) < last,
        "the entry is the last write of its batch, so a prefix of it is never an entry without \
         its markers: {ops:?}"
    );

    // An entry in pieces: pieces after the markers, before the entry.
    let mark = store.mark();
    let id = dev.put(&c, large(), options()).await.unwrap();
    let entry = log_name(dev.name(), Some(&c), id.seq.0);
    let calls = store.since(mark);
    let ops = the_batch(&calls, &entry);
    let last = at(ops, &entry);
    let pieces: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| {
            matches!(op, StoreOp::Insert(n, _)
                if parse_piece_name(n).is_some_and(|p| p.version == entry))
        })
        .map(|(i, _)| i)
        .collect();
    assert!(!pieces.is_empty(), "the large entry has pieces: {ops:?}");
    assert!(
        pieces.iter().all(|p| *p < last)
            && pieces
                .iter()
                .all(|p| *p > at(ops, &written_name(&entry)).max(at(ops, &verified_name(&entry)))),
        "markers, then pieces, then the entry: {ops:?}"
    );
    dev.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_group_reaches_the_store_as_one_batch() {
    let store = Recording::over(Arc::new(MemoryStore::new()));
    let dev = laptop(Arc::clone(&store) as Arc<dyn DataStore>).await;
    let items = |tag: &str| -> Vec<(Name, Edit)> {
        (0..6)
            .map(|j| {
                (
                    n(&format!("/alice/32=data/grp/c{j}")),
                    Edit::Fields(Content::new().with("t", format!("{tag} {j}"))),
                )
            })
            .collect()
    };
    // The first group makes each collection's record too: the records and the
    // versions are one batch.
    let mark = store.mark();
    let ids = dev.put_group(items("first"), options()).await.unwrap();
    let calls = store.since(mark);
    let entries: Vec<Name> = ids
        .iter()
        .enumerate()
        .map(|(j, id)| {
            let c = n(&format!("/alice/32=data/grp/c{j}"));
            log_name(dev.name(), Some(&c), id.seq.0)
        })
        .collect();
    let first = the_batch(&calls, &entries[0]);
    for e in &entries {
        at(first, e);
        at(first, &written_name(e));
        let single = calls
            .iter()
            .any(|c| matches!(c, Call::Insert(n) | Call::Remove(n) if about(e, n)));
        assert!(
            !single,
            "{e} was written on its own, not in the group's batch"
        );
    }
    // A record's entry is in the batch twice (the same name and bytes), so the
    // names are counted once.
    let log_entries: BTreeSet<String> = first
        .iter()
        .filter_map(|op| match op {
            StoreOp::Insert(n, _) if n.has_prefix(dev.name()) => Some(n.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        log_entries.len(),
        2 * entries.len(),
        "the group's versions and the records the first group makes are one batch: {log_entries:#?}"
    );

    // A second group: the six versions, with their markers, one batch.
    let mark = store.mark();
    let ids = dev.put_group(items("second"), options()).await.unwrap();
    let calls = store.since(mark);
    let entries: Vec<Name> = ids
        .iter()
        .enumerate()
        .map(|(j, id)| {
            log_name(
                dev.name(),
                Some(&n(&format!("/alice/32=data/grp/c{j}"))),
                id.seq.0,
            )
        })
        .collect();
    let batch = the_batch(&calls, &entries[0]);
    for e in &entries {
        assert!(at(batch, &written_name(e)) < at(batch, e));
        assert!(at(batch, &verified_name(e)) < at(batch, e));
    }
    let ordered: Vec<usize> = entries.iter().map(|e| at(batch, e)).collect();
    assert!(
        ordered.windows(2).all(|w| w[0] < w[1]),
        "the group's members are in seq order in its batch: {ordered:?}"
    );
    dev.shutdown();
}

// ---- a batch cut short on a store with no atomic batch -----------------------------------------

/// A memory store with the trait's default `apply` (one call at a time, not
/// atomic) that stops writing after a budget of writes, as a process killed
/// there does: what it kept is what a restart finds.
struct Dying {
    inner: Arc<MemoryStore>,
    budget: AtomicUsize,
    writes: AtomicUsize,
}

impl Dying {
    fn spend(&self) -> bool {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |b| b.checked_sub(1))
            .is_ok()
    }
}

impl DataStore for Dying {
    fn insert(&self, name: Name, wire: Bytes) {
        if self.spend() {
            self.inner.insert(name, wire);
        }
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.inner.get(name)
    }
    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.inner.find_under(prefix)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.inner.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        if self.spend() {
            self.inner.remove(name);
        }
    }
    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }
    fn sync_is_immediate(&self) -> bool {
        true
    }
}

/// A device on `dying`, its collection shared and settled, with `budget`
/// writes left to it.
async fn dying_device(budget: usize) -> (Device, Arc<Dying>, Arc<MemoryStore>) {
    let inner = Arc::new(MemoryStore::new());
    let dying = Arc::new(Dying {
        inner: Arc::clone(&inner),
        budget: AtomicUsize::new(usize::MAX),
        writes: AtomicUsize::new(0),
    });
    let dev = laptop(Arc::clone(&dying) as Arc<dyn DataStore>).await;
    shared_log(&dev).await;
    dying.budget.store(budget, Ordering::SeqCst);
    (dev, dying, inner)
}

/// A store that does not batch atomically, cut off after any `k` writes of a
/// put: what it kept is never an entry without its markers or pieces, and the
/// device restarted on it is sound — it takes an entry it kept as its own, and
/// after one it did not keep it signs that seq afresh, with no event of an
/// honest writer twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_prefix_of_a_put_on_a_store_without_atomic_batches_is_a_state_a_restart_accepts() {
    let c = collection();
    // What a whole put writes, and keeps.
    let (dev, dying, whole) = dying_device(usize::MAX).await;
    let before = dying.writes.load(Ordering::SeqCst);
    let id = dev.put(&c, large(), options()).await.unwrap();
    let writes = dying.writes.load(Ordering::SeqCst) - before;
    let entry = log_name(dev.name(), Some(&c), id.seq.0);
    let kept_whole = whole.scan_under(&entry, 0).len();
    assert!(kept_whole > 2, "an entry and its pieces: {kept_whole}");
    dev.shutdown();

    for k in 0..=writes + 2 {
        let (dev, _dying, kept) = dying_device(k).await;
        let id = dev.put(&c, large(), options()).await.unwrap();
        let entry = log_name(dev.name(), Some(&c), id.seq.0);
        dev.shutdown();

        let stored = kept.get(&entry).is_some();
        if stored {
            assert!(
                kept.get(&written_name(&entry)).is_some(),
                "after {k} of the put's writes the store holds the entry {entry} without the \
                 marker that says this device wrote it: a restart would take it as another \
                 writer's"
            );
            assert!(
                kept.get(&verified_name(&entry)).is_some(),
                "after {k} of the put's writes the store holds {entry} without its verified marker"
            );
            assert_eq!(
                kept.scan_under(&entry, 0).len(),
                kept_whole,
                "after {k} of the put's writes the store holds {entry} without all its pieces"
            );
        }

        let again = laptop(Arc::clone(&kept) as Arc<dyn DataStore>).await;
        assert!(
            again.pending_events().is_empty(),
            "after {k} writes a restart reported events: {:?}",
            again.pending_events()
        );
        let next = again
            .put(&c, Content::new().with("text", "after"), options())
            .await
            .unwrap();
        let want = if stored { id.seq.0 + 1 } else { id.seq.0 };
        assert_eq!(
            next.seq.0,
            want,
            "after {k} writes (the entry is {}), the restarted device signs at seq {} but should \
             at {want}",
            if stored { "kept" } else { "lost" },
            next.seq.0
        );
        assert!(again.inner.published(next.seq.0).await);
        assert!(
            again.pending_events().is_empty(),
            "after {k} writes the restarted device's next put raised events: {:?}",
            again.pending_events()
        );
        again.shutdown();
    }
}

// ---- order across a burst, a restart, a recovery -----------------------------------------------

/// Own entries of `c` that `ops` stores, as seqs, in the order stored.
fn seqs_stored(dev: &Device, c: &Name, ops: &[StoreOp]) -> Vec<u64> {
    ops.iter()
        .filter_map(|op| match op {
            StoreOp::Insert(n, _) => parse_log_name(n)
                .filter(|l| l.device == *dev.name() && l.subject.as_ref() == Some(c))
                .map(|l| l.seq),
            StoreOp::Remove(_) => None,
        })
        .collect()
}

/// What a peer is served of the own entries `seqs` of `c`.
fn served_of(dev: &Device, c: &Name, seqs: &[u64]) -> Vec<(u64, Bytes)> {
    seqs.iter()
        .map(|s| {
            let wire = dev
                .inner
                .packet_for(&log_name(dev.name(), Some(c), *s), false)
                .unwrap_or_else(|| panic!("seq {s} is not served"));
            (*s, wire)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_puts_keeps_its_order_in_the_store_across_a_restart_and_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live");
    let store = Recording::over(Arc::new(BackendStore::open_fjall(&live).unwrap()));
    let dev = laptop(Arc::clone(&store) as Arc<dyn DataStore>).await;
    shared_log(&dev).await;
    let c = collection();

    let mark = store.mark();
    let mut seqs = Vec::new();
    for i in 0..60 {
        let id = dev
            .put(&c, Content::new().with("k", format!("{i:04}")), options())
            .await
            .unwrap();
        seqs.push(id.seq.0);
    }
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0] + 1),
        "a burst takes consecutive seqs: {seqs:?}"
    );
    let stored: Vec<u64> = store
        .since(mark)
        .iter()
        .filter_map(|call| match call {
            Call::Batch(ops) => Some(seqs_stored(&dev, &c, ops)),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(
        stored, seqs,
        "the store was handed the entries in the order they were put, one batch each"
    );
    assert!(dev.inner.published(*seqs.last().unwrap()).await);
    dev.inner.flushed().await;
    let before = served_of(&dev, &c, &seqs);
    dev.shutdown();
    // The restart opens the same files: the first device's handles go first.
    let until = std::time::Instant::now() + Duration::from_secs(20);
    drop(dev);
    while Arc::strong_count(&store) > 1 {
        assert!(
            std::time::Instant::now() < until,
            "the stopped device still holds its store after 20 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    drop(store);

    let reopened = laptop(Arc::new(BackendStore::open_fjall(&live).unwrap())).await;
    assert_eq!(
        served_of(&reopened, &c, &seqs),
        before,
        "after a restart a peer is served the same entries"
    );
    let next = reopened
        .put(&c, Content::new().with("k", "after"), options())
        .await
        .unwrap();
    assert_eq!(
        next.seq.0,
        seqs.last().unwrap() + 1,
        "the restarted device continues its log where it left it"
    );
    reopened.shutdown();
}

// ---- the stage itself --------------------------------------------------------------------------

#[test]
fn a_batch_of_the_stage_is_handed_to_the_store_whole_when_it_ends() {
    let rec = Recording::over(Arc::new(MemoryStore::new()));
    let stage = stage::Stage::new(Arc::clone(&rec) as Arc<dyn DataStore>);
    {
        let _batch = stage.batch();
        stage.insert(n("/s/a"), Bytes::from_static(b"1"));
        {
            // A batch inside it joins it.
            let _inner = stage.batch();
            stage.insert(n("/s/b"), Bytes::from_static(b"2"));
        }
        stage.remove(&n("/s/a"));
        assert_eq!(
            rec.mark(),
            0,
            "nothing reaches the store while the batch is open"
        );
        assert_eq!(
            stage.get(&n("/s/b")).as_deref(),
            Some(&b"2"[..]),
            "the batch's own write"
        );
        assert!(stage.contains(&n("/s/b")));
        assert!(
            stage.get(&n("/s/a")).is_none(),
            "its own removal hides the write before it"
        );
        assert!(!stage.contains(&n("/s/a")));
    }
    let calls = rec.since(0);
    assert_eq!(
        calls.len(),
        1,
        "one apply, not one call per write: {calls:?}"
    );
    let Call::Batch(ops) = &calls[0] else {
        panic!("not a batch: {calls:?}")
    };
    assert_eq!(
        *ops,
        vec![
            StoreOp::Insert(n("/s/a"), Bytes::from_static(b"1")),
            StoreOp::Insert(n("/s/b"), Bytes::from_static(b"2")),
            StoreOp::Remove(n("/s/a")),
        ],
        "in the order made"
    );
    // With none open, a write goes straight through.
    stage.insert(n("/s/c"), Bytes::from_static(b"3"));
    assert!(matches!(rec.since(1)[..], [Call::Insert(_)]));
}

#[test]
fn another_threads_writes_do_not_join_a_batch_and_do_not_see_it() {
    let rec = Recording::over(Arc::new(MemoryStore::new()));
    let stage = stage::Stage::new(Arc::clone(&rec) as Arc<dyn DataStore>);
    let batch = stage.batch();
    stage.insert(n("/s/mine"), Bytes::from_static(b"1"));
    std::thread::scope(|s| {
        s.spawn(|| {
            stage.insert(n("/s/theirs"), Bytes::from_static(b"2"));
            assert!(
                stage.get(&n("/s/mine")).is_none(),
                "another thread does not see a batch it did not open"
            );
            assert_eq!(
                stage.scan_under(&n("/s"), 0).len(),
                1,
                "nor does its read by prefix: it sees the store's"
            );
            // And a batch of its own, while one is open, writes through.
            let _other = stage.batch();
            stage.insert(n("/s/theirs2"), Bytes::from_static(b"3"));
        });
    });
    assert_eq!(
        rec.since(0)
            .iter()
            .filter(|c| matches!(c, Call::Insert(_)))
            .count(),
        2,
        "the other thread's writes went straight to the store"
    );
    drop(batch);
    let calls = rec.since(0);
    assert_eq!(
        calls.len(),
        3,
        "the batch ends as one apply, and an ended batch with nothing left makes no call: {calls:?}"
    );
    assert!(matches!(calls.last(), Some(Call::Batch(ops)) if ops.len() == 1));
}

/// What `stage` and a model of the store (the same writes made on a store
/// with no stage) answer to every read by prefix.
fn same_reads(stage: &stage::Stage, model: &MemoryStore, what: &str) {
    for prefix in ["/", "/s", "/s/b", "/s/b/x", "/s/zz", "/t", "/s/new"] {
        let prefix = if prefix == "/" {
            Name::root()
        } else {
            n(prefix)
        };
        for limit in [0, 1, 2, 3, 100] {
            assert_eq!(
                stage.scan_under(&prefix, limit),
                model.scan_under(&prefix, limit),
                "{what}: the scan of {prefix} (limit {limit}) through the open batch is not what \
                 the store would answer with the batch applied"
            );
        }
        assert_eq!(
            stage.find_under(&prefix),
            model.find_under(&prefix),
            "{what}: the find under {prefix} through the open batch is not what the store would \
             answer with the batch applied"
        );
    }
}

#[test]
fn a_read_by_prefix_through_an_open_batch_sees_its_writes_hides_its_removals_and_applies_nothing() {
    let value = |s: &'static str| Bytes::from_static(s.as_bytes());
    let base = [
        ("/s/a", "old a"),
        ("/s/b", "old b"),
        ("/s/b/x", "old b x"),
        ("/s/c", "old c"),
        ("/t/a", "old t"),
    ];
    let rec = Recording::over(Arc::new(MemoryStore::new()));
    let model = MemoryStore::new();
    for (name, v) in base {
        rec.inner.insert(n(name), value(v));
        model.insert(n(name), value(v));
    }
    let stage = stage::Stage::new(Arc::clone(&rec) as Arc<dyn DataStore>);
    same_reads(&stage, &model, "before any write");

    let batch = stage.batch();
    // Every kind of change a batch holds: a new name before, between and
    // after the store's; a removal of a stored name; one overwritten; one
    // written and removed; one removed and written again; a removal of a
    // name nothing stores.
    let ops = [
        StoreOp::Insert(n("/s/0"), value("new 0")),
        StoreOp::Insert(n("/s/bb"), value("new bb")),
        StoreOp::Insert(n("/s/new"), value("new new")),
        StoreOp::Insert(n("/s/new/deep"), value("new deep")),
        StoreOp::Remove(n("/s/a")),
        StoreOp::Insert(n("/s/c"), value("new c")),
        StoreOp::Insert(n("/s/gone"), value("written, then removed")),
        StoreOp::Remove(n("/s/gone")),
        StoreOp::Remove(n("/s/b")),
        StoreOp::Insert(n("/s/b"), value("new b")),
        StoreOp::Remove(n("/s/nothing")),
        StoreOp::Insert(n("/t/a"), value("new t")),
        StoreOp::Remove(n("/t/a")),
    ];
    for op in ops.clone() {
        match op {
            StoreOp::Insert(name, wire) => stage.insert(name, wire),
            StoreOp::Remove(name) => stage.remove(&name),
        }
    }
    model.apply(ops.to_vec());
    same_reads(&stage, &model, "inside the batch");
    assert_eq!(
        rec.mark(),
        0,
        "a read by prefix inside an open batch handed the store a part of it (an `apply` before the \
         batch ended): a kill after that leaves a half of a put"
    );
    // The same through a nested batch, and after the removal of every name
    // under a prefix.
    {
        let _inner = stage.batch();
        for name in [
            "/s/0",
            "/s/b",
            "/s/b/x",
            "/s/bb",
            "/s/c",
            "/s/new",
            "/s/new/deep",
        ] {
            stage.remove(&n(name));
            model.remove(&n(name));
        }
        same_reads(&stage, &model, "after removing what was left under /s");
        assert!(stage.scan_under(&n("/s"), 0).is_empty());
        assert!(stage.find_under(&n("/s")).is_none());
    }
    assert_eq!(rec.mark(), 0, "a nested batch ended: the outer one is open");
    drop(batch);
    assert_eq!(
        rec.since(0).len(),
        1,
        "one apply when the batch ends: {:?}",
        rec.since(0)
    );
    for prefix in ["/s", "/t", "/s/b"] {
        assert_eq!(
            rec.scan_under(&n(prefix), 0),
            model.scan_under(&n(prefix), 0),
            "the store ends where the model does"
        );
    }
}

// ---- a members record and the key of the epoch it starts ---------------------------------------

/// `/alice/laptop`'s key store, the same in every run: its signing key and
/// its recipient secret (the epoch keys it makes are wrapped to that), so
/// that a run started on what a killed run left can open them.
fn laptop_keys() -> Arc<SecurityManager> {
    let device = n("/alice/laptop");
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(device.clone().append("KEY").append("1"), &[7; 32])
        .unwrap();
    keys.put_secret(secret_name(&device), &[9; 32]).unwrap();
    keys
}

async fn laptop_on(keys: &Arc<SecurityManager>, store: Arc<dyn DataStore>) -> Device {
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n("/alice/laptop"),
        Arc::clone(keys),
        validator,
        store,
        Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// Share `c` as a log its owner's namespace writes and `readers` read: a
/// members record that starts an epoch, and the epoch's key, made here.
async fn share_sealed(dev: &Device, c: &Name, readers: &[&str]) {
    dev.share(
        c,
        Share {
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
        },
    )
    .await
    .unwrap();
}

/// Share `c` with Bob ([`share_sealed`]), put a version into it and prune
/// it, and share it again without Bob: a reader removed is a new epoch, and
/// the old one's key is erased, its version being pruned
/// ([`Inner::destroy_key`], which scans the store) — in the very put that
/// signs the new members record.
async fn rotate(dev: &Device, c: &Name) {
    share_sealed(dev, c, &["/alice", "/bob"]).await;
    let id = dev
        .put(c, Content::new().with("k", "one"), options())
        .await
        .unwrap();
    dev.prune(c, &[id].into_iter().collect()).await.unwrap();
    share_sealed(dev, c, &["/alice"]).await;
}

/// The epoch `dev` holds in force over `c` that it made itself, if it is one.
fn made_here(dev: &Device, c: &Name) -> Option<Epoch> {
    let st = dev.inner.st.lock();
    st.colls
        .get(c)?
        .members
        .as_ref()?
        .epoch
        .clone()
        .filter(|e| e.creator == *dev.name())
}

/// The names `ops` writes, in order, for a message.
fn short(ops: &[StoreOp]) -> String {
    ops.iter()
        .map(|op| match op {
            StoreOp::Insert(n, _) => format!("+{n}"),
            StoreOp::Remove(n) => format!("-{n}"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The one batch of `calls` that stores the key `dev` made of epoch `e` of
/// `c`; no other call stores it.
fn the_batch_with_key(calls: &[Call], dev: &Device, c: &Name, e: &Epoch) -> Vec<StoreOp> {
    let made = made_key_name(dev.name(), c, e);
    let holding: Vec<&Vec<StoreOp>> = calls
        .iter()
        .filter_map(|call| match call {
            Call::Batch(ops)
                if ops
                    .iter()
                    .any(|op| matches!(op, StoreOp::Insert(n, _) if *n == made)) =>
            {
                Some(ops)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        holding.len(),
        1,
        "the key of {e:?} was stored by {} batches, not one with the record that names it: \
         {calls:?}",
        holding.len()
    );
    holding[0].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_members_record_is_stored_in_one_batch_with_its_key_before_it() {
    let store = Recording::over(Arc::new(MemoryStore::new()));
    let keys = laptop_keys();
    let dev = laptop_on(&keys, Arc::clone(&store) as Arc<dyn DataStore>).await;
    let c = collection();
    let mark = store.mark();
    share_sealed(&dev, &c, &["/alice", "/bob"]).await;
    let first = made_here(&dev, &c).expect("the device made the first epoch");
    let ops = the_batch_with_key(&store.since(mark), &dev, &c, &first);
    let record = ops
        .iter()
        .position(|op| {
            matches!(op, StoreOp::Insert(n, _)
            if parse_log_name(n).is_some_and(|l| l.subject.as_ref() == Some(&c)))
        })
        .expect("the batch stores the members record");
    assert!(
        at(&ops, &made_key_name(dev.name(), &c, &first)) < record,
        "the key of the epoch is stored before the record that names it, so that a prefix of the \
         batch is never a record with no key: {}",
        short(&ops)
    );

    // The same when the record erases an epoch key: it scans the store.
    let id = dev
        .put(&c, Content::new().with("k", "one"), options())
        .await
        .unwrap();
    dev.prune(&c, &[id].into_iter().collect()).await.unwrap();
    let mark = store.mark();
    share_sealed(&dev, &c, &["/alice"]).await;
    let second = made_here(&dev, &c).expect("the device made the second epoch");
    assert_ne!(first, second, "a reader removed: a new epoch");
    let ops = the_batch_with_key(&store.since(mark), &dev, &c, &second);
    let record = ops
        .iter()
        .position(|op| {
            matches!(op, StoreOp::Insert(n, _)
            if parse_log_name(n).is_some_and(|l| l.subject.as_ref() == Some(&c)))
        })
        .expect("the batch stores the members record");
    assert!(
        at(&ops, &made_key_name(dev.name(), &c, &second)) < record,
        "the key is stored before the record that names it: {}",
        short(&ops)
    );
    assert!(
        ops.iter().any(
            |op| matches!(op, StoreOp::Remove(n) if *n == made_key_name(dev.name(), &c, &first))
        ),
        "the old epoch's key is erased in the same batch: {}",
        short(&ops)
    );
    dev.shutdown();
}

/// A store that does not batch atomically, cut off after any `k` writes of
/// a rotation: whenever the members record that names an epoch this device
/// made is there, so is the epoch's key, and the device writes into the
/// collection (it is not [`DataError::NotReady`] for a key it made and lost).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_prefix_of_a_rotation_on_a_store_without_atomic_batches_holds_the_key_of_a_stored_record()
 {
    let c = collection();
    let rotated = |budget: usize| {
        let c = c.clone();
        async move {
            let keys = laptop_keys();
            let inner = Arc::new(MemoryStore::new());
            let dying = Arc::new(Dying {
                inner: Arc::clone(&inner),
                budget: AtomicUsize::new(usize::MAX),
                writes: AtomicUsize::new(0),
            });
            let dev = laptop_on(&keys, Arc::clone(&dying) as Arc<dyn DataStore>).await;
            share_sealed(&dev, &c, &["/alice", "/bob"]).await;
            let id = dev
                .put(&c, Content::new().with("k", "one"), options())
                .await
                .unwrap();
            dev.prune(&c, &[id].into_iter().collect()).await.unwrap();
            dev.inner.flushed().await;
            dying.budget.store(budget, Ordering::SeqCst);
            let before = dying.writes.load(Ordering::SeqCst);
            share_sealed(&dev, &c, &["/alice"]).await;
            let writes = dying.writes.load(Ordering::SeqCst) - before;
            dev.shutdown();
            drop(dev);
            (keys, inner, writes)
        }
    };
    let (_, _, writes) = rotated(usize::MAX).await;
    assert!(
        writes > 4,
        "a rotation writes a record, a key, markers: {writes}"
    );
    for k in 0..=writes + 2 {
        let (keys, kept, _) = rotated(k).await;
        let again = laptop_on(&keys, Arc::clone(&kept) as Arc<dyn DataStore>).await;
        if let Some(e) = made_here(&again, &c) {
            assert!(
                again.inner.st.lock().keys.key(&c, &e).is_some(),
                "after {k} of the rotation's {writes} writes the store holds the members record \
                 that names {e:?}, made by this device, and the epoch's key was never stored: \
                 the restarted device cannot write into {c}"
            );
        }
        let next = again
            .put(&c, Content::new().with("k", "after"), options())
            .await;
        assert!(
            next.is_ok(),
            "after {k} of the rotation's {writes} writes the restarted device cannot write into \
             {c}: {next:?}"
        );
        again.shutdown();
    }
}

// ---- a kill in the middle of a rotation, on a real engine --------------------------------------

/// The environment variable that makes [`rotation_kill_child`] run:
/// `<engine>|<directory>`.
const ROTATION_ROLE: &str = "NDN_DATA_ROTATION_KILL";

/// One run of a device in a process of its own, rotating the key of one
/// collection after another, each announced before and reported after.
/// Nothing when no case started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a child process of the kill case; it runs only when it starts it"]
async fn rotation_kill_child() {
    use std::io::Write;
    let Ok(role) = std::env::var(ROTATION_ROLE) else {
        return;
    };
    let (engine, dir) = role.split_once('|').expect("<engine>|<directory>");
    let engine = match engine {
        "fjall" => Engine::Fjall,
        "redb" => Engine::Redb,
        other => panic!("{ROTATION_ROLE} names engine {other:?}; it is fjall or redb"),
    };
    let dev = laptop_on(
        &laptop_keys(),
        open_engine(engine, std::path::Path::new(dir)),
    )
    .await;
    for i in 0.. {
        println!("start {i}");
        std::io::stdout().flush().unwrap();
        rotate(&dev, &n(&format!("/alice/32=data/rot{i}"))).await;
        println!("done {i}");
        std::io::stdout().flush().unwrap();
    }
}

fn a_kill_in_the_middle_of_a_rotation_leaves_a_record_only_with_its_key(engine: Engine) {
    use std::io::{BufRead, BufReader};
    let mut rng = std::hash::BuildHasher::hash_one(
        &std::collections::hash_map::RandomState::new(),
        engine.label(),
    );
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        (rng % 1000) as f64 / 1000.0
    };
    let mut mid_rotation = 0;
    for round in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "device::batching_tests::rotation_kill_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(
                ROTATION_ROLE,
                format!("{}|{}", engine.label(), dir.path().display()),
            )
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // How long a rotation takes, from the second; then cut one inside.
        let (mut lines, mut began) = (Vec::new(), None);
        let took = loop {
            let line = rx
                .recv_timeout(Duration::from_secs(120))
                .unwrap_or_else(|e| {
                    let _ = child.kill();
                    panic!("the {} child said nothing for 120 s ({e})", engine.label())
                });
            if line == "start 1" {
                began = Some(std::time::Instant::now());
            }
            if line == "done 1" {
                lines.push(line);
                break began.expect("start 1 came first").elapsed();
            }
            if line.starts_with("start ") || line.starts_with("done ") {
                lines.push(line);
            }
        };
        std::thread::sleep(took.mul_f64(next() * 6.0));
        child.kill().unwrap();
        child.wait().unwrap();
        lines.extend(rx.iter());
        let number = |what: &str| {
            lines
                .iter()
                .filter_map(|l| l.strip_prefix(what)?.parse::<usize>().ok())
                .max()
                .unwrap()
        };
        let (started, done) = (number("start "), number("done "));
        if started > done {
            mid_rotation += 1;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = open_engine(engine, dir.path());
            let dev = laptop_on(&laptop_keys(), Arc::clone(&store)).await;
            let mut seen = 0;
            for i in 0..=started {
                let c = n(&format!("/alice/32=data/rot{i}"));
                let Some(e) = made_here(&dev, &c) else {
                    continue;
                };
                seen += 1;
                assert!(
                    dev.inner.st.lock().keys.key(&c, &e).is_some(),
                    "{} round {round}: after kill -9 (rotation {started} started, {done} \
                     reported done) the store holds the members record of {c} that names {e:?}, \
                     made by this device, and not the epoch's key",
                    engine.label()
                );
                let put = dev
                    .put(&c, Content::new().with("k", "after"), options())
                    .await;
                assert!(
                    put.is_ok(),
                    "{} round {round}: after kill -9 the restarted device cannot write into {c}: \
                     {put:?}",
                    engine.label()
                );
            }
            assert!(
                seen > done,
                "{} round {round}: {} rotations were reported done before kill -9; the store \
                 holds {seen} collections with a record of their own",
                engine.label(),
                done + 1
            );
            dev.shutdown();
        });
    }
    assert!(
        mid_rotation >= 1,
        "{}: none of eight kills landed while a rotation was under way, so the case shows nothing",
        engine.label()
    );
}

#[test]
fn a_kill_in_the_middle_of_a_rotation_leaves_a_record_only_with_its_key_on_fjall() {
    a_kill_in_the_middle_of_a_rotation_leaves_a_record_only_with_its_key(Engine::Fjall);
}

#[test]
fn a_kill_in_the_middle_of_a_rotation_leaves_a_record_only_with_its_key_on_redb() {
    a_kill_in_the_middle_of_a_rotation_leaves_a_record_only_with_its_key(Engine::Redb);
}
