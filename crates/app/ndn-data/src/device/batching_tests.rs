//! Per-put store batching (spec §4.2, "Batching"): what a put writes reaches
//! the store as one batch, behind the same barrier as before.
//!
//! The measurement at the end is the harness behind the numbers in the spec
//! and in `handoff-ndf-rs/SHAPES-R5.md`.

use super::durability_tests::{Engine, collection, laptop, percentiles};
use super::group_tests::{n, options};
use super::*;
use crate::layer::Share;
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
fn another_threads_writes_do_not_join_a_batch_and_a_prefix_read_settles_it() {
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
    // A read by prefix must see what the batch holds: it hands it over first.
    let under = stage.scan_under(&n("/s"), 0);
    assert_eq!(under.len(), 3);
    assert!(matches!(rec.since(0).last(), Some(Call::Batch(ops)) if ops.len() == 1));
    drop(batch);
    assert_eq!(
        rec.since(0).len(),
        3,
        "an ended batch with nothing left makes no call"
    );
}
