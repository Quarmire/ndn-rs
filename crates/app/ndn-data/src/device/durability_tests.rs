//! Storage conformance case d3 (spec §4.2, §18): nothing is published before it
//! is durable, so a device cut off between a put and the flush that would
//! have made it durable never signs a different entry at a seq a peer saw.
//!
//! Each case runs the device in a child process — this test binary started
//! again on [`power_cut_child`] — on a real on-disk store (fjall, then
//! redb), and kills it with SIGKILL. The power loss is simulated by
//! dropping every write the engine had not made durable, as each engine
//! makes writes durable: fjall when it is flushed ([`DataStore::sync`]
//! fsyncs its journal; a write that returned is only in the operating
//! system's buffers), redb at every write (each is its own transaction,
//! committed with fsync). The store is wrapped so that once a write is
//! durable by that rule a copy of the store's files is taken (writes are
//! held off while it is taken). That copy is what a disk holds after a
//! power loss that takes everything not durable, the worst case the
//! barrier must survive; the torn states in between are case 2's
//! (`ndn-sync`'s `tests/durability.rs`). Before the cut the store is
//! frozen: a flush asked for from then on never finishes, as a disk that
//! loses power during it.
//!
//! The peer is what the device answers to Interests ([`Inner::packet_for`],
//! the function its producer serves with): its own log entries by name and
//! its summary root by discovery name. The first run shares a collection,
//! puts a version and waits until it is served, then freezes the store,
//! puts another and watches what is served until it is cut. The store is
//! put back to its copy, and the second run puts a different version. No
//! name may be served with two contents across both runs.

use super::group_tests::{Unconnected, n, options};
use super::*;
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::store::BackendStore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::RwLock;

/// The environment variable that makes [`power_cut_child`] run:
/// `<engine>|<phase>|<dir>`.
const ROLE: &str = "NDN_DATA_POWER_CUT";

/// How long a child may take before the case gives up on it.
const CHILD_LIMIT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug)]
enum Engine {
    Fjall,
    Redb,
}

impl Engine {
    fn label(self) -> &'static str {
        match self {
            Engine::Fjall => "fjall",
            Engine::Redb => "redb",
        }
    }

    fn parse(s: &str) -> Engine {
        match s {
            "fjall" => Engine::Fjall,
            "redb" => Engine::Redb,
            other => panic!("{ROLE} names engine {other:?}; it is fjall or redb"),
        }
    }

    /// The store's files under `dir`: fjall's directory, redb's file.
    fn live(self, dir: &Path) -> PathBuf {
        match self {
            Engine::Fjall => dir.join("live"),
            Engine::Redb => dir.join("live.redb"),
        }
    }
}

/// A copy of `from` (a file or a directory) at `to`, replacing what is
/// there.
fn copy_tree(from: &Path, to: &Path) {
    if to.is_dir() {
        std::fs::remove_dir_all(to).unwrap();
    } else if to.exists() {
        std::fs::remove_file(to).unwrap();
    }
    if from.is_file() {
        std::fs::copy(from, to).unwrap();
        return;
    }
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        copy_tree(&entry.path(), &to.join(entry.file_name()));
    }
}

/// A store whose disk keeps only what is durable: on fjall each returned
/// [`DataStore::sync`] of the inner store, on redb each returned write,
/// copies its files to `image`, what a power loss leaves. Frozen, a flush
/// never finishes.
struct PowerCut {
    inner: Box<dyn DataStore>,
    live: PathBuf,
    image: PathBuf,
    /// Whether a write is durable when it returns (redb).
    per_write: bool,
    /// Writes hold it shared; taking the image holds it alone.
    gate: RwLock<()>,
    frozen: AtomicBool,
}

impl PowerCut {
    fn open(engine: Engine, dir: &Path) -> PowerCut {
        let live = engine.live(dir);
        let inner: Box<dyn DataStore> = match engine {
            Engine::Fjall => Box::new(BackendStore::open_fjall(&live).unwrap()),
            Engine::Redb => Box::new(BackendStore::open_redb(&live).unwrap()),
        };
        let image = dir.join("image");
        // What the disk holds as the store opens.
        copy_tree(&live, &image);
        PowerCut {
            inner,
            live,
            image,
            per_write: matches!(engine, Engine::Redb),
            gate: RwLock::new(()),
            frozen: AtomicBool::new(false),
        }
    }

    /// Do `op`, a write, and take the image when it is durable on return.
    fn write(&self, op: impl FnOnce()) {
        if self.per_write {
            let _alone = self.gate.write().unwrap();
            op();
            copy_tree(&self.live, &self.image);
        } else {
            let _w = self.gate.read().unwrap();
            op();
        }
    }
}

impl DataStore for PowerCut {
    fn insert(&self, name: Name, wire: Bytes) {
        self.write(|| self.inner.insert(name, wire));
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
        self.write(|| self.inner.remove(name));
    }
    fn sync(&self) -> std::io::Result<()> {
        while self.frozen.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
        self.inner.sync()?;
        let _alone = self.gate.write().unwrap();
        copy_tree(&self.live, &self.image);
        Ok(())
    }
}

fn collection() -> Name {
    n("/alice/32=data/notes")
}

/// `/alice/laptop`, its key the same in every run, on `store`.
async fn laptop(store: Arc<dyn DataStore>) -> Device {
    device_on("/alice/laptop", store).await
}

/// Alice's device `device`, its key the same in every run, on `store`.
async fn device_on(device: &str, store: Arc<dyn DataStore>) -> Device {
    device_over(device, store, Arc::new(Unconnected)).await
}

/// Alice's device `device`, its key the same in every run, on `store`,
/// sending over `conn`.
async fn device_over(device: &str, store: Arc<dyn DataStore>, conn: Arc<dyn Connection>) -> Device {
    let device = n(device);
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(device.clone().append("KEY").append("1"), &[7; 32])
        .unwrap();
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
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

/// What a peer gets of the device now: each of its log entries in
/// [`collection`] up to seq 12, and its summary root, as
/// `(name, digest of the packet's content)`.
fn served(dev: &Device) -> Vec<(String, String)> {
    let c = collection();
    let mut out = Vec::new();
    let mut take = |wire: Bytes| {
        let data = Data::decode(wire).unwrap();
        let content = data.content().cloned().unwrap_or_default();
        let digest: String = Sha256::digest(&content)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        out.push((data.name.to_string(), digest));
    };
    for seq in 1..=12 {
        if let Some(wire) = dev
            .inner
            .packet_for(&log_name(dev.name(), Some(&c), seq), false)
        {
            take(wire);
        }
    }
    if let Some(wire) = dev
        .inner
        .packet_for(&root_prefix(dev.name(), dev.namespace()), true)
    {
        take(wire);
    }
    out
}

/// Print what the device serves, again and again for `span`.
async fn watch_served(dev: &Device, span: Duration) {
    let until = std::time::Instant::now() + span;
    let mut printed = BTreeSet::new();
    while std::time::Instant::now() < until {
        for seen in served(dev) {
            if printed.insert(seen.clone()) {
                println!("seen {} {}", seen.0, seen.1);
            }
        }
        std::io::stdout().flush().unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait until the device serves its own entry at `seq` in [`collection`].
async fn until_published(dev: &Device, seq: u64) {
    let name = log_name(dev.name(), Some(&collection()), seq);
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while dev.inner.packet_for(&name, false).is_none() {
        assert!(
            std::time::Instant::now() < until,
            "{name} was not published within 10 s of its put: the commit barrier never let it \
             through"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// One run of the device, in a process of its own: what the case it is
/// started by asks ([`ROLE`]). Nothing when no case started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a child process of the durability cases; it runs only when one starts it"]
async fn power_cut_child() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let mut parts = role.splitn(3, '|');
    let (engine, phase, dir) = (
        Engine::parse(parts.next().unwrap()),
        parts.next().unwrap().to_owned(),
        PathBuf::from(parts.next().unwrap()),
    );
    let store = Arc::new(PowerCut::open(engine, &dir));
    let dev = laptop(Arc::clone(&store) as Arc<dyn DataStore>).await;
    let c = collection();
    match phase.as_str() {
        "first" => {
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
            let kept = dev
                .put(&c, Content::new().with("text", "kept"), options())
                .await
                .unwrap();
            until_published(&dev, kept.seq.0).await;
            watch_served(&dev, Duration::from_millis(100)).await;
            // From now on no flush finishes: the power goes during it.
            store.frozen.store(true, Ordering::SeqCst);
            dev.put(&c, Content::new().with("text", "lost"), options())
                .await
                .unwrap();
            watch_served(&dev, Duration::from_millis(300)).await;
            println!("cut");
            std::io::stdout().flush().unwrap();
            futures::future::pending::<()>().await;
        }
        "second" => {
            let after = dev
                .put(&c, Content::new().with("text", "after"), options())
                .await
                .unwrap();
            until_published(&dev, after.seq.0).await;
            watch_served(&dev, Duration::from_millis(300)).await;
            println!("done");
        }
        other => panic!("{ROLE} names phase {other:?}; it is first or second"),
    }
}

/// Run [`power_cut_child`] as `phase` on `dir`: every `seen` line it
/// prints, until it prints `cut` (it is then killed with SIGKILL) or ends
/// (it must end well).
fn run_child(engine: Engine, phase: &str, dir: &Path) -> Vec<(String, String)> {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "device::durability_tests::power_cut_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            ROLE,
            format!("{}|{phase}|{}", engine.label(), dir.display()),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
    let mut seen = Vec::new();
    loop {
        match rx.recv_timeout(CHILD_LIMIT) {
            Ok(line) if line == "cut" => {
                child.kill().unwrap();
                child.wait().unwrap();
                return seen;
            }
            Ok(line) => {
                let mut words = line.split_whitespace();
                if words.next() == Some("seen")
                    && let (Some(name), Some(digest)) = (words.next(), words.next())
                {
                    seen.push((name.to_owned(), digest.to_owned()));
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = child.wait().unwrap();
                assert!(
                    status.success(),
                    "the {phase} run on {} failed ({status}); run power_cut_child with {ROLE} \
                     set to see why",
                    engine.label()
                );
                return seen;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                panic!(
                    "the {phase} run on {} printed nothing for {CHILD_LIMIT:?}",
                    engine.label()
                );
            }
        }
    }
}

fn power_cut_case(engine: Engine) {
    let dir = tempfile::tempdir().unwrap();
    let first = run_child(engine, "first", dir.path());
    assert!(
        !first.is_empty(),
        "the first run served nothing before its cut, so the case shows nothing"
    );
    // The power loss: the disk holds what was flushed, nothing more.
    copy_tree(&dir.path().join("image"), &engine.live(dir.path()));
    let second = run_child(engine, "second", dir.path());
    let mut contents: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (name, digest) in first.iter().chain(&second) {
        contents.entry(name).or_default().insert(digest);
    }
    let twice: Vec<_> = contents.iter().filter(|(_, d)| d.len() > 1).collect();
    assert!(
        twice.is_empty(),
        "on {}, after a power loss the device served names a peer had already been served with \
         other content — an honest writer equivocating: {twice:?}",
        engine.label()
    );
}

#[test]
fn a_device_cut_off_between_put_and_flush_never_re_signs_a_seq_a_peer_saw_on_fjall() {
    power_cut_case(Engine::Fjall);
}

#[test]
fn a_device_cut_off_between_put_and_flush_never_re_signs_a_seq_a_peer_saw_on_redb() {
    power_cut_case(Engine::Redb);
}

/// A memory store whose flush waits while it is held.
#[derive(Default)]
struct Held {
    inner: ndn_sync::MemoryStore,
    held: std::sync::Mutex<bool>,
    let_go: std::sync::Condvar,
}

impl Held {
    /// Hold every flush until the guard returned is dropped. The guard
    /// lets go also when a case fails while holding: a flush still held
    /// then would keep the case's runtime, which waits for its blocking
    /// threads as it shuts down, waiting for ever — a failure would hang.
    fn hold(&self) -> Holding<'_> {
        *self.held.lock().unwrap() = true;
        Holding(self)
    }
}

/// Flushes of a [`Held`] store wait while this lives.
struct Holding<'a>(&'a Held);

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        *self
            .0
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        self.0.let_go.notify_all();
    }
}

/// A connection that keeps the highest seq the sync Interests sent into
/// `group` announce for `device`: what the device announced.
struct Announced {
    group: Name,
    device: Name,
    seq: tokio::sync::watch::Sender<u64>,
}

#[async_trait::async_trait]
impl Connection for Announced {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Some(interest) = bare_interest(wire) else {
            return Ok(());
        };
        if !interest.name.has_prefix(&self.group) {
            return Ok(());
        }
        let vector = interest.app_parameters().and_then(|p| {
            SvsConfig::default()
                .dialect
                .decode_state_vector(&Bytes::copy_from_slice(p))
        });
        for entry in vector.into_iter().flatten() {
            if entry.name == self.device {
                self.seq.send_if_modified(|seq| {
                    let higher = entry.seq > *seq;
                    *seq = (*seq).max(entry.seq);
                    higher
                });
            }
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

impl DataStore for Held {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
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
        self.inner.remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.let_go.wait(held).unwrap();
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_is_served_listed_and_announced_only_once_its_flush_returned() {
    let store = Arc::new(Held::default());
    let (seq, mut announced) = tokio::sync::watch::channel(0);
    let sent: Arc<dyn Connection> = Arc::new(Announced {
        group: sync_group(&n("/alice")),
        device: n("/alice/laptop"),
        seq,
    });
    let dev = device_over(
        "/alice/laptop",
        Arc::clone(&store) as Arc<dyn DataStore>,
        sent,
    )
    .await;
    let c = collection();
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
    dev.inner.flushed().await;
    let ns = dev.namespace().clone();
    let root_head = || {
        let wire = dev
            .inner
            .packet_for(&root_prefix(dev.name(), &ns), true)
            .unwrap();
        parse_summary_name(&Data::decode(wire).unwrap().name)
            .and_then(|s| s.head)
            .unwrap()
    };
    let listed = root_head();

    let holding = store.hold();
    // A commit round takes an announcement (counts it) before its flush
    // and sends it after: one taken from now on is taken by a round whose
    // flush waits for the hold, so none above those taken so far may go
    // out — whichever round the put's announcement falls in.
    let may_go_out = dev.inner.st.lock().groups[&ns].announced;
    let id = dev
        .put(&c, Content::new().with("text", "held"), options())
        .await
        .expect("a put applies locally whatever the disk does");
    let entry = log_name(dev.name(), Some(&c), id.seq.0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        dev.inner.packet_for(&entry, false).is_none(),
        "an entry is not served before it is durable"
    );
    assert!(
        root_head() < id.seq.0,
        "a summary does not list an entry before it is durable"
    );
    assert!(
        *announced.borrow() <= may_go_out,
        "nothing is announced before what it announces is durable"
    );
    assert!(
        dev.get(&c).await.is_ok(),
        "the device reads its own put at once"
    );

    drop(holding);
    assert!(dev.inner.published(id.seq.0).await);
    dev.inner.flushed().await;
    assert!(dev.inner.packet_for(&entry, false).is_some());
    assert!(root_head() >= id.seq.0 && root_head() > listed);
    let out = tokio::time::timeout(
        Duration::from_secs(10),
        announced.wait_for(|seq| *seq > may_go_out),
    )
    .await;
    assert!(
        out.is_ok_and(|seen| seen.is_ok()),
        "the put is announced once its flush returned"
    );
    dev.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_store_instance_has_its_own_barrier() {
    let (held, free) = (Arc::new(Held::default()), Arc::new(Held::default()));
    let laptop = device_on("/alice/laptop", Arc::clone(&held) as Arc<dyn DataStore>).await;
    let phone = device_on("/alice/phone", Arc::clone(&free) as Arc<dyn DataStore>).await;
    let c = collection();
    let share = Share {
        rule: Rule::Log,
        writers: vec![n("/alice")],
        readers: Vec::new(),
    };
    laptop.share(&c, share.clone()).await.unwrap();
    laptop.inner.flushed().await;
    let holding = held.hold();
    let stuck = laptop
        .put(&c, Content::new().with("text", "held"), options())
        .await
        .unwrap();
    phone.share(&c, share).await.unwrap();
    let moved = phone
        .put(&c, Content::new().with("text", "free"), options())
        .await
        .unwrap();
    assert!(
        phone.inner.published(moved.seq.0).await,
        "a device on its own store publishes whatever another store's disk does"
    );
    assert!(
        laptop
            .inner
            .packet_for(&log_name(laptop.name(), Some(&c), stuck.seq.0), false)
            .is_none(),
        "the held store's device still waits for its own flush"
    );
    drop(holding);
    assert!(laptop.inner.published(stuck.seq.0).await);
    laptop.shutdown();
    phone.shutdown();
}

/// Median and 99th percentile of `samples`, in microseconds.
fn percentiles(samples: &mut [Duration]) -> (f64, f64) {
    samples.sort();
    let at = |q: f64| {
        let i = ((samples.len() as f64 - 1.0) * q).round() as usize;
        samples[i].as_secs_f64() * 1e6
    };
    (at(0.5), at(0.99))
}

/// How long `put` takes, and how long until what it wrote is published
/// (durable, so served and announced), on each engine — measured, never
/// asserted. Two loads: one put at a time, each waiting until published
/// (a flush per put), and puts back to back (the committer flushes once
/// for all that came during the last flush). Run with
/// `cargo test --release -p ndn-data --lib put_latency -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run on purpose"]
async fn put_latency() {
    const PUTS: usize = 2000;
    let c = collection();
    for engine in [Engine::Fjall, Engine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let live = engine.live(dir.path());
        let store: Arc<dyn DataStore> = match engine {
            Engine::Fjall => Arc::new(BackendStore::open_fjall(&live).unwrap()),
            Engine::Redb => Arc::new(BackendStore::open_redb(&live).unwrap()),
        };
        let dev = laptop(store).await;
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
        let keystroke = |i: usize| Content::new().with("k", format!("{i:08}"));

        let (mut put, mut published) = (Vec::new(), Vec::new());
        for i in 0..PUTS {
            let t0 = std::time::Instant::now();
            let id = dev.put(&c, keystroke(i), options()).await.unwrap();
            let t1 = std::time::Instant::now();
            assert!(dev.inner.published(id.seq.0).await);
            put.push(t1 - t0);
            published.push(t0.elapsed());
        }
        let (pm, p99) = percentiles(&mut put);
        let (bm, b99) = percentiles(&mut published);
        println!(
            "{} one at a time: put median {pm:.1} µs p99 {p99:.1} µs; put to published median \
             {bm:.1} µs p99 {b99:.1} µs",
            engine.label()
        );

        // Back to back: a watcher notes when each seq is published.
        let inner = Arc::clone(&dev.inner);
        let first = inner.st.lock().head + 1;
        let rounds = inner.st.lock().round;
        let last = first + PUTS as u64 - 1;
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
                if seen >= last {
                    return at;
                }
                notified.await;
            }
        });
        let mut started = BTreeMap::new();
        let mut put = Vec::new();
        for i in 0..PUTS {
            let t0 = std::time::Instant::now();
            let id = dev.put(&c, keystroke(i), options()).await.unwrap();
            put.push(t0.elapsed());
            started.insert(id.seq.0, t0);
        }
        let at = watcher.await.unwrap();
        let mut published: Vec<Duration> = started.iter().map(|(s, t0)| at[s] - *t0).collect();
        let flushes = dev.inner.st.lock().round - rounds;
        let (pm, p99) = percentiles(&mut put);
        let (bm, b99) = percentiles(&mut published);
        println!(
            "{} back to back: put median {pm:.1} µs p99 {p99:.1} µs; put to published median \
             {bm:.1} µs p99 {b99:.1} µs; {PUTS} puts in {flushes} flushes",
            engine.label()
        );
        dev.shutdown();
    }
}
