//! The put -> watch benchmark of the data layer (plan §3.14, "Verification").
//!
//! Two `ndn_heap::Node`s, one per device of `/alice`, on two app faces of ONE
//! forwarder (`ndn_engine`), each with a fjall store on disk. A's `put` starts
//! the clock; it stops when B's `watch` yields that `Put`. For every size
//! (1 KiB, 16 KiB, 1 MiB) there are warm-ups, then the runs; p50 and p95 are
//! printed as markdown rows like `ndn-link`'s ladder, with the plan's gate
//! beside them, the machine's load average, and the cores the process may run
//! on (pin it: `taskset -c 8-11 put_watch`).
//!
//! The devices are certified under the namespace's root and every validator
//! holds every certificate, so each entry B takes goes through the whole
//! `validate_durable` walk (one verification, certificates from the cache).
//!
//! Environment:
//!
//! - `LADDER_DIR`: where the stores live (default `/tmp/ndn-heap-bench`; a
//!   `run-<pid>` directory below it, removed at the end).
//! - `LADDER_RUNS` (200) timed runs per size after `LADDER_WARM` (10) warm-ups.
//! - `LADDER_ONLY`: `1,2,3` picks the sizes (1 KiB, 16 KiB, 1 MiB).
//! - `LADDER_GAP_MS` (0): idle time between runs. Back-to-back (0) is how the
//!   ladder asks (the next put follows the previous watch at once); a gap lets
//!   the tail of a run (A's flush, B's store write) finish and lets the cores
//!   cool, and every put then starts cold: 10 ms and 100 ms cost 0.1 and 0.2
//!   ms at 1 KiB on a schedutil machine.
//! - `LADDER_TL_SETTLE_MS` (5): idle time after each traced run; `0` makes
//!   the traced runs back-to-back like the timed ones (a flush stage may then
//!   belong to the previous run).
//! - `LADDER_SERIES=1`: also print every timed run's microseconds in run
//!   order (to see whether a spread is two modes or a drift).
//! - `LADDER_SEALED=1`: a private space (owner only) instead of a public one.
//! - `LADDER_THREADS`: worker threads of the runtime (default: the cores the
//!   process may run on, at most 8).
//! - `TIMELINE=1`: after the timed runs, `LADDER_TL` (60) more runs per size
//!   with the timeline recorder on (target `ndn_heap::timeline`): per-run
//!   stage times and the per-stage summary. The timed runs have no subscriber.
//! - `COLD_OPEN=1`: only the cold-open measurement: a space with
//!   `COLD_ENTRIES` (100,000) entries (`durable: Some(false)`, 32-octet
//!   payloads, at `COLD_PATHS` paths, default every entry its own path), then
//!   flush, close, and the time of `Node::start` + the first `get` on reopen,
//!   after a clean close and after a `shutdown` (an unclean start).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_foundation_types::Name;
use ndn_heap::{
    Change, Changes, Config, Frontier, Heap, Node, PutOptions, Readers, Share, Transport,
};
use ndn_security::{SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_sync::DataStore;
use ndn_sync::store::BackendStore;
use tokio_util::sync::CancellationToken;

const TIMELINE: &str = "ndn_heap::timeline";

/// (label, octets, p50 target ms, p50 hard fail ms)
const SIZES: [(&str, usize, f64, f64); 3] = [
    ("1 KiB", 1024, 0.7, 1.0),
    ("16 KiB", 16 * 1024, 1.6, 3.0),
    ("1 MiB", 1 << 20, 45.0, 70.0),
];

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

fn pctf(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|_| "?".into())
}

fn cpus_allowed() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Cpus_allowed_list:")
                    .map(|v| v.trim().to_owned())
            })
        })
        .unwrap_or_else(|| "?".into())
}

fn name(uri: &str) -> Name {
    uri.parse().expect("a valid name")
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => total += dir_size(&e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// Removes the run's directory (and `LADDER_DIR` when that leaves it empty).
struct Cleanup(PathBuf, PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_dir(&self.1);
    }
}

// -- The world: devices certified under the namespace's root ---------------------------

/// What a node is started with besides its store.
struct Ident {
    name: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
}

async fn identities(namespace: &str, devices: &[&str]) -> Vec<Ident> {
    let ns = name(namespace);
    let root = SecurityManager::new();
    let root_key = ns.clone().append("KEY").append("root");
    root.generate_ed25519(root_key.clone()).unwrap();
    let pk = root
        .get_signer_sync(&root_key)
        .unwrap()
        .public_key()
        .unwrap();
    let anchor = root.issue_self_signed(&root_key, pk, u64::MAX).unwrap();
    let mut made = Vec::new();
    for d in devices {
        let device = name(d);
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(device.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, &root_key, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        made.push((device, keys, cert));
    }
    made.iter()
        .map(|(device, keys, _)| {
            let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
            let ctx = SignedTrustContext::hierarchical(ns.clone());
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
            for (_, _, cert) in &made {
                validator.cert_cache().insert(cert.clone());
            }
            Ident {
                name: device.clone(),
                keys: Arc::clone(keys),
                validator,
            }
        })
        .collect()
}

fn open_store(path: &Path) -> std::io::Result<Arc<dyn DataStore>> {
    Ok(Arc::new(BackendStore::open_fjall(path)?))
}

async fn new_engine(namespace: &Name) -> ForwarderEngine {
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    ndn_namespace::sync_group::carry(&engine, namespace);
    engine
}

async fn start(
    engine: &ForwarderEngine,
    id: &Ident,
    store: Arc<dyn DataStore>,
    cancel: &CancellationToken,
) -> Node {
    tokio::time::timeout(
        Duration::from_secs(120),
        Node::start(
            Transport {
                node: engine.app_node(cancel.child_token()),
                sync: engine.app_face(cancel.child_token()),
            },
            id.name.clone(),
            Arc::clone(&id.keys),
            Arc::clone(&id.validator),
            store,
            Config::new(),
        ),
    )
    .await
    .expect("the node starts within 120 s")
    .expect("the node starts")
}

// -- The recorder of the timeline ---------------------------------------------------------

mod tape {
    use std::sync::{LazyLock, Mutex};
    use std::time::Instant;

    pub struct Ev {
        pub at: u128,
        pub msg: String,
        pub fields: String,
    }

    pub static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);
    pub static TAPE: Mutex<Vec<Ev>> = Mutex::new(Vec::new());

    /// Nanoseconds since the process began timing.
    pub fn now_ns() -> u128 {
        BASE.elapsed().as_nanos()
    }

    pub struct Tape;
    struct Text(String, String);

    impl tracing::field::Visit for Text {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            if f.name() == "message" {
                self.0 = format!("{v:?}");
            } else {
                self.1.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
    }

    impl tracing::Subscriber for Tape {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            m.target() == super::TIMELINE
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let at = now_ns();
            let mut t = Text(String::new(), String::new());
            e.record(&mut t);
            TAPE.lock().unwrap().push(Ev {
                at,
                msg: t.0,
                fields: t.1,
            });
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
}

// -- The rig: A and B on one forwarder -----------------------------------------------------

struct Rig {
    a_name: Name,
    a: Heap,
    changes: Changes,
    path: Name,
    counter: u64,
    gap: Duration,
    // Keep the nodes (and their tasks and stores) alive.
    _nodes: (Node, Node),
    _b: Heap,
}

impl Rig {
    async fn new(dir: &Path, sealed: bool, gap: Duration) -> Rig {
        let ids = identities("/alice", &["/alice/a", "/alice/b"]).await;
        let engine = new_engine(&name("/alice")).await;
        let cancel = CancellationToken::new();
        let a_node = start(
            &engine,
            &ids[0],
            open_store(&dir.join("a")).expect("a fjall store"),
            &cancel,
        )
        .await;
        let b_node = start(
            &engine,
            &ids[1],
            open_store(&dir.join("b")).expect("a fjall store"),
            &cancel,
        )
        .await;
        let space = name("/alice/32=data/bench");
        let share = Share {
            readers: if sealed {
                Readers::Persons(vec![])
            } else {
                Readers::Anyone
            },
            writers: vec![],
        };
        let a = a_node
            .create(&space, share)
            .await
            .expect("A creates the space");
        let b = b_node.open(&space).await.expect("B opens the space");
        wait("B is ready", || b.ready()).await;
        // B writes once so that A knows a peer (its puts are then not durable by
        // default: the flush is off the path) and B has A's vector.
        let hello = name("/hello");
        b.put(&hello, Bytes::from_static(b"hello"), PutOptions::default())
            .await
            .expect("B puts");
        for _ in 0..1500 {
            if matches!(a.kept(&hello).await, Ok(Some(_))) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let changes = b.watch(&Frontier::new()).await.expect("B watches");
        Rig {
            a_name: ids[0].name.clone(),
            a,
            changes,
            path: name("/bench/value"),
            counter: 0,
            gap,
            _nodes: (a_node, b_node),
            _b: b,
        }
    }

    fn payload(&mut self, size: usize) -> (u64, Bytes) {
        self.counter += 1;
        let tag = self.counter;
        let mut v = vec![0u8; size];
        v[..8].copy_from_slice(&tag.to_be_bytes());
        let mut x = tag.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        for chunk in v[8..].chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let b = x.to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        (tag, Bytes::from(v))
    }

    /// One put on A until B's watch yields it: (put -> watch, put returns, the
    /// recorder's clock at the put's start).
    async fn once(&mut self, size: usize) -> (Duration, Duration, u128) {
        let (tag, bytes) = self.payload(size);
        if !self.gap.is_zero() {
            tokio::time::sleep(self.gap).await;
        }
        let t0_ns = tape::now_ns();
        let t0 = Instant::now();
        self.a
            .put(&self.path, bytes, PutOptions::default())
            .await
            .expect("A puts");
        let returned = t0.elapsed();
        loop {
            let next = tokio::time::timeout(Duration::from_secs(20), self.changes.next())
                .await
                .expect("B's watch yields within 20 s");
            match next {
                Some(Ok(Change::Put(item)))
                    if item.bytes.len() >= 8 && item.bytes[..8] == tag.to_be_bytes() =>
                {
                    return (t0.elapsed(), returned, t0_ns);
                }
                Some(Ok(_)) => {}
                other => panic!("B's watch ended: {other:?}"),
            }
        }
    }
}

async fn wait(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..1500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not within 15 s: {what}");
}

// -- What one traced run did ----------------------------------------------------------------

/// The recorder's events in the order a put meets them. `judged`, `admitted`
/// and `routed` are the seams inside B's `take` (between `verify_begin` and
/// `verify_end`): the validator's verdict, the log's admission under the
/// space's lock, the watchers told and the store batch handed over.
const STAGES: [&str; 13] = [
    "put_returns",
    "flush_begin",
    "flush_end",
    "announce",
    "sync_update",
    "fetch_out",
    "fetch_in",
    "verify_begin",
    "judged",
    "admitted",
    "routed",
    "verify_end",
    "watch_send",
];

struct Run {
    /// Milliseconds after the put began, per stage: the first occurrence,
    /// except `fetch_in` and `verify_end` (the last).
    at: [Option<f64>; STAGES.len()],
    fetches: usize,
    again: usize,
    missed: usize,
    durable: Option<bool>,
}

fn analyse(events: &[tape::Ev], t0: u128, a: &Name) -> Run {
    let since = |e: &tape::Ev| e.at.saturating_sub(t0) as f64 / 1e6;
    let mut run = Run {
        at: [None; STAGES.len()],
        fetches: 0,
        again: 0,
        missed: 0,
        durable: None,
    };
    let a_update = format!("device={a} ");
    for e in events.iter().filter(|e| e.at >= t0) {
        let Some(k) = STAGES.iter().position(|s| *s == e.msg) else {
            if e.msg == "fetch_miss" {
                run.missed += 1;
            }
            continue;
        };
        if e.msg == "sync_update" && !e.fields.contains(&a_update) {
            continue;
        }
        if e.msg == "fetch_out" {
            run.fetches += 1;
        }
        if e.msg == "fetch_in" {
            let expressed = e
                .fields
                .split("expressed=")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1);
            if expressed > 1 {
                run.again += 1;
            }
        }
        if e.msg == "put_returns" && run.durable.is_none() {
            run.durable = Some(e.fields.contains("durable=true"));
        }
        let last = matches!(e.msg.as_str(), "fetch_in" | "verify_end");
        if last || run.at[k].is_none() {
            run.at[k] = Some(since(e));
        }
    }
    run
}

// -- The measurement --------------------------------------------------------------------------

struct Measured {
    label: &'static str,
    p50: Duration,
    p95: Duration,
    max: Duration,
    put_p50: Duration,
    runs: usize,
    p50_target: f64,
    hard: f64,
    over_150ms: usize,
    load: String,
    /// p10 / p25 / p75 / p90, ms.
    spread: String,
    /// Every run's put -> watch time, microseconds, in run order.
    series: Vec<u32>,
}

async fn measure(rig: &mut Rig, k: usize, warm: usize, runs: usize) -> Measured {
    let (label, size, p50_target, hard) = SIZES[k];
    for _ in 0..warm {
        rig.once(size).await;
    }
    let (mut total, mut put) = (Vec::new(), Vec::new());
    for _ in 0..runs {
        let (t, p, _) = rig.once(size).await;
        total.push(t);
        put.push(p);
    }
    let over_150ms = total.iter().filter(|t| t.as_millis() > 150).count();
    let series: Vec<u32> = total.iter().map(|t| t.as_micros() as u32).collect();
    let spread = [0.1, 0.25, 0.75, 0.9]
        .map(|p| format!("{:.3}", ms(pct(&mut total, p))))
        .join(" / ");
    Measured {
        label,
        p50: pct(&mut total, 0.5),
        p95: pct(&mut total, 0.95),
        max: pct(&mut total, 1.0),
        put_p50: pct(&mut put, 0.5),
        runs,
        p50_target,
        hard,
        over_150ms,
        load: load_average(),
        spread,
        series,
    }
}

async fn timeline(rig: &mut Rig, k: usize, runs: usize, per_run: bool) -> String {
    let (label, size, _, _) = SIZES[k];
    let mut t = String::new();
    let _ = writeln!(
        t,
        "\n### Timeline of the {label} put -> watch ({runs} traced runs, ms after the put began)\n"
    );
    if per_run {
        let _ = writeln!(t, "| run | {} | total | fetches |", STAGES.join(" | "));
        let _ = writeln!(t, "|---|{}---|---|", "---|".repeat(STAGES.len()));
    }
    let mut all: Vec<Run> = Vec::new();
    let mut totals = Vec::new();
    for i in 0..runs {
        tape::TAPE.lock().unwrap().clear();
        let (total, _, t0) = rig.once(size).await;
        // The tail of a run (B's store write, A's flush) may still be recording:
        // with no settle, a flush of this run is attributed to the next one.
        let settle: u64 = env_num("LADDER_TL_SETTLE_MS", 5);
        if settle > 0 {
            tokio::time::sleep(Duration::from_millis(settle)).await;
        }
        let events = std::mem::take(&mut *tape::TAPE.lock().unwrap());
        let run = analyse(&events, t0, &rig.a_name);
        if per_run {
            let cells: Vec<String> = run
                .at
                .iter()
                .map(|v| v.map_or("-".into(), |v| format!("{v:.3}")))
                .collect();
            let _ = writeln!(
                t,
                "| {i} | {} | {:.3} | {} |",
                cells.join(" | "),
                ms(total),
                run.fetches
            );
        }
        totals.push(ms(total));
        all.push(run);
    }
    let _ = writeln!(
        t,
        "\n| step | p50 | p95 | step (p50 delta) | runs with it |\n|---|---|---|---|---|"
    );
    let mut before = 0.0;
    for (k, stage) in STAGES.iter().enumerate() {
        let mut v: Vec<f64> = all.iter().filter_map(|r| r.at[k]).collect();
        if v.is_empty() {
            let _ = writeln!(t, "| {stage} | - | - | - | 0 of {runs} |");
            continue;
        }
        let (p50, p95) = (pctf(&mut v, 0.5), pctf(&mut v, 0.95));
        let _ = writeln!(
            t,
            "| {stage} | {p50:.3} | {p95:.3} | {:+.3} | {} of {runs} |",
            p50 - before,
            v.len()
        );
        before = p50;
    }
    let (p50, p95) = (pctf(&mut totals.clone(), 0.5), pctf(&mut totals, 0.95));
    let _ = writeln!(
        t,
        "| (B's watch yields) | {p50:.3} | {p95:.3} | - | {runs} of {runs} |"
    );
    let mut fetches: Vec<f64> = all.iter().map(|r| r.fetches as f64).collect();
    let again: usize = all.iter().map(|r| r.again).sum();
    let missed: usize = all.iter().map(|r| r.missed).sum();
    let nondurable = all.iter().filter(|r| r.durable == Some(false)).count();
    let _ = writeln!(
        t,
        "\nB's fetches per put: p50 {} (min {}, max {}); answered after a re-expression: {again}; missed: {missed}; puts that returned without waiting for a flush: {nondurable} of {runs}.",
        pctf(&mut fetches.clone(), 0.5),
        pctf(&mut fetches.clone(), 0.0),
        pctf(&mut fetches, 1.0),
    );
    t
}

// -- Cold open ------------------------------------------------------------------------------------

/// Open the store, retrying while a previous run's tasks still hold its lock.
async fn reopen_store(path: &Path) -> (Arc<dyn DataStore>, Duration) {
    let mut tries = 0;
    loop {
        let t = Instant::now();
        match open_store(path) {
            Ok(s) => return (s, t.elapsed()),
            Err(_) if tries < 100 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("the store does not reopen: {e}"),
        }
    }
}

async fn cold_open(dir: &Path, entries: usize, paths: usize) -> String {
    let mut out = String::new();
    let path = dir.join("cold");
    let id = identities("/alice", &["/alice/cold"]).await.remove(0);
    let engine = new_engine(&name("/alice")).await;
    let space = name("/alice/32=data/cold");
    {
        let store = open_store(&path).expect("a fjall store");
        let cancel = CancellationToken::new();
        let node = start(&engine, &id, store, &cancel).await;
        let heap = node
            .create(
                &space,
                Share {
                    readers: Readers::Anyone,
                    writers: vec![],
                },
            )
            .await
            .expect("the space is created");
        let opts = PutOptions {
            durable: Some(false),
        };
        let t_build = Instant::now();
        for i in 0..entries {
            let p = name(&format!("/e/{}", i % paths));
            heap.put(&p, Bytes::from(format!("{i:032}")), opts.clone())
                .await
                .expect("a put");
        }
        let built = t_build.elapsed();
        let t = Instant::now();
        node.flush().await.expect("the flush");
        let flushed = t.elapsed();
        let t = Instant::now();
        drop(heap);
        node.close().await;
        let _ = writeln!(
            out,
            "built {entries} entries at {paths} paths in {:.1} s ({:.0} puts/s); flush {:.0} ms; close {:.0} ms.",
            built.as_secs_f64(),
            entries as f64 / built.as_secs_f64(),
            ms(flushed),
            ms(t.elapsed())
        );
    }
    let _ = writeln!(
        out,
        "store on disk: {:.1} MiB.\n",
        dir_size(&path) as f64 / 1048576.0
    );
    let _ = writeln!(
        out,
        "| reopen | store open ms | Node::start ms | first get ms | start + first get ms | first watch listing ms |\n|---|---|---|---|---|---|"
    );
    let probe = name(&format!("/e/{}", (entries / 2) % paths));
    for (round, clean) in [
        ("after a clean close", true),
        ("after a shutdown (unclean start)", false),
    ] {
        let (store, t_store) = reopen_store(&path).await;
        let cancel = CancellationToken::new();
        let t = Instant::now();
        let node = start(&engine, &id, store, &cancel).await;
        let started = t.elapsed();
        let heap = node.space(&space).expect("start restored the space");
        let t = Instant::now();
        let got = heap.kept(&probe).await.expect("a get");
        let first_get = t.elapsed();
        assert!(got.is_some(), "the first get finds the entry");
        // A watcher's first listing reads every head's entry from the store.
        let t = Instant::now();
        let changes = heap.watch(&Frontier::new()).await.expect("a watch");
        let first_watch = t.elapsed();
        drop(changes);
        let _ = writeln!(
            out,
            "| {round} | {:.1} | {:.1} | {:.3} | {:.1} | {:.1} |",
            ms(t_store),
            ms(started),
            ms(first_get),
            ms(started + first_get),
            ms(first_watch)
        );
        drop(heap);
        if clean {
            // Leaves `R > head`: the next start is unclean.
            node.shutdown();
            drop(node);
        } else {
            node.close().await;
        }
        cancel.cancel();
    }
    out
}

fn main() {
    LazyLock::force(&tape::BASE);
    let dir = PathBuf::from(env("LADDER_DIR", "/tmp/ndn-heap-bench"));
    let run_dir = dir.join(format!("run-{}", std::process::id()));
    std::fs::create_dir_all(&run_dir).expect("the run directory");
    let _cleanup = Cleanup(run_dir.clone(), dir.clone());
    let allowed = cpus_allowed();
    let threads: usize = env_num(
        "LADDER_THREADS",
        std::thread::available_parallelism().map_or(4, |n| n.get().min(8)),
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .expect("a runtime");
    macro_rules! say {
        ($($t:tt)*) => {
            println!($($t)*)
        };
    }
    let started = load_average();
    if env("COLD_OPEN", "0") == "1" {
        let entries: usize = env_num("COLD_ENTRIES", 100_000);
        let paths: usize = env_num("COLD_PATHS", entries).max(1);
        say!("# ndn-heap cold open of {entries} entries ({paths} paths), fjall");
        say!(
            "- load average (1 5 15 min) at start: {started}; cores allowed: {allowed}; worker threads: {threads}\n"
        );
        let text = rt.block_on(cold_open(&run_dir, entries, paths));
        say!("{text}");
        say!("- load average at end: {}", load_average());
        rt.shutdown_timeout(Duration::from_secs(2));
        return;
    }

    let runs: usize = env_num("LADDER_RUNS", 200);
    let warm: usize = env_num("LADDER_WARM", 10);
    let gap = Duration::from_millis(env_num("LADDER_GAP_MS", 0));
    let sealed = env("LADDER_SEALED", "0") == "1";
    let traced = env("TIMELINE", "0") == "1";
    let tl_runs: usize = env_num("LADDER_TL", 60);
    let only: Vec<usize> = env("LADDER_ONLY", "1,2,3")
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|k| (1..=SIZES.len()).contains(k))
        .map(|k| k - 1)
        .collect();
    say!("# ndn-heap put on A -> B's watch yields (one forwarder, two app faces, fjall)");
    say!(
        "- {runs} runs per size after {warm} warm-ups; gap between runs {} ms; space {}; worker threads {threads}; cores allowed: {allowed}",
        gap.as_millis(),
        if sealed {
            "private (owner only)"
        } else {
            "public"
        }
    );
    say!("- load average (1 5 15 min) at start: {started}\n");
    let mut results = Vec::new();
    let mut timelines = String::new();
    rt.block_on(async {
        let mut rig = Rig::new(&run_dir, sealed, gap).await;
        for &k in &only {
            results.push(measure(&mut rig, k, warm, runs).await);
        }
        if traced {
            // Installed after the timed runs: they have no subscriber.
            let _ = tracing::subscriber::set_global_default(tape::Tape);
            for &k in &only {
                timelines.push_str(&timeline(&mut rig, k, tl_runs, true).await);
            }
        }
    });
    say!("## Latency, p50 / p95 ms\n");
    say!(
        "| row | {} |",
        results
            .iter()
            .map(|m| m.label)
            .collect::<Vec<_>>()
            .join(" | ")
    );
    say!("|---|{}", "---|".repeat(results.len()));
    say!(
        "| ndn-heap put on A -> B's watch yields | {} |",
        results
            .iter()
            .map(|m| format!("{:.3} / {:.3}", ms(m.p50), ms(m.p95)))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    say!(
        "| (A's put returns, p50) | {} |",
        results
            .iter()
            .map(|m| format!("{:.3}", ms(m.put_p50)))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    say!("\n## Gate\n");
    say!(
        "| size | p50 ms | p95 ms | max ms | runs | target p50 | hard fail | verdict | runs over 150 ms | load average at end of size |"
    );
    say!("|---|---|---|---|---|---|---|---|---|---|");
    for m in &results {
        let (p50, p95) = (ms(m.p50), ms(m.p95));
        let mut verdict = if p50 <= m.p50_target {
            "PASS"
        } else if p50 <= m.hard {
            "MISS: profile"
        } else {
            "HARD FAIL"
        }
        .to_owned();
        if m.label == "1 KiB" && p95 > 1.5 {
            verdict.push_str(" (p95 above 1.5)");
        }
        say!(
            "| {} | {p50:.3} | {p95:.3} | {:.3} | {} | {} | {} | {verdict} | {} | {} |",
            m.label,
            ms(m.max),
            m.runs,
            m.p50_target,
            m.hard,
            m.over_150ms,
            m.load
        );
    }
    say!("\nSpread, ms (p10 / p25 / p75 / p90):\n");
    for m in &results {
        say!("- {}: {}", m.label, m.spread);
    }
    if env("LADDER_SERIES", "0") == "1" {
        for m in &results {
            say!("\nSeries {} (us, run order): {:?}", m.label, m.series);
        }
    }
    if !timelines.is_empty() {
        say!("{timelines}");
    }
    say!("\n- load average at end: {}", load_average());
    rt.shutdown_timeout(Duration::from_secs(2));
}
