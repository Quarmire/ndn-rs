//! Start-up cost of a device holding many merge collections (spec §5.2,
//! the merge state built lazily): a device puts `n` merge collections under
//! one folder — each three edits, a checkpoint and an edit after it — into
//! an on-disk store (fjall) and stops; a fresh process then starts the
//! device again from that store. Reported for the second start: the time
//! `Device::start` takes, and the process memory (RSS before and after,
//! and its high-water mark, which in that process is the start's peak).
//!
//! ```text
//! cargo run --release -p ndn-data --example restore_scale [n]
//! ```
//!
//! (`make <dir> <n>` and `restore <dir>` run one side each.)

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_app::{AppError, Connection, Node};
use ndn_data::{
    Config, Counting, DataLayer, Device, Keep, MergeError, MergeRule, MergeRules, MergeState, Name,
    Op, OpKind, PutOptions, Rule, Share, Transport, TypeId, Value, VersionId, Writer,
};
use ndn_security::{SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_sync::DataStore;
use ndn_sync::store::BackendStore;

/// `/bench/merge/tally/v=1`: an edit (`E`) adds one; a checkpoint (`C`,
/// then the count as 8 octets) stands for its past, keeping the edits
/// applied concurrent to it.
struct Tally {
    function: Name,
}

impl MergeRule for Tally {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _collection: &Name, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(TallyState::default())
    }
}

#[derive(Default)]
struct TallyState {
    base: u64,
    edits: BTreeSet<VersionId>,
}

impl MergeState for TallyState {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        match op.bytes {
            [b'E'] => Ok(OpKind::Edit),
            [b'C', rest @ ..] if rest.len() == 8 => Ok(OpKind::Checkpoint),
            _ => Err(MergeError("not a tally operation".into())),
        }
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        match op.bytes {
            [b'E'] => {
                self.edits.insert(op.id.clone());
            }
            [b'C', rest @ ..] => {
                self.edits.retain(|id| !op.past.contains(id));
                self.base = u64::from_be_bytes(rest.try_into().expect("checked"));
            }
            _ => return Err(MergeError("not a tally operation".into())),
        }
        Ok(Counting::Counted)
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        let n = self.base
            + self
                .edits
                .iter()
                .filter(|id| !excluded.contains(id))
                .count() as u64;
        Value::Rule(Bytes::copy_from_slice(&n.to_be_bytes()))
    }
}

/// A forwarder that delivers nothing.
struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

const RULE: &str = "/bench/merge/tally/v=1";

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn folder() -> Name {
    n("/alice/32=data/notes")
}

fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/tally"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// The device's key, the same in both processes (the key store is the
/// process's memory): made from a fixed seed.
fn keys() -> Arc<SecurityManager> {
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(n("/alice/laptop/KEY/1"), &[7; 32])
        .unwrap();
    keys
}

async fn start(store: Arc<dyn DataStore>) -> Device {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n("/alice/laptop"),
        keys(),
        validator,
        store,
        Config {
            rules: MergeRules::standard().with(Arc::new(Tally { function: n(RULE) })),
            first_look: Duration::from_millis(10),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// VmRSS and VmHWM of this process, in KiB.
fn rss() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let kb = |key: &str| {
        status
            .lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (kb("VmRSS:"), kb("VmHWM:"))
}

async fn make(dir: &Path, count: usize) {
    let store: Arc<dyn DataStore> = Arc::new(BackendStore::open_fjall(dir).unwrap());
    let dev = start(store).await;
    dev.share_folder(
        &folder(),
        Share {
            rule: Rule::Merge { function: n(RULE) },
            writers: vec![n("/alice")],
            readers: Vec::new(),
        }
        .into(),
    )
    .await
    .unwrap();
    let ops: [Bytes; 5] = [
        Bytes::from_static(b"E"),
        Bytes::from_static(b"E"),
        Bytes::from_static(b"E"),
        Bytes::from([b"C".as_slice(), &3u64.to_be_bytes()].concat()),
        Bytes::from_static(b"E"),
    ];
    let colls: Vec<Name> = (0..count)
        .map(|i| folder().append(format!("c{i}")))
        .collect();
    let at = Instant::now();
    for op in &ops {
        for chunk in colls.chunks(256) {
            let puts = chunk.iter().map(|c| dev.put_op(c, op.clone(), options()));
            for r in futures::future::join_all(puts).await {
                r.unwrap();
            }
        }
    }
    println!(
        "made {count} merge collections, {} versions, in {:.1?}",
        count * ops.len(),
        at.elapsed()
    );
    dev.shutdown();
}

async fn restore(dir: &Path) {
    let store: Arc<dyn DataStore> = Arc::new(BackendStore::open_fjall(dir).unwrap());
    let (rss_before, _) = rss();
    let at = Instant::now();
    let dev = start(store).await;
    let took = at.elapsed();
    let (rss_after, hwm) = rss();
    println!("start from the store: {took:.1?}");
    println!(
        "memory: RSS {rss_before} KiB before, {rss_after} KiB after (+{} KiB); peak {hwm} KiB \
         (+{} KiB over before)",
        rss_after.saturating_sub(rss_before),
        hwm.saturating_sub(rss_before)
    );
    let c0 = folder().append("c0");
    let at = Instant::now();
    let got = dev.get(&c0).await.unwrap();
    println!("first get of {c0}: {:.1?}, {:?}", at.elapsed(), got.got);
    dev.shutdown();
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, dir, count] if mode == "make" => make(Path::new(dir), count.parse().unwrap()).await,
        [mode, dir] if mode == "restore" => restore(Path::new(dir)).await,
        rest => {
            let count = rest
                .first()
                .and_then(|a| a.parse().ok())
                .unwrap_or(10_000usize);
            let dir = tempfile::tempdir().unwrap();
            let me = std::env::current_exe().unwrap();
            for args in [
                vec![
                    "make".to_owned(),
                    dir.path().display().to_string(),
                    count.to_string(),
                ],
                vec!["restore".to_owned(), dir.path().display().to_string()],
            ] {
                let status = std::process::Command::new(&me)
                    .args(&args)
                    .status()
                    .unwrap();
                assert!(status.success(), "{args:?} failed");
            }
        }
    }
}
