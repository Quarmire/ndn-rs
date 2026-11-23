//! Test kit: the store doubles the durability cases run over, and the
//! helpers that start a child process on a real engine and kill it.
//!
//! * [`CrashStore`] keeps what a power cut leaves: the image at the last
//!   returned `sync`, and any prefix of the writes after it.
//! * [`Held`] is a store whose `sync` blocks until released: a disk that
//!   stalls.
//! * [`PowerCut`] and [`ChildRun`] run the case on fjall and redb in a child
//!   process that is killed with SIGKILL.
//!
//! * [`cluster`]: devices over one `ndn_engine` forwarder, for the cases that
//!   need more than one node.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::{DataStore, MemoryStore, StoreOp};
use parking_lot::{Condvar, Mutex, RwLock};

pub(crate) mod cluster;
#[cfg(test)]
mod tests;

/// A name from its URI. Panics on a malformed one: a test's typo.
pub(crate) fn n(uri: &str) -> Name {
    uri.parse().expect("a valid name")
}

/// Whether a store's `sync` is held, and who waits for it to be released.
#[derive(Default)]
struct Gate {
    held: Mutex<bool>,
    let_go: Condvar,
}

impl Gate {
    fn hold(&self) -> Holding<'_> {
        *self.held.lock() = true;
        Holding(self)
    }

    /// Return once the gate is not held.
    fn pass(&self) {
        let mut held = self.held.lock();
        while *held {
            self.let_go.wait(&mut held);
        }
    }
}

/// `sync` of the store that returned this blocks while it lives. Dropping it
/// lets go also when a case fails while holding: a sync still held then
/// would keep the case's runtime, which waits for its blocking threads as it
/// shuts down, waiting for ever, and a failure would hang.
#[must_use = "the store's sync is held only while the guard lives"]
pub(crate) struct Holding<'a>(&'a Gate);

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        *self.0.held.lock() = false;
        self.0.let_go.notify_all();
    }
}

/// What a disk holds: the durable image, and the writes made since the last
/// sync that a power cut may take (each `apply` is one write: an engine's
/// batch is atomic).
#[derive(Default)]
struct Disk {
    image: BTreeMap<Name, Bytes>,
    unsynced: Vec<Vec<StoreOp>>,
}

impl Disk {
    fn fold(&mut self, writes: impl IntoIterator<Item = Vec<StoreOp>>) {
        for op in writes.into_iter().flatten() {
            match op {
                StoreOp::Insert(name, wire) => {
                    self.image.insert(name, wire);
                }
                StoreOp::Remove(name) => {
                    self.image.remove(&name);
                }
            }
        }
    }
}

/// A memory store that models a disk with a write cache. Reads and writes go
/// to the live state; what a power cut leaves is [`Self::crash`]: the
/// image at the last `sync` that returned, which covers the writes that
/// returned before it was called and no later one. [`Self::crash_torn`]
/// keeps a prefix of the writes after it too, as a disk
/// that wrote some of its cache does.
pub(crate) struct CrashStore {
    live: MemoryStore,
    disk: Mutex<Disk>,
    gate: Gate,
    failure: Mutex<Option<String>>,
    syncs: AtomicUsize,
}

impl Default for CrashStore {
    fn default() -> CrashStore {
        CrashStore::new()
    }
}

impl CrashStore {
    /// An empty store.
    pub(crate) fn new() -> CrashStore {
        CrashStore {
            live: MemoryStore::new(),
            disk: Mutex::new(Disk::default()),
            gate: Gate::default(),
            failure: Mutex::new(None),
            syncs: AtomicUsize::new(0),
        }
    }

    /// A store that starts as `image`: live and durable alike.
    fn booted(image: BTreeMap<Name, Bytes>) -> CrashStore {
        let store = CrashStore::new();
        for (name, wire) in &image {
            store.live.insert(name.clone(), wire.clone());
        }
        store.disk.lock().image = image;
        store
    }

    /// The store a restart finds after a power cut that kept exactly what
    /// the last returned `sync` covered.
    pub(crate) fn crash(&self) -> CrashStore {
        self.crash_torn(0)
    }

    /// The store a restart finds after a power cut that also kept the first
    /// `keep` writes made since the last returned `sync` (a batch is one
    /// write; more than there are keeps them all).
    pub(crate) fn crash_torn(&self, keep: usize) -> CrashStore {
        let disk = self.disk.lock();
        let mut after = Disk {
            image: disk.image.clone(),
            unsynced: Vec::new(),
        };
        after.fold(disk.unsynced.iter().take(keep).cloned());
        CrashStore::booted(after.image)
    }

    /// How many writes a power cut now would take.
    pub(crate) fn unsynced(&self) -> usize {
        self.disk.lock().unsynced.len()
    }

    /// Calls of `sync` that began.
    pub(crate) fn syncs_started(&self) -> usize {
        self.syncs.load(Ordering::SeqCst)
    }

    /// Hold every `sync` until the guard returned is dropped.
    pub(crate) fn hold(&self) -> Holding<'_> {
        self.gate.hold()
    }

    /// From now on every `sync` fails with `why`, until [`Self::heal_syncs`].
    pub(crate) fn fail_syncs(&self, why: &str) {
        *self.failure.lock() = Some(why.to_owned());
    }

    /// Syncs succeed again.
    pub(crate) fn heal_syncs(&self) {
        *self.failure.lock() = None;
    }

    fn write(&self, ops: Vec<StoreOp>) {
        // One lock over both, so the log is in the order the live store saw.
        let mut disk = self.disk.lock();
        self.live.apply(ops.clone());
        disk.unsynced.push(ops);
    }
}

impl DataStore for CrashStore {
    fn insert(&self, name: Name, wire: Bytes) {
        self.write(vec![StoreOp::Insert(name, wire)]);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.live.get(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.live.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.live.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        self.write(vec![StoreOp::Remove(name.clone())]);
    }

    fn apply(&self, ops: Vec<StoreOp>) {
        if !ops.is_empty() {
            self.write(ops);
        }
    }

    fn sync(&self) -> std::io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        let covered = self.disk.lock().unsynced.len();
        self.gate.pass();
        if let Some(why) = self.failure.lock().clone() {
            return Err(std::io::Error::other(why));
        }
        let mut disk = self.disk.lock();
        let covered = covered.min(disk.unsynced.len());
        let done: Vec<_> = disk.unsynced.drain(..covered).collect();
        disk.fold(done);
        Ok(())
    }
}

/// A memory store whose `sync` waits while it is held, and that counts its
/// batches, gets and syncs.
#[derive(Default)]
pub(crate) struct Held {
    inner: MemoryStore,
    gate: Gate,
    batches: AtomicUsize,
    gets: AtomicUsize,
    syncs: AtomicUsize,
}

impl Held {
    /// Hold every `sync` until the guard returned is dropped.
    pub(crate) fn hold(&self) -> Holding<'_> {
        self.gate.hold()
    }

    /// Calls of `apply`.
    pub(crate) fn batches(&self) -> usize {
        self.batches.load(Ordering::SeqCst)
    }

    /// Calls of `get`.
    pub(crate) fn gets(&self) -> usize {
        self.gets.load(Ordering::SeqCst)
    }

    /// Calls of `sync` that began.
    pub(crate) fn syncs_started(&self) -> usize {
        self.syncs.load(Ordering::SeqCst)
    }
}

impl DataStore for Held {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.gets.fetch_add(1, Ordering::SeqCst);
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

    fn apply(&self, ops: Vec<StoreOp>) {
        self.batches.fetch_add(1, Ordering::SeqCst);
        self.inner.apply(ops);
    }

    fn sync(&self) -> std::io::Result<()> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        self.gate.pass();
        Ok(())
    }
}

/// A store that counts the octets its reads hand out (`get`, `find_under`
/// and every value a `scan_under` lists): what a case measures to show that
/// a step reads no more than it needs.
pub(crate) struct Metered {
    inner: Arc<dyn DataStore>,
    octets: AtomicUsize,
}

impl Metered {
    /// A counting view of `inner`.
    pub(crate) fn new(inner: Arc<dyn DataStore>) -> Metered {
        Metered {
            inner,
            octets: AtomicUsize::new(0),
        }
    }

    /// Octets of values read since the last [`Self::reset`].
    pub(crate) fn octets_read(&self) -> usize {
        self.octets.load(Ordering::SeqCst)
    }

    /// Start counting again from nothing.
    pub(crate) fn reset(&self) {
        self.octets.store(0, Ordering::SeqCst);
    }

    fn count(&self, wire: &Bytes) {
        self.octets.fetch_add(wire.len(), Ordering::SeqCst);
    }
}

impl DataStore for Metered {
    fn insert(&self, name: Name, wire: Bytes) {
        self.inner.insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        let found = self.inner.get(name);
        found.iter().for_each(|wire| self.count(wire));
        found
    }

    fn contains(&self, name: &Name) -> bool {
        self.inner.contains(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        let found = self.inner.find_under(prefix);
        found.iter().for_each(|wire| self.count(wire));
        found
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        let found = self.inner.scan_under(prefix, limit);
        found.iter().for_each(|(_, wire)| self.count(wire));
        found
    }

    fn remove(&self, name: &Name) {
        self.inner.remove(name);
    }

    fn apply(&self, ops: Vec<StoreOp>) {
        self.inner.apply(ops);
    }

    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()
    }

    fn sync_is_immediate(&self) -> bool {
        self.inner.sync_is_immediate()
    }
}

// -- Real engines under a killed process -----------------------------------------

/// An on-disk engine.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Engine {
    Fjall,
    Redb,
}

impl Engine {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Engine::Fjall => "fjall",
            Engine::Redb => "redb",
        }
    }

    /// The engine `label` names. Panics on another: a case's typo.
    pub(crate) fn parse(label: &str) -> Engine {
        match label {
            "fjall" => Engine::Fjall,
            "redb" => Engine::Redb,
            other => panic!("{other:?} is not an engine; it is fjall or redb"),
        }
    }

    /// The store's files under `dir`: fjall's directory, redb's file.
    pub(crate) fn live(self, dir: &Path) -> PathBuf {
        match self {
            Engine::Fjall => dir.join("live"),
            Engine::Redb => dir.join("live.redb"),
        }
    }
}

/// A copy of `from` (a file or a directory) at `to`, replacing what is
/// there.
pub(crate) fn copy_tree(from: &Path, to: &Path) {
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
/// `sync` of the inner store, on redb each returned write, copies its files
/// to `dir/image`, what a power cut leaves.
pub(crate) struct PowerCut {
    inner: Box<dyn DataStore>,
    live: PathBuf,
    image: PathBuf,
    /// Whether a write is durable when it returns (redb).
    per_write: bool,
    /// Writes hold it shared; taking the image holds it alone.
    gate: RwLock<()>,
}

impl PowerCut {
    /// Open (create) `engine`'s store in `dir`; the image starts as what the
    /// disk holds as it opens.
    pub(crate) fn open(engine: Engine, dir: &Path) -> PowerCut {
        use ndn_sync::store::BackendStore;
        let live = engine.live(dir);
        let inner: Box<dyn DataStore> = match engine {
            Engine::Fjall => Box::new(BackendStore::open_fjall(&live).unwrap()),
            Engine::Redb => Box::new(BackendStore::open_redb(&live).unwrap()),
        };
        let image = dir.join("image");
        copy_tree(&live, &image);
        PowerCut {
            inner,
            live,
            image,
            per_write: matches!(engine, Engine::Redb),
            gate: RwLock::new(()),
        }
    }

    /// Do `op`, a write, and take the image when it is durable on return.
    fn write(&self, op: impl FnOnce()) {
        if self.per_write {
            let _alone = self.gate.write();
            op();
            copy_tree(&self.live, &self.image);
        } else {
            let _shared = self.gate.read();
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

    fn apply(&self, ops: Vec<StoreOp>) {
        self.write(|| self.inner.apply(ops));
    }

    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync()?;
        let _alone = self.gate.write();
        copy_tree(&self.live, &self.image);
        Ok(())
    }
}

/// How long a child may stay silent before a case gives up on it.
const CHILD_LIMIT: Duration = Duration::from_secs(120);

/// This test binary started again on one `#[ignore]`d test, the child of a
/// case, in a process of its own, and its standard output line by line.
pub(crate) struct ChildRun {
    child: Child,
    lines: std::sync::mpsc::Receiver<String>,
}

impl ChildRun {
    /// Start `exact_test` (`module::path::name`, run as an ignored test) with
    /// `role_env` set to `role`: what the test reads to know which child it
    /// is.
    pub(crate) fn start(exact_test: &str, role_env: &str, role: String) -> ChildRun {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                exact_test,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(role_env, role)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        ChildRun { child, lines }
    }

    /// The child's next line. Panics when it ends, or says nothing for
    /// [`CHILD_LIMIT`].
    pub(crate) fn next_line(&mut self) -> String {
        match self.lines.recv_timeout(CHILD_LIMIT) {
            Ok(line) => line,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = self.child.wait().unwrap();
                panic!("the child ended ({status}) before the case was done with it");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                panic!("the child printed nothing for {CHILD_LIMIT:?}");
            }
        }
    }

    /// SIGKILL the child and wait for it to be gone.
    pub(crate) fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
}

impl Drop for ChildRun {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
