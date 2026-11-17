//! Persistent [`DataStore`] over `ndn-storage`'s synchronous `SyncBackend`.
//!
//! fjall and redb are synchronous underneath (`ndn-storage`'s async `Backend`
//! is a `spawn_blocking` wrapper over the same core), so a durable publication
//! store bridges to them **without** changing the sync [`DataStore`] trait — no
//! downstream `impl DataStore` breaks, and the value bytes live on disk rather
//! than in RAM. This closes NS-8: a restarted publisher's store is non-empty,
//! so it re-serves its whole history and (via [`DataStore::scan_under`])
//! resumes its sequence space, instead of a lagging peer starving forever.
//!
//! Reads run inline on the caller's task (the per-node SVS demux), blocking it
//! for the duration of a point read. That is an off-forwarding-path, µs-scale
//! LSM/B-tree lookup — acceptable here, unlike the router's content store which
//! is async precisely because it sits on the packet path.
//!
//! # Durability
//!
//! An `insert`/`remove` returns once the backend write returned, so it is in
//! the engine's file as the OS holds it and survives `kill -9` (fjall flushes
//! each write to the OS; redb commits each with an fsync).
//! [`DataStore::sync`](crate::svsync::DataStore::sync) is a group commit over
//! the backend's [`SyncBackend::sync`](ndn_storage::SyncBackend::sync): the
//! store counts the writes it accepted and the writes known durable; a
//! `sync` whose writes are already durable returns at once, otherwise one
//! caller (the leader) flushes for everything accepted so far while the
//! others wait and then find their writes covered — one disk flush per round,
//! however many callers. A failed write or flush is sticky: from then on
//! every `sync` of the store fails, naming it, because a change the store
//! accepted may be gone and nothing it holds can be promised durable. Writes
//! made directly on [`backend`](crate::store::BackendStore::backend) are not
//! counted; make them durable with the backend's own `sync`.
//!
//! [`apply`](crate::svsync::DataStore::apply) hands several changes to the
//! backend as one [`SyncBackend::write_batch`](ndn_storage::SyncBackend::write_batch)
//! and counts it as one accepted write. On fjall (one engine batch), redb (one
//! write transaction) and the memory and flash backends it is atomic: after a
//! kill or a power loss all of it is there or none of it, and the next `sync`
//! covers all of it or none. Like a single write it has returned, and
//! survives `kill -9`, once the backend call returned (fjall's batch is
//! committed with `PersistMode::Buffer`, as a single insert is). A backend
//! with the trait's sequential default `write_batch` leaves a prefix, as the
//! same writes made one by one would. A failed batch is sticky like a failed
//! write.
//!
//! ```no_run
//! # #[cfg(feature = "store-fjall")]
//! # fn main() -> std::io::Result<()> {
//! use std::sync::Arc;
//! use ndn_sync::store::BackendStore;
//! use ndn_sync::svsync::DataStore;
//!
//! // Persistent across restarts; a fresh boot recovers its seq from disk.
//! let store: Arc<dyn DataStore> = Arc::new(BackendStore::open_fjall("./repo")?);
//! # let _ = store;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "store-fjall"))]
//! # fn main() {}
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_storage::{SyncBackend, WriteOp, name_key};

use crate::svsync::{DataStore, StoreOp};

/// A [`DataStore`] backed by any `ndn-storage` [`SyncBackend`]
/// ([`SyncMemoryBackend`](ndn_storage::SyncMemoryBackend), `FjallBackend`,
/// `RedbBackend`). Names are encoded to storage keys with [`name_key`], so a
/// publication name is a byte-prefix of its segments and `CanBePrefix`
/// (`find_under`) is a prefix scan. See the [module docs](self) for what it
/// keeps across a kill and a power loss.
pub struct BackendStore<S> {
    backend: S,
    /// Writes accepted: bumped after each backend write returned `Ok`.
    accepted: AtomicU64,
    /// Every accepted write up to this count is known durable.
    durable: AtomicU64,
    /// Held by the one `sync` flushing (the leader); callers arriving
    /// meanwhile wait here and then usually find their writes covered.
    leader: Mutex<()>,
    /// The first write or flush that failed. Once set, every `sync` fails.
    failed: OnceLock<String>,
}

impl<S: SyncBackend> BackendStore<S> {
    /// Wrap an already-open backend.
    pub fn new(backend: S) -> Self {
        Self {
            backend,
            accepted: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            leader: Mutex::new(()),
            failed: OnceLock::new(),
        }
    }

    /// The underlying backend.
    pub fn backend(&self) -> &S {
        &self.backend
    }

    /// Record a lost write or flush; the first one is kept and reported by
    /// every later `sync`.
    fn fail(&self, what: String) {
        tracing::warn!(
            error = %what,
            "BackendStore: a change may be lost; every later sync of this store fails"
        );
        let _ = self.failed.set(what);
    }

    /// `Err` once any write or flush failed.
    fn check(&self) -> std::io::Result<()> {
        match self.failed.get() {
            None => Ok(()),
            Some(what) => Err(std::io::Error::other(format!(
                "BackendStore ({}): {what}, so a change this store accepted may not be kept \
                 and none can be promised durable any more; restart on a working store (free \
                 space, or fix the disk or its permissions)",
                self.backend.name()
            ))),
        }
    }

    /// Count a write that returned, or record why it failed.
    fn record(&self, result: ndn_storage::StorageResult<()>, what: impl FnOnce() -> String) {
        match result {
            Ok(()) => {
                self.accepted.fetch_add(1, Ordering::Release);
            }
            Err(e) => self.fail(format!("{} failed ({e})", what())),
        }
    }
}

impl BackendStore<ndn_storage::SyncMemoryBackend> {
    /// An in-memory `SyncBackend`-backed store — the persistent store's shape
    /// without the disk (tests, ephemeral nodes). Distinct from
    /// [`MemoryStore`](crate::svsync::MemoryStore): it exercises the same
    /// `SyncBackend` path the on-disk engines use.
    pub fn memory() -> Self {
        Self::new(ndn_storage::SyncMemoryBackend::new())
    }
}

#[cfg(feature = "store-fjall")]
impl BackendStore<ndn_storage::FjallBackend> {
    /// Open (or create) a persistent fjall-backed store at `path`.
    pub fn open_fjall(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        ndn_storage::FjallBackend::open(path)
            .map(Self::new)
            .map_err(std::io::Error::other)
    }
}

#[cfg(feature = "store-redb")]
impl BackendStore<ndn_storage::RedbBackend> {
    /// Open (or create) a persistent redb-backed store at `path`.
    pub fn open_redb(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        ndn_storage::RedbBackend::open(path).map(Self::new)
    }
}

impl<S: SyncBackend> DataStore for BackendStore<S> {
    fn insert(&self, name: Name, wire: Bytes) {
        // The trait returns unit: a failed write is logged and made sticky,
        // so the next `sync` reports it rather than promising it durable.
        let result = self.backend.put(&name_key(&name), wire);
        self.record(result, || format!("the insert of {name}"));
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.backend.get(&name_key(name)).ok().flatten()
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.backend
            .first_under(&name_key(prefix))
            .ok()
            .flatten()
            .map(|(_, v)| v)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.backend
            .scan_prefix(&name_key(prefix), limit)
            .unwrap_or_default()
            .into_iter()
            // Keys are `name_key` bytes = the inner component TLVs, exactly what
            // `Name::decode` consumes; a key that fails to decode is skipped.
            .filter_map(|(k, v)| Name::decode(k).ok().map(|n| (n, v)))
            .collect()
    }

    fn remove(&self, name: &Name) {
        let result = self.backend.delete(&name_key(name));
        self.record(result, || format!("the removal of {name}"));
    }

    /// One [`SyncBackend::write_batch`], counted as one accepted write: the
    /// next [`sync`](DataStore::sync) covers all of it or none. Atomic on
    /// the backends whose `write_batch` is (fjall: one engine batch; redb:
    /// one write transaction; the memory and flash backends), so after a
    /// kill or a power loss every change of `ops` is there or none is; on a
    /// backend with the sequential default it leaves a prefix. A failure is
    /// sticky, as for a single write.
    fn apply(&self, ops: Vec<StoreOp>) {
        let Some(first) = ops.first() else {
            return;
        };
        let (count, first) = (
            ops.len(),
            match first {
                StoreOp::Insert(name, _) => format!("the insert of {name}"),
                StoreOp::Remove(name) => format!("the removal of {name}"),
            },
        );
        let ops = ops
            .into_iter()
            .map(|op| match op {
                StoreOp::Insert(name, wire) => WriteOp::Put(name_key(&name), wire),
                StoreOp::Remove(name) => WriteOp::Delete(name_key(&name)),
            })
            .collect();
        let result = self.backend.write_batch(ops);
        self.record(result, || {
            format!("the batch of {count} changes, the first {first},")
        });
    }

    /// Group commit: returns at once when every write accepted before the
    /// call is already durable; otherwise the leader flushes the backend for
    /// everything accepted so far, and callers that waited on it re-check.
    fn sync(&self) -> std::io::Result<()> {
        self.check()?;
        let target = self.accepted.load(Ordering::Acquire);
        if self.durable.load(Ordering::Acquire) >= target {
            return Ok(());
        }
        let _leader = self.leader.lock().unwrap_or_else(PoisonError::into_inner);
        if self.durable.load(Ordering::Acquire) < target {
            // Every write counted here returned before this flush starts.
            let upto = self.accepted.load(Ordering::Acquire);
            if let Err(e) = self.backend.sync() {
                self.fail(format!("a flush to disk failed ({e})"));
            } else {
                self.durable.fetch_max(upto, Ordering::Release);
            }
        }
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn roundtrip_get_find_scan() {
        let store = BackendStore::memory();
        store.insert(n("/a/g/1"), Bytes::from_static(b"one"));
        store.insert(n("/a/g/2"), Bytes::from_static(b"two"));
        store.insert(n("/a/other"), Bytes::from_static(b"x"));

        assert_eq!(store.get(&n("/a/g/1")).as_deref(), Some(&b"one"[..]));
        assert_eq!(store.get(&n("/a/g/9")), None);
        // find_under is the CanBePrefix lookup → lexicographically smallest.
        assert_eq!(store.find_under(&n("/a/g")).as_deref(), Some(&b"one"[..]));

        let under: Vec<Name> = store
            .scan_under(&n("/a/g"), 0)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            under,
            vec![n("/a/g/1"), n("/a/g/2")],
            "scan is prefix-scoped and ordered"
        );
    }

    /// A backend that tells which writes a flush covered, and fails on cue.
    #[derive(Default)]
    struct Ledger {
        inner: ndn_storage::SyncMemoryBackend,
        /// Keys in the order their writes returned, and how many of them the
        /// last flush covered.
        log: Mutex<(Vec<Vec<u8>>, usize)>,
        fail_put: AtomicBool,
        fail_sync: AtomicBool,
        /// Calls of `write_batch`.
        batches: AtomicUsize,
        /// `write_batch` makes its writes one by one, as the trait's
        /// default does (not atomic); otherwise it lands whole.
        sequential: AtomicBool,
        /// The disk fails every write once the log holds this many keys.
        dies_after: Mutex<Option<usize>>,
    }

    impl Ledger {
        fn is_durable(&self, key: &[u8]) -> bool {
            let log = self.log.lock().unwrap();
            log.0[..log.1].iter().any(|k| k == key)
        }
    }

    impl SyncBackend for Ledger {
        fn get(&self, key: &[u8]) -> ndn_storage::StorageResult<Option<Bytes>> {
            self.inner.get(key)
        }
        fn put(&self, key: &[u8], value: Bytes) -> ndn_storage::StorageResult<()> {
            let dead = self
                .dies_after
                .lock()
                .unwrap()
                .is_some_and(|k| self.log.lock().unwrap().0.len() >= k);
            if self.fail_put.load(Ordering::SeqCst) || dead {
                return Err(ndn_storage::StorageError::backend("disk full"));
            }
            self.inner.put(key, value)?;
            self.log.lock().unwrap().0.push(key.to_vec());
            Ok(())
        }
        fn write_batch(&self, ops: Vec<WriteOp>) -> ndn_storage::StorageResult<()> {
            self.batches.fetch_add(1, Ordering::SeqCst);
            if self.sequential.load(Ordering::SeqCst) {
                for op in ops {
                    match op {
                        WriteOp::Put(k, v) => self.put(&k, v)?,
                        WriteOp::Delete(k) => self.delete(&k)?,
                    }
                }
                return Ok(());
            }
            if self.fail_put.load(Ordering::SeqCst) {
                return Err(ndn_storage::StorageError::backend("disk full"));
            }
            // Whole: the keys join the log in one step, so a flush covers all or none.
            let mut log = self.log.lock().unwrap();
            for op in ops {
                match op {
                    WriteOp::Put(k, v) => {
                        self.inner.put(&k, v)?;
                        log.0.push(k);
                    }
                    WriteOp::Delete(k) => {
                        self.inner.delete(&k)?;
                        log.0.push(k);
                    }
                }
            }
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> ndn_storage::StorageResult<()> {
            self.inner.delete(key)?;
            self.log.lock().unwrap().0.push(key.to_vec());
            Ok(())
        }
        fn scan_prefix(
            &self,
            prefix: &[u8],
            limit: usize,
        ) -> ndn_storage::StorageResult<Vec<(Bytes, Bytes)>> {
            self.inner.scan_prefix(prefix, limit)
        }
        fn sync(&self) -> ndn_storage::StorageResult<()> {
            if self.fail_sync.load(Ordering::SeqCst) {
                return Err(ndn_storage::StorageError::backend("EIO"));
            }
            let mut log = self.log.lock().unwrap();
            log.1 = log.0.len();
            Ok(())
        }
    }

    #[test]
    fn a_returned_sync_covers_every_write_before_it_under_concurrency() {
        let store = BackendStore::new(Ledger::default());
        std::thread::scope(|s| {
            for t in 0..8 {
                let store = &store;
                s.spawn(move || {
                    for i in 0..200 {
                        let name = n(&format!("/t/{t}/{i}"));
                        if i % 3 == 2 {
                            store.remove(&n(&format!("/t/{t}/{}", i - 1)));
                        }
                        store.insert(name.clone(), Bytes::from_static(b"v"));
                        store.sync().expect("sync");
                        assert!(
                            store.backend().is_durable(&name_key(&name)),
                            "{name} was inserted before a sync that returned Ok, yet no \
                             flush covered it"
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn a_failed_write_fails_every_later_sync() {
        let store = BackendStore::new(Ledger::default());
        store.insert(n("/a/1"), Bytes::from_static(b"one"));
        store.sync().expect("nothing failed yet");
        store.backend().fail_put.store(true, Ordering::SeqCst);
        store.insert(n("/a/2"), Bytes::from_static(b"two"));
        store.backend().fail_put.store(false, Ordering::SeqCst);
        store.insert(n("/a/3"), Bytes::from_static(b"three"));
        for _ in 0..2 {
            let e = store.sync().expect_err("a write was lost");
            assert!(e.to_string().contains("/a/2"), "names the lost write: {e}");
        }
    }

    #[test]
    fn a_failed_flush_fails_every_later_sync() {
        let store = BackendStore::new(Ledger::default());
        store.insert(n("/a/1"), Bytes::from_static(b"one"));
        store.backend().fail_sync.store(true, Ordering::SeqCst);
        store.sync().expect_err("the flush failed");
        store.backend().fail_sync.store(false, Ordering::SeqCst);
        // A later flush succeeding does not bring back what the failed one
        // may have dropped (an fsync error can discard dirty pages).
        store.insert(n("/a/2"), Bytes::from_static(b"two"));
        store.sync().expect_err("still failed");
    }

    fn batch(group: &str, k: usize) -> Vec<StoreOp> {
        let mut ops: Vec<StoreOp> = (0..k)
            .map(|i| StoreOp::Insert(n(&format!("/{group}/{i}")), Bytes::from_static(b"v")))
            .collect();
        ops.push(StoreOp::Remove(n(&format!("/{group}/gone"))));
        ops
    }

    #[test]
    fn a_batch_is_one_accepted_unit_the_next_flush_covers_whole() {
        let store = BackendStore::new(Ledger::default());
        store.apply(batch("b", 3));
        assert_eq!(
            store.backend().batches.load(Ordering::SeqCst),
            1,
            "a batch is handed to the backend as one write_batch, not one call per change"
        );
        assert_eq!(
            store.accepted.load(Ordering::SeqCst),
            1,
            "a batch is one accepted write for the group commit"
        );
        for i in 0..3 {
            assert!(
                !store
                    .backend()
                    .is_durable(&name_key(&n(&format!("/b/{i}"))))
            );
        }
        store.sync().expect("sync");
        for i in 0..3 {
            let key = name_key(&n(&format!("/b/{i}")));
            assert!(
                store.backend().is_durable(&key),
                "/b/{i} is covered by the sync"
            );
        }
        assert!(store.backend().is_durable(&name_key(&n("/b/gone"))));
        // An empty batch does nothing and counts nothing.
        store.apply(Vec::new());
        assert_eq!(store.backend().batches.load(Ordering::SeqCst), 1);
        assert_eq!(store.accepted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_batch_leaves_nothing_and_fails_every_later_sync() {
        let store = BackendStore::new(Ledger::default());
        store.insert(n("/a/1"), Bytes::from_static(b"one"));
        store.sync().expect("nothing failed yet");
        store.backend().fail_put.store(true, Ordering::SeqCst);
        store.apply(batch("b", 3));
        store.backend().fail_put.store(false, Ordering::SeqCst);
        store.insert(n("/a/2"), Bytes::from_static(b"two"));
        for _ in 0..2 {
            let e = store.sync().expect_err("a batch was lost");
            assert!(
                e.to_string().contains("batch of 4 changes"),
                "names the lost batch: {e}"
            );
        }
        assert!(
            (0..3).all(|i| store.get(&n(&format!("/b/{i}"))).is_none()),
            "a batch that failed left none of its changes"
        );
    }

    #[test]
    fn a_batch_under_concurrent_sync_is_covered() {
        let store = BackendStore::new(Ledger::default());
        std::thread::scope(|s| {
            for t in 0..8 {
                let store = &store;
                s.spawn(move || {
                    for i in 0..100 {
                        let group = format!("t{t}x{i}");
                        store.apply(batch(&group, 3));
                        store.sync().expect("sync");
                        for j in 0..3 {
                            let key = name_key(&n(&format!("/{group}/{j}")));
                            assert!(
                                store.backend().is_durable(&key),
                                "/{group}/{j} was in a batch applied before a sync that returned \
                                 Ok, yet no flush covered it"
                            );
                        }
                    }
                });
            }
        });
        assert_eq!(
            store.backend().batches.load(Ordering::SeqCst),
            800,
            "one write_batch per batch"
        );
    }

    #[test]
    fn a_backend_without_an_atomic_batch_leaves_the_in_order_prefix() {
        let store = BackendStore::new(Ledger::default());
        store.backend().sequential.store(true, Ordering::SeqCst);
        *store.backend().dies_after.lock().unwrap() = Some(2);
        store.apply(batch("b", 4));
        assert!(
            store.get(&n("/b/0")).is_some() && store.get(&n("/b/1")).is_some(),
            "the changes before the failure were made, in order"
        );
        assert!(
            store.get(&n("/b/2")).is_none() && store.get(&n("/b/3")).is_none(),
            "none after the failure was made: a prefix, never a gap"
        );
        store.sync().expect_err("the failed batch fails the sync");
    }

    /// A store that only keeps a log of the calls made on it.
    #[derive(Default)]
    struct Calls(Mutex<Vec<String>>);

    impl DataStore for Calls {
        fn insert(&self, name: Name, _: Bytes) {
            self.0.lock().unwrap().push(format!("insert {name}"));
        }
        fn get(&self, _: &Name) -> Option<Bytes> {
            None
        }
        fn remove(&self, name: &Name) {
            self.0.lock().unwrap().push(format!("remove {name}"));
        }
        fn sync(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_default_apply_makes_the_calls_one_by_one_in_order() {
        let store = Calls::default();
        store.apply(vec![
            StoreOp::Insert(n("/x/2"), Bytes::new()),
            StoreOp::Remove(n("/x/1")),
            StoreOp::Insert(n("/x/1"), Bytes::new()),
        ]);
        assert_eq!(
            *store.0.lock().unwrap(),
            ["insert /x/2", "remove /x/1", "insert /x/1"]
        );
    }

    #[test]
    fn a_memory_store_applies_a_batch_whole_under_one_lock() {
        let store = crate::svsync::MemoryStore::new();
        store.insert(n("/m/gone"), Bytes::from_static(b"old"));
        std::thread::scope(|s| {
            let store = &store;
            s.spawn(move || {
                for _ in 0..2000 {
                    store.apply(vec![
                        StoreOp::Insert(n("/m/a"), Bytes::from_static(b"1")),
                        StoreOp::Insert(n("/m/b"), Bytes::from_static(b"1")),
                        StoreOp::Remove(n("/m/gone")),
                    ]);
                    store.apply(vec![
                        StoreOp::Remove(n("/m/a")),
                        StoreOp::Remove(n("/m/b")),
                        StoreOp::Insert(n("/m/gone"), Bytes::from_static(b"old")),
                    ]);
                }
            });
            s.spawn(move || {
                for _ in 0..20_000 {
                    let seen = store.scan_under(&n("/m"), 0);
                    let (a, b) = (
                        seen.iter().any(|(k, _)| *k == n("/m/a")),
                        seen.iter().any(|(k, _)| *k == n("/m/b")),
                    );
                    assert_eq!(a, b, "a reader saw half of a batch");
                    let gone = seen.iter().any(|(k, _)| *k == n("/m/gone"));
                    assert_ne!(a, gone, "a reader saw half of a batch");
                }
            });
        });
    }
}
