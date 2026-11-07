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
use ndn_storage::{SyncBackend, name_key};

use crate::svsync::DataStore;

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
    use std::sync::atomic::AtomicBool;

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
            if self.fail_put.load(Ordering::SeqCst) {
                return Err(ndn_storage::StorageError::backend("disk full"));
            }
            self.inner.put(key, value)?;
            self.log.lock().unwrap().0.push(key.to_vec());
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
}
