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

use bytes::Bytes;
use ndn_packet::Name;
use ndn_storage::{SyncBackend, name_key};

use crate::svsync::DataStore;

/// A [`DataStore`] backed by any `ndn-storage` [`SyncBackend`]
/// ([`SyncMemoryBackend`](ndn_storage::SyncMemoryBackend), `FjallBackend`,
/// `RedbBackend`). Names are encoded to storage keys with [`name_key`], so a
/// publication name is a byte-prefix of its segments and `CanBePrefix`
/// (`find_under`) is a prefix scan.
pub struct BackendStore<S> {
    backend: S,
}

impl<S: SyncBackend> BackendStore<S> {
    /// Wrap an already-open backend.
    pub fn new(backend: S) -> Self {
        Self { backend }
    }

    /// The underlying backend.
    pub fn backend(&self) -> &S {
        &self.backend
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
        // Fire-and-forget per the `DataStore` contract; a backend write error is
        // logged, not surfaced (the trait returns unit). A dropped write re-heals
        // on the next publish/ingest of the same name.
        if let Err(e) = self.backend.put(&name_key(&name), wire) {
            tracing::warn!(%name, error = %e, "BackendStore: put failed");
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let under: Vec<Name> = store.scan_under(&n("/a/g"), 0).into_iter().map(|(k, _)| k).collect();
        assert_eq!(under, vec![n("/a/g/1"), n("/a/g/2")], "scan is prefix-scoped and ordered");
    }
}
