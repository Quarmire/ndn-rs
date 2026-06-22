//! **Pluggable async storage engine** — an ordered byte key→value [`Backend`].
//!
//! *Layer 0* of the storage stack: domain-agnostic ordered bytes, no NDN names and
//! no blocks. Data-model layers build **on** a `Backend`:
//!
//! - the named-data store (name→wire CS/Repo) — [`NamedStore`] here / `ndn-repo`,
//! - a content-addressed blob store (CID→bytes) — for FLIC manifests / dedup,
//! - NDF's `BlockStore` (content-addressed chains) — in `ndf-rs`.
//!
//! Separating the *engine* from the *data model* lets one fjall (or in-memory, or
//! object-store) adapter be written **once** and reused by every model. Mirrors
//! `object_store` (engine) vs Delta/Lance (models), and IPFS's `Datastore` under its
//! content-addressed `Blockstore`.
//!
//! The trait is **async** and **object-safe** (`Arc<dyn Backend>`): a sync engine
//! (fjall) does its blocking work inside `spawn_blocking` *in the adapter*, so call
//! sites are clean `.await`s with no boilerplate; a natively-async engine (S3) fits
//! the same trait without a thread hop. Object-safety is via boxed futures
//! (`async_trait`) — the boxing lands only on the durable tier, never the ring path.

use async_trait::async_trait;
use bytes::Bytes;

/// An ordered byte key→value store. Keys sort lexicographically, so a parent
/// byte-prefix precedes all its descendants — making prefix/range scans the
/// primitive for "CanBePrefix" lookups and "last-N under a name".
#[async_trait]
pub trait Backend: Send + Sync {
    /// Fetch the value stored under `key`.
    async fn get(&self, key: Vec<u8>) -> Option<Bytes>;

    /// Store `value` under `key` (overwriting any existing value).
    async fn put(&self, key: Vec<u8>, value: Bytes);

    /// Remove `key` if present.
    async fn delete(&self, key: Vec<u8>);

    /// `(key, value)` pairs whose key starts with `prefix`, in ascending key order,
    /// at most `limit` (0 = unlimited). Owned, so the result moves cleanly across a
    /// `spawn_blocking` boundary.
    async fn scan_prefix(&self, prefix: Vec<u8>, limit: usize) -> Vec<(Bytes, Bytes)>;

    /// The lexicographically-smallest `(key, value)` whose key starts with `prefix`
    /// (a `CanBePrefix` lookup). Default: first of [`scan_prefix`](Self::scan_prefix).
    async fn first_under(&self, prefix: Vec<u8>) -> Option<(Bytes, Bytes)> {
        self.scan_prefix(prefix, 1).await.into_iter().next()
    }
}

/// In-memory [`Backend`] (a `BTreeMap` behind an `RwLock`). The default for tests,
/// browser/wasm, and process-lifetime data. Its async methods complete immediately
/// (no thread hop).
#[derive(Default)]
pub struct MemoryBackend {
    map: std::sync::RwLock<std::collections::BTreeMap<Vec<u8>, Bytes>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map.read().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.read().unwrap().is_empty()
    }
}

#[async_trait]
impl Backend for MemoryBackend {
    async fn get(&self, key: Vec<u8>) -> Option<Bytes> {
        self.map.read().unwrap().get(&key).cloned()
    }
    async fn put(&self, key: Vec<u8>, value: Bytes) {
        self.map.write().unwrap().insert(key, value);
    }
    async fn delete(&self, key: Vec<u8>) {
        self.map.write().unwrap().remove(&key);
    }
    async fn scan_prefix(&self, prefix: Vec<u8>, limit: usize) -> Vec<(Bytes, Bytes)> {
        let map = self.map.read().unwrap();
        let mut out = Vec::new();
        for (k, v) in map.range(prefix.clone()..) {
            if !k.starts_with(&prefix) {
                break;
            }
            out.push((Bytes::copy_from_slice(k), v.clone()));
            if limit != 0 && out.len() >= limit {
                break;
            }
        }
        out
    }
}

#[cfg(feature = "named")]
pub use named::{NamedReadStore, NamedStore, NamedWriteStore, StoreRouter, name_key};

/// Layer 1: a name→wire store over any [`Backend`] (the CS/Repo model). Keys are
/// NDN component-TLVs, so a parent name is a byte-prefix of its descendants and
/// `CanBePrefix` lookups are prefix scans.
#[cfg(feature = "named")]
mod named {
    use super::{Backend, Bytes, async_trait};
    use ndn_packet::Name;
    use std::sync::Arc;

    /// Encode a [`Name`] to a storage key: its component TLVs (the NAME value,
    /// without the outer `0x07` header). NDN canonical component order is preserved
    /// byte-for-byte, so `name_key(parent)` is a prefix of `name_key(child)`.
    pub fn name_key(name: &Name) -> Vec<u8> {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
        w.finish().to_vec()
    }

    /// Object-safe **read** facet of a name→wire store — the narrow contract any data
    /// model (the surface tier; NDF's BlockStore via `get_by_name`) exposes to join
    /// the name-addressed data plane.
    #[async_trait]
    pub trait NamedReadStore: Send + Sync {
        async fn get(&self, name: &Name) -> Option<Bytes>;
        async fn find_under(&self, prefix: &Name) -> Option<Bytes>;
        async fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Bytes, Bytes)>;
    }

    /// Object-safe **write** facet (write-behind retention + eviction).
    #[async_trait]
    pub trait NamedWriteStore: NamedReadStore {
        async fn insert(&self, name: &Name, wire: Bytes);
        async fn remove(&self, name: &Name);
    }

    /// Name → wire Data store over a pluggable [`Backend`]. `NamedStore<FjallBackend>`
    /// is a persistent repo; `NamedStore<MemoryBackend>` an in-process content store.
    pub struct NamedStore<B> {
        backend: B,
    }

    impl<B: Backend> NamedStore<B> {
        pub fn new(backend: B) -> Self {
            Self { backend }
        }
        pub fn backend(&self) -> &B {
            &self.backend
        }
        pub async fn insert(&self, name: &Name, wire: Bytes) {
            self.backend.put(name_key(name), wire).await;
        }
        pub async fn get(&self, name: &Name) -> Option<Bytes> {
            self.backend.get(name_key(name)).await
        }
        pub async fn remove(&self, name: &Name) {
            self.backend.delete(name_key(name)).await;
        }
        pub async fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            self.backend.first_under(name_key(prefix)).await.map(|(_, v)| v)
        }
        pub async fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Bytes, Bytes)> {
            self.backend.scan_prefix(name_key(prefix), limit).await
        }
    }

    #[async_trait]
    impl<B: Backend> NamedReadStore for NamedStore<B> {
        async fn get(&self, name: &Name) -> Option<Bytes> {
            NamedStore::get(self, name).await
        }
        async fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            NamedStore::find_under(self, prefix).await
        }
        async fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Bytes, Bytes)> {
            NamedStore::scan_under(self, prefix, limit).await
        }
    }

    #[async_trait]
    impl<B: Backend> NamedWriteStore for NamedStore<B> {
        async fn insert(&self, name: &Name, wire: Bytes) {
            NamedStore::insert(self, name, wire).await
        }
        async fn remove(&self, name: &Name) {
            NamedStore::remove(self, name).await
        }
    }

    /// Layer 2: route names to **different stores by name prefix** — "different data,
    /// different backend". Longest-prefix match wins; an optional default catches the
    /// rest. Itself a `NamedReadStore`/`NamedWriteStore`, so it composes anywhere a
    /// single store does.
    #[derive(Default)]
    pub struct StoreRouter {
        routes: Vec<(Vec<u8>, Arc<dyn NamedWriteStore>)>,
        fallback: Option<Arc<dyn NamedWriteStore>>,
    }

    impl StoreRouter {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn route(mut self, prefix: &Name, store: Arc<dyn NamedWriteStore>) -> Self {
            self.routes.push((name_key(prefix), store));
            self
        }
        pub fn with_default(mut self, store: Arc<dyn NamedWriteStore>) -> Self {
            self.fallback = Some(store);
            self
        }
        fn pick(&self, name: &Name) -> Option<&Arc<dyn NamedWriteStore>> {
            let key = name_key(name);
            let mut best: Option<&(Vec<u8>, Arc<dyn NamedWriteStore>)> = None;
            for r in &self.routes {
                if key.starts_with(&r.0) && best.is_none_or(|b| r.0.len() > b.0.len()) {
                    best = Some(r);
                }
            }
            best.map(|r| &r.1).or(self.fallback.as_ref())
        }
    }

    #[async_trait]
    impl NamedReadStore for StoreRouter {
        async fn get(&self, name: &Name) -> Option<Bytes> {
            match self.pick(name) {
                Some(s) => s.get(name).await,
                None => None,
            }
        }
        async fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            match self.pick(prefix) {
                Some(s) => s.find_under(prefix).await,
                None => None,
            }
        }
        async fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Bytes, Bytes)> {
            match self.pick(prefix) {
                Some(s) => s.scan_under(prefix, limit).await,
                None => Vec::new(),
            }
        }
    }

    #[async_trait]
    impl NamedWriteStore for StoreRouter {
        async fn insert(&self, name: &Name, wire: Bytes) {
            if let Some(s) = self.pick(name) {
                s.insert(name, wire).await;
            }
        }
        async fn remove(&self, name: &Name) {
            if let Some(s) = self.pick(name) {
                s.remove(name).await;
            }
        }
    }
}

#[cfg(feature = "fjall")]
pub use fjall_backend::FjallBackend;

#[cfg(feature = "fjall")]
mod fjall_backend {
    use super::{Backend, Bytes, async_trait};

    /// On-disk [`Backend`] backed by [fjall](https://docs.rs/fjall) (an LSM
    /// key-value store). Persistent across restarts. The single fjall adapter every
    /// model shares. Each blocking fjall op runs inside `spawn_blocking` so it never
    /// stalls the async runtime — the offload is centralized here, not at call sites.
    pub struct FjallBackend {
        keyspace: fjall::Keyspace,
        #[allow(dead_code)]
        db: fjall::Database,
    }

    impl FjallBackend {
        pub fn open(path: impl AsRef<std::path::Path>) -> fjall::Result<Self> {
            Self::open_keyspace(path, "ndn")
        }
        pub fn open_keyspace(
            path: impl AsRef<std::path::Path>,
            keyspace: &str,
        ) -> fjall::Result<Self> {
            let db = fjall::Database::builder(path).open()?;
            let keyspace = db.keyspace(keyspace, fjall::KeyspaceCreateOptions::default)?;
            Ok(Self { keyspace, db })
        }
    }

    #[async_trait]
    impl Backend for FjallBackend {
        async fn get(&self, key: Vec<u8>) -> Option<Bytes> {
            let ks = self.keyspace.clone();
            tokio::task::spawn_blocking(move || {
                ks.get(&key).ok().flatten().map(|s| Bytes::copy_from_slice(&s))
            })
            .await
            .ok()
            .flatten()
        }
        async fn put(&self, key: Vec<u8>, value: Bytes) {
            let ks = self.keyspace.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = ks.insert(&key, value.as_ref());
            })
            .await;
        }
        async fn delete(&self, key: Vec<u8>) {
            let ks = self.keyspace.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let _ = ks.remove(&key);
            })
            .await;
        }
        async fn scan_prefix(&self, prefix: Vec<u8>, limit: usize) -> Vec<(Bytes, Bytes)> {
            let ks = self.keyspace.clone();
            tokio::task::spawn_blocking(move || {
                let mut out = Vec::new();
                for guard in ks.prefix(&prefix) {
                    match guard.into_inner() {
                        Ok((k, v)) => {
                            out.push((Bytes::copy_from_slice(&k), Bytes::copy_from_slice(&v)));
                            if limit != 0 && out.len() >= limit {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                out
            })
            .await
            .unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn conformance(b: &dyn Backend) {
        assert!(b.get(b"missing".to_vec()).await.is_none());
        b.put(b"/a/b".to_vec(), Bytes::from_static(b"v-ab")).await;
        b.put(b"/a/b/c".to_vec(), Bytes::from_static(b"v-abc")).await;
        b.put(b"/a/d".to_vec(), Bytes::from_static(b"v-ad")).await;
        b.put(b"/z".to_vec(), Bytes::from_static(b"v-z")).await;

        assert_eq!(b.get(b"/a/b".to_vec()).await.as_deref(), Some(&b"v-ab"[..]));
        assert_eq!(b.first_under(b"/a/b".to_vec()).await.unwrap().0.as_ref(), b"/a/b");
        assert_eq!(b.first_under(b"/a/d".to_vec()).await.unwrap().1.as_ref(), b"v-ad");
        assert!(b.first_under(b"/nope".to_vec()).await.is_none());

        let under: Vec<String> = b
            .scan_prefix(b"/a".to_vec(), 0)
            .await
            .into_iter()
            .map(|(k, _)| String::from_utf8_lossy(&k).into_owned())
            .collect();
        assert_eq!(under, vec!["/a/b", "/a/b/c", "/a/d"]); // ascending, /z excluded

        assert_eq!(b.scan_prefix(b"/a".to_vec(), 1).await.len(), 1); // limit

        b.delete(b"/a/b".to_vec()).await;
        assert!(b.get(b"/a/b".to_vec()).await.is_none());
        assert_eq!(b.get(b"/a/b/c".to_vec()).await.as_deref(), Some(&b"v-abc"[..]));
    }

    #[tokio::test]
    async fn memory_backend_conformance() {
        conformance(&MemoryBackend::new()).await;
    }

    #[cfg(feature = "named")]
    #[tokio::test]
    async fn named_store_over_backend() {
        use ndn_packet::Name;
        let s = NamedStore::new(MemoryBackend::new());
        let n: Name = "/app/surface".parse().unwrap();
        let v0: Name = "/app/surface/v=0".parse().unwrap();
        let v1: Name = "/app/surface/v=1".parse().unwrap();

        s.insert(&v0, Bytes::from_static(b"frame0")).await;
        s.insert(&v1, Bytes::from_static(b"frame1")).await;
        assert_eq!(s.get(&v0).await.as_deref(), Some(&b"frame0"[..]));
        assert_eq!(s.find_under(&n).await.as_deref(), Some(&b"frame0"[..]));
        assert!(name_key(&v0).starts_with(&name_key(&n)));
        assert_eq!(s.scan_under(&n, 0).await.len(), 2);

        s.remove(&v0).await;
        assert!(s.get(&v0).await.is_none());
        assert_eq!(s.get(&v1).await.as_deref(), Some(&b"frame1"[..]));
    }

    #[cfg(feature = "named")]
    #[tokio::test]
    async fn store_router_dispatches_by_prefix() {
        use ndn_packet::Name;
        use std::sync::Arc;
        let a: Arc<dyn NamedWriteStore> = Arc::new(NamedStore::new(MemoryBackend::new()));
        let b: Arc<dyn NamedWriteStore> = Arc::new(NamedStore::new(MemoryBackend::new()));
        let d: Arc<dyn NamedWriteStore> = Arc::new(NamedStore::new(MemoryBackend::new()));
        let router = StoreRouter::new()
            .route(&"/a".parse::<Name>().unwrap(), a.clone())
            .route(&"/b".parse::<Name>().unwrap(), b.clone())
            .with_default(d.clone());

        let na: Name = "/a/x".parse().unwrap();
        let nc: Name = "/c/z".parse().unwrap();
        router.insert(&na, Bytes::from_static(b"A")).await;
        router.insert(&nc, Bytes::from_static(b"C")).await;
        assert_eq!(a.get(&na).await.as_deref(), Some(&b"A"[..]));
        assert!(b.get(&na).await.is_none());
        assert_eq!(d.get(&nc).await.as_deref(), Some(&b"C"[..])); // default
        assert_eq!(router.get(&na).await.as_deref(), Some(&b"A"[..]));
    }

    #[cfg(feature = "fjall")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fjall_backend_conformance_and_persistence() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ndn-storage-test-{}-{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let b = FjallBackend::open(&dir).unwrap();
            conformance(&b).await;
            b.put(b"/persist".to_vec(), Bytes::from_static(b"survives")).await;
        }
        {
            let b = FjallBackend::open(&dir).unwrap();
            assert_eq!(b.get(b"/persist".to_vec()).await.as_deref(), Some(&b"survives"[..]));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
