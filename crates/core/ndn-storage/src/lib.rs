//! **Pluggable storage engine** — an ordered byte key→value [`Backend`].
//!
//! This is *Layer 0* of the storage stack: domain-agnostic ordered bytes, no NDN
//! names and no blocks. Data-model layers build **on** a `Backend`:
//!
//! - the named-data store (name→wire CS/Repo) — `ndn-repo` / `ndn-sync`,
//! - a content-addressed blob store (CID→bytes) — for FLIC manifests / dedup,
//! - NDF's `BlockStore` (content-addressed chains) — in `ndf-rs`.
//!
//! Separating the *engine* from the *data model* is what lets one fjall (or
//! in-memory, or object-store) adapter be written **once** and reused by every
//! model — instead of each store binding its own engine (the redundancy this
//! crate removes). Mirrors `object_store` (engine) vs Delta/Lance (models), and
//! IPFS's generic `Datastore` under its content-addressed `Blockstore`.
//!
//! The trait is **object-safe** (usable as `Arc<dyn Backend>`) and synchronous —
//! LSM engines are sync; async callers wrap a call in `spawn_blocking`.

use bytes::Bytes;

/// An ordered byte key→value store. Keys sort lexicographically, so a parent
/// byte-prefix precedes all its descendants — which makes prefix/range scans the
/// primitive for "CanBePrefix" lookups and "last-N under a name".
pub trait Backend: Send + Sync {
    /// Fetch the value stored under `key`.
    fn get(&self, key: &[u8]) -> Option<Bytes>;

    /// Store `value` under `key` (overwriting any existing value).
    fn put(&self, key: &[u8], value: Bytes);

    /// Remove `key` if present.
    fn delete(&self, key: &[u8]);

    /// Visit `(key, value)` pairs whose key starts with `prefix`, in ascending key
    /// order, calling `f` for each until it returns `false`. Callback form (not
    /// `impl Iterator`) so the trait stays object-safe.
    fn scan_prefix(&self, prefix: &[u8], f: &mut dyn FnMut(&[u8], &[u8]) -> bool);

    /// The lexicographically-smallest `(key, value)` whose key starts with
    /// `prefix` — the answer to a `CanBePrefix` lookup. Default: first of
    /// [`scan_prefix`](Self::scan_prefix).
    fn first_under(&self, prefix: &[u8]) -> Option<(Bytes, Bytes)> {
        let mut out = None;
        self.scan_prefix(prefix, &mut |k, v| {
            out = Some((Bytes::copy_from_slice(k), Bytes::copy_from_slice(v)));
            false // stop after the first match
        });
        out
    }
}

/// In-memory [`Backend`] (a `BTreeMap` behind an `RwLock`). The default for tests,
/// browser/wasm, and process-lifetime data.
#[derive(Default)]
pub struct MemoryBackend {
    map: std::sync::RwLock<std::collections::BTreeMap<Vec<u8>, Bytes>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.map.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.read().unwrap().is_empty()
    }
}

impl Backend for MemoryBackend {
    fn get(&self, key: &[u8]) -> Option<Bytes> {
        self.map.read().unwrap().get(key).cloned()
    }

    fn put(&self, key: &[u8], value: Bytes) {
        self.map.write().unwrap().insert(key.to_vec(), value);
    }

    fn delete(&self, key: &[u8]) {
        self.map.write().unwrap().remove(key);
    }

    fn scan_prefix(&self, prefix: &[u8], f: &mut dyn FnMut(&[u8], &[u8]) -> bool) {
        let map = self.map.read().unwrap();
        for (k, v) in map.range(prefix.to_vec()..) {
            if !k.starts_with(prefix) {
                break;
            }
            if !f(k, v) {
                break;
            }
        }
    }
}

#[cfg(feature = "named")]
pub use named::{NamedReadStore, NamedStore, NamedWriteStore, StoreRouter, name_key};

/// Layer 1: a name→wire store over any [`Backend`] (the CS/Repo model). Keys are
/// NDN component-TLVs, so a parent name is a byte-prefix of its descendants and
/// `CanBePrefix` lookups are prefix scans.
#[cfg(feature = "named")]
mod named {
    use super::{Backend, Bytes};
    use ndn_packet::Name;

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

    /// Object-safe **read** facet of a name→wire store — the narrow contract any
    /// data model (the surface tier, NDF's BlockStore via `get_by_name`) exposes to
    /// join the name-addressed data plane.
    pub trait NamedReadStore: Send + Sync {
        fn get(&self, name: &Name) -> Option<Bytes>;
        fn find_under(&self, prefix: &Name) -> Option<Bytes>;
        fn scan_under(&self, prefix: &Name, f: &mut dyn FnMut(&[u8], &[u8]) -> bool);
    }

    /// Object-safe **write** facet (write-behind retention).
    pub trait NamedWriteStore: NamedReadStore {
        fn insert(&self, name: &Name, wire: Bytes);
    }

    impl<B: Backend> NamedReadStore for NamedStore<B> {
        fn get(&self, name: &Name) -> Option<Bytes> {
            NamedStore::get(self, name)
        }
        fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            NamedStore::find_under(self, prefix)
        }
        fn scan_under(&self, prefix: &Name, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) {
            NamedStore::scan_under(self, prefix, f)
        }
    }

    impl<B: Backend> NamedWriteStore for NamedStore<B> {
        fn insert(&self, name: &Name, wire: Bytes) {
            NamedStore::insert(self, name, wire)
        }
    }

    use std::sync::Arc;

    /// Layer 2: route names to **different stores by name prefix** — "different data,
    /// different backend" (a hot fjall store for one namespace, an object-store for
    /// big objects, NDF's BlockStore-facet for `/…/blocks/…`, etc.). Longest-prefix
    /// match wins; an optional default catches the rest. Is itself a
    /// `NamedReadStore`/`NamedWriteStore`, so it composes anywhere a single store does.
    #[derive(Default)]
    pub struct StoreRouter {
        routes: Vec<(Vec<u8>, Arc<dyn NamedWriteStore>)>,
        fallback: Option<Arc<dyn NamedWriteStore>>,
    }

    impl StoreRouter {
        pub fn new() -> Self {
            Self::default()
        }
        /// Route names under `prefix` to `store` (longest matching prefix wins).
        pub fn route(mut self, prefix: &Name, store: Arc<dyn NamedWriteStore>) -> Self {
            self.routes.push((name_key(prefix), store));
            self
        }
        /// Store for names matching no route.
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

    impl NamedReadStore for StoreRouter {
        fn get(&self, name: &Name) -> Option<Bytes> {
            self.pick(name)?.get(name)
        }
        fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            self.pick(prefix)?.find_under(prefix)
        }
        fn scan_under(&self, prefix: &Name, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) {
            if let Some(s) = self.pick(prefix) {
                s.scan_under(prefix, f);
            }
        }
    }

    impl NamedWriteStore for StoreRouter {
        fn insert(&self, name: &Name, wire: Bytes) {
            if let Some(s) = self.pick(name) {
                s.insert(name, wire);
            }
        }
    }

    /// Name → wire Data store over a pluggable [`Backend`]. `NamedStore<FjallBackend>`
    /// is a persistent repo; `NamedStore<MemoryBackend>` an in-process content store.
    /// (Inherent API mirrors the legacy `DataStore` trait, so a bridge impl is a few
    /// lines when unifying `ndn-repo`/`ndn-sync`.)
    pub struct NamedStore<B> {
        backend: B,
    }

    impl<B: Backend> NamedStore<B> {
        pub fn new(backend: B) -> Self {
            Self { backend }
        }
        /// The underlying engine (e.g. to share a DB across stores).
        pub fn backend(&self) -> &B {
            &self.backend
        }
        /// Store the encoded Data `wire` under `name`.
        pub fn insert(&self, name: &Name, wire: Bytes) {
            self.backend.put(&name_key(name), wire);
        }
        /// Fetch the Data wire stored under `name`.
        pub fn get(&self, name: &Name) -> Option<Bytes> {
            self.backend.get(&name_key(name))
        }
        /// Remove `name` if present.
        pub fn remove(&self, name: &Name) {
            self.backend.delete(&name_key(name));
        }
        /// The lexicographically-smallest stored Data whose name has `prefix` as a
        /// prefix — the answer to a `CanBePrefix` Interest.
        pub fn find_under(&self, prefix: &Name) -> Option<Bytes> {
            self.backend.first_under(&name_key(prefix)).map(|(_k, v)| v)
        }
        /// Visit `(name_key, wire)` under `prefix` in ascending name order, until
        /// `f` returns `false` — for "last-N"/range fetches (callers decode the key
        /// to a Name if needed). Keys are component-TLVs, not a full NAME TLV.
        pub fn scan_under(&self, prefix: &Name, f: &mut dyn FnMut(&[u8], &[u8]) -> bool) {
            self.backend.scan_prefix(&name_key(prefix), f);
        }
    }
}

#[cfg(feature = "fjall")]
pub use fjall_backend::FjallBackend;

#[cfg(feature = "fjall")]
mod fjall_backend {
    use super::{Backend, Bytes};

    /// On-disk [`Backend`] backed by [fjall](https://docs.rs/fjall) (an LSM
    /// key-value store). Persistent across process restarts. This is the single
    /// fjall adapter every named/blob/block model can share, rather than each
    /// binding fjall itself.
    pub struct FjallBackend {
        keyspace: fjall::Keyspace,
        #[allow(dead_code)] // keeps the database open for the keyspace's lifetime
        db: fjall::Database,
    }

    impl FjallBackend {
        /// Open (or create) a backend rooted at `path`, in the default `ndn`
        /// keyspace.
        pub fn open(path: impl AsRef<std::path::Path>) -> fjall::Result<Self> {
            Self::open_keyspace(path, "ndn")
        }

        /// Open (or create) a backend at `path` using the named keyspace — so
        /// distinct data models (names, blobs, blocks) can share one database file
        /// in separate keyspaces.
        pub fn open_keyspace(
            path: impl AsRef<std::path::Path>,
            keyspace: &str,
        ) -> fjall::Result<Self> {
            let db = fjall::Database::builder(path).open()?;
            let keyspace = db.keyspace(keyspace, fjall::KeyspaceCreateOptions::default)?;
            Ok(Self { keyspace, db })
        }
    }

    impl Backend for FjallBackend {
        fn get(&self, key: &[u8]) -> Option<Bytes> {
            let slice = self.keyspace.get(key).ok()??;
            Some(Bytes::copy_from_slice(&slice))
        }

        fn put(&self, key: &[u8], value: Bytes) {
            let _ = self.keyspace.insert(key, value.as_ref());
        }

        fn delete(&self, key: &[u8]) {
            let _ = self.keyspace.remove(key);
        }

        fn scan_prefix(&self, prefix: &[u8], f: &mut dyn FnMut(&[u8], &[u8]) -> bool) {
            for guard in self.keyspace.prefix(prefix) {
                match guard.into_inner() {
                    Ok((k, v)) => {
                        if !f(&k, &v) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance suite run against any backend.
    fn conformance(b: &dyn Backend) {
        assert!(b.get(b"missing").is_none());
        b.put(b"/a/b", Bytes::from_static(b"v-ab"));
        b.put(b"/a/b/c", Bytes::from_static(b"v-abc"));
        b.put(b"/a/d", Bytes::from_static(b"v-ad"));
        b.put(b"/z", Bytes::from_static(b"v-z"));

        assert_eq!(b.get(b"/a/b").as_deref(), Some(&b"v-ab"[..]));
        assert_eq!(b.get(b"/a/b/c").as_deref(), Some(&b"v-abc"[..]));

        // first_under = smallest key with the prefix (CanBePrefix).
        assert_eq!(b.first_under(b"/a/b").unwrap().0.as_ref(), b"/a/b");
        assert_eq!(b.first_under(b"/a/d").unwrap().1.as_ref(), b"v-ad");
        assert!(b.first_under(b"/nope").is_none());

        // scan_prefix yields ascending, prefix-bounded.
        let mut keys = Vec::new();
        b.scan_prefix(b"/a", &mut |k, _| {
            keys.push(String::from_utf8_lossy(k).into_owned());
            true
        });
        assert_eq!(keys, vec!["/a/b", "/a/b/c", "/a/d"]); // /z excluded, ascending

        // early stop.
        let mut n = 0;
        b.scan_prefix(b"/a", &mut |_, _| {
            n += 1;
            false
        });
        assert_eq!(n, 1);

        // delete.
        b.delete(b"/a/b");
        assert!(b.get(b"/a/b").is_none());
        assert_eq!(b.get(b"/a/b/c").as_deref(), Some(&b"v-abc"[..])); // sibling intact
    }

    #[test]
    fn memory_backend_conformance() {
        conformance(&MemoryBackend::new());
    }

    #[cfg(feature = "named")]
    #[test]
    fn named_store_over_backend() {
        use ndn_packet::Name;
        let s = NamedStore::new(MemoryBackend::new());
        let n: Name = "/app/surface".parse().unwrap();
        let v0: Name = "/app/surface/v=0".parse().unwrap();
        let v1: Name = "/app/surface/v=1".parse().unwrap();

        s.insert(&v0, Bytes::from_static(b"frame0"));
        s.insert(&v1, Bytes::from_static(b"frame1"));
        assert_eq!(s.get(&v0).as_deref(), Some(&b"frame0"[..]));

        // CanBePrefix: smallest under the surface prefix is v=0.
        assert_eq!(s.find_under(&n).as_deref(), Some(&b"frame0"[..]));

        // parent key is a byte-prefix of the child (range-scannable).
        assert!(name_key(&v0).starts_with(&name_key(&n)));

        // scan under the prefix yields both versions in order.
        let mut count = 0;
        s.scan_under(&n, &mut |_, _| {
            count += 1;
            true
        });
        assert_eq!(count, 2);

        s.remove(&v0);
        assert!(s.get(&v0).is_none());
        assert_eq!(s.get(&v1).as_deref(), Some(&b"frame1"[..]));
    }

    #[cfg(feature = "named")]
    #[test]
    fn store_router_dispatches_by_prefix() {
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
        let nb: Name = "/b/y".parse().unwrap();
        let nc: Name = "/c/z".parse().unwrap();
        router.insert(&na, Bytes::from_static(b"A"));
        router.insert(&nb, Bytes::from_static(b"B"));
        router.insert(&nc, Bytes::from_static(b"C"));

        // Each landed in the right backend, and only there.
        assert_eq!(a.get(&na).as_deref(), Some(&b"A"[..]));
        assert!(b.get(&na).is_none());
        assert_eq!(b.get(&nb).as_deref(), Some(&b"B"[..]));
        assert_eq!(d.get(&nc).as_deref(), Some(&b"C"[..])); // default
        assert!(a.get(&nc).is_none());

        // Reads route the same way.
        assert_eq!(router.get(&na).as_deref(), Some(&b"A"[..]));
        assert_eq!(router.get(&nc).as_deref(), Some(&b"C"[..]));
    }

    #[cfg(feature = "fjall")]
    #[test]
    fn fjall_backend_conformance_and_persistence() {
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
            conformance(&b);
            // Re-stamp a known key to check persistence after reopen.
            b.put(b"/persist", Bytes::from_static(b"survives"));
        }
        {
            let b = FjallBackend::open(&dir).unwrap();
            assert_eq!(
                b.get(b"/persist").as_deref(),
                Some(&b"survives"[..]),
                "value must survive reopen"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
