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
