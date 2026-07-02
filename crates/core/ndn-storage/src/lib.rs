//! **Pluggable async storage engine** — an ordered byte key→value [`Backend`].
//!
//! *Layer 0* of the storage stack: domain-agnostic ordered bytes, no NDN names and
//! no blocks. Data-model layers build **on** a `Backend`:
//!
//! - the named-data store (name→wire CS/Repo) — `NamedStore` here / `ndn-repo`,
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
//!
//! # The synchronous facet (F21)
//!
//! [`SyncBackend`] is the **local sync core**: `get`/`put`/`delete`/`scan_prefix` and a
//! batch, all *synchronous*. fjall and redb are blocking underneath, so they implement
//! it directly; the async [`Backend`] above is then a thin `spawn_blocking` wrapper over
//! the same core (one source of truth). This is what lets a **synchronous** consumer —
//! NDF's `BlockStore`, driven by the *pure* AC.12 verifier — use the store without
//! threading `await` through pure logic or `block_on`-panicking inside an async context.
//! Genuinely-async engines (an S3 cold tier) don't live *under* such a model; they
//! belong at the `StoreRouter`/tier-resolver layer above it.
//!
//! ## `no_std` (embedded)
//!
//! `SyncBackend` is `no_std + alloc`. With `--no-default-features --features sync` the
//! crate drops the async surface (which needs tokio/`std::sync`) and keeps the sync
//! core plus the in-memory `SyncMemoryBackend` (a `critical-section` mutex) — the
//! storage floor for an MCU. A flash engine (`sequential-storage`/`ekv` over
//! `embedded-storage`) is just another `SyncBackend`. On `std`, [`SyncAsAsync`] bridges
//! any `SyncBackend` into the async [`Backend`] so a sync engine composes with the
//! named layer.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use bytes::Bytes;

#[cfg(feature = "std")]
use async_trait::async_trait;

// The synchronous core is always available (it underpins the async engines and the
// embedded path); the in-memory engine + async bridge are feature-gated.
#[cfg(feature = "std")]
pub use sync::SyncAsAsync;
pub use sync::SyncBackend;
#[cfg(feature = "sync")]
pub use sync::SyncMemoryBackend;

// Embedded flash engine (generic over `embedded-storage::NorFlash`).
#[cfg(feature = "flash")]
mod flash;
#[cfg(feature = "flash")]
pub use flash::{FlashError, FlashLogBackend};

/// One operation in an atomic [`Backend::write_batch`] / [`SyncBackend::write_batch`].
#[derive(Clone, Debug)]
pub enum WriteOp {
    Put(Vec<u8>, Bytes),
    Delete(Vec<u8>),
}

/// A storage-engine failure. Returned by every fallible [`Backend`]/[`SyncBackend`]
/// operation so a real engine error (disk I/O, a failed transaction, exhausted flash)
/// is **surfaced** to the caller rather than silently collapsing into "miss" / "no-op".
/// A genuine absence is `Ok(None)` — only an actual fault is `Err`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The underlying engine failed; carries its diagnostic message.
    Backend(alloc::string::String),
}

impl StorageError {
    /// Wrap an engine error (anything `Display`) as a [`StorageError::Backend`].
    pub fn backend(e: impl core::fmt::Display) -> Self {
        use alloc::string::ToString;
        StorageError::Backend(e.to_string())
    }
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StorageError::Backend(m) => write!(f, "storage backend error: {m}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StorageError {}

/// Result of a fallible storage operation.
pub type StorageResult<T> = core::result::Result<T, StorageError>;

/// An ordered byte key→value store. Keys sort lexicographically, so a parent
/// byte-prefix precedes all its descendants — making prefix/range scans the
/// primitive for "CanBePrefix" lookups and "last-N under a name".
#[cfg(feature = "std")]
#[async_trait]
pub trait Backend: Send + Sync {
    /// Fetch the value stored under `key`. `Ok(None)` is a genuine miss; `Err` is an
    /// engine failure (the two are no longer conflated).
    async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>>;

    /// Store `value` under `key` (overwriting any existing value).
    async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()>;

    /// Remove `key` if present.
    async fn delete(&self, key: Vec<u8>) -> StorageResult<()>;

    /// `(key, value)` pairs whose key starts with `prefix`, in ascending key order,
    /// at most `limit` (0 = unlimited). Owned, so the result moves cleanly across a
    /// `spawn_blocking` boundary.
    async fn scan_prefix(
        &self,
        prefix: Vec<u8>,
        limit: usize,
    ) -> StorageResult<Vec<(Bytes, Bytes)>>;

    /// The lexicographically-smallest `(key, value)` whose key starts with `prefix`
    /// (a `CanBePrefix` lookup). Default: first of [`scan_prefix`](Self::scan_prefix).
    async fn first_under(&self, prefix: Vec<u8>) -> StorageResult<Option<(Bytes, Bytes)>> {
        Ok(self.scan_prefix(prefix, 1).await?.into_iter().next())
    }

    /// Apply all `ops` **atomically** (all-or-nothing) and amortize the durability
    /// cost across them. The default applies them sequentially — **not** atomic;
    /// engines with a native batch/transaction (`MemoryBackend`, `FjallBackend`,
    /// `RedbBackend`) override this for real atomicity. Also the efficient path for
    /// bulk/write-behind flushing.
    async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
        for op in ops {
            match op {
                WriteOp::Put(k, v) => self.put(k, v).await?,
                WriteOp::Delete(k) => self.delete(k).await?,
            }
        }
        Ok(())
    }

    /// Short, low-cardinality engine label (`"memory"` / `"fjall"` / `"redb"`) for
    /// telemetry. Used by [`Instrumented`] as a span field; never on a hot path.
    fn name(&self) -> &'static str {
        "backend"
    }
}

/// In-memory [`Backend`] (a `BTreeMap` behind an `RwLock`). The default for tests,
/// browser/wasm, and process-lifetime data. Its async methods complete immediately
/// (no thread hop). For `no_std`/embedded use `SyncMemoryBackend` instead.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct MemoryBackend {
    map: std::sync::RwLock<std::collections::BTreeMap<Vec<u8>, Bytes>>,
}

#[cfg(feature = "std")]
impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
    pub fn is_empty(&self) -> bool {
        self.map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }
}

#[cfg(feature = "std")]
#[async_trait]
impl Backend for MemoryBackend {
    async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
        Ok(self
            .map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned())
    }
    async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()> {
        self.map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, value);
        Ok(())
    }
    async fn delete(&self, key: Vec<u8>) -> StorageResult<()> {
        self.map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
        Ok(())
    }
    async fn scan_prefix(
        &self,
        prefix: Vec<u8>,
        limit: usize,
    ) -> StorageResult<Vec<(Bytes, Bytes)>> {
        let map = self
            .map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        Ok(out)
    }
    async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
        // Atomic: one lock for the whole batch.
        let mut map = self
            .map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for op in ops {
            match op {
                WriteOp::Put(k, v) => {
                    map.insert(k, v);
                }
                WriteOp::Delete(k) => {
                    map.remove(&k);
                }
            }
        }
        Ok(())
    }
    fn name(&self) -> &'static str {
        "memory"
    }
}

/// A [`Backend`] **decorator** that emits a `tracing` span per operation — the
/// observability seam for the storage tier. Wrapping is opt-in and zero-cost when
/// absent (an unwrapped engine emits nothing): `Instrumented::new(FjallBackend::open(p)?)`.
///
/// It only uses the `tracing` *facade* — no exporter, no metrics crate, nothing
/// wasm-hostile. A **binary** that wants OpenTelemetry adds `tracing-opentelemetry`
/// plus an OTLP layer to its subscriber and every storage span exports to a collector
/// with no change here (libraries emit spans; binaries own subscriber init). Spans:
/// `ndn_storage.{get,put,delete,scan_prefix,first_under,write_batch}` at TRACE, with
/// `backend`, key/prefix length, byte counts, hit/miss, op/result counts — let the
/// OTel layer derive latency histograms from span durations.
///
/// Because it sits at Layer 0 it instruments **every** consumer uniformly: the named
/// surface path *and* NDF's direct `Backend` use.
#[cfg(feature = "std")]
pub struct Instrumented<B> {
    inner: B,
}

#[cfg(feature = "std")]
impl<B: Backend> Instrumented<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }
    /// Borrow the wrapped engine.
    pub fn inner(&self) -> &B {
        &self.inner
    }
    /// Unwrap, dropping instrumentation.
    pub fn into_inner(self) -> B {
        self.inner
    }
}

#[cfg(feature = "std")]
#[async_trait]
impl<B: Backend> Backend for Instrumented<B> {
    async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
        use tracing::{Instrument, field::Empty};
        let span = tracing::trace_span!(
            "ndn_storage.get",
            backend = self.inner.name(),
            key_len = key.len(),
            hit = Empty,
            bytes = Empty,
            error = Empty,
        );
        async {
            let r = self.inner.get(key).await;
            let s = tracing::Span::current();
            match &r {
                Ok(v) => {
                    s.record("hit", v.is_some());
                    if let Some(b) = v {
                        s.record("bytes", b.len());
                    }
                }
                Err(e) => {
                    s.record("error", tracing::field::display(e));
                }
            }
            r
        }
        .instrument(span)
        .await
    }
    async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()> {
        use tracing::Instrument;
        let span = tracing::trace_span!(
            "ndn_storage.put",
            backend = self.inner.name(),
            key_len = key.len(),
            bytes = value.len(),
        );
        self.inner.put(key, value).instrument(span).await
    }
    async fn delete(&self, key: Vec<u8>) -> StorageResult<()> {
        use tracing::Instrument;
        let span = tracing::trace_span!(
            "ndn_storage.delete",
            backend = self.inner.name(),
            key_len = key.len(),
        );
        self.inner.delete(key).instrument(span).await
    }
    async fn scan_prefix(
        &self,
        prefix: Vec<u8>,
        limit: usize,
    ) -> StorageResult<Vec<(Bytes, Bytes)>> {
        use tracing::{Instrument, field::Empty};
        let span = tracing::trace_span!(
            "ndn_storage.scan_prefix",
            backend = self.inner.name(),
            prefix_len = prefix.len(),
            limit,
            count = Empty,
            bytes = Empty,
            error = Empty,
        );
        async {
            let r = self.inner.scan_prefix(prefix, limit).await;
            let s = tracing::Span::current();
            match &r {
                Ok(rows) => {
                    s.record("count", rows.len());
                    s.record("bytes", rows.iter().map(|(_, v)| v.len()).sum::<usize>());
                }
                Err(e) => {
                    s.record("error", tracing::field::display(e));
                }
            }
            r
        }
        .instrument(span)
        .await
    }
    async fn first_under(&self, prefix: Vec<u8>) -> StorageResult<Option<(Bytes, Bytes)>> {
        use tracing::{Instrument, field::Empty};
        let span = tracing::trace_span!(
            "ndn_storage.first_under",
            backend = self.inner.name(),
            prefix_len = prefix.len(),
            hit = Empty,
        );
        async {
            let r = self.inner.first_under(prefix).await;
            if let Ok(v) = &r {
                tracing::Span::current().record("hit", v.is_some());
            }
            r
        }
        .instrument(span)
        .await
    }
    async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
        use tracing::Instrument;
        let (mut puts, mut dels, mut bytes) = (0usize, 0usize, 0usize);
        for op in &ops {
            match op {
                WriteOp::Put(_, v) => {
                    puts += 1;
                    bytes += v.len();
                }
                WriteOp::Delete(_) => dels += 1,
            }
        }
        let span = tracing::trace_span!(
            "ndn_storage.write_batch",
            backend = self.inner.name(),
            ops = ops.len(),
            puts,
            deletes = dels,
            bytes,
        );
        self.inner.write_batch(ops).instrument(span).await
    }
    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

/// The synchronous storage core (F21). Always available — `no_std + alloc`, no async,
/// no tokio — so it can underpin both the async engines (which wrap it in
/// `spawn_blocking`) and an embedded MCU (no thread pool, no `std::sync`).
mod sync {
    use super::{Bytes, Vec, WriteOp};

    /// An ordered byte key→value store, **synchronous**. The local sync core: fjall
    /// and redb implement this directly (they block underneath), and the async
    /// [`Backend`](super::Backend) is a thin `spawn_blocking` wrapper over it. A
    /// synchronous consumer (NDF's `BlockStore`, driven by the pure verifier) uses
    /// this without any async runtime; an embedded engine implements the same trait.
    ///
    /// Keys are **borrowed** (`&[u8]`) — there is no thread-hop boundary to own them
    /// across, so the sync core avoids the per-call allocation the async trait needs.
    use super::StorageResult;

    pub trait SyncBackend: Send + Sync {
        /// Fetch the value stored under `key`. `Ok(None)` is a genuine miss; `Err` is an
        /// engine failure.
        fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;
        /// Store `value` under `key` (overwriting any existing value).
        fn put(&self, key: &[u8], value: Bytes) -> StorageResult<()>;
        /// Remove `key` if present.
        fn delete(&self, key: &[u8]) -> StorageResult<()>;
        /// `(key, value)` pairs whose key starts with `prefix`, ascending, at most
        /// `limit` (0 = unlimited).
        fn scan_prefix(&self, prefix: &[u8], limit: usize) -> StorageResult<Vec<(Bytes, Bytes)>>;
        /// Lexicographically-smallest `(key, value)` under `prefix` (a `CanBePrefix`
        /// lookup). Default: first of [`scan_prefix`](Self::scan_prefix).
        fn first_under(&self, prefix: &[u8]) -> StorageResult<Option<(Bytes, Bytes)>> {
            Ok(self.scan_prefix(prefix, 1)?.into_iter().next())
        }
        /// Apply `ops` as a group. Default: sequential, **not** atomic; engines with a
        /// native batch override for atomicity.
        fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            for op in ops {
                match op {
                    WriteOp::Put(k, v) => self.put(&k, v)?,
                    WriteOp::Delete(k) => self.delete(&k)?,
                }
            }
            Ok(())
        }
        /// Short, low-cardinality engine label for telemetry.
        fn name(&self) -> &'static str {
            "sync-backend"
        }
    }

    /// In-memory [`SyncBackend`] — a `BTreeMap` behind a mutex, no allocator beyond
    /// `alloc`. The embedded storage floor (an MCU holds few items) and a sync
    /// in-process store on std. The mutex is `std::sync::Mutex` on std and a
    /// `critical-section` mutex on `no_std` (correct on a single-core MCU: it masks
    /// interrupts rather than spinning). `const`-constructible for a `static`.
    #[cfg(feature = "sync")]
    pub struct SyncMemoryBackend {
        #[cfg(feature = "std")]
        map: std::sync::Mutex<alloc::collections::BTreeMap<Vec<u8>, Bytes>>,
        #[cfg(not(feature = "std"))]
        map: critical_section::Mutex<
            core::cell::RefCell<alloc::collections::BTreeMap<Vec<u8>, Bytes>>,
        >,
    }

    #[cfg(feature = "sync")]
    impl Default for SyncMemoryBackend {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(feature = "sync")]
    impl SyncMemoryBackend {
        pub const fn new() -> Self {
            #[cfg(feature = "std")]
            {
                Self {
                    map: std::sync::Mutex::new(alloc::collections::BTreeMap::new()),
                }
            }
            #[cfg(not(feature = "std"))]
            {
                Self {
                    map: critical_section::Mutex::new(core::cell::RefCell::new(
                        alloc::collections::BTreeMap::new(),
                    )),
                }
            }
        }

        /// Run `f` with `&mut` access to the map, under whichever mutex is configured.
        fn with_map<R>(
            &self,
            f: impl FnOnce(&mut alloc::collections::BTreeMap<Vec<u8>, Bytes>) -> R,
        ) -> R {
            #[cfg(feature = "std")]
            {
                f(&mut self
                    .map
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner))
            }
            #[cfg(not(feature = "std"))]
            {
                critical_section::with(|cs| f(&mut self.map.borrow_ref_mut(cs)))
            }
        }
    }

    #[cfg(feature = "sync")]
    impl SyncBackend for SyncMemoryBackend {
        fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
            Ok(self.with_map(|m| m.get(key).cloned()))
        }
        fn put(&self, key: &[u8], value: Bytes) -> StorageResult<()> {
            self.with_map(|m| m.insert(key.to_vec(), value));
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> StorageResult<()> {
            self.with_map(|m| m.remove(key));
            Ok(())
        }
        fn scan_prefix(&self, prefix: &[u8], limit: usize) -> StorageResult<Vec<(Bytes, Bytes)>> {
            Ok(self.with_map(|m| {
                let mut out = Vec::new();
                for (k, v) in m.range(prefix.to_vec()..) {
                    if !k.starts_with(prefix) {
                        break;
                    }
                    out.push((Bytes::copy_from_slice(k), v.clone()));
                    if limit != 0 && out.len() >= limit {
                        break;
                    }
                }
                out
            }))
        }
        fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            // Atomic: the whole group under one lock / critical section.
            self.with_map(|m| {
                for op in ops {
                    match op {
                        WriteOp::Put(k, v) => {
                            m.insert(k, v);
                        }
                        WriteOp::Delete(k) => {
                            m.remove(&k);
                        }
                    }
                }
            });
            Ok(())
        }
        fn name(&self) -> &'static str {
            "sync-memory"
        }
    }

    /// Bridge any [`SyncBackend`] into the async [`Backend`](super::Backend) so a sync
    /// engine (the embedded `SyncMemoryBackend`) composes with the async named layer /
    /// `StoreRouter` on std. Calls run **inline** (the sync op completes within the
    /// poll, no offload) — intended for *non-blocking* sync engines (in-memory). A
    /// genuinely blocking engine on std should use a native async backend
    /// (`FjallBackend`/`RedbBackend`), which offloads via `spawn_blocking` internally.
    #[cfg(feature = "std")]
    pub struct SyncAsAsync<S> {
        inner: S,
    }

    #[cfg(feature = "std")]
    impl<S: SyncBackend> SyncAsAsync<S> {
        pub fn new(inner: S) -> Self {
            Self { inner }
        }
        /// Borrow the wrapped sync backend (e.g. for direct synchronous access).
        pub fn inner(&self) -> &S {
            &self.inner
        }
    }

    #[cfg(feature = "std")]
    #[super::async_trait]
    impl<S: SyncBackend> super::Backend for SyncAsAsync<S> {
        async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
            self.inner.get(&key)
        }
        async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()> {
            self.inner.put(&key, value)
        }
        async fn delete(&self, key: Vec<u8>) -> StorageResult<()> {
            self.inner.delete(&key)
        }
        async fn scan_prefix(
            &self,
            prefix: Vec<u8>,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            self.inner.scan_prefix(&prefix, limit)
        }
        async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            self.inner.write_batch(ops)
        }
        fn name(&self) -> &'static str {
            self.inner.name()
        }
    }
}

#[cfg(feature = "named")]
pub use named::{
    Batch, NamedOp, NamedReadStore, NamedStore, NamedWriteStore, StoreRouter, name_key,
};

/// Layer 1: a name→wire store over any [`Backend`] (the CS/Repo model). Keys are
/// NDN component-TLVs, so a parent name is a byte-prefix of its descendants and
/// `CanBePrefix` lookups are prefix scans.
#[cfg(feature = "named")]
mod named {
    use super::{Backend, Bytes, StorageResult, WriteOp, async_trait};
    use ndn_packet::Name;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// One atomic step in a named [`Batch`] — insert wire under a name, or remove a
    /// name. Translated to a Layer-0 [`WriteOp`] by the concrete store.
    pub enum NamedOp {
        Insert(Name, Bytes),
        Remove(Name),
    }

    impl NamedOp {
        fn name(&self) -> &Name {
            match self {
                NamedOp::Insert(n, _) | NamedOp::Remove(n) => n,
            }
        }
    }

    /// Ergonomic builder for an **atomic** group of named writes. Commits as one
    /// transaction where the store supports it (`NamedStore<RedbBackend>` → a single
    /// redb txn; `NamedStore<FjallBackend>` → one fjall batch; `MemoryBackend` → under
    /// one lock). Usage: `Batch::new().insert(&n, wire).remove(&old).commit(&store).await`.
    #[derive(Default)]
    pub struct Batch {
        ops: Vec<NamedOp>,
    }

    impl Batch {
        pub fn new() -> Self {
            Self::default()
        }
        #[must_use]
        pub fn insert(mut self, name: &Name, wire: Bytes) -> Self {
            self.ops.push(NamedOp::Insert(name.clone(), wire));
            self
        }
        #[must_use]
        pub fn remove(mut self, name: &Name) -> Self {
            self.ops.push(NamedOp::Remove(name.clone()));
            self
        }
        pub fn len(&self) -> usize {
            self.ops.len()
        }
        pub fn is_empty(&self) -> bool {
            self.ops.is_empty()
        }
        /// Apply every step atomically (per routed store) against `store`.
        pub async fn commit(self, store: &dyn NamedWriteStore) -> StorageResult<()> {
            store.write_batch(self.ops).await
        }
    }

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
        async fn get(&self, name: &Name) -> StorageResult<Option<Bytes>>;
        async fn find_under(&self, prefix: &Name) -> StorageResult<Option<Bytes>>;
        async fn scan_under(
            &self,
            prefix: &Name,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>>;
    }

    /// Object-safe **write** facet (write-behind retention + eviction).
    #[async_trait]
    pub trait NamedWriteStore: NamedReadStore {
        async fn insert(&self, name: &Name, wire: Bytes) -> StorageResult<()>;
        async fn remove(&self, name: &Name) -> StorageResult<()>;
        /// Apply a group of [`NamedOp`]s. Default: sequential and **non-atomic**;
        /// concrete stores override to commit as one transaction.
        async fn write_batch(&self, ops: Vec<NamedOp>) -> StorageResult<()> {
            for op in ops {
                match op {
                    NamedOp::Insert(n, w) => self.insert(&n, w).await?,
                    NamedOp::Remove(n) => self.remove(&n).await?,
                }
            }
            Ok(())
        }
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
        pub async fn insert(&self, name: &Name, wire: Bytes) -> StorageResult<()> {
            self.backend.put(name_key(name), wire).await
        }
        pub async fn get(&self, name: &Name) -> StorageResult<Option<Bytes>> {
            self.backend.get(name_key(name)).await
        }
        pub async fn remove(&self, name: &Name) -> StorageResult<()> {
            self.backend.delete(name_key(name)).await
        }
        pub async fn find_under(&self, prefix: &Name) -> StorageResult<Option<Bytes>> {
            Ok(self
                .backend
                .first_under(name_key(prefix))
                .await?
                .map(|(_, v)| v))
        }
        pub async fn scan_under(
            &self,
            prefix: &Name,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            self.backend.scan_prefix(name_key(prefix), limit).await
        }
    }

    #[async_trait]
    impl<B: Backend> NamedReadStore for NamedStore<B> {
        async fn get(&self, name: &Name) -> StorageResult<Option<Bytes>> {
            NamedStore::get(self, name).await
        }
        async fn find_under(&self, prefix: &Name) -> StorageResult<Option<Bytes>> {
            NamedStore::find_under(self, prefix).await
        }
        async fn scan_under(
            &self,
            prefix: &Name,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            NamedStore::scan_under(self, prefix, limit).await
        }
    }

    #[async_trait]
    impl<B: Backend> NamedWriteStore for NamedStore<B> {
        async fn insert(&self, name: &Name, wire: Bytes) -> StorageResult<()> {
            NamedStore::insert(self, name, wire).await
        }
        async fn remove(&self, name: &Name) -> StorageResult<()> {
            NamedStore::remove(self, name).await
        }
        async fn write_batch(&self, ops: Vec<NamedOp>) -> StorageResult<()> {
            // Translate named ops → Layer-0 ops, commit atomically via the engine.
            let backend_ops = ops
                .into_iter()
                .map(|op| match op {
                    NamedOp::Insert(n, w) => WriteOp::Put(name_key(&n), w),
                    NamedOp::Remove(n) => WriteOp::Delete(name_key(&n)),
                })
                .collect();
            self.backend.write_batch(backend_ops).await
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
            self.pick_idx(name).map(|i| self.store_at(i))
        }
        /// Which store a name routes to: a specific route, or the fallback. Returned (rather
        /// than the `&Arc` directly) so batch ops can be grouped by destination via a plain
        /// `Hash`/`Eq` key, no pointer identity.
        ///
        /// The match is a **linear scan** over the routes (longest-prefix wins) — fine for
        /// the handful of routes a node configures; a trie would only matter at hundreds of
        /// routes and is deferred.
        fn pick_idx(&self, name: &Name) -> Option<RouteSel> {
            let key = name_key(name);
            let mut best: Option<usize> = None;
            let mut best_len = 0;
            for (i, r) in self.routes.iter().enumerate() {
                if key.starts_with(&r.0) && (best.is_none() || r.0.len() > best_len) {
                    best = Some(i);
                    best_len = r.0.len();
                }
            }
            best.map(RouteSel::Indexed)
                .or_else(|| self.fallback.as_ref().map(|_| RouteSel::Fallback))
        }
        fn store_at(&self, sel: RouteSel) -> &Arc<dyn NamedWriteStore> {
            match sel {
                RouteSel::Fallback => self
                    .fallback
                    .as_ref()
                    .expect("fallback present for RouteSel::Fallback"),
                RouteSel::Indexed(i) => &self.routes[i].1,
            }
        }
    }

    /// Which [`StoreRouter`] destination a name resolved to — a typed replacement for the
    /// old `usize::MAX`-means-fallback sentinel. `Copy`/`Hash` so it keys a batch-grouping map.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    enum RouteSel {
        Indexed(usize),
        Fallback,
    }

    #[async_trait]
    impl NamedReadStore for StoreRouter {
        async fn get(&self, name: &Name) -> StorageResult<Option<Bytes>> {
            match self.pick(name) {
                Some(s) => s.get(name).await,
                None => Ok(None),
            }
        }
        async fn find_under(&self, prefix: &Name) -> StorageResult<Option<Bytes>> {
            match self.pick(prefix) {
                Some(s) => s.find_under(prefix).await,
                None => Ok(None),
            }
        }
        async fn scan_under(
            &self,
            prefix: &Name,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            match self.pick(prefix) {
                Some(s) => s.scan_under(prefix, limit).await,
                None => Ok(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl NamedWriteStore for StoreRouter {
        async fn insert(&self, name: &Name, wire: Bytes) -> StorageResult<()> {
            if let Some(s) = self.pick(name) {
                s.insert(name, wire).await?;
            }
            Ok(())
        }
        async fn remove(&self, name: &Name) -> StorageResult<()> {
            if let Some(s) = self.pick(name) {
                s.remove(name).await?;
            }
            Ok(())
        }
        async fn write_batch(&self, ops: Vec<NamedOp>) -> StorageResult<()> {
            // Group ops by destination store; each store commits its group atomically.
            // (Cross-store atomicity is not offered — routes are independent engines.)
            let mut groups: HashMap<RouteSel, Vec<NamedOp>> = HashMap::new();
            for op in ops {
                if let Some(sel) = self.pick_idx(op.name()) {
                    groups.entry(sel).or_default().push(op);
                }
            }
            for (sel, group) in groups {
                self.store_at(sel).write_batch(group).await?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "fjall")]
pub use fjall_backend::{FjallBackend, FjallBatch, FjallDb};

#[cfg(feature = "fjall")]
mod fjall_backend {
    use super::{Backend, Bytes, StorageError, StorageResult, SyncBackend, WriteOp, async_trait};

    /// On-disk [`Backend`] backed by [fjall](https://docs.rs/fjall) (an LSM
    /// key-value store). Persistent across restarts. The single fjall adapter every
    /// model shares.
    ///
    /// fjall is **synchronous** underneath, so this is fundamentally a [`SyncBackend`]
    /// (the F21 sync core — usable directly by a synchronous consumer like NDF's
    /// `BlockStore`, no async runtime needed). The async [`Backend`] impl is a thin
    /// `spawn_blocking` wrapper over that same core, so an async caller never stalls
    /// the runtime — one source of truth, two surfaces. Cheap to `clone` (handles are
    /// `Arc`s), which is how the async wrapper moves it onto the blocking pool.
    #[derive(Clone)]
    pub struct FjallBackend {
        keyspace: fjall::Keyspace,
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

    // The sync core: direct (blocking) fjall calls, no offload.
    impl SyncBackend for FjallBackend {
        fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
            // A real read error is surfaced (was previously collapsed into `None`).
            let v = self.keyspace.get(key).map_err(StorageError::backend)?;
            Ok(v.map(|s| Bytes::copy_from_slice(&s)))
        }
        fn put(&self, key: &[u8], value: Bytes) -> StorageResult<()> {
            self.keyspace
                .insert(key, value.as_ref())
                .map_err(StorageError::backend)
        }
        fn delete(&self, key: &[u8]) -> StorageResult<()> {
            self.keyspace.remove(key).map_err(StorageError::backend)
        }
        fn scan_prefix(&self, prefix: &[u8], limit: usize) -> StorageResult<Vec<(Bytes, Bytes)>> {
            let mut out = Vec::new();
            for guard in self.keyspace.prefix(prefix) {
                // An iteration error aborts the scan with the error (was `break` → a
                // silently-truncated result indistinguishable from a real end).
                let (k, v) = guard.into_inner().map_err(StorageError::backend)?;
                out.push((Bytes::copy_from_slice(&k), Bytes::copy_from_slice(&v)));
                if limit != 0 && out.len() >= limit {
                    break;
                }
            }
            Ok(out)
        }
        fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            let mut batch = self.db.batch(); // atomic across keyspaces
            for op in ops {
                match op {
                    WriteOp::Put(k, v) => batch.insert(&self.keyspace, &k, v.as_ref()),
                    WriteOp::Delete(k) => batch.remove(&self.keyspace, &k),
                }
            }
            batch.commit().map_err(StorageError::backend)
        }
        fn name(&self) -> &'static str {
            "fjall"
        }
    }

    // The async surface: a thin `spawn_blocking` wrapper over the sync core.
    #[async_trait]
    impl Backend for FjallBackend {
        async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::get(&this, &key))
                .await
                .map_err(StorageError::backend)?
        }
        async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::put(&this, &key, value))
                .await
                .map_err(StorageError::backend)?
        }
        async fn delete(&self, key: Vec<u8>) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::delete(&this, &key))
                .await
                .map_err(StorageError::backend)?
        }
        async fn scan_prefix(
            &self,
            prefix: Vec<u8>,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::scan_prefix(&this, &prefix, limit))
                .await
                .map_err(StorageError::backend)?
        }
        async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::write_batch(&this, ops))
                .await
                .map_err(StorageError::backend)?
        }
        fn name(&self) -> &'static str {
            "fjall"
        }
    }

    /// A shared fjall [`Database`](fjall::Database) that opens **multiple partitions**
    /// (LSM trees) over one on-disk keyspace and can commit a write batch **atomically
    /// across them** — closing F22. Open N partitions as [`FjallBackend`]s that share
    /// this db's transaction domain, then group their writes in one [`FjallBatch`]; a
    /// crash leaves either all or none (e.g. NDF's ≥5-partition block `put`: headers,
    /// payloads, idx_by_name/kind/parent). This surfaces fjall's native
    /// `Database::batch()` cross-partition atomicity, bringing fjall to parity with
    /// [`RedbDb`](super::RedbDb)'s cross-table transaction — the engine choice stays a
    /// pure perf/feature tradeoff, never "pick fjall ⇒ lose atomicity".
    ///
    /// (Partitions opened via [`FjallBackend::open_keyspace`] each get their *own*
    /// `Database`, so they **cannot** be batched together — use `FjallDb` when you need
    /// multi-partition atomicity.)
    pub struct FjallDb {
        db: fjall::Database,
    }

    impl FjallDb {
        /// Open (or create) the shared keyspace at `path`.
        pub fn open(path: impl AsRef<std::path::Path>) -> fjall::Result<Self> {
            Ok(Self {
                db: fjall::Database::builder(path).open()?,
            })
        }

        /// Open (or get) a named partition as a [`FjallBackend`] sharing this db — so
        /// its writes can be committed atomically with sibling partitions' writes via
        /// [`batch`](Self::batch). It is a fully-functional `Backend` on its own too.
        pub fn partition(&self, name: &str) -> fjall::Result<FjallBackend> {
            let keyspace = self
                .db
                .keyspace(name, fjall::KeyspaceCreateOptions::default)?;
            Ok(FjallBackend {
                keyspace,
                db: self.db.clone(),
            })
        }

        /// Begin a cross-partition atomic batch over this db's partitions.
        pub fn batch(&self) -> FjallBatch {
            FjallBatch {
                db: self.db.clone(),
                ops: Vec::new(),
            }
        }
    }

    /// A batch of writes spanning one or more [`FjallBackend`] partitions of a single
    /// [`FjallDb`], committed **atomically** (all-or-nothing). The engine-layer
    /// counterpart of the named [`Batch`](crate::Batch): an explicit partition per op,
    /// for models (NDF's BlockStore) that own their key codec and span partitions.
    /// Build then `commit().await`:
    /// `db.batch().insert(&headers, k, v).insert(&payloads, k2, v2).commit().await?`.
    #[must_use = "a FjallBatch does nothing until committed"]
    pub struct FjallBatch {
        db: fjall::Database,
        ops: Vec<(fjall::Keyspace, WriteOp)>,
    }

    impl FjallBatch {
        /// Stage an insert into `partition`.
        pub fn insert(mut self, partition: &FjallBackend, key: Vec<u8>, value: Bytes) -> Self {
            self.ops
                .push((partition.keyspace.clone(), WriteOp::Put(key, value)));
            self
        }
        /// Stage a delete from `partition`.
        pub fn remove(mut self, partition: &FjallBackend, key: Vec<u8>) -> Self {
            self.ops
                .push((partition.keyspace.clone(), WriteOp::Delete(key)));
            self
        }
        /// Number of staged ops.
        pub fn len(&self) -> usize {
            self.ops.len()
        }
        /// `true` if no ops are staged.
        pub fn is_empty(&self) -> bool {
            self.ops.is_empty()
        }
        /// Commit every staged op as **one** atomic fjall batch (all partitions or
        /// none), **synchronously** — for a sync consumer (NDF's `BlockStore`, an
        /// embedded node). Errors surface a failed commit so the caller knows the group
        /// did not land — the whole point of atomic block writes.
        pub fn commit_blocking(self) -> std::io::Result<()> {
            let FjallBatch { db, ops } = self;
            let n = ops.len();
            let mut batch = db.batch(); // spans every partition of `db`
            for (ks, op) in ops {
                match op {
                    WriteOp::Put(k, v) => batch.insert(&ks, &k, v.as_ref()),
                    WriteOp::Delete(k) => batch.remove(&ks, &k),
                }
            }
            batch
                .commit()
                .map_err(|e| std::io::Error::other(format!("fjall batch commit: {e}")))?;
            tracing::trace!(target: "ndn_storage", backend = "fjall", ops = n, "cross_partition_batch");
            Ok(())
        }

        /// Async commit — a `spawn_blocking` wrapper over [`commit_blocking`](Self::commit_blocking).
        pub async fn commit(self) -> std::io::Result<()> {
            tokio::task::spawn_blocking(move || self.commit_blocking())
                .await
                .map_err(|e| std::io::Error::other(format!("fjall batch join: {e}")))?
        }
    }
}

#[cfg(feature = "redb")]
pub use redb_backend::{RedbBackend, RedbBatch, RedbDb};

#[cfg(feature = "redb")]
mod redb_backend {
    use super::{Backend, Bytes, StorageError, StorageResult, SyncBackend, WriteOp, async_trait};
    use redb::ReadableDatabase; // brings `begin_read` into scope
    use std::sync::Arc;

    // Pin the K/V refs to 'static so the table-name lifetime stays free
    // (an elided `&[u8]` would inherit `name`'s lifetime and force it 'static).
    type Tbl<'a> = redb::TableDefinition<'a, &'static [u8], &'static [u8]>;

    fn table(name: &str) -> Tbl<'_> {
        redb::TableDefinition::new(name)
    }

    /// On-disk [`Backend`] backed by [redb](https://docs.rs/redb) — a pure-Rust
    /// embedded B-tree with **real ACID transactions**. Use it (over fjall) where
    /// point-read latency or **atomic multi-key writes** matter.
    ///
    /// ⚠️ **Write cost (G11S.3):** every single `put`/`delete` opens, commits, and *fsyncs*
    /// a full write transaction — durable, but expensive per op. For bulk writes use
    /// [`write_batch`](SyncBackend::write_batch) (one txn for the group) or [`RedbDb`] +
    /// [`RedbBatch`] (one txn across tables); a hot single-op write loop will be
    /// fsync-bound. (fjall's LSM amortizes writes and is the better choice for
    /// write-heavy workloads.)
    ///
    /// redb is **synchronous** underneath, so this is a [`SyncBackend`] (the F21 sync
    /// core); the async [`Backend`] is a thin `spawn_blocking` wrapper over it. Cheap
    /// to `clone` (an `Arc` + the table name).
    #[derive(Clone)]
    pub struct RedbBackend {
        db: Arc<redb::Database>,
        table: String,
    }

    impl RedbBackend {
        /// Open (or create) a redb-backed store at `path`, default table `ndn`.
        pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
            Self::open_table(path, "ndn")
        }

        /// Open (or create) at `path` using a named table (so distinct models can
        /// share one file across tables).
        pub fn open_table(
            path: impl AsRef<std::path::Path>,
            table_name: &str,
        ) -> std::io::Result<Self> {
            let db = redb::Database::create(path).map_err(std::io::Error::other)?;
            // Ensure the table exists (an empty write txn creates it).
            let w = db.begin_write().map_err(std::io::Error::other)?;
            {
                w.open_table(table(table_name))
                    .map_err(std::io::Error::other)?;
            }
            w.commit().map_err(std::io::Error::other)?;
            Ok(Self {
                db: Arc::new(db),
                table: table_name.to_string(),
            })
        }
    }

    // The sync core: direct (blocking) redb transactions, no offload.
    impl SyncBackend for RedbBackend {
        fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
            // Each step's error is surfaced (was previously `.ok()?` → an error became a
            // miss). A genuine absence is the inner `None`.
            let txn = self.db.begin_read().map_err(StorageError::backend)?;
            let t = txn
                .open_table(table(&self.table))
                .map_err(StorageError::backend)?;
            let g = t.get(key).map_err(StorageError::backend)?;
            Ok(g.map(|g| Bytes::copy_from_slice(g.value())))
        }
        fn put(&self, key: &[u8], value: Bytes) -> StorageResult<()> {
            SyncBackend::write_batch(self, vec![WriteOp::Put(key.to_vec(), value)])
        }
        fn delete(&self, key: &[u8]) -> StorageResult<()> {
            SyncBackend::write_batch(self, vec![WriteOp::Delete(key.to_vec())])
        }
        fn scan_prefix(&self, prefix: &[u8], limit: usize) -> StorageResult<Vec<(Bytes, Bytes)>> {
            let mut out = Vec::new();
            let txn = self.db.begin_read().map_err(StorageError::backend)?;
            let t = txn
                .open_table(table(&self.table))
                .map_err(StorageError::backend)?;
            let iter = t.range(prefix..).map_err(StorageError::backend)?;
            for item in iter {
                // A real iteration error aborts with the error (not a silent truncation).
                let (k, v) = item.map_err(StorageError::backend)?;
                if !k.value().starts_with(prefix) {
                    break;
                }
                out.push((
                    Bytes::copy_from_slice(k.value()),
                    Bytes::copy_from_slice(v.value()),
                ));
                if limit != 0 && out.len() >= limit {
                    break;
                }
            }
            Ok(out)
        }
        fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            (|| -> Result<(), redb::Error> {
                let txn = self.db.begin_write()?;
                {
                    let mut t = txn.open_table(table(&self.table))?;
                    for op in ops {
                        match op {
                            WriteOp::Put(k, v) => {
                                t.insert(k.as_slice(), v.as_ref())?;
                            }
                            WriteOp::Delete(k) => {
                                t.remove(k.as_slice())?;
                            }
                        }
                    }
                } // table dropped before commit
                txn.commit()?; // ACID: all ops or none
                Ok(())
            })()
            .map_err(StorageError::backend)
        }
        fn name(&self) -> &'static str {
            "redb"
        }
    }

    // The async surface: a thin `spawn_blocking` wrapper over the sync core.
    #[async_trait]
    impl Backend for RedbBackend {
        async fn get(&self, key: Vec<u8>) -> StorageResult<Option<Bytes>> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::get(&this, &key))
                .await
                .map_err(StorageError::backend)?
        }
        async fn put(&self, key: Vec<u8>, value: Bytes) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::put(&this, &key, value))
                .await
                .map_err(StorageError::backend)?
        }
        async fn delete(&self, key: Vec<u8>) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::delete(&this, &key))
                .await
                .map_err(StorageError::backend)?
        }
        async fn scan_prefix(
            &self,
            prefix: Vec<u8>,
            limit: usize,
        ) -> StorageResult<Vec<(Bytes, Bytes)>> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::scan_prefix(&this, &prefix, limit))
                .await
                .map_err(StorageError::backend)?
        }
        async fn write_batch(&self, ops: Vec<WriteOp>) -> StorageResult<()> {
            let this = self.clone();
            tokio::task::spawn_blocking(move || SyncBackend::write_batch(&this, ops))
                .await
                .map_err(StorageError::backend)?
        }
        fn name(&self) -> &'static str {
            "redb"
        }
    }

    /// A shared redb [`Database`](redb::Database) that opens **multiple tables** over
    /// one file and can commit a write batch **atomically across them** — the redb
    /// counterpart of [`FjallDb`](super::FjallDb), so cross-partition atomicity exists
    /// on *both* engines (F22 parity). Open N tables as [`RedbBackend`]s sharing this
    /// db, then group their writes in one [`RedbBatch`] = one redb `WriteTransaction`
    /// spanning every table.
    pub struct RedbDb {
        db: Arc<redb::Database>,
    }

    impl RedbDb {
        /// Open (or create) the shared database file at `path`.
        pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
            let db = redb::Database::create(path).map_err(std::io::Error::other)?;
            Ok(Self { db: Arc::new(db) })
        }

        /// Open (or get) a named table as a [`RedbBackend`] sharing this db — so its
        /// writes can be committed atomically with sibling tables' writes via
        /// [`batch`](Self::batch). A fully-functional `Backend` on its own too.
        pub fn partition(&self, name: &str) -> std::io::Result<RedbBackend> {
            let w = self.db.begin_write().map_err(std::io::Error::other)?;
            {
                w.open_table(table(name)).map_err(std::io::Error::other)?;
            }
            w.commit().map_err(std::io::Error::other)?;
            Ok(RedbBackend {
                db: self.db.clone(),
                table: name.to_string(),
            })
        }

        /// Begin a cross-table atomic batch over this db's tables.
        pub fn batch(&self) -> RedbBatch {
            RedbBatch {
                db: self.db.clone(),
                ops: Vec::new(),
            }
        }
    }

    /// A batch of writes spanning one or more [`RedbBackend`] tables of a single
    /// [`RedbDb`], committed **atomically** in one `WriteTransaction`. The redb mirror
    /// of [`FjallBatch`](super::FjallBatch).
    #[must_use = "a RedbBatch does nothing until committed"]
    pub struct RedbBatch {
        db: Arc<redb::Database>,
        ops: Vec<(String, WriteOp)>,
    }

    impl RedbBatch {
        /// Stage an insert into `partition`.
        pub fn insert(mut self, partition: &RedbBackend, key: Vec<u8>, value: Bytes) -> Self {
            self.ops
                .push((partition.table.clone(), WriteOp::Put(key, value)));
            self
        }
        /// Stage a delete from `partition`.
        pub fn remove(mut self, partition: &RedbBackend, key: Vec<u8>) -> Self {
            self.ops
                .push((partition.table.clone(), WriteOp::Delete(key)));
            self
        }
        /// Number of staged ops.
        pub fn len(&self) -> usize {
            self.ops.len()
        }
        /// `true` if no ops are staged.
        pub fn is_empty(&self) -> bool {
            self.ops.is_empty()
        }
        /// Commit every staged op as one redb transaction spanning all touched tables
        /// (all-or-nothing), **synchronously** — for a sync consumer. Errors surface a
        /// failed commit.
        pub fn commit_blocking(self) -> std::io::Result<()> {
            let RedbBatch { db, ops } = self;
            let n = ops.len();
            (|| -> Result<(), redb::Error> {
                // Group by table so each is opened exactly once within the txn.
                let mut by_table: std::collections::HashMap<String, Vec<WriteOp>> =
                    std::collections::HashMap::new();
                for (t, op) in ops {
                    by_table.entry(t).or_default().push(op);
                }
                let txn = db.begin_write()?;
                for (tname, tops) in by_table {
                    let mut t = txn.open_table(table(&tname))?;
                    for op in tops {
                        match op {
                            WriteOp::Put(k, v) => {
                                t.insert(k.as_slice(), v.as_ref())?;
                            }
                            WriteOp::Delete(k) => {
                                t.remove(k.as_slice())?;
                            }
                        }
                    }
                    // `t` dropped here, before the next table / the commit.
                }
                txn.commit()?; // ACID across every table
                Ok(())
            })()
            .map_err(|e| std::io::Error::other(format!("redb batch commit: {e}")))?;
            tracing::trace!(target: "ndn_storage", backend = "redb", ops = n, "cross_partition_batch");
            Ok(())
        }

        /// Async commit — a `spawn_blocking` wrapper over [`commit_blocking`](Self::commit_blocking).
        pub async fn commit(self) -> std::io::Result<()> {
            tokio::task::spawn_blocking(move || self.commit_blocking())
                .await
                .map_err(|e| std::io::Error::other(format!("redb batch join: {e}")))?
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    async fn conformance(b: &dyn Backend) {
        assert!(b.get(b"missing".to_vec()).await.unwrap().is_none());
        b.put(b"/a/b".to_vec(), Bytes::from_static(b"v-ab"))
            .await
            .unwrap();
        b.put(b"/a/b/c".to_vec(), Bytes::from_static(b"v-abc"))
            .await
            .unwrap();
        b.put(b"/a/d".to_vec(), Bytes::from_static(b"v-ad"))
            .await
            .unwrap();
        b.put(b"/z".to_vec(), Bytes::from_static(b"v-z"))
            .await
            .unwrap();

        assert_eq!(
            b.get(b"/a/b".to_vec()).await.unwrap().as_deref(),
            Some(&b"v-ab"[..])
        );
        assert_eq!(
            b.first_under(b"/a/b".to_vec())
                .await
                .unwrap()
                .unwrap()
                .0
                .as_ref(),
            b"/a/b"
        );
        assert_eq!(
            b.first_under(b"/a/d".to_vec())
                .await
                .unwrap()
                .unwrap()
                .1
                .as_ref(),
            b"v-ad"
        );
        assert!(b.first_under(b"/nope".to_vec()).await.unwrap().is_none());

        let under: Vec<String> = b
            .scan_prefix(b"/a".to_vec(), 0)
            .await
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8_lossy(&k).into_owned())
            .collect();
        assert_eq!(under, vec!["/a/b", "/a/b/c", "/a/d"]); // ascending, /z excluded

        assert_eq!(b.scan_prefix(b"/a".to_vec(), 1).await.unwrap().len(), 1); // limit

        b.delete(b"/a/b".to_vec()).await.unwrap();
        assert!(b.get(b"/a/b".to_vec()).await.unwrap().is_none());
        assert_eq!(
            b.get(b"/a/b/c".to_vec()).await.unwrap().as_deref(),
            Some(&b"v-abc"[..])
        );
    }

    /// `write_batch` applies every op and is observable as a unit.
    async fn batch_conformance(b: &dyn Backend) {
        b.put(b"/keep".to_vec(), Bytes::from_static(b"old"))
            .await
            .unwrap();
        b.write_batch(vec![
            WriteOp::Put(b"/k1".to_vec(), Bytes::from_static(b"v1")),
            WriteOp::Put(b"/k2".to_vec(), Bytes::from_static(b"v2")),
            WriteOp::Put(b"/keep".to_vec(), Bytes::from_static(b"new")),
            WriteOp::Delete(b"/keep".to_vec()), // last-writer-wins ordering within a batch
        ])
        .await
        .unwrap();
        assert_eq!(
            b.get(b"/k1".to_vec()).await.unwrap().as_deref(),
            Some(&b"v1"[..])
        );
        assert_eq!(
            b.get(b"/k2".to_vec()).await.unwrap().as_deref(),
            Some(&b"v2"[..])
        );
        assert!(b.get(b"/keep".to_vec()).await.unwrap().is_none()); // put-then-delete in order
    }

    #[tokio::test]
    async fn memory_backend_conformance() {
        conformance(&MemoryBackend::new()).await;
        batch_conformance(&MemoryBackend::new()).await;
    }

    #[tokio::test]
    async fn instrumented_delegates_transparently() {
        // The telemetry decorator must be behaviorally identical to its inner engine.
        let b = Instrumented::new(MemoryBackend::new());
        conformance(&b).await;
        batch_conformance(&Instrumented::new(MemoryBackend::new())).await;
        assert_eq!(b.name(), "memory"); // label propagates from the inner engine
    }

    #[cfg(feature = "named")]
    #[tokio::test]
    async fn named_batch_atomic_over_store() {
        use ndn_packet::Name;
        let s = NamedStore::new(MemoryBackend::new());
        let v0: Name = "/app/s/v=0".parse().unwrap();
        let v1: Name = "/app/s/v=1".parse().unwrap();
        let v2: Name = "/app/s/v=2".parse().unwrap();
        s.insert(&v0, Bytes::from_static(b"f0")).await.unwrap();

        // Builder: add two, evict the oldest — all in one commit.
        Batch::new()
            .insert(&v1, Bytes::from_static(b"f1"))
            .insert(&v2, Bytes::from_static(b"f2"))
            .remove(&v0)
            .commit(&s)
            .await
            .unwrap();

        assert!(s.get(&v0).await.unwrap().is_none());
        assert_eq!(s.get(&v1).await.unwrap().as_deref(), Some(&b"f1"[..]));
        assert_eq!(s.get(&v2).await.unwrap().as_deref(), Some(&b"f2"[..]));
    }

    #[cfg(feature = "named")]
    #[tokio::test]
    async fn router_batch_groups_by_store() {
        use ndn_packet::Name;
        use std::sync::Arc;
        let a: Arc<dyn NamedWriteStore> = Arc::new(NamedStore::new(MemoryBackend::new()));
        let d: Arc<dyn NamedWriteStore> = Arc::new(NamedStore::new(MemoryBackend::new()));
        let router = StoreRouter::new()
            .route(&"/a".parse::<Name>().unwrap(), a.clone())
            .with_default(d.clone());

        let na: Name = "/a/x".parse().unwrap();
        let nc: Name = "/c/z".parse().unwrap();
        Batch::new()
            .insert(&na, Bytes::from_static(b"A"))
            .insert(&nc, Bytes::from_static(b"C"))
            .commit(&router)
            .await
            .unwrap();

        assert_eq!(a.get(&na).await.unwrap().as_deref(), Some(&b"A"[..])); // routed
        assert_eq!(d.get(&nc).await.unwrap().as_deref(), Some(&b"C"[..])); // fallback group
        assert!(a.get(&nc).await.unwrap().is_none());
    }

    #[cfg(feature = "named")]
    #[tokio::test]
    async fn named_store_over_backend() {
        use ndn_packet::Name;
        let s = NamedStore::new(MemoryBackend::new());
        let n: Name = "/app/surface".parse().unwrap();
        let v0: Name = "/app/surface/v=0".parse().unwrap();
        let v1: Name = "/app/surface/v=1".parse().unwrap();

        s.insert(&v0, Bytes::from_static(b"frame0")).await.unwrap();
        s.insert(&v1, Bytes::from_static(b"frame1")).await.unwrap();
        assert_eq!(s.get(&v0).await.unwrap().as_deref(), Some(&b"frame0"[..]));
        assert_eq!(
            s.find_under(&n).await.unwrap().as_deref(),
            Some(&b"frame0"[..])
        );
        assert!(name_key(&v0).starts_with(&name_key(&n)));
        assert_eq!(s.scan_under(&n, 0).await.unwrap().len(), 2);

        s.remove(&v0).await.unwrap();
        assert!(s.get(&v0).await.unwrap().is_none());
        assert_eq!(s.get(&v1).await.unwrap().as_deref(), Some(&b"frame1"[..]));
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
        router.insert(&na, Bytes::from_static(b"A")).await.unwrap();
        router.insert(&nc, Bytes::from_static(b"C")).await.unwrap();
        assert_eq!(a.get(&na).await.unwrap().as_deref(), Some(&b"A"[..]));
        assert!(b.get(&na).await.unwrap().is_none());
        assert_eq!(d.get(&nc).await.unwrap().as_deref(), Some(&b"C"[..])); // default
        assert_eq!(router.get(&na).await.unwrap().as_deref(), Some(&b"A"[..]));
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
            batch_conformance(&b).await;
            // UFCS: FjallBackend impls both Backend and SyncBackend, so a bare `.put`
            // is ambiguous with both traits in scope.
            Backend::put(&b, b"/persist".to_vec(), Bytes::from_static(b"survives"))
                .await
                .unwrap();
        }
        {
            let b = FjallBackend::open(&dir).unwrap();
            assert_eq!(
                Backend::get(&b, b"/persist".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"survives"[..])
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "redb")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redb_backend_conformance_and_persistence() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ndn-storage-redb-{}-{}.redb",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let b = RedbBackend::open(&path).unwrap();
            conformance(&b).await;
            batch_conformance(&b).await;
            Backend::put(&b, b"/persist".to_vec(), Bytes::from_static(b"survives"))
                .await
                .unwrap();
        }
        {
            let b = RedbBackend::open(&path).unwrap();
            assert_eq!(
                Backend::get(&b, b"/persist".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"survives"[..])
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// F22: a `FjallDb` opens multiple partitions sharing one transaction domain, and
    /// a `FjallBatch` commits across them atomically (NDF's ≥5-partition block `put`).
    #[cfg(feature = "fjall")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fjall_cross_partition_atomic_batch() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ndn-storage-fjalldb-{}-{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        {
            let db = FjallDb::open(&dir).unwrap();
            let headers = db.partition("headers").unwrap();
            let payloads = db.partition("payloads").unwrap();
            let idx = db.partition("idx_by_name").unwrap();

            // One block lands across three partitions atomically.
            db.batch()
                .insert(&headers, b"h1".to_vec(), Bytes::from_static(b"H"))
                .insert(&payloads, b"p1".to_vec(), Bytes::from_static(b"P"))
                .insert(&idx, b"n1".to_vec(), Bytes::from_static(b"h1"))
                .commit()
                .await
                .unwrap();
            // UFCS to disambiguate the dual (Backend / SyncBackend) impls in scope.
            assert_eq!(
                Backend::get(&headers, b"h1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"H"[..])
            );
            assert_eq!(
                Backend::get(&payloads, b"p1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"P"[..])
            );
            assert_eq!(
                Backend::get(&idx, b"n1".to_vec()).await.unwrap().as_deref(),
                Some(&b"h1"[..])
            );

            // A cross-partition delete in one batch (e.g. retract a block).
            db.batch()
                .remove(&headers, b"h1".to_vec())
                .remove(&idx, b"n1".to_vec())
                .commit()
                .await
                .unwrap();
            assert!(
                Backend::get(&headers, b"h1".to_vec())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(Backend::get(&idx, b"n1".to_vec()).await.unwrap().is_none());
            assert_eq!(
                Backend::get(&payloads, b"p1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"P"[..])
            );
        }
        // Survives reopen.
        {
            let db = FjallDb::open(&dir).unwrap();
            let payloads = db.partition("payloads").unwrap();
            assert_eq!(
                Backend::get(&payloads, b"p1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"P"[..])
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F22 parity: the same cross-table atomic batch on `RedbDb`.
    #[cfg(feature = "redb")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redb_cross_partition_atomic_batch() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ndn-storage-redbdb-{}-{}.redb",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        {
            let db = RedbDb::open(&path).unwrap();
            let headers = db.partition("headers").unwrap();
            let payloads = db.partition("payloads").unwrap();
            let idx = db.partition("idx_by_name").unwrap();
            db.batch()
                .insert(&headers, b"h1".to_vec(), Bytes::from_static(b"H"))
                .insert(&payloads, b"p1".to_vec(), Bytes::from_static(b"P"))
                .insert(&idx, b"n1".to_vec(), Bytes::from_static(b"h1"))
                .commit()
                .await
                .unwrap();
            assert_eq!(
                Backend::get(&headers, b"h1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"H"[..])
            );
            assert_eq!(
                Backend::get(&payloads, b"p1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"P"[..])
            );
            assert_eq!(
                Backend::get(&idx, b"n1".to_vec()).await.unwrap().as_deref(),
                Some(&b"h1"[..])
            );

            db.batch()
                .remove(&headers, b"h1".to_vec())
                .remove(&idx, b"n1".to_vec())
                .commit()
                .await
                .unwrap();
            assert!(
                Backend::get(&headers, b"h1".to_vec())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                Backend::get(&payloads, b"p1".to_vec())
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"P"[..])
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    // ---- F21: the synchronous facet ----

    /// Drives a `SyncBackend` with no async runtime — exactly how NDF's sync
    /// `BlockStore` / the pure verifier / an MCU consume it.
    // Callers are per-backend and feature-gated; gate the helper to match so
    // a default-features build doesn't see it as dead code.
    #[cfg(any(feature = "sync", feature = "fjall", feature = "redb"))]
    fn sync_conformance(b: &dyn SyncBackend) {
        assert!(b.get(b"missing").unwrap().is_none());
        b.put(b"/a/b", Bytes::from_static(b"v-ab")).unwrap();
        b.put(b"/a/b/c", Bytes::from_static(b"v-abc")).unwrap();
        b.put(b"/a/d", Bytes::from_static(b"v-ad")).unwrap();
        b.put(b"/z", Bytes::from_static(b"v-z")).unwrap();

        assert_eq!(b.get(b"/a/b").unwrap().as_deref(), Some(&b"v-ab"[..]));
        assert_eq!(b.first_under(b"/a/b").unwrap().unwrap().0.as_ref(), b"/a/b");
        assert!(b.first_under(b"/nope").unwrap().is_none());
        let under: Vec<String> = b
            .scan_prefix(b"/a", 0)
            .unwrap()
            .into_iter()
            .map(|(k, _)| String::from_utf8_lossy(&k).into_owned())
            .collect();
        assert_eq!(under, vec!["/a/b", "/a/b/c", "/a/d"]);
        assert_eq!(b.scan_prefix(b"/a", 1).unwrap().len(), 1);

        // Atomic group (last-writer-wins ordering within the batch).
        b.write_batch(vec![
            WriteOp::Put(b"/k1".to_vec(), Bytes::from_static(b"v1")),
            WriteOp::Delete(b"/a/b".to_vec()),
        ])
        .unwrap();
        assert_eq!(b.get(b"/k1").unwrap().as_deref(), Some(&b"v1"[..]));
        assert!(b.get(b"/a/b").unwrap().is_none());
    }

    #[cfg(feature = "sync")]
    #[test]
    fn sync_memory_backend_conformance() {
        sync_conformance(&SyncMemoryBackend::new());
    }

    /// fjall is usable as the sync core with no Tokio runtime present (plain `#[test]`).
    #[cfg(feature = "fjall")]
    #[test]
    fn fjall_sync_facet_conformance() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ndn-storage-fjall-sync-{}-{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        sync_conformance(&FjallBackend::open(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// fjall cross-partition atomic batch committed **synchronously** (the migration
    /// path NDF's sync `BlockStore` takes).
    #[cfg(feature = "fjall")]
    #[test]
    fn fjall_sync_cross_partition_batch() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "ndn-storage-fjall-syncbatch-{}-{}",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = FjallDb::open(&dir).unwrap();
        let headers = db.partition("headers").unwrap();
        let payloads = db.partition("payloads").unwrap();
        db.batch()
            .insert(&headers, b"h1".to_vec(), Bytes::from_static(b"H"))
            .insert(&payloads, b"p1".to_vec(), Bytes::from_static(b"P"))
            .commit_blocking()
            .unwrap();
        assert_eq!(
            SyncBackend::get(&headers, b"h1").unwrap().as_deref(),
            Some(&b"H"[..])
        );
        assert_eq!(
            SyncBackend::get(&payloads, b"p1").unwrap().as_deref(),
            Some(&b"P"[..])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "redb")]
    #[test]
    fn redb_sync_facet_conformance() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ndn-storage-redb-sync-{}-{}.redb",
            std::process::id(),
            CTR.fetch_add(1, Ordering::Relaxed)
        ));
        sync_conformance(&RedbBackend::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);
    }

    /// `SyncAsAsync` bridges a sync engine into the async named layer (so an embedded
    /// engine / the sync in-memory store composes with `NamedStore`/`StoreRouter`).
    #[cfg(all(feature = "sync", feature = "named"))]
    #[tokio::test]
    async fn sync_backend_bridges_to_async_named_store() {
        use ndn_packet::Name;
        let store = NamedStore::new(SyncAsAsync::new(SyncMemoryBackend::new()));
        let v0: Name = "/app/s/v=0".parse().unwrap();
        store.insert(&v0, Bytes::from_static(b"f0")).await.unwrap();
        assert_eq!(store.get(&v0).await.unwrap().as_deref(), Some(&b"f0"[..]));
    }
}
