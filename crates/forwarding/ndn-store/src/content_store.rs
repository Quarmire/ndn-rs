use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::{Interest, Name};

/// A cache entry holding wire-format Data bytes (no re-encoding on hit).
#[derive(Clone, Debug)]
pub struct CsEntry {
    pub data: Bytes,
    /// Nanoseconds since Unix epoch, derived from `FreshnessPeriod`.
    pub stale_at: u64,
    pub name: Arc<Name>,
}

impl CsEntry {
    pub fn is_fresh(&self, now_ns: u64) -> bool {
        ndn_fwd_core::freshness::fresh_until(now_ns, self.stale_at)
    }
}

pub struct CsMeta {
    pub stale_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult {
    Inserted,
    Replaced,
    Skipped,
}

#[derive(Debug, Clone, Copy)]
pub struct CsCapacity {
    pub max_bytes: usize,
}

impl CsCapacity {
    pub fn zero() -> Self {
        Self { max_bytes: 0 }
    }
    pub fn bytes(n: usize) -> Self {
        Self { max_bytes: n }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CsStats {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
}

/// Content store interface. Methods are `async` so persistent (disk-backed)
/// implementations are supported; in-memory ones complete synchronously.
pub trait ContentStore: Send + Sync + 'static {
    fn get(&self, interest: &Interest) -> impl Future<Output = Option<CsEntry>> + Send;

    /// Insert a Data packet. Callers must supply well-formed, signed Data —
    /// the CS does not re-verify signatures.
    fn insert(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> impl Future<Output = InsertResult> + Send;

    fn evict(&self, name: &Name) -> impl Future<Output = bool> + Send;

    fn capacity(&self) -> CsCapacity;

    fn len(&self) -> usize {
        0
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn current_bytes(&self) -> usize {
        0
    }

    fn set_capacity(&self, _max_bytes: usize) {}

    /// NFD CS `cs/config` Admit (BIT 0): when false, `insert` is a no-op.
    /// Default true.
    fn admit_enabled(&self) -> bool {
        true
    }
    /// NFD CS `cs/config` Serve (BIT 1): when false, `get` returns `None`
    /// (the CS does not satisfy Interests from cache). Default true.
    fn serve_enabled(&self) -> bool {
        true
    }
    fn set_admit(&self, _enabled: bool) {}
    fn set_serve(&self, _enabled: bool) {}

    fn variant_name(&self) -> &str {
        "unknown"
    }

    fn evict_prefix(
        &self,
        _prefix: &Name,
        _limit: Option<usize>,
    ) -> impl Future<Output = usize> + Send {
        async { 0 }
    }

    fn stats(&self) -> CsStats {
        CsStats::default()
    }
}

/// Object-safe [`ContentStore`] with boxed futures. A blanket impl wraps any
/// `ContentStore` implementor.
pub trait ErasedContentStore: Send + Sync + 'static {
    fn get_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> Pin<Box<dyn Future<Output = Option<CsEntry>> + Send + 'a>>;

    fn insert_erased(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> Pin<Box<dyn Future<Output = InsertResult> + Send + '_>>;

    fn evict_erased<'a>(
        &'a self,
        name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    fn evict_prefix_erased<'a>(
        &'a self,
        prefix: &'a Name,
        limit: Option<usize>,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>>;

    fn capacity(&self) -> CsCapacity;
    fn set_capacity(&self, max_bytes: usize);
    fn admit_enabled(&self) -> bool;
    fn serve_enabled(&self) -> bool;
    fn set_admit(&self, enabled: bool);
    fn set_serve(&self, enabled: bool);
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn current_bytes(&self) -> usize;
    fn variant_name(&self) -> &str;
    fn stats(&self) -> CsStats;
}

impl<T: ContentStore> ErasedContentStore for T {
    fn get_erased<'a>(
        &'a self,
        interest: &'a Interest,
    ) -> Pin<Box<dyn Future<Output = Option<CsEntry>> + Send + 'a>> {
        Box::pin(self.get(interest))
    }

    fn insert_erased(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> Pin<Box<dyn Future<Output = InsertResult> + Send + '_>> {
        Box::pin(self.insert(data, name, meta))
    }

    fn evict_erased<'a>(
        &'a self,
        name: &'a Name,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(self.evict(name))
    }

    fn evict_prefix_erased<'a>(
        &'a self,
        prefix: &'a Name,
        limit: Option<usize>,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>> {
        Box::pin(self.evict_prefix(prefix, limit))
    }

    fn capacity(&self) -> CsCapacity {
        ContentStore::capacity(self)
    }

    fn set_capacity(&self, max_bytes: usize) {
        ContentStore::set_capacity(self, max_bytes)
    }

    fn admit_enabled(&self) -> bool {
        ContentStore::admit_enabled(self)
    }
    fn serve_enabled(&self) -> bool {
        ContentStore::serve_enabled(self)
    }
    fn set_admit(&self, enabled: bool) {
        ContentStore::set_admit(self, enabled)
    }
    fn set_serve(&self, enabled: bool) {
        ContentStore::set_serve(self, enabled)
    }

    fn len(&self) -> usize {
        ContentStore::len(self)
    }

    fn is_empty(&self) -> bool {
        ContentStore::is_empty(self)
    }

    fn current_bytes(&self) -> usize {
        ContentStore::current_bytes(self)
    }

    fn variant_name(&self) -> &str {
        ContentStore::variant_name(self)
    }

    fn stats(&self) -> CsStats {
        ContentStore::stats(self)
    }
}

/// Policy controlling whether a Data packet is admitted to the CS.
pub trait CsAdmissionPolicy: Send + Sync + 'static {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool;
}

/// Admit only Data with a positive `FreshnessPeriod`. Matches NFD's default
/// `admit` policy: caching `FreshnessPeriod=0` Data churns evictions without
/// ever satisfying `MustBeFresh` Interests.
pub struct DefaultAdmissionPolicy;

impl CsAdmissionPolicy for DefaultAdmissionPolicy {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool {
        matches!(
            data.meta_info().and_then(|m| m.freshness_period),
            Some(d) if !d.is_zero()
        )
    }
}

/// Admit every Data unconditionally.
pub struct AdmitAllPolicy;

impl CsAdmissionPolicy for AdmitAllPolicy {
    fn should_admit(&self, _: &ndn_packet::Data) -> bool {
        true
    }
}

/// No-op content store.
pub struct NullCs;

impl ContentStore for NullCs {
    async fn get(&self, _: &Interest) -> Option<CsEntry> {
        None
    }
    async fn insert(&self, _: Bytes, _: Arc<Name>, _: CsMeta) -> InsertResult {
        InsertResult::Skipped
    }
    async fn evict(&self, _: &Name) -> bool {
        false
    }
    fn capacity(&self) -> CsCapacity {
        CsCapacity::zero()
    }
    fn variant_name(&self) -> &str {
        "null"
    }
}
