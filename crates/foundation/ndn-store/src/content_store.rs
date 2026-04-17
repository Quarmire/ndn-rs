use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::{Interest, Name};

/// A cache entry: wire-format Data bytes plus derived metadata.
///
/// Storing wire bytes (not decoded `Data`) means CS hits produce send-ready
/// bytes with no re-encoding cost.
#[derive(Clone, Debug)]
pub struct CsEntry {
    pub data: Bytes,
    /// Nanoseconds since Unix epoch, derived from `FreshnessPeriod`.
    pub stale_at: u64,
    pub name: Arc<Name>,
}

impl CsEntry {
    pub fn is_fresh(&self, now_ns: u64) -> bool {
        self.stale_at > now_ns
    }
}

/// Metadata provided to the CS on insert.
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

/// The ContentStore trait.
///
/// All methods are `async` to allow persistent (disk-backed) implementations.
/// In-memory implementations complete synchronously but Tokio will inline the
/// no-op future at zero cost.
pub trait ContentStore: Send + Sync + 'static {
    fn get(&self, interest: &Interest) -> impl Future<Output = Option<CsEntry>> + Send;

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

/// Object-safe version of [`ContentStore`] that boxes its futures.
///
/// A blanket impl automatically wraps any `ContentStore` implementor, so custom
/// CS implementations only need to implement `ContentStore`.
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

/// Policy that decides whether a Data packet should be admitted to the CS.
pub trait CsAdmissionPolicy: Send + Sync + 'static {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool;
}

/// Default policy: admit only Data packets that have a positive FreshnessPeriod.
///
/// Data without FreshnessPeriod or with FreshnessPeriod=0 is immediately stale
/// and not worth caching — it would fill the CS with entries that can never
/// satisfy `MustBeFresh` Interests, causing eviction churn under high throughput.
/// This matches NFD's default `admit` policy behavior.
pub struct DefaultAdmissionPolicy;

impl CsAdmissionPolicy for DefaultAdmissionPolicy {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool {
        matches!(
            data.meta_info().and_then(|m| m.freshness_period),
            Some(d) if !d.is_zero()
        )
    }
}

/// Admit everything unconditionally — useful when the application manages
/// freshness externally or for testing.
pub struct AdmitAllPolicy;

impl CsAdmissionPolicy for AdmitAllPolicy {
    fn should_admit(&self, _: &ndn_packet::Data) -> bool {
        true
    }
}

/// No-op content store for cache-less operation.
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
