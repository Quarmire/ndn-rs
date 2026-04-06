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
    /// Wire-format Data packet.
    pub data: Bytes,
    /// Expiry time (ns since Unix epoch). Derived from `FreshnessPeriod`.
    pub stale_at: u64,
    /// Name of the cached Data.
    pub name: Arc<Name>,
}

impl CsEntry {
    pub fn is_fresh(&self, now_ns: u64) -> bool {
        self.stale_at > now_ns
    }
}

/// Metadata provided to the CS on insert.
pub struct CsMeta {
    /// When this entry becomes stale (ns since Unix epoch).
    pub stale_at: u64,
}

/// Result of a CS insert operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertResult {
    /// Entry was stored.
    Inserted,
    /// Entry replaced an existing entry for the same name.
    Replaced,
    /// Entry was not stored (e.g., CS is disabled or at capacity with no eviction).
    Skipped,
}

/// Capacity of a content store.
#[derive(Debug, Clone, Copy)]
pub struct CsCapacity {
    /// Maximum bytes the store will hold.
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

/// Snapshot of content store hit/miss/insert/eviction counters.
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
    /// Look up a Data packet matching `interest`.
    /// Honours `MustBeFresh` and `CanBePrefix` selectors.
    fn get(&self, interest: &Interest) -> impl Future<Output = Option<CsEntry>> + Send;

    /// Store a Data packet. May evict least-recently-used entries to make room.
    fn insert(
        &self,
        data: Bytes,
        name: Arc<Name>,
        meta: CsMeta,
    ) -> impl Future<Output = InsertResult> + Send;

    /// Explicitly evict the entry for `name`.
    fn evict(&self, name: &Name) -> impl Future<Output = bool> + Send;

    /// Current capacity configuration.
    fn capacity(&self) -> CsCapacity;

    /// Number of entries currently cached.
    fn len(&self) -> usize {
        0
    }

    /// Returns `true` if the content store contains no entries.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total bytes currently used.
    fn current_bytes(&self) -> usize {
        0
    }

    /// Update the maximum byte capacity at runtime.
    fn set_capacity(&self, _max_bytes: usize) {}

    /// Human-readable name of this CS implementation (e.g. "lru", "sharded-lru").
    fn variant_name(&self) -> &str {
        "unknown"
    }

    /// Evict all entries matching `prefix`, up to `limit` entries (None = unlimited).
    /// Returns the number of entries evicted.
    fn evict_prefix(
        &self,
        _prefix: &Name,
        _limit: Option<usize>,
    ) -> impl Future<Output = usize> + Send {
        async { 0 }
    }

    /// Snapshot of hit/miss/insert/eviction counters.
    fn stats(&self) -> CsStats {
        CsStats::default()
    }
}

// ─── ErasedContentStore (object-safe) ───────────────────────────────────────

/// Object-safe version of [`ContentStore`] that boxes its futures.
///
/// Follows the same pattern as `ErasedStrategy` — a blanket impl automatically
/// wraps any `ContentStore` implementor, so custom CS implementations only need
/// to implement `ContentStore`.
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

// ─── Admission policies ─────────────────────────────────────────────────────

/// Policy that decides whether a Data packet should be admitted to the CS.
///
/// Implementations can inspect the decoded Data to make admission decisions
/// based on FreshnessPeriod, ContentType, name prefix, etc.
pub trait CsAdmissionPolicy: Send + Sync + 'static {
    /// Returns `true` if the Data should be cached.
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

/// A no-op content store — disables caching entirely at zero pipeline cost.
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
