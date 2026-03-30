use bytes::Bytes;
use std::future::Future;

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
    pub name: std::sync::Arc<Name>,
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
    pub fn zero() -> Self { Self { max_bytes: 0 } }
    pub fn bytes(n: usize) -> Self { Self { max_bytes: n } }
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
        name: std::sync::Arc<Name>,
        meta: CsMeta,
    ) -> impl Future<Output = InsertResult> + Send;

    /// Explicitly evict the entry for `name`.
    fn evict(&self, name: &Name) -> impl Future<Output = bool> + Send;

    fn capacity(&self) -> CsCapacity;
}

/// Policy that decides whether a Data packet should be admitted to the CS.
///
/// Implementations can inspect the decoded Data to make admission decisions
/// based on FreshnessPeriod, ContentType, name prefix, etc.
pub trait CsAdmissionPolicy: Send + Sync + 'static {
    /// Returns `true` if the Data should be cached.
    fn should_admit(&self, data: &ndn_packet::Data) -> bool;
}

/// Default policy: admit all Data packets that have a non-zero FreshnessPeriod,
/// or that lack FreshnessPeriod (treated as "no freshness constraint" by the spec).
///
/// Data with FreshnessPeriod=0 is immediately stale and typically not worth caching.
pub struct DefaultAdmissionPolicy;

impl CsAdmissionPolicy for DefaultAdmissionPolicy {
    fn should_admit(&self, data: &ndn_packet::Data) -> bool {
        match data.meta_info().and_then(|m| m.freshness_period) {
            Some(d) if d.is_zero() => false,
            _ => true,
        }
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
    async fn get(&self, _: &Interest) -> Option<CsEntry> { None }
    async fn insert(&self, _: Bytes, _: std::sync::Arc<Name>, _: CsMeta) -> InsertResult {
        InsertResult::Skipped
    }
    async fn evict(&self, _: &Name) -> bool { false }
    fn capacity(&self) -> CsCapacity { CsCapacity::zero() }
}
