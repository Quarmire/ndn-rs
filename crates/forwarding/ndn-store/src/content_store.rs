use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::{Interest, Name};

/// A cache entry holding wire-format Data bytes (no re-encoding on hit).
#[derive(Clone, Debug)]
pub struct CsEntry {
    pub data: Bytes,
    /// Unix-epoch nanoseconds, on the caller's clock, after which the entry
    /// no longer satisfies `MustBeFresh` (arrival + `FreshnessPeriod`).
    pub stale_at: u64,
    pub name: Arc<Name>,
    /// The validator keyring's revocation epoch this Data was last judged
    /// under (validated, or since re-checked by [`ContentStore::restamp`]);
    /// `None` if it was cached without validation. A persistent store
    /// reports [`EARLIER_PROCESS_EPOCH`] for an entry stamped by an earlier
    /// process.
    pub revocation_epoch: Option<u64>,
}

/// The [`CsEntry::revocation_epoch`] of an entry a persistent store holds
/// from an earlier process. Keyring epochs count from 0 in each process and
/// never reach it, so such an entry is always re-checked before it is served.
pub const EARLIER_PROCESS_EPOCH: u64 = u64::MAX;

impl CsEntry {
    pub fn is_fresh(&self, now_ns: u64) -> bool {
        ndn_fwd_core::freshness::fresh_until(now_ns, self.stale_at)
    }
}

pub struct CsMeta {
    pub stale_at: u64,
    /// The revocation epoch read before the Data was validated; `None` if it
    /// was not validated. Stored as the entry's
    /// [`revocation_epoch`](CsEntry::revocation_epoch).
    pub revocation_epoch: Option<u64>,
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

/// A predicate over a cached Data's wire bytes (see
/// [`ContentStore::evict_matching`]).
pub type CsEntryFilter = dyn Fn(&Bytes) -> bool + Send + Sync;

/// Content store interface. Methods are `async` so persistent (disk-backed)
/// implementations are supported; in-memory ones complete synchronously.
///
/// Freshness is never judged on a store's own clock. `get` is told the lookup
/// time and compares it with the `stale_at` its caller stamped at insert, so
/// both sides of the comparison come from ONE clock — the engine runtime's
/// (`ctx.arrival`). Reading the system clock here instead made the two sides
/// disagree under a simulated runtime: `stale_at` was virtual time, the lookup
/// was wall time, so FreshnessPeriod stopped meaning what the producer set.
pub trait ContentStore: Send + Sync + 'static {
    /// Look up a Data satisfying `interest` at time `now_ns` (Unix-epoch ns,
    /// the same time base as [`CsMeta::stale_at`]).
    fn get(&self, interest: &Interest, now_ns: u64)
    -> impl Future<Output = Option<CsEntry>> + Send;

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

    /// Evict every entry named under `prefix` whose Data wire satisfies
    /// `matches`; returns how many were evicted. Scans that subtree and
    /// may decode each entry: for rare events (a signing key revoked), never
    /// the forwarding path. An entry replaced while it is judged is kept.
    fn evict_matching(
        &self,
        prefix: &Name,
        matches: &CsEntryFilter,
    ) -> impl Future<Output = usize> + Send;

    /// Mark the entry named `name`, if it still holds `data`, as judged
    /// under revocation `epoch` (sets its
    /// [`revocation_epoch`](CsEntry::revocation_epoch)). An entry replaced by
    /// other bytes or evicted meanwhile is left alone.
    fn restamp(&self, name: &Name, data: &Bytes, epoch: u64) -> impl Future<Output = ()> + Send;

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
        now_ns: u64,
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

    fn evict_matching_erased<'a>(
        &'a self,
        prefix: &'a Name,
        matches: &'a CsEntryFilter,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>>;

    fn restamp_erased<'a>(
        &'a self,
        name: &'a Name,
        data: &'a Bytes,
        epoch: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

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
        now_ns: u64,
    ) -> Pin<Box<dyn Future<Output = Option<CsEntry>> + Send + 'a>> {
        Box::pin(self.get(interest, now_ns))
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

    fn evict_matching_erased<'a>(
        &'a self,
        prefix: &'a Name,
        matches: &'a CsEntryFilter,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>> {
        Box::pin(self.evict_matching(prefix, matches))
    }

    fn restamp_erased<'a>(
        &'a self,
        name: &'a Name,
        data: &'a Bytes,
        epoch: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(self.restamp(name, data, epoch))
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
    async fn get(&self, _: &Interest, _: u64) -> Option<CsEntry> {
        None
    }
    async fn insert(&self, _: Bytes, _: Arc<Name>, _: CsMeta) -> InsertResult {
        InsertResult::Skipped
    }
    async fn evict(&self, _: &Name) -> bool {
        false
    }
    async fn evict_matching(&self, _: &Name, _: &CsEntryFilter) -> usize {
        0
    }
    async fn restamp(&self, _: &Name, _: &Bytes, _: u64) {}
    fn capacity(&self) -> CsCapacity {
        CsCapacity::zero()
    }
    fn variant_name(&self) -> &str {
        "null"
    }
}
