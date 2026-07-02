//! Dead Nonce List: cross-PIT-lifetime loop detection.
//!
//! `nonces_seen` on [`PitEntry`](crate::pit::PitEntry) covers loop detection
//! within a single PIT entry's lifetime; once the entry is satisfied or
//! expires those nonces are forgotten. The DNL retains a `(name_hash, nonce)`
//! fingerprint past PIT erasure for a configurable window.
//!
//! Spec: <https://named-data.net/doc/NFD/current/specs/dead-nonce-list.html>.

use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;

/// NFD's default DNL entry lifetime
/// (`daemon/table/dead-nonce-list.cpp:32`). Override via
/// [`DeadNonceList::with_lifetime`].
pub const DEFAULT_DEAD_NONCE_LIFETIME: Duration = Duration::from_secs(6);

/// Hard ceiling on DNL entries (audit D-1). The list is time-bounded, but
/// without a capacity cap an Interest flood with unique `(name, nonce)` grows it
/// to `rate × lifetime` between GC ticks (tens-to-hundreds of MB at high pps).
/// NFD's DNL is capacity-bounded; this is the analogue. ~1M entries (≈ tens of
/// MB) is far above any legitimate `rate × 6 s` working set (e.g. 100k pps →
/// 600k) so it never evicts a live nonce under normal load.
pub const DEFAULT_DEAD_NONCE_CAPACITY: usize = 1 << 20;

/// A `(name_hash, nonce)` fingerprint. Names are hashed before reaching the
/// DNL so the table key is fixed-size regardless of name length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonceFingerprint {
    pub name_hash: u64,
    pub nonce: u32,
}

impl NonceFingerprint {
    pub fn new(name_hash: u64, nonce: u32) -> Self {
        Self { name_hash, nonce }
    }
}

/// Cross-PIT-lifetime nonce history. Each entry expires at `now_ns +
/// lifetime_ns`; callers should run [`Self::purge_expired`] periodically
/// (the PIT GC tick is the natural cadence).
pub struct DeadNonceList {
    #[cfg(not(target_arch = "wasm32"))]
    entries: DashMap<NonceFingerprint, u64>,
    #[cfg(target_arch = "wasm32")]
    entries: std::sync::Mutex<std::collections::HashMap<NonceFingerprint, u64>>,
    lifetime_ns: u64,
    capacity: usize,
}

impl DeadNonceList {
    pub fn new() -> Self {
        Self::with_lifetime(DEFAULT_DEAD_NONCE_LIFETIME)
    }

    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self::with_lifetime_and_capacity(lifetime, DEFAULT_DEAD_NONCE_CAPACITY)
    }

    pub fn with_lifetime_and_capacity(lifetime: Duration, capacity: usize) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            entries: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
            lifetime_ns: lifetime.as_nanos() as u64,
            capacity: capacity.max(1),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn lifetime_ns(&self) -> u64 {
        self.lifetime_ns
    }

    /// Insert a fingerprint with expiry `now_ns + lifetime_ns`. Re-inserting
    /// the same fingerprint bumps the expiry (matches NFD).
    pub fn insert(&self, fp: NonceFingerprint, now_ns: u64) {
        let expiry = now_ns.saturating_add(self.lifetime_ns);
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.entries.insert(fp, expiry);
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.entries.lock().unwrap().insert(fp, expiry);
        }
        // Hard cap (audit D-1): drop expired first, then evict the
        // soonest-to-expire down to 90% if a flood still has us over capacity.
        if self.len() > self.capacity {
            self.enforce_capacity(now_ns);
        }
    }

    /// Bound the table to `capacity`: purge expired, then if still over, evict
    /// the soonest-to-expire entries down to 90% of capacity so the next
    /// enforcement is amortized over ~10% of capacity inserts.
    fn enforce_capacity(&self, now_ns: u64) {
        self.purge_expired(now_ns);
        let len = self.len();
        if len <= self.capacity {
            return;
        }
        let target = self.capacity - self.capacity / 10;
        let to_remove = len - target;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut by_expiry: Vec<(u64, NonceFingerprint)> = self
                .entries
                .iter()
                .map(|r| (*r.value(), *r.key()))
                .collect();
            by_expiry.sort_unstable_by_key(|(e, _)| *e);
            for (_, fp) in by_expiry.into_iter().take(to_remove) {
                self.entries.remove(&fp);
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let mut by_expiry: Vec<(u64, NonceFingerprint)> =
                entries.iter().map(|(k, e)| (*e, *k)).collect();
            by_expiry.sort_unstable_by_key(|(e, _)| *e);
            for (_, fp) in by_expiry.into_iter().take(to_remove) {
                entries.remove(&fp);
            }
        }
    }

    /// `true` iff `fp` is present and its entry has not expired by `now_ns`.
    /// Expired entries are treated as absent without a purge.
    pub fn contains(&self, fp: NonceFingerprint, now_ns: u64) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.entries.get(&fp).is_some_and(|e| now_ns < *e)
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.entries
                .lock()
                .unwrap()
                .get(&fp)
                .is_some_and(|e| now_ns < *e)
        }
    }

    /// Drop expired entries. Returns the number of entries removed.
    pub fn purge_expired(&self, now_ns: u64) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let stale: Vec<NonceFingerprint> = self
                .entries
                .iter()
                .filter(|r| now_ns >= *r.value())
                .map(|r| *r.key())
                .collect();
            for fp in &stale {
                self.entries.remove(fp);
            }
            stale.len()
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let stale: Vec<NonceFingerprint> = entries
                .iter()
                .filter(|(_, e)| now_ns >= **e)
                .map(|(k, _)| *k)
                .collect();
            for fp in &stale {
                entries.remove(fp);
            }
            stale.len()
        }
    }

    pub fn len(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.len();
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().len();
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.is_empty();
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().is_empty();
    }
}

impl Default for DeadNonceList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(name: u64, nonce: u32) -> NonceFingerprint {
        NonceFingerprint::new(name, nonce)
    }

    #[test]
    fn n06_insert_and_lookup_within_lifetime() {
        let dnl = DeadNonceList::with_lifetime(Duration::from_millis(100));
        let key = fp(0xDEAD_BEEF, 42);
        let now = 1_000_000_000u64;
        dnl.insert(key, now);
        assert!(dnl.contains(key, now));
        assert!(dnl.contains(key, now + 50_000_000));
        assert!(!dnl.contains(key, now + 101_000_000));
    }

    #[test]
    fn n06_lookup_absent_entry() {
        let dnl = DeadNonceList::new();
        assert!(!dnl.contains(fp(1, 1), 0));
        assert!(!dnl.contains(fp(1, 1), u64::MAX));
    }

    #[test]
    fn n06_reinsert_bumps_expiry() {
        let dnl = DeadNonceList::with_lifetime(Duration::from_millis(50));
        let key = fp(0xAA, 7);
        let t0 = 0u64;
        dnl.insert(key, t0);
        let t1 = t0 + 30_000_000;
        dnl.insert(key, t1);
        assert!(dnl.contains(key, t0 + 60_000_000));
        assert!(!dnl.contains(key, t0 + 90_000_000));
    }

    #[test]
    fn n06_purge_expired_drops_stale_only() {
        let dnl = DeadNonceList::with_lifetime(Duration::from_millis(10));
        let now = 1_000_000_000u64;
        dnl.insert(fp(1, 1), now);
        dnl.insert(fp(2, 2), now);
        dnl.insert(fp(3, 3), now + 5_000_000);
        assert_eq!(dnl.len(), 3);

        let removed = dnl.purge_expired(now + 11_000_000);
        assert_eq!(removed, 2);
        assert_eq!(dnl.len(), 1);
        assert!(dnl.contains(fp(3, 3), now + 11_000_000));
    }

    #[test]
    fn n06_distinct_nonces_under_same_name_hash() {
        let dnl = DeadNonceList::new();
        let now = 1_000_000_000u64;
        dnl.insert(fp(0xCAFE, 100), now);
        dnl.insert(fp(0xCAFE, 200), now);
        assert!(dnl.contains(fp(0xCAFE, 100), now));
        assert!(dnl.contains(fp(0xCAFE, 200), now));
        assert!(!dnl.contains(fp(0xCAFE, 300), now));
    }

    #[test]
    fn d1_capacity_cap_bounds_unique_nonce_flood() {
        // Long lifetime so nothing expires; small capacity so the cap, not the
        // clock, is what bounds the table under a unique-nonce flood.
        let cap = 100;
        let dnl = DeadNonceList::with_lifetime_and_capacity(Duration::from_secs(3600), cap);
        let now = 1_000_000_000u64;
        for i in 0..10_000u64 {
            dnl.insert(fp(i, i as u32), now);
        }
        // Never exceeds the ceiling (eviction keeps it at/under capacity).
        assert!(
            dnl.len() <= cap,
            "DNL grew past capacity: {} > {cap}",
            dnl.len()
        );
        // The most-recently-inserted nonce is still present (we evict oldest).
        assert!(dnl.contains(fp(9_999, 9_999), now));
    }

    #[test]
    fn n06_default_lifetime_matches_nfd() {
        let dnl = DeadNonceList::default();
        assert_eq!(
            dnl.lifetime_ns(),
            DEFAULT_DEAD_NONCE_LIFETIME.as_nanos() as u64
        );
    }
}
