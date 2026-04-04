//! Minimal Content Store for embedded NDN nodes.
//!
//! Uses a fixed-capacity array with round-robin eviction. The content store
//! caches Data packets keyed by name hash, enabling the forwarder to satisfy
//! repeated Interests without re-forwarding them upstream.
//!
//! This module is behind the `cs` feature flag because:
//! - Content stores require storing packet bytes, which costs RAM.
//! - Many embedded nodes (sensors producing unique readings) don't benefit
//!   from a cache.
//!
//! Enable with: `ndn-embedded = { features = ["cs"] }`.

use crate::pit::fnv1a64;

/// A cached Data packet entry.
pub struct CsEntry<const MAX_LEN: usize> {
    /// FNV-1a hash of the Data Name wire bytes.
    pub name_hash: u64,
    /// Raw wire bytes of the Data packet (truncated if larger than MAX_LEN).
    data: [u8; MAX_LEN],
    /// Number of valid bytes in `data`.
    len: usize,
    /// Freshness period in milliseconds (0 = stale immediately).
    pub freshness_ms: u32,
    /// Timestamp when this entry was stored.
    pub stored_ms: u32,
}

impl<const MAX_LEN: usize> CsEntry<MAX_LEN> {
    fn empty() -> Self {
        Self {
            name_hash: 0,
            data: [0u8; MAX_LEN],
            len: 0,
            freshness_ms: 0,
            stored_ms: 0,
        }
    }

    /// Returns the stored Data wire bytes.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Returns `true` if this entry is still fresh at `now_ms`.
    pub fn is_fresh(&self, now_ms: u32) -> bool {
        if self.freshness_ms == 0 {
            return false;
        }
        let age = now_ms.wrapping_sub(self.stored_ms);
        age < self.freshness_ms
    }
}

/// Fixed-capacity Content Store with round-robin eviction.
///
/// # Type parameters
///
/// - `N`: maximum number of cached entries.
/// - `MAX_LEN`: maximum wire size of a single Data packet (bytes).
pub struct ContentStore<const N: usize, const MAX_LEN: usize> {
    entries: [CsEntry<MAX_LEN>; N],
    /// Index of the slot to overwrite on the next insert (round-robin).
    next_slot: usize,
    /// Number of valid (non-empty) entries.
    count: usize,
}

impl<const N: usize, const MAX_LEN: usize> ContentStore<N, MAX_LEN> {
    /// Creates an empty ContentStore.
    pub fn new() -> Self {
        // SAFETY: CsEntry is all-integer with no interior pointers.
        // We initialize it to "empty" state manually.
        Self {
            entries: core::array::from_fn(|_| CsEntry::empty()),
            next_slot: 0,
            count: 0,
        }
    }

    /// Look up a cached Data packet by name hash.
    ///
    /// Returns the raw Data wire bytes if found and fresh, or `None` otherwise.
    pub fn lookup(&self, name_hash: u64, now_ms: u32) -> Option<&[u8]> {
        for entry in &self.entries {
            if entry.len > 0 && entry.name_hash == name_hash && entry.is_fresh(now_ms) {
                return Some(entry.data());
            }
        }
        None
    }

    /// Insert a Data packet into the cache.
    ///
    /// If `data` is larger than `MAX_LEN`, it is silently truncated and the
    /// entry is stored with `len = MAX_LEN` (the wire bytes won't be valid,
    /// but the name hash can still be used for PIT matching).
    ///
    /// In practice, choose `MAX_LEN` to match your link MTU.
    pub fn insert(&mut self, name_hash: u64, data: &[u8], freshness_ms: u32, now_ms: u32) {
        // Overwrite any existing entry for the same name.
        for entry in self.entries.iter_mut() {
            if entry.len > 0 && entry.name_hash == name_hash {
                let n = data.len().min(MAX_LEN);
                entry.data[..n].copy_from_slice(&data[..n]);
                entry.len = n;
                entry.freshness_ms = freshness_ms;
                entry.stored_ms = now_ms;
                return;
            }
        }

        // Insert into the next slot (round-robin eviction).
        let slot = self.next_slot;
        let n = data.len().min(MAX_LEN);
        self.entries[slot].name_hash = name_hash;
        self.entries[slot].data[..n].copy_from_slice(&data[..n]);
        self.entries[slot].len = n;
        self.entries[slot].freshness_ms = freshness_ms;
        self.entries[slot].stored_ms = now_ms;

        self.next_slot = (slot + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    /// Returns the number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Compute the name hash for a raw Name TLV value byte slice.
    pub fn hash_name(name_wire: &[u8]) -> u64 {
        fnv1a64(name_wire)
    }
}

impl<const N: usize, const MAX_LEN: usize> Default for ContentStore<N, MAX_LEN> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let mut cs = ContentStore::<4, 64>::new();
        cs.insert(0xABCD, b"data-bytes", 1000, 0);
        let result = cs.lookup(0xABCD, 500);
        assert_eq!(result, Some(b"data-bytes" as &[u8]));
    }

    #[test]
    fn stale_entry_not_returned() {
        let mut cs = ContentStore::<4, 64>::new();
        cs.insert(0xABCD, b"data", 100, 0); // freshness 100ms, stored at t=0
        // At t=200ms, the entry is stale.
        assert!(cs.lookup(0xABCD, 200).is_none());
    }

    #[test]
    fn round_robin_eviction() {
        let mut cs = ContentStore::<2, 32>::new();
        cs.insert(1, b"one", 1000, 0);
        cs.insert(2, b"two", 1000, 0);
        cs.insert(3, b"three", 1000, 0); // evicts slot 0 (entry 1)
        assert!(cs.lookup(1, 0).is_none());
        assert!(cs.lookup(2, 0).is_some());
        assert!(cs.lookup(3, 0).is_some());
    }
}
