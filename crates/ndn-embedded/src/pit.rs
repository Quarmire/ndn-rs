//! Pending Interest Table (PIT) for embedded NDN nodes.
//!
//! Uses a fixed-capacity [`heapless::Vec`] — no heap allocation required.
//! Entries are keyed by a 64-bit FNV-1a hash of the Interest Name wire bytes,
//! which avoids storing a full [`Name`](ndn_packet::Name) struct (SmallVec +
//! Bytes) in each entry.
//!
//! **Collision probability**: FNV-1a 64-bit has ~2^-64 collision probability
//! per pair. For a PIT of 64 entries in a sensor node, this is negligible.
//! The nonce check provides an additional guard against false positives.

use heapless::Vec;

use crate::face::FaceId;

/// A PIT entry.
#[derive(Clone, Debug)]
pub struct PitEntry {
    /// FNV-1a 64-bit hash of the Interest Name wire bytes.
    pub name_hash: u64,
    /// Face the Interest arrived on (the face to satisfy back to).
    pub incoming_face: FaceId,
    /// Interest nonce — used for loop detection.
    pub nonce: u32,
    /// Timestamp at which this entry was created (ms ticks).
    pub created_ms: u32,
    /// Interest lifetime in milliseconds.
    pub lifetime_ms: u32,
}

/// Pending Interest Table with fixed capacity `N`.
///
/// # Type parameter
///
/// `N` is the maximum number of pending Interests. For a simple sensor node
/// 16–64 entries are typical; for an edge router 128–256 may be appropriate
/// (check your RAM budget first).
pub struct Pit<const N: usize> {
    entries: Vec<PitEntry, N>,
}

impl<const N: usize> Pit<N> {
    /// Creates an empty PIT.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Inserts a new PIT entry.
    ///
    /// If the table is full, the oldest entry (index 0) is evicted to make room.
    /// This implements a simple FIFO eviction policy — oldest pending Interests
    /// are dropped first, which is appropriate for sensor nodes with burst traffic.
    pub fn insert(&mut self, entry: PitEntry) {
        if self.entries.is_full() {
            self.entries.remove(0);
        }
        // Safety: we just ensured there is space.
        let _ = self.entries.push(entry);
    }

    /// Looks up a PIT entry by name hash.
    ///
    /// Returns the first matching entry, or `None` if no match is found.
    pub fn lookup(&self, name_hash: u64) -> Option<&PitEntry> {
        self.entries.iter().find(|e| e.name_hash == name_hash)
    }

    /// Removes a PIT entry by name hash.
    ///
    /// Returns the removed entry, or `None` if not found.
    pub fn remove(&mut self, name_hash: u64) -> Option<PitEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.name_hash == name_hash) {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }

    /// Returns `true` if `nonce` is already recorded in any PIT entry.
    ///
    /// Used for loop detection: an Interest with a nonce already in the PIT
    /// is a duplicate (or a loop) and should be dropped.
    pub fn has_nonce(&self, nonce: u32) -> bool {
        self.entries.iter().any(|e| e.nonce == nonce)
    }

    /// Evicts all entries whose lifetime has expired.
    ///
    /// `now_ms` should come from the [`Clock`](crate::Clock) passed to the
    /// forwarder. If `NoOpClock` is used (always returns 0), this function
    /// never evicts anything.
    pub fn purge_expired(&mut self, now_ms: u32) {
        self.entries.retain(|e| {
            let age = now_ms.wrapping_sub(e.created_ms);
            age < e.lifetime_ms
        });
    }

    /// Returns the current number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the PIT is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<const N: usize> Default for Pit<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute FNV-1a 64-bit hash of a byte slice.
///
/// Used to hash Interest Name wire bytes for PIT/FIB keying.
#[inline]
pub fn fnv1a64(data: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: u64, nonce: u32, incoming: FaceId) -> PitEntry {
        PitEntry {
            name_hash: hash,
            incoming_face: incoming,
            nonce,
            created_ms: 0,
            lifetime_ms: 4000,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut pit = Pit::<8>::new();
        pit.insert(entry(0xABCD, 1, 0));
        assert!(pit.lookup(0xABCD).is_some());
        assert!(pit.lookup(0x1234).is_none());
    }

    #[test]
    fn remove() {
        let mut pit = Pit::<8>::new();
        pit.insert(entry(0xABCD, 1, 0));
        let removed = pit.remove(0xABCD);
        assert!(removed.is_some());
        assert!(pit.lookup(0xABCD).is_none());
    }

    #[test]
    fn nonce_detection() {
        let mut pit = Pit::<8>::new();
        pit.insert(entry(0xABCD, 42, 0));
        assert!(pit.has_nonce(42));
        assert!(!pit.has_nonce(99));
    }

    #[test]
    fn eviction_when_full() {
        let mut pit = Pit::<4>::new();
        for i in 0..5u64 {
            pit.insert(entry(i, i as u32, 0));
        }
        // Oldest entry (hash=0) should have been evicted.
        assert_eq!(pit.len(), 4);
        assert!(pit.lookup(0).is_none());
        assert!(pit.lookup(4).is_some());
    }

    #[test]
    fn purge_expired() {
        let mut pit = Pit::<8>::new();
        pit.insert(PitEntry {
            name_hash: 1,
            incoming_face: 0,
            nonce: 1,
            created_ms: 0,
            lifetime_ms: 100,
        });
        pit.insert(PitEntry {
            name_hash: 2,
            incoming_face: 0,
            nonce: 2,
            created_ms: 0,
            lifetime_ms: 500,
        });
        // At t=200ms, entry 1 (lifetime=100) expired; entry 2 (lifetime=500) still alive.
        pit.purge_expired(200);
        assert!(pit.lookup(1).is_none());
        assert!(pit.lookup(2).is_some());
    }

    #[test]
    fn fnv1a64_deterministic() {
        assert_eq!(fnv1a64(b""), 0xcbf29ce484222325);
        let h1 = fnv1a64(b"/ndn/test");
        let h2 = fnv1a64(b"/ndn/test");
        assert_eq!(h1, h2);
        assert_ne!(fnv1a64(b"/ndn/test"), fnv1a64(b"/ndn/other"));
    }
}
