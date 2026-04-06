//! Forwarding Information Base (FIB) for embedded NDN nodes.
//!
//! Uses a fixed-capacity [`heapless::Vec`] with linear scan for longest-prefix
//! match. For a typical embedded node with 4–16 static routes this is faster
//! than a hash map (no hashing overhead, cache-friendly scan of small arrays).
//!
//! Entries are keyed by (prefix_hash, prefix_len) pairs. Prefix hashes are
//! computed with [`crate::pit::fnv1a64`] over the wire-encoded Name bytes.
//! Longest-prefix match iterates all entries and returns the nexthop of the
//! entry with the highest `prefix_len` that matches the Interest name's prefix.

use heapless::Vec;

use crate::face::FaceId;
use crate::pit::fnv1a64;

/// A single FIB entry.
#[derive(Clone, Debug)]
pub struct FibEntry {
    /// FNV-1a 64-bit hash of the prefix Name wire bytes.
    pub prefix_hash: u64,
    /// Number of name components in the prefix (0 = default route).
    pub prefix_len: u8,
    /// Nexthop face to forward matching Interests on.
    pub nexthop: FaceId,
    /// Route cost (lower is preferred; used for tie-breaking in future).
    pub cost: u8,
}

/// Forwarding Information Base with fixed capacity `N`.
pub struct Fib<const N: usize> {
    entries: Vec<FibEntry, N>,
}

impl<const N: usize> Fib<N> {
    /// Creates an empty FIB.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a route.
    ///
    /// If an entry with the same (prefix_hash, prefix_len) already exists,
    /// it is replaced (updated nexthop/cost). If the table is full and no
    /// existing entry matches, the new route is silently dropped.
    pub fn add(&mut self, entry: FibEntry) {
        // Update existing entry if the prefix is already present.
        for e in self.entries.iter_mut() {
            if e.prefix_hash == entry.prefix_hash && e.prefix_len == entry.prefix_len {
                e.nexthop = entry.nexthop;
                e.cost = entry.cost;
                return;
            }
        }
        // Otherwise insert (silently drops if full).
        let _ = self.entries.push(entry);
    }

    /// Ergonomic helper: add a route from a slash-delimited NDN name string.
    ///
    /// Parses `prefix` (e.g. `"/ndn/sensor"`) by splitting on `'/'` and
    /// skipping empty segments. Uses a stack-allocated buffer of up to 16
    /// components; silently returns early if the name exceeds that limit.
    ///
    /// Equivalent to computing `prefix_hash` / `prefix_len` manually and
    /// calling [`add`](Self::add).
    ///
    /// ```rust,ignore
    /// fib.add_route("/ndn/sensor", 1);
    /// fib.add_route("/",           0); // default route (face 0)
    /// ```
    pub fn add_route(&mut self, prefix: &str, nexthop: FaceId) {
        let mut components: heapless::Vec<&[u8], 16> = heapless::Vec::new();
        for part in prefix.split('/') {
            if part.is_empty() {
                continue;
            }
            if components.push(part.as_bytes()).is_err() {
                return; // >16 components: silently drop, same contract as add() when full
            }
        }
        self.add(FibEntry {
            prefix_hash: hash_prefix(&components),
            prefix_len: components.len() as u8,
            nexthop,
            cost: 0,
        });
    }

    /// Removes a route by prefix hash and length.
    pub fn remove(&mut self, prefix_hash: u64, prefix_len: u8) {
        self.entries
            .retain(|e| !(e.prefix_hash == prefix_hash && e.prefix_len == prefix_len));
    }

    /// Longest-prefix match against the name components supplied as raw TLV slices.
    ///
    /// `components` is a slice of per-component wire bytes (just the TLV value,
    /// not including the outer type/length). The forwarder calls this after
    /// parsing the Interest name. For each candidate prefix length (from longest
    /// to shortest), the function hashes the corresponding prefix and checks
    /// the FIB.
    ///
    /// Returns the nexthop `FaceId` of the best matching route, or `None` if
    /// no route matches (not even a default route).
    pub fn lookup(&self, components: &[&[u8]]) -> Option<FaceId> {
        let mut best_len: i16 = -1;
        let mut best_face = None;

        for entry in self.entries.iter() {
            let plen = entry.prefix_len as usize;
            if plen > components.len() {
                continue;
            }
            // Hash the first `plen` components to form the prefix hash.
            let hash = hash_prefix(&components[..plen]);
            if hash == entry.prefix_hash && (plen as i16) > best_len {
                best_len = plen as i16;
                best_face = Some(entry.nexthop);
            }
        }

        best_face
    }

    /// Returns the number of routes in the FIB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the FIB is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<const N: usize> Default for Fib<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash a prefix (slice of name component byte slices) to a u64.
///
/// The hash is computed by feeding all component bytes through FNV-1a,
/// with a 0xFF separator between components to prevent prefix collisions
/// (e.g. `/a/bc` ≠ `/ab/c`).
fn hash_prefix(components: &[&[u8]]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for (i, comp) in components.iter().enumerate() {
        if i > 0 {
            // Separator byte between components.
            hash ^= 0xFF_u64;
            hash = hash.wrapping_mul(PRIME);
        }
        for &b in *comp {
            hash ^= b as u64;
            hash = hash.wrapping_mul(PRIME);
        }
    }
    hash
}

/// Compute the prefix hash for a given list of component byte slices.
///
/// Use this to pre-compute `FibEntry::prefix_hash` when building static routes.
pub fn prefix_hash(components: &[&[u8]]) -> u64 {
    hash_prefix(components)
}

/// Convenience: compute the prefix hash for a single-component prefix.
pub fn single_component_hash(comp: &[u8]) -> u64 {
    fnv1a64(comp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(comps: &[&[u8]], nexthop: FaceId) -> FibEntry {
        FibEntry {
            prefix_hash: prefix_hash(comps),
            prefix_len: comps.len() as u8,
            nexthop,
            cost: 0,
        }
    }

    #[test]
    fn basic_lookup() {
        let mut fib = Fib::<8>::new();
        fib.add(entry(&[b"ndn"], 1));
        fib.add(entry(&[b"ndn", b"ucla"], 2));

        // /ndn/ucla/data should match /ndn/ucla (face 2)
        let result = fib.lookup(&[b"ndn" as &[u8], b"ucla", b"data"]);
        assert_eq!(result, Some(2));
    }

    #[test]
    fn default_route() {
        let mut fib = Fib::<4>::new();
        // A zero-length prefix acts as a default route.
        fib.add(FibEntry {
            prefix_hash: prefix_hash(&[]),
            prefix_len: 0,
            nexthop: 3,
            cost: 0,
        });

        let result = fib.lookup(&[b"anything"]);
        assert_eq!(result, Some(3));
    }

    #[test]
    fn no_match_returns_none() {
        let fib = Fib::<4>::new();
        assert_eq!(fib.lookup(&[b"ndn"]), None);
    }

    #[test]
    fn longest_prefix_wins() {
        let mut fib = Fib::<8>::new();
        fib.add(entry(&[b"ndn"], 1));
        fib.add(entry(&[b"ndn", b"edu"], 2));
        fib.add(entry(&[b"ndn", b"edu", b"ucla"], 3));

        // /ndn/edu/ucla/data → longest match = /ndn/edu/ucla (face 3)
        assert_eq!(fib.lookup(&[b"ndn", b"edu", b"ucla", b"data"]), Some(3));
        // /ndn/edu/mit/data → longest match = /ndn/edu (face 2)
        assert_eq!(fib.lookup(&[b"ndn", b"edu", b"mit", b"data"]), Some(2));
        // /ndn/something/else → longest match = /ndn (face 1)
        assert_eq!(fib.lookup(&[b"ndn", b"something"]), Some(1));
    }

    #[test]
    fn update_existing_route() {
        let mut fib = Fib::<4>::new();
        fib.add(entry(&[b"ndn"], 1));
        // Overwrite with a different nexthop.
        fib.add(FibEntry {
            prefix_hash: prefix_hash(&[b"ndn"]),
            prefix_len: 1,
            nexthop: 99,
            cost: 0,
        });
        assert_eq!(fib.len(), 1);
        assert_eq!(fib.lookup(&[b"ndn", b"test"]), Some(99));
    }

    #[test]
    fn remove_route() {
        let mut fib = Fib::<4>::new();
        fib.add(entry(&[b"ndn"], 1));
        fib.remove(prefix_hash(&[b"ndn"]), 1);
        assert_eq!(fib.lookup(&[b"ndn"]), None);
    }
}
