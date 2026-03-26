use std::sync::Arc;
use ndn_packet::Name;
use ndn_store::NameTrie;
use ndn_transport::FaceId;

/// A single FIB nexthop: a face with an associated routing cost.
#[derive(Clone, Debug)]
pub struct FibNexthop {
    pub face_id: FaceId,
    pub cost:    u32,
}

/// A FIB entry at a name prefix: one or more nexthops.
#[derive(Clone, Debug)]
pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

impl FibEntry {
    pub fn nexthops_excluding(&self, exclude: FaceId) -> Vec<FibNexthop> {
        self.nexthops.iter().filter(|n| n.face_id != exclude).cloned().collect()
    }
}

/// The Forwarding Information Base.
///
/// A name trie mapping prefixes to `FibEntry` values. Concurrent longest-prefix
/// match with per-node `RwLock` (via `NameTrie`).
pub struct Fib {
    trie: NameTrie<Arc<FibEntry>>,
}

impl Fib {
    pub fn new() -> Self {
        Self { trie: NameTrie::new() }
    }

    /// Longest-prefix match lookup.
    pub fn lpm(&self, name: &Name) -> Option<Arc<FibEntry>> {
        self.trie.lpm(name)
    }

    /// Register a nexthop for `prefix`. Replaces any existing entry.
    pub fn add_nexthop(&self, prefix: &Name, face_id: FaceId, cost: u32) {
        let existing = self.trie.get(prefix);
        let mut nexthops = existing
            .map(|e| e.nexthops.clone())
            .unwrap_or_default();
        // Remove any existing entry for this face, then add the new one.
        nexthops.retain(|n| n.face_id != face_id);
        nexthops.push(FibNexthop { face_id, cost });
        self.trie.insert(prefix, Arc::new(FibEntry { nexthops }));
    }

    /// Remove the nexthop for `face_id` from `prefix`.
    pub fn remove_nexthop(&self, prefix: &Name, face_id: FaceId) {
        let Some(existing) = self.trie.get(prefix) else { return };
        let nexthops: Vec<_> = existing.nexthops
            .iter()
            .filter(|n| n.face_id != face_id)
            .cloned()
            .collect();
        if nexthops.is_empty() {
            self.trie.remove(prefix);
        } else {
            self.trie.insert(prefix, Arc::new(FibEntry { nexthops }));
        }
    }
}

impl Default for Fib {
    fn default() -> Self { Self::new() }
}
