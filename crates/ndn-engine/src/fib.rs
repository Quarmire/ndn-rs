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

    /// Return all FIB entries as `(prefix_uri, [(face_id, cost)])` tuples.
    pub fn dump(&self) -> Vec<(Name, Arc<FibEntry>)> {
        self.trie.dump()
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn name1(s: &'static str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::from_static(s.as_bytes()))])
    }

    fn name2(a: &'static str, b: &'static str) -> Name {
        Name::from_components([
            NameComponent::generic(Bytes::from_static(a.as_bytes())),
            NameComponent::generic(Bytes::from_static(b.as_bytes())),
        ])
    }

    #[test]
    fn lpm_empty_returns_none() {
        let fib = Fib::new();
        assert!(fib.lpm(&name1("a")).is_none());
    }

    #[test]
    fn add_nexthop_and_lpm() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
        assert_eq!(entry.nexthops[0].face_id, FaceId(1));
        assert_eq!(entry.nexthops[0].cost, 10);
    }

    #[test]
    fn lpm_returns_longest_prefix() {
        let fib = Fib::new();
        fib.add_nexthop(&Name::root(), FaceId(1), 10);
        fib.add_nexthop(&name1("a"), FaceId(2), 10);
        // "a/b" should match "a" (longer than root)
        let entry = fib.lpm(&name2("a", "b")).unwrap();
        assert_eq!(entry.nexthops[0].face_id, FaceId(2));
    }

    #[test]
    fn add_nexthop_updates_cost() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.add_nexthop(&name1("a"), FaceId(1), 20);
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
        assert_eq!(entry.nexthops[0].cost, 20);
    }

    #[test]
    fn add_multiple_nexthops() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.add_nexthop(&name1("a"), FaceId(2), 20);
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 2);
    }

    #[test]
    fn remove_nexthop_removes_face() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.add_nexthop(&name1("a"), FaceId(2), 20);
        fib.remove_nexthop(&name1("a"), FaceId(1));
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
        assert_eq!(entry.nexthops[0].face_id, FaceId(2));
    }

    #[test]
    fn remove_last_nexthop_deletes_entry() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.remove_nexthop(&name1("a"), FaceId(1));
        assert!(fib.lpm(&name1("a")).is_none());
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.remove_nexthop(&name1("a"), FaceId(99));
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
    }

    #[test]
    fn nexthops_excluding_filters_in_face() {
        let entry = FibEntry {
            nexthops: vec![
                FibNexthop { face_id: FaceId(1), cost: 0 },
                FibNexthop { face_id: FaceId(2), cost: 0 },
            ],
        };
        let filtered = entry.nexthops_excluding(FaceId(1));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].face_id, FaceId(2));
    }
}
