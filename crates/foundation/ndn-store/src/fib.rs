use std::sync::Arc;

use ndn_packet::Name;

use crate::NameTrie;

/// A nexthop in the FIB.
///
/// Uses `u32` for `face_id` (consistent with PIT records). The engine layer
/// maps this to a typed `FaceId` from `ndn-transport`; keeping them as `u32`
/// here avoids a same-layer dependency between `ndn-store` and `ndn-transport`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FibNexthop {
    pub face_id: u32,
    pub cost: u32,
}

#[derive(Clone, Debug)]
pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

impl FibEntry {
    pub fn new(nexthops: Vec<FibNexthop>) -> Self {
        Self { nexthops }
    }
}

/// The Forwarding Information Base.
///
/// Wraps a `NameTrie<Arc<FibEntry>>`. Lookup uses longest-prefix match, so
/// the most specific registered prefix wins. All methods are `&self` — the
/// trie's per-node `RwLock` provides the necessary interior mutability.
pub struct Fib(NameTrie<Arc<FibEntry>>);

impl Fib {
    pub fn new() -> Self {
        Self(NameTrie::new())
    }

    pub fn lpm(&self, name: &Name) -> Option<Arc<FibEntry>> {
        self.0.lpm(name)
    }

    pub fn get(&self, prefix: &Name) -> Option<Arc<FibEntry>> {
        self.0.get(prefix)
    }

    pub fn insert(&self, prefix: &Name, entry: FibEntry) {
        self.0.insert(prefix, Arc::new(entry));
    }

    pub fn add_nexthop(&self, prefix: &Name, nexthop: FibNexthop) {
        let nexthops = match self.0.get(prefix) {
            Some(existing) => {
                let mut v = existing.nexthops.clone();
                v.push(nexthop);
                v
            }
            None => vec![nexthop],
        };
        self.0.insert(prefix, Arc::new(FibEntry { nexthops }));
    }

    pub fn remove(&self, prefix: &Name) {
        self.0.remove(prefix);
    }
}

impl Default for Fib {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn name(components: &[&str]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        )
    }

    fn nexthop(face_id: u32, cost: u32) -> FibNexthop {
        FibNexthop { face_id, cost }
    }

    #[test]
    fn lpm_empty_returns_none() {
        let fib = Fib::new();
        assert!(fib.lpm(&name(&["edu", "ucla"])).is_none());
    }

    #[test]
    fn lpm_exact_match() {
        let fib = Fib::new();
        fib.insert(&name(&["edu", "ucla"]), FibEntry::new(vec![nexthop(1, 0)]));
        let entry = fib.lpm(&name(&["edu", "ucla"])).unwrap();
        assert_eq!(entry.nexthops[0].face_id, 1);
    }

    #[test]
    fn lpm_most_specific_wins() {
        let fib = Fib::new();
        fib.insert(&name(&["edu"]), FibEntry::new(vec![nexthop(1, 10)]));
        fib.insert(&name(&["edu", "ucla"]), FibEntry::new(vec![nexthop(2, 0)]));
        let entry = fib.lpm(&name(&["edu", "ucla", "data"])).unwrap();
        assert_eq!(entry.nexthops[0].face_id, 2);
    }

    #[test]
    fn lpm_falls_back_to_shorter_prefix() {
        let fib = Fib::new();
        fib.insert(&name(&["edu"]), FibEntry::new(vec![nexthop(3, 5)]));
        let entry = fib.lpm(&name(&["edu", "mit"])).unwrap();
        assert_eq!(entry.nexthops[0].face_id, 3);
    }

    #[test]
    fn add_nexthop_creates_entry() {
        let fib = Fib::new();
        fib.add_nexthop(&name(&["a"]), nexthop(7, 1));
        let entry = fib.get(&name(&["a"])).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
        assert_eq!(entry.nexthops[0].face_id, 7);
    }

    #[test]
    fn add_nexthop_appends_to_existing() {
        let fib = Fib::new();
        fib.add_nexthop(&name(&["a"]), nexthop(1, 0));
        fib.add_nexthop(&name(&["a"]), nexthop(2, 10));
        let entry = fib.get(&name(&["a"])).unwrap();
        assert_eq!(entry.nexthops.len(), 2);
        assert!(entry.nexthops.iter().any(|n| n.face_id == 1));
        assert!(entry.nexthops.iter().any(|n| n.face_id == 2));
    }

    #[test]
    fn remove_clears_prefix() {
        let fib = Fib::new();
        fib.insert(&name(&["a", "b"]), FibEntry::new(vec![nexthop(5, 0)]));
        fib.remove(&name(&["a", "b"]));
        assert!(fib.get(&name(&["a", "b"])).is_none());
    }

    #[test]
    fn remove_does_not_affect_parent() {
        let fib = Fib::new();
        fib.insert(&name(&["a"]), FibEntry::new(vec![nexthop(1, 0)]));
        fib.insert(&name(&["a", "b"]), FibEntry::new(vec![nexthop(2, 0)]));
        fib.remove(&name(&["a", "b"]));
        assert!(fib.get(&name(&["a"])).is_some());
    }
}
