use std::sync::Arc;

use ndn_packet::Name;

use crate::NameTrie;

/// A FIB nexthop. `face_id` is `u32` (not the typed `ndn-transport::FaceId`)
/// to avoid a same-layer dependency.
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

/// Forwarding Information Base. Lookup is longest-prefix match; the trie's
/// per-node `RwLock` provides interior mutability.
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
        self.0.update(prefix, |slot| {
            let nexthops = match slot {
                Some(existing) => {
                    let mut v = existing.nexthops.clone();
                    v.push(nexthop);
                    v
                }
                None => vec![nexthop],
            };
            *slot = Some(Arc::new(FibEntry { nexthops }));
        });
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

    /// Concurrent `add_nexthop` calls for the same prefix must not lose
    /// updates to a check-then-act race.
    #[test]
    fn concurrent_add_nexthop_preserves_all() {
        use std::sync::{Arc, Barrier};
        const N: u32 = 50;
        let fib = Arc::new(Fib::new());
        let prefix = Arc::new(name(&["d19", "fib"]));
        let barrier = Arc::new(Barrier::new(N as usize));

        let mut handles = Vec::with_capacity(N as usize);
        for face_id in 0..N {
            let fib = Arc::clone(&fib);
            let prefix = Arc::clone(&prefix);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                fib.add_nexthop(&prefix, nexthop(face_id, 0));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let entry = fib.get(&prefix).expect("FIB entry must exist");
        assert_eq!(
            entry.nexthops.len(),
            N as usize,
            "expected {N} nexthops; got {} (race lost {})",
            entry.nexthops.len(),
            N as usize - entry.nexthops.len()
        );
    }
}
