use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ndn_packet::{Name, NameComponent};
use ndn_transport::FaceId;

#[derive(Clone, Debug)]
pub struct FibNexthop {
    pub face_id: FaceId,
    pub cost: u32,
}

#[derive(Clone, Debug)]
pub struct FibEntry {
    pub nexthops: Vec<FibNexthop>,
}

impl FibEntry {
    pub fn nexthops_excluding(&self, exclude: FaceId) -> Vec<FibNexthop> {
        self.nexthops
            .iter()
            .filter(|n| n.face_id != exclude)
            .cloned()
            .collect()
    }
}

/// Immutable, lock-free name trie holding the FIB. Reads (LPM on every
/// Interest) traverse a frozen snapshot with no locks; writes copy-on-write a
/// fresh trie and atomically swap it in. Mirrors NDN-DPDK's lock-free FIB-read
/// design (liburcu there; `arc-swap` here) — see
/// `.claude/notes/high-throughput-forwarding.md` Tier 1.
#[derive(Clone, Default)]
struct FibTrie {
    entry: Option<Arc<FibEntry>>,
    children: HashMap<NameComponent, FibTrie>,
}

impl FibTrie {
    fn lpm(&self, name: &Name) -> Option<Arc<FibEntry>> {
        let mut best = self.entry.clone();
        let mut node = self;
        for comp in name.components() {
            match node.children.get(comp) {
                Some(child) => {
                    if child.entry.is_some() {
                        best = child.entry.clone();
                    }
                    node = child;
                }
                None => break,
            }
        }
        best
    }

    fn get(&self, name: &Name) -> Option<Arc<FibEntry>> {
        let mut node = self;
        for comp in name.components() {
            match node.children.get(comp) {
                Some(child) => node = child,
                None => return None,
            }
        }
        node.entry.clone()
    }

    fn insert(&mut self, name: &Name, value: Arc<FibEntry>) {
        let mut node = self;
        for comp in name.components() {
            node = node.children.entry(comp.clone()).or_default();
        }
        node.entry = Some(value);
    }

    /// Clear the entry at `name` (intermediate nodes are left in place, like
    /// the prior `NameTrie`; `dump`/`lpm` ignore `None` entries).
    fn remove(&mut self, name: &Name) {
        let mut node = self;
        for comp in name.components() {
            match node.children.get_mut(comp) {
                Some(child) => node = child,
                None => return,
            }
        }
        node.entry = None;
    }

    fn dump(&self, path: &mut Vec<NameComponent>, out: &mut Vec<(Name, Arc<FibEntry>)>) {
        if let Some(e) = &self.entry {
            out.push((Name::from_components(path.iter().cloned()), Arc::clone(e)));
        }
        for (comp, child) in &self.children {
            path.push(comp.clone());
            child.dump(path, out);
            path.pop();
        }
    }
}

pub struct Fib {
    trie: ArcSwap<FibTrie>,
}

impl Fib {
    pub fn new() -> Self {
        Self {
            trie: ArcSwap::from_pointee(FibTrie::default()),
        }
    }

    pub fn lpm(&self, name: &Name) -> Option<Arc<FibEntry>> {
        self.trie.load().lpm(name)
    }

    pub fn add_nexthop(&self, prefix: &Name, face_id: FaceId, cost: u32) {
        // `rcu` retries the closure on a concurrent swap, so the
        // read-modify-write is atomic (the prior trie did this per-leaf; the
        // engine-side get-then-insert here used to race).
        self.trie.rcu(|cur| {
            let mut t = FibTrie::clone(cur);
            let mut nexthops = t
                .get(prefix)
                .map(|e| e.nexthops.clone())
                .unwrap_or_default();
            nexthops.retain(|n| n.face_id != face_id);
            nexthops.push(FibNexthop { face_id, cost });
            // FIB invariant: nexthops are kept sorted by ascending cost, so
            // `BestRouteStrategy` (which forwards on `nexthops.first()`) takes the
            // cheapest face regardless of insertion order. Without this, adding a
            // lower-cost nexthop after a higher-cost one (e.g. a NAN NDP face at
            // cost 10 after the NAN-coordination face at cost 20) would be ignored.
            nexthops.sort_by_key(|n| n.cost);
            t.insert(prefix, Arc::new(FibEntry { nexthops }));
            t
        });
    }

    pub fn dump(&self) -> Vec<(Name, Arc<FibEntry>)> {
        let mut out = Vec::new();
        self.trie.load().dump(&mut Vec::new(), &mut out);
        out
    }

    pub fn remove_prefix(&self, prefix: &Name) {
        self.trie.rcu(|cur| {
            let mut t = FibTrie::clone(cur);
            t.remove(prefix);
            t
        });
    }

    pub fn set_nexthops(&self, prefix: &Name, nexthops: Vec<FibNexthop>) {
        self.trie.rcu(|cur| {
            let mut t = FibTrie::clone(cur);
            if nexthops.is_empty() {
                t.remove(prefix);
            } else {
                let mut nexthops = nexthops.clone();
                nexthops.sort_by_key(|n| n.cost); // FIB invariant: cost-sorted (see add_nexthop)
                t.insert(prefix, Arc::new(FibEntry { nexthops }));
            }
            t
        });
    }

    pub fn remove_face(&self, face_id: FaceId) {
        self.trie.rcu(|cur| {
            let mut t = FibTrie::clone(cur);
            let mut entries = Vec::new();
            t.dump(&mut Vec::new(), &mut entries);
            for (prefix, entry) in entries {
                if entry.nexthops.iter().any(|n| n.face_id == face_id) {
                    let nexthops: Vec<_> = entry
                        .nexthops
                        .iter()
                        .filter(|n| n.face_id != face_id)
                        .cloned()
                        .collect();
                    if nexthops.is_empty() {
                        t.remove(&prefix);
                    } else {
                        t.insert(&prefix, Arc::new(FibEntry { nexthops }));
                    }
                }
            }
            t
        });
    }

    pub fn remove_nexthop(&self, prefix: &Name, face_id: FaceId) {
        self.trie.rcu(|cur| {
            let mut t = FibTrie::clone(cur);
            if let Some(existing) = t.get(prefix) {
                let nexthops: Vec<_> = existing
                    .nexthops
                    .iter()
                    .filter(|n| n.face_id != face_id)
                    .cloned()
                    .collect();
                if nexthops.is_empty() {
                    t.remove(prefix);
                } else {
                    t.insert(prefix, Arc::new(FibEntry { nexthops }));
                }
            }
            t
        });
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
    fn remove_face_cleans_all_prefixes() {
        let fib = Fib::new();
        fib.add_nexthop(&name1("a"), FaceId(1), 10);
        fib.add_nexthop(&name1("a"), FaceId(2), 20);
        fib.add_nexthop(&name1("b"), FaceId(1), 5);
        fib.add_nexthop(&name2("c", "d"), FaceId(1), 0);

        fib.remove_face(FaceId(1));

        // /a still has face 2
        let entry = fib.lpm(&name1("a")).unwrap();
        assert_eq!(entry.nexthops.len(), 1);
        assert_eq!(entry.nexthops[0].face_id, FaceId(2));
        // /b was the only nexthop for face 1 → entry removed
        assert!(fib.lpm(&name1("b")).is_none());
        // /c/d was the only nexthop for face 1 → entry removed
        assert!(fib.lpm(&name2("c", "d")).is_none());
    }

    #[test]
    fn nexthops_excluding_filters_in_face() {
        let entry = FibEntry {
            nexthops: vec![
                FibNexthop {
                    face_id: FaceId(1),
                    cost: 0,
                },
                FibNexthop {
                    face_id: FaceId(2),
                    cost: 0,
                },
            ],
        };
        let filtered = entry.nexthops_excluding(FaceId(1));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].face_id, FaceId(2));
    }
}
