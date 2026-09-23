//! CanBePrefix index for the in-memory Content Store: a name trie in which
//! every node also records the freshest entry of its subtree.
//!
//! A CanBePrefix Interest may be answered by ANY cached descendant, and with
//! MustBeFresh only by a fresh one. The previous index (`NameTrie`) could only
//! hand back an arbitrary descendant — its children are a `HashMap` — and the
//! CS then applied MustBeFresh to that one entry and missed if it was stale,
//! never looking at the others. A `LatestPublisher` mints a new version per
//! publication, so a telemetry prefix accumulates many versioned descendants
//! of which exactly one is fresh: the CS answered ~1/N of the time, and
//! caching MORE made it worse. Measured on the fleet (nfd-divergence-findings
//! Round 14): 0.60% hit rate before, 58.67% once the freshest admissible
//! descendant was returned.
//!
//! Answering must not cost a scan of the subtree: one telemetry prefix held
//! ~13k descendants. So each node keeps the maximum of its subtree under
//! [`Rank`], and a lookup is one walk down the Interest name:
//! - the subtree maximum is the freshest descendant (latest `stale_at`; with
//!   one FreshnessPeriod per publisher, the most recently received version);
//! - if even that one is stale, every descendant is, so MustBeFresh misses
//!   without looking further.
//!
//! Costs: insert O(depth). Removal O(depth), plus O(fan-out) at each level
//! whose maximum was the removed entry — rare under LRU, which evicts the
//! least recently used entries while the freshest version is the one being
//! read. `remove_prefix` rebuilds the affected subtree once, O(subtree).

use std::collections::HashMap;
use std::sync::Arc;

use ndn_packet::{Name, NameComponent};

/// Freshness order: later `stale_at` wins; ties go to the later insertion.
/// `seq` is unique per insertion, so every subtree has exactly one maximum and
/// the choice never depends on `HashMap` iteration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    stale_at: u64,
    seq: u64,
}

#[derive(Clone)]
struct Entry {
    rank: Rank,
    name: Arc<Name>,
}

#[derive(Default)]
struct Node {
    /// This exact name, if cached.
    own: Option<Entry>,
    /// Freshest entry in this subtree, `own` included.
    best: Option<Entry>,
    children: HashMap<NameComponent, Node>,
}

impl Node {
    fn is_empty(&self) -> bool {
        self.own.is_none() && self.children.is_empty()
    }

    fn raise(&mut self, entry: &Entry) {
        if self.best.as_ref().is_none_or(|b| entry.rank > b.rank) {
            self.best = Some(entry.clone());
        }
    }

    fn recompute_best(&mut self) {
        self.best = self
            .own
            .iter()
            .chain(self.children.values().filter_map(|c| c.best.as_ref()))
            .max_by_key(|e| e.rank)
            .cloned();
    }
}

pub(crate) struct FreshIndex {
    root: Node,
    next_seq: u64,
}

impl FreshIndex {
    pub(crate) fn new() -> Self {
        Self {
            root: Node::default(),
            next_seq: 0,
        }
    }

    /// Record `name` as cached until `stale_at` (a re-insert replaces it).
    pub(crate) fn insert(&mut self, name: Arc<Name>, stale_at: u64) {
        if self.stale_at(&name).is_some_and(|old| old > stale_at) {
            // Lowering a subtree maximum needs recomputation, which removal
            // does; raising one (the usual re-arrival) is a plain compare.
            self.remove(&name);
        }
        let entry = Entry {
            rank: Rank {
                stale_at,
                seq: self.next_seq,
            },
            name,
        };
        self.next_seq += 1;

        let mut node = &mut self.root;
        node.raise(&entry);
        for c in entry.name.components() {
            node = node.children.entry(c.clone()).or_default();
            node.raise(&entry);
        }
        node.own = Some(entry);
    }

    /// Forget `name`. Returns whether it was indexed.
    pub(crate) fn remove(&mut self, name: &Name) -> bool {
        remove_at(&mut self.root, name.components()).is_some()
    }

    /// The freshest entry at or below `prefix` and its `stale_at`.
    pub(crate) fn freshest(&self, prefix: &Name) -> Option<(&Arc<Name>, u64)> {
        let best = self.node(prefix)?.best.as_ref()?;
        Some((&best.name, best.rank.stale_at))
    }

    /// Remove up to `limit` entries at or below `prefix`, in canonical name
    /// order (NFD's `cs/erase` order), returning their names. Subtree maxima
    /// are rebuilt once at the end rather than once per removal.
    pub(crate) fn remove_prefix(&mut self, prefix: &Name, limit: usize) -> Vec<Arc<Name>> {
        let Some(node) = self.node_mut(prefix) else {
            return Vec::new();
        };
        let mut names = Vec::new();
        collect(node, &mut names);
        names.sort_unstable();
        names.truncate(limit);
        for name in &names {
            let mut n = &mut *node;
            for c in &name.components()[prefix.len()..] {
                n = n.children.get_mut(c).expect("collected from this subtree");
            }
            n.own = None;
        }
        rebuild_along(&mut self.root, prefix.components());
        names
    }

    fn stale_at(&self, name: &Name) -> Option<u64> {
        Some(self.node(name)?.own.as_ref()?.rank.stale_at)
    }

    fn node(&self, name: &Name) -> Option<&Node> {
        let mut node = &self.root;
        for c in name.components() {
            node = node.children.get(c)?;
        }
        Some(node)
    }

    fn node_mut(&mut self, name: &Name) -> Option<&mut Node> {
        let mut node = &mut self.root;
        for c in name.components() {
            node = node.children.get_mut(c)?;
        }
        Some(node)
    }

    /// Nodes allocated below the root. The CS index sees one unique name per
    /// video chunk, so a removal that leaves its path behind is an unbounded
    /// leak (the field failure the trie's own regression test records).
    #[cfg(test)]
    fn node_count(&self) -> usize {
        fn count(n: &Node) -> usize {
            n.children.values().map(|c| 1 + count(c)).sum()
        }
        count(&self.root)
    }
}

/// Clear `rest` below `node`, prune emptied nodes, and repair every maximum
/// that was the removed entry. Returns the removed entry's rank.
fn remove_at(node: &mut Node, rest: &[NameComponent]) -> Option<Rank> {
    let rank = match rest.split_first() {
        None => node.own.take()?.rank,
        Some((c, tail)) => {
            let child = node.children.get_mut(c)?;
            let rank = remove_at(child, tail)?;
            if child.is_empty() {
                node.children.remove(c);
            }
            rank
        }
    };
    // Ranks are unique, so only nodes whose maximum WAS this entry change.
    if node.best.as_ref().is_some_and(|b| b.rank == rank) {
        node.recompute_best();
    }
    Some(rank)
}

fn collect(node: &Node, out: &mut Vec<Arc<Name>>) {
    if let Some(own) = &node.own {
        out.push(Arc::clone(&own.name));
    }
    for child in node.children.values() {
        collect(child, out);
    }
}

/// Rebuild maxima (and prune empties) for the whole subtree at `rest`, then
/// for each ancestor on the way back up.
fn rebuild_along(node: &mut Node, rest: &[NameComponent]) {
    match rest.split_first() {
        None => rebuild_subtree(node),
        Some((c, tail)) => {
            if let Some(child) = node.children.get_mut(c) {
                rebuild_along(child, tail);
                if child.is_empty() {
                    node.children.remove(c);
                }
            }
            node.recompute_best();
        }
    }
}

fn rebuild_subtree(node: &mut Node) {
    node.children.retain(|_, child| {
        rebuild_subtree(child);
        !child.is_empty()
    });
    node.recompute_best();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(uri: &str) -> Arc<Name> {
        Arc::new(uri.parse().unwrap())
    }

    fn freshest(index: &FreshIndex, prefix: &str) -> Option<(String, u64)> {
        index
            .freshest(&n(prefix))
            .map(|(name, stale_at)| (name.to_string(), stale_at))
    }

    /// Removing the subtree's freshest entry hands the title to the next
    /// freshest, at every level — the case eager maxima must repair.
    #[test]
    fn removing_the_freshest_promotes_the_next() {
        let mut index = FreshIndex::new();
        index.insert(n("/p/a/1"), 30);
        index.insert(n("/p/b/1"), 20);
        index.insert(n("/p/a/2"), 10);
        assert_eq!(freshest(&index, "/p"), Some(("/p/a/1".into(), 30)));

        index.remove(&n("/p/a/1"));
        assert_eq!(freshest(&index, "/p"), Some(("/p/b/1".into(), 20)));
        assert_eq!(freshest(&index, "/p/a"), Some(("/p/a/2".into(), 10)));

        // A re-insert that LOWERS an entry's stale_at must not leave it as
        // the maximum it no longer is.
        index.insert(n("/p/b/1"), 5);
        assert_eq!(freshest(&index, "/p"), Some(("/p/a/2".into(), 10)));
    }

    #[test]
    fn remove_prefix_honours_limit_in_name_order_and_repairs_maxima() {
        let mut index = FreshIndex::new();
        for (v, stale_at) in [(3, 30), (1, 10), (2, 20)] {
            index.insert(n(&format!("/p/v{v}")), stale_at);
        }
        index.insert(n("/q"), 99);

        let removed = index.remove_prefix(&n("/p"), 2);
        let removed: Vec<String> = removed.iter().map(|x| x.to_string()).collect();
        assert_eq!(removed, ["/p/v1", "/p/v2"]);
        assert_eq!(freshest(&index, "/p"), Some(("/p/v3".into(), 30)));

        index.remove_prefix(&n("/p"), usize::MAX);
        assert_eq!(freshest(&index, "/p"), None);
        assert_eq!(freshest(&index, "/"), Some(("/q".into(), 99)));
        index.remove(&n("/q"));
        assert_eq!(index.node_count(), 0, "every emptied node is pruned");
    }

    /// Churning unique names must not leave trie nodes behind.
    #[test]
    fn churn_leaves_no_nodes_behind() {
        let mut index = FreshIndex::new();
        for i in 0..500u64 {
            let name = n(&format!("/muas/v2/iuas-01/video/{i}"));
            index.insert(Arc::clone(&name), i);
            index.remove(&name);
        }
        assert_eq!(index.node_count(), 0);
    }
}
