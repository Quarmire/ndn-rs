use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ndn_packet::{Name, NameComponent};

/// Concurrent name trie mapping name prefixes to values. Per-node `RwLock`
/// lets readers descend without holding parent locks. Used by both the FIB
/// and the `StrategyTable`.
pub struct NameTrie<V: Clone + Send + Sync + 'static> {
    root: Arc<RwLock<TrieNode<V>>>,
}

struct TrieNode<V> {
    entry: Option<V>,
    children: HashMap<NameComponent, Arc<RwLock<TrieNode<V>>>>,
}

impl<V> TrieNode<V> {
    fn new() -> Self {
        Self {
            entry: None,
            children: HashMap::new(),
        }
    }
}

impl<V: Clone + Send + Sync + 'static> NameTrie<V> {
    pub fn new() -> Self {
        Self {
            root: Arc::new(RwLock::new(TrieNode::new())),
        }
    }

    pub fn lpm(&self, name: &Name) -> Option<V> {
        let root = self.root.read().unwrap();
        let mut best = root.entry.clone();
        let mut current: Arc<RwLock<TrieNode<V>>> = Arc::clone(&self.root);
        drop(root);

        for component in name.components() {
            let child_arc = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child_arc {
                None => break,
                Some(child) => {
                    let node = child.read().unwrap();
                    if node.entry.is_some() {
                        best = node.entry.clone();
                    }
                    drop(node);
                    current = child;
                }
            }
        }
        best
    }

    pub fn get(&self, name: &Name) -> Option<V> {
        let mut current = Arc::clone(&self.root);
        for component in name.components() {
            let child = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child {
                None => return None,
                Some(c) => current = c,
            }
        }
        let node = current.read().unwrap();
        node.entry.clone()
    }

    pub fn insert(&self, name: &Name, value: V) {
        let mut current = Arc::clone(&self.root);
        for component in name.components() {
            let child = {
                let mut node = current.write().unwrap();
                node.children
                    .entry(component.clone())
                    .or_insert_with(|| Arc::new(RwLock::new(TrieNode::new())))
                    .clone()
            };
            current = child;
        }
        let mut node = current.write().unwrap();
        node.entry = Some(value);
    }

    /// Atomic read-modify-write at the leaf, holding the leaf's write lock
    /// across `f`. `f` receives `&mut Option<V>`: `Some` for an existing
    /// entry, `None` for a vacant leaf; mutating to `None` clears the entry.
    pub fn update<F: FnOnce(&mut Option<V>)>(&self, name: &Name, f: F) {
        let mut current = Arc::clone(&self.root);
        for component in name.components() {
            let child = {
                let mut node = current.write().unwrap();
                node.children
                    .entry(component.clone())
                    .or_insert_with(|| Arc::new(RwLock::new(TrieNode::new())))
                    .clone()
            };
            current = child;
        }
        let mut node = current.write().unwrap();
        f(&mut node.entry);
    }

    pub fn remove(&self, name: &Name) {
        // Remember the path so empty nodes can be pruned on the way back up.
        //
        // This used to clear `entry` and stop, leaving the node itself in its
        // parent's `children` map forever. Every name ever inserted then
        // leaked its whole chain of nodes, even after the value was removed --
        // and for the Content Store's prefix index that is one chain per
        // unique Data name. A live video stream mints a fresh name per chunk,
        // so on a 3-airframe fleet the forwarder grew ~1-1.5 GB/day and hit
        // hard memory exhaustion in about three days (2.9 GB RSS on a 3.7 GB
        // node with no swap), while the CS itself sat correctly at its 64 MB
        // cap -- the entry count plateaued and RSS kept climbing to 45x it.
        let mut path: Vec<(Arc<RwLock<TrieNode<V>>>, NameComponent)> = Vec::new();
        let mut current = Arc::clone(&self.root);
        for component in name.components() {
            let child = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child {
                None => return,
                Some(c) => {
                    path.push((Arc::clone(&current), component.clone()));
                    current = c;
                }
            }
        }
        {
            let mut node = current.write().unwrap();
            node.entry = None;
            if !node.children.is_empty() {
                // Still needed as an interior node on some other name's path.
                return;
            }
        }
        drop(current);
        // Walk back up dropping nodes that now hold neither a value nor any
        // children. Stop at the first one that is still needed. Locks are
        // always taken parent-then-child here, the same order every descent
        // uses, so this cannot deadlock against a concurrent lookup; a reader
        // already holding an Arc to a pruned node keeps it alive and simply
        // finds nothing.
        for (parent, component) in path.into_iter().rev() {
            let mut parent_node = parent.write().unwrap();
            let prunable = match parent_node.children.get(&component) {
                Some(child) => match child.try_read() {
                    Ok(c) => c.entry.is_none() && c.children.is_empty(),
                    // Somebody is working in that subtree; leave it.
                    Err(_) => false,
                },
                None => false,
            };
            if !prunable {
                break;
            }
            parent_node.children.remove(&component);
        }
    }

    /// Total nodes currently allocated, excluding the root.
    ///
    /// Exists so the "remove leaves the node behind" regression is observable:
    /// entry counts alone cannot see it, which is why it grew unbounded in the
    /// field for days while every other table looked correct.
    pub fn node_count(&self) -> usize {
        fn count<V>(node: &Arc<RwLock<TrieNode<V>>>) -> usize {
            let n = node.read().unwrap();
            n.children.values().map(|c| 1 + count(c)).sum()
        }
        count(&self.root)
    }

    pub fn dump(&self) -> Vec<(Name, V)> {
        let mut out = Vec::new();
        dump_subtree(&self.root, &mut Vec::new(), &mut out);
        out
    }

    pub fn descendants(&self, prefix: &Name) -> Vec<V> {
        let mut current = Arc::clone(&self.root);
        for component in prefix.components() {
            let child = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child {
                None => return Vec::new(),
                Some(c) => current = c,
            }
        }
        let mut out = Vec::new();
        collect_subtree(&current, &mut out);
        out
    }

    pub fn first_descendant(&self, prefix: &Name) -> Option<V> {
        let mut current = Arc::clone(&self.root);
        for component in prefix.components() {
            let child = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child {
                None => return None,
                Some(c) => current = c,
            }
        }
        first_in_subtree(&current)
    }
}

impl<V: Clone + Send + Sync + 'static> Default for NameTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}

fn dump_subtree<V: Clone + Send + Sync + 'static>(
    node: &Arc<RwLock<TrieNode<V>>>,
    path: &mut Vec<NameComponent>,
    out: &mut Vec<(Name, V)>,
) {
    let guard = node.read().unwrap();
    if let Some(v) = &guard.entry {
        out.push((Name::from_components(path.iter().cloned()), v.clone()));
    }
    let children: Vec<(NameComponent, Arc<RwLock<TrieNode<V>>>)> = guard
        .children
        .iter()
        .map(|(k, v)| (k.clone(), Arc::clone(v)))
        .collect();
    drop(guard);
    for (comp, child) in children {
        path.push(comp);
        dump_subtree(&child, path, out);
        path.pop();
    }
}

fn collect_subtree<V: Clone + Send + Sync + 'static>(
    node: &Arc<RwLock<TrieNode<V>>>,
    out: &mut Vec<V>,
) {
    let guard = node.read().unwrap();
    if let Some(v) = &guard.entry {
        out.push(v.clone());
    }
    let children: Vec<Arc<RwLock<TrieNode<V>>>> = guard.children.values().map(Arc::clone).collect();
    drop(guard);
    for child in children {
        collect_subtree(&child, out);
    }
}

fn first_in_subtree<V: Clone>(node: &Arc<RwLock<TrieNode<V>>>) -> Option<V> {
    let guard = node.read().unwrap();
    if let Some(v) = &guard.entry {
        return Some(v.clone());
    }
    for child in guard.children.values() {
        if let Some(v) = first_in_subtree(child) {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::{Name, NameComponent};

    #[test]
    fn remove_prunes_empty_nodes_instead_of_leaking_them() {
        // The field failure this guards: `remove` cleared the value but left
        // the node in its parent's children map, so every unique name ever
        // inserted leaked its whole chain. The Content Store's prefix index
        // sees one unique name per video chunk, so the forwarder grew
        // ~1-1.5 GB/day and exhausted a 3.7 GB node in ~3 days while the CS
        // entry count sat correctly at its cap.
        let trie: NameTrie<u32> = NameTrie::new();
        assert_eq!(trie.node_count(), 0);

        // Churn distinct names the way a live stream mints cursors.
        for i in 0..500u32 {
            let n = name(&["muas", "v2", "iuas-01", "video", &i.to_string()]);
            trie.insert(&n, i);
            trie.remove(&n);
        }
        // Every one was removed, so nothing may remain allocated.
        assert_eq!(
            trie.node_count(),
            0,
            "removed names left trie nodes behind — this is the unbounded leak"
        );
    }

    #[test]
    fn remove_keeps_nodes_that_are_still_needed() {
        let trie: NameTrie<u32> = NameTrie::new();
        let parent = name(&["a", "b"]);
        let child = name(&["a", "b", "c"]);
        trie.insert(&parent, 1);
        trie.insert(&child, 2);

        // Removing the child must not disturb the parent's entry.
        trie.remove(&child);
        assert_eq!(trie.get(&parent), Some(1));
        assert_eq!(trie.get(&child), None);

        // Removing a prefix that still has descendants must keep the path.
        trie.insert(&child, 3);
        trie.remove(&parent);
        assert_eq!(trie.get(&child), Some(3));
        assert_eq!(trie.get(&parent), None);

        trie.remove(&child);
        assert_eq!(trie.node_count(), 0);
    }

    fn name(components: &[&str]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        )
    }

    #[test]
    fn lpm_empty_trie_returns_none() {
        let trie: NameTrie<u32> = NameTrie::new();
        assert!(trie.lpm(&name(&["a", "b"])).is_none());
    }

    #[test]
    fn lpm_exact_match() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b"]), 42);
        assert_eq!(trie.lpm(&name(&["a", "b"])), Some(42));
    }

    #[test]
    fn lpm_prefix_wins() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a"]), 1);
        trie.insert(&name(&["a", "b"]), 2);
        // Query /a/b/c — most specific match is /a/b.
        assert_eq!(trie.lpm(&name(&["a", "b", "c"])), Some(2));
    }

    #[test]
    fn lpm_shorter_prefix_fallback() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a"]), 1);
        // /a/b is not in the trie; fallback to /a.
        assert_eq!(trie.lpm(&name(&["a", "b"])), Some(1));
    }

    #[test]
    fn lpm_root_matches_everything() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&Name::root(), 99);
        assert_eq!(trie.lpm(&name(&["x", "y", "z"])), Some(99));
    }

    #[test]
    fn get_returns_none_for_missing_prefix() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b"]), 5);
        assert!(trie.get(&name(&["a"])).is_none());
        assert!(trie.get(&name(&["a", "b", "c"])).is_none());
    }

    #[test]
    fn get_returns_exact_entry() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b"]), 7);
        assert_eq!(trie.get(&name(&["a", "b"])), Some(7));
    }

    #[test]
    fn insert_replaces_value() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a"]), 1);
        trie.insert(&name(&["a"]), 2);
        assert_eq!(trie.get(&name(&["a"])), Some(2));
    }

    #[test]
    fn remove_clears_entry() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b"]), 10);
        trie.remove(&name(&["a", "b"]));
        assert!(trie.get(&name(&["a", "b"])).is_none());
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.remove(&name(&["x"])); // should not panic
    }

    #[test]
    fn first_descendant_exact_node_has_value() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b"]), 5);
        // first_descendant of /a/b finds the value at /a/b itself.
        assert_eq!(trie.first_descendant(&name(&["a", "b"])), Some(5));
    }

    #[test]
    fn first_descendant_finds_child() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a", "b", "c"]), 42);
        // first_descendant of /a/b finds /a/b/c.
        assert_eq!(trie.first_descendant(&name(&["a", "b"])), Some(42));
    }

    #[test]
    fn first_descendant_missing_prefix_returns_none() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["x"]), 1);
        assert!(trie.first_descendant(&name(&["y"])).is_none());
    }

    #[test]
    fn first_descendant_empty_prefix_returns_any() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a"]), 10);
        // first_descendant of root (empty prefix) returns some value.
        assert!(trie.first_descendant(&Name::root()).is_some());
    }

    #[test]
    fn first_descendant_no_children_no_value_returns_none() {
        let trie: NameTrie<u32> = NameTrie::new();
        trie.insert(&name(&["a"]), 1);
        // /a/b exists in path as intermediate node but has no value or children.
        assert!(trie.first_descendant(&name(&["a", "b"])).is_none());
    }
}
