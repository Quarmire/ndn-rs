use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ndn_packet::{Name, NameComponent};

/// A concurrent name trie mapping name prefixes to values of type `V`.
///
/// Uses per-node `RwLock` so that many readers can descend simultaneously
/// without holding parent locks. This is the shared structure used by both
/// the FIB and the StrategyTable.
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

    /// Longest-prefix match — returns the value at the deepest matching node.
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

    /// Exact-prefix lookup — only returns a value if `name` exactly matches
    /// a registered prefix.
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

    /// Insert or replace the value at `name`.
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

    /// Remove the value at exactly `name`. Does not prune empty nodes.
    pub fn remove(&self, name: &Name) {
        let mut current = Arc::clone(&self.root);
        for component in name.components() {
            let child = {
                let node = current.read().unwrap();
                node.children.get(component).map(Arc::clone)
            };
            match child {
                None => return,
                Some(c) => current = c,
            }
        }
        let mut node = current.write().unwrap();
        node.entry = None;
    }

    /// Walk the entire trie and return all `(Name, V)` pairs in depth-first order.
    pub fn dump(&self) -> Vec<(Name, V)> {
        let mut out = Vec::new();
        dump_subtree(&self.root, &mut Vec::new(), &mut out);
        out
    }

    /// Collect all values stored at or below `prefix` in the trie.
    ///
    /// Used for prefix-based eviction (e.g. `cs erase /prefix`).
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

    /// Returns the first value found at or below `prefix` in the trie.
    ///
    /// Used for `CanBePrefix` CS lookups: walk to the Interest name position,
    /// then return any Data stored at or below that node. The traversal order
    /// within a level is unspecified (HashMap iteration order).
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

/// Depth-first collection of all (Name, V) entries at or below `node`.
fn dump_subtree<V: Clone + Send + Sync + 'static>(
    node: &Arc<RwLock<TrieNode<V>>>,
    path: &mut Vec<NameComponent>,
    out: &mut Vec<(Name, V)>,
) {
    let guard = node.read().unwrap();
    if let Some(v) = &guard.entry {
        out.push((Name::from_components(path.iter().cloned()), v.clone()));
    }
    // Collect children first to release the lock before recursing.
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

/// Collect all values at or below `node` into `out`.
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

/// Depth-first search for the first value at or below `node`.
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

    fn name(components: &[&str]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        )
    }

    // ── lpm ──────────────────────────────────────────────────────────────────

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

    // ── get (exact) ───────────────────────────────────────────────────────────

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

    // ── insert / remove ───────────────────────────────────────────────────────

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

    // ── first_descendant ─────────────────────────────────────────────────────

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
