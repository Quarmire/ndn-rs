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
    entry:    Option<V>,
    children: HashMap<NameComponent, Arc<RwLock<TrieNode<V>>>>,
}

impl<V> TrieNode<V> {
    fn new() -> Self {
        Self { entry: None, children: HashMap::new() }
    }
}

impl<V: Clone + Send + Sync + 'static> NameTrie<V> {
    pub fn new() -> Self {
        Self { root: Arc::new(RwLock::new(TrieNode::new())) }
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
}

impl<V: Clone + Send + Sync + 'static> Default for NameTrie<V> {
    fn default() -> Self {
        Self::new()
    }
}
