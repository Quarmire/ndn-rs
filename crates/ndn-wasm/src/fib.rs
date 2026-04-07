//! Forwarding Information Base (FIB) for the WASM simulation.
//!
//! A simple name-prefix trie backed by `HashMap`. Supports:
//! - Exact-prefix route insertion
//! - Longest-prefix match (LPM)
//! - Route removal

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A nexthop in the FIB: a face ID and cost.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibNexthop {
    pub face_id: u32,
    pub cost: u32,
}

/// A trie node representing one name component level.
#[derive(Default)]
struct TrieNode {
    nexthops: Vec<FibNexthop>,
    children: HashMap<String, TrieNode>,
}

/// Snapshot of a single FIB entry for JS serialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FibEntry {
    pub prefix: String,
    pub nexthops: Vec<FibNexthop>,
}

/// The Forwarding Information Base.
pub struct SimFib {
    root: TrieNode,
}

impl SimFib {
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    /// Add a route: `prefix` is a slash-separated name like `/ndn/ucla`.
    pub fn add_route(&mut self, prefix: &str, face_id: u32, cost: u32) {
        let components = parse_name(prefix);
        let mut node = &mut self.root;
        for comp in &components {
            node = node.children.entry(comp.clone()).or_default();
        }
        // Replace existing nexthop for the same face or add new.
        if let Some(nh) = node.nexthops.iter_mut().find(|n| n.face_id == face_id) {
            nh.cost = cost;
        } else {
            node.nexthops.push(FibNexthop { face_id, cost });
        }
    }

    /// Remove all routes for a face on a given prefix.
    pub fn remove_route(&mut self, prefix: &str, face_id: u32) {
        let components = parse_name(prefix);
        let mut node = &mut self.root;
        for comp in &components {
            match node.children.get_mut(comp.as_str()) {
                Some(n) => node = n,
                None => return,
            }
        }
        node.nexthops.retain(|nh| nh.face_id != face_id);
    }

    /// Remove all nexthops for a face from the entire FIB.
    pub fn remove_face(&mut self, face_id: u32) {
        Self::remove_face_recursive(&mut self.root, face_id);
    }

    fn remove_face_recursive(node: &mut TrieNode, face_id: u32) {
        node.nexthops.retain(|nh| nh.face_id != face_id);
        for child in node.children.values_mut() {
            Self::remove_face_recursive(child, face_id);
        }
    }

    /// Longest-prefix match: returns nexthops for the most specific matching prefix.
    /// Returns an empty `Vec` if no route exists (including the default `/` route).
    pub fn lpm(&self, name: &str) -> Vec<FibNexthop> {
        let components = parse_name(name);
        let mut best: Vec<FibNexthop> = Vec::new();
        let mut node = &self.root;

        // Root-level nexthops act as the default route.
        if !node.nexthops.is_empty() {
            best.clone_from(&node.nexthops);
        }

        for comp in &components {
            match node.children.get(comp.as_str()) {
                Some(n) => {
                    node = n;
                    if !node.nexthops.is_empty() {
                        best.clone_from(&node.nexthops);
                    }
                }
                None => break,
            }
        }
        best
    }

    /// Return a sorted snapshot of all FIB entries for JS display.
    pub fn snapshot(&self) -> Vec<FibEntry> {
        let mut entries = Vec::new();
        Self::collect_entries(&self.root, &mut Vec::new(), &mut entries);
        entries.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        entries
    }

    fn collect_entries(node: &TrieNode, path: &mut Vec<String>, out: &mut Vec<FibEntry>) {
        if !node.nexthops.is_empty() {
            let prefix = if path.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", path.join("/"))
            };
            out.push(FibEntry {
                prefix,
                nexthops: node.nexthops.clone(),
            });
        }
        for (comp, child) in &node.children {
            path.push(comp.clone());
            Self::collect_entries(child, path, out);
            path.pop();
        }
    }
}

impl Default for SimFib {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a slash-separated NDN name into a `Vec<String>` of components.
/// Leading and trailing slashes are stripped.
pub fn parse_name(name: &str) -> Vec<String> {
    name.trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Format a name component list back to a canonical string.
pub fn format_name(components: &[String]) -> String {
    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm_exact_match() {
        let mut fib = SimFib::new();
        fib.add_route("/ndn/ucla", 1, 0);
        let nexthops = fib.lpm("/ndn/ucla/paper.pdf");
        assert_eq!(nexthops.len(), 1);
        assert_eq!(nexthops[0].face_id, 1);
    }

    #[test]
    fn lpm_longer_beats_shorter() {
        let mut fib = SimFib::new();
        fib.add_route("/ndn", 1, 0);
        fib.add_route("/ndn/ucla", 2, 0);
        let nexthops = fib.lpm("/ndn/ucla/paper");
        assert_eq!(nexthops[0].face_id, 2);
    }

    #[test]
    fn lpm_no_match_returns_empty() {
        let fib = SimFib::new();
        assert!(fib.lpm("/ndn/data").is_empty());
    }

    #[test]
    fn default_route() {
        let mut fib = SimFib::new();
        fib.add_route("/", 99, 0); // root = default
        assert_eq!(fib.lpm("/anything/deep").len(), 1);
    }
}
