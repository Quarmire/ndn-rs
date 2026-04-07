//! Content Store (CS) for the WASM simulation.
//!
//! Simple LRU cache keyed by name string.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single CS entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsEntry {
    pub name: String,
    pub content: String, // human-readable content for display
    pub content_bytes: usize,
    pub freshness_ms: u64,
    pub inserted_at: f64, // Date.now()
    pub sig_type: String,
}

/// Snapshot of CS for JS display.
pub type CsSnapshot = Vec<CsEntry>;

/// The Content Store.
pub struct SimCs {
    entries: HashMap<String, CsEntry>,
    insertion_order: Vec<String>, // for LRU eviction (oldest first)
    pub capacity: usize,
}

impl SimCs {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: Vec::new(),
            capacity,
        }
    }

    /// Check if the CS contains a Data packet satisfying `interest_name`.
    /// `can_be_prefix`: if true, any entry whose name starts with `interest_name` qualifies.
    /// `must_be_fresh`: if true, check freshness.
    pub fn lookup(&self, interest_name: &str, can_be_prefix: bool, must_be_fresh: bool, now_ms: f64) -> Option<&CsEntry> {
        // Exact match first.
        if let Some(entry) = self.entries.get(interest_name) {
            if !must_be_fresh || is_fresh(entry, now_ms) {
                return Some(entry);
            }
        }
        if can_be_prefix {
            // Find any entry whose name is a more specific version of interest_name.
            for (name, entry) in &self.entries {
                if name.starts_with(interest_name) && (!must_be_fresh || is_fresh(entry, now_ms)) {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Insert a Data packet into the CS, evicting the oldest entry if at capacity.
    pub fn insert(&mut self, name: String, content: String, content_bytes: usize, freshness_ms: u64, now_ms: f64, sig_type: String) {
        // Remove existing entry if updating.
        if self.entries.contains_key(&name) {
            self.insertion_order.retain(|n| n != &name);
        }
        // Evict oldest entries if at capacity.
        while !self.insertion_order.is_empty() && self.entries.len() >= self.capacity {
            let oldest = self.insertion_order.remove(0);
            self.entries.remove(&oldest);
        }
        let entry = CsEntry { name: name.clone(), content, content_bytes, freshness_ms, inserted_at: now_ms, sig_type };
        self.entries.insert(name.clone(), entry);
        self.insertion_order.push(name);
    }

    /// Remove a specific entry (used for scenarios where we pre-populate then clear).
    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
        self.insertion_order.retain(|n| n != name);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn hit_rate(&self) -> f64 {
        // Placeholder — in real engine this tracks per-request stats.
        // Here we return the CS occupancy ratio as a proxy.
        if self.capacity == 0 { 0.0 } else { self.entries.len() as f64 / self.capacity as f64 }
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Snapshot of all CS entries for JS display (most-recently-inserted first).
    pub fn snapshot(&self) -> CsSnapshot {
        let mut entries: Vec<CsEntry> = self.insertion_order
            .iter()
            .rev()
            .filter_map(|name| self.entries.get(name).cloned())
            .collect();
        entries.truncate(50); // cap for display
        entries
    }
}

impl Default for SimCs {
    fn default() -> Self {
        Self::new(100)
    }
}

fn is_fresh(entry: &CsEntry, now_ms: f64) -> bool {
    if entry.freshness_ms == 0 {
        return true; // treat 0 as eternal freshness for simulation
    }
    now_ms < entry.inserted_at + entry.freshness_ms as f64
}
