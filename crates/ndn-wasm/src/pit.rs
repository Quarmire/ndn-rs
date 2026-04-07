//! Pending Interest Table (PIT) for the WASM simulation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A single PIT in-record (one per consumer face).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PitInRecord {
    pub face_id: u32,
    pub nonce: u32,
    pub expires_at: f64, // ms since epoch (Date.now())
}

/// A PIT entry keyed by Interest name (with CanBePrefix / MustBeFresh folded in).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PitEntry {
    pub name: String,
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
    pub in_records: Vec<PitInRecord>,
    pub expires_at: f64,
}

impl PitEntry {
    pub fn new(name: String, can_be_prefix: bool, must_be_fresh: bool, face_id: u32, nonce: u32, now_ms: f64, lifetime_ms: f64) -> Self {
        let expires = now_ms + lifetime_ms;
        Self {
            name,
            can_be_prefix,
            must_be_fresh,
            in_records: vec![PitInRecord { face_id, nonce, expires_at: expires }],
            expires_at: expires,
        }
    }

    /// Add an in-record if the nonce is not a duplicate.
    /// Returns `true` if this was an aggregation (entry already existed), `false` if new nonce added.
    pub fn add_in_record(&mut self, face_id: u32, nonce: u32, expires_at: f64) -> bool {
        // Nonce deduplication.
        if self.in_records.iter().any(|r| r.nonce == nonce) {
            return false; // duplicate nonce — loop detected
        }
        self.in_records.push(PitInRecord { face_id, nonce, expires_at });
        true
    }

    pub fn in_faces(&self) -> Vec<u32> {
        self.in_records.iter().map(|r| r.face_id).collect()
    }
}

/// Snapshot of PIT for JS display.
pub type PitSnapshot = Vec<PitEntry>;

/// The Pending Interest Table.
pub struct SimPit {
    entries: HashMap<PitKey, PitEntry>,
}

/// Composite key: (name, can_be_prefix, must_be_fresh).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PitKey {
    name: String,
    can_be_prefix: bool,
    must_be_fresh: bool,
}

impl SimPit {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Check if a PIT entry exists for this Interest (for aggregation).
    pub fn get_mut(&mut self, name: &str, can_be_prefix: bool, must_be_fresh: bool) -> Option<&mut PitEntry> {
        let key = PitKey { name: name.to_string(), can_be_prefix, must_be_fresh };
        self.entries.get_mut(&key)
    }

    /// Check if any PIT entry can satisfy the given Data name.
    /// Returns the first matching entry's key if found.
    pub fn match_data(&self, data_name: &str) -> Option<String> {
        for (_, entry) in &self.entries {
            if data_name == entry.name || (entry.can_be_prefix && data_name.starts_with(&entry.name)) {
                return Some(entry.name.clone());
            }
        }
        None
    }

    /// Insert or update a PIT entry. Returns `(is_new, did_aggregate)`.
    pub fn insert(
        &mut self,
        name: &str,
        can_be_prefix: bool,
        must_be_fresh: bool,
        face_id: u32,
        nonce: u32,
        now_ms: f64,
        lifetime_ms: f64,
    ) -> (bool, bool) {
        let key = PitKey { name: name.to_string(), can_be_prefix, must_be_fresh };
        if let Some(entry) = self.entries.get_mut(&key) {
            let added = entry.add_in_record(face_id, nonce, now_ms + lifetime_ms);
            (false, added) // existing entry, aggregated
        } else {
            self.entries.insert(
                key,
                PitEntry::new(name.to_string(), can_be_prefix, must_be_fresh, face_id, nonce, now_ms, lifetime_ms),
            );
            (true, false) // new entry
        }
    }

    /// Remove and return all PIT entries matching a Data name.
    /// Returns list of (entry, satisfied) pairs.
    pub fn remove_matching(&mut self, data_name: &str) -> Vec<PitEntry> {
        let mut matched_keys = Vec::new();
        for (key, entry) in &self.entries {
            if data_name == entry.name || (entry.can_be_prefix && data_name.starts_with(&entry.name)) {
                matched_keys.push(key.clone());
            }
        }
        matched_keys.into_iter().filter_map(|k| self.entries.remove(&k)).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict expired entries given `now_ms`.
    pub fn evict_expired(&mut self, now_ms: f64) {
        self.entries.retain(|_, e| e.expires_at > now_ms);
    }

    /// Snapshot of all PIT entries for JS display.
    pub fn snapshot(&self) -> PitSnapshot {
        let mut entries: Vec<PitEntry> = self.entries.values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

impl Default for SimPit {
    fn default() -> Self {
        Self::new()
    }
}
