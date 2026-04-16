use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use smallvec::SmallVec;

use ndn_packet::{Name, NameComponent, Selector};

/// Pre-computed cumulative name-prefix hashes.
///
/// Computed once at TLV decode and reused for all PIT lookups (check, match,
/// nack) without re-hashing name components on every probe.
///
/// Inspired by NDN-DPDK's memoized name hashing: the FIB/PIT dispatch layer
/// hashes the name once at RX and reuses the hash for NDT, PCCT, and FIB
/// lookups.
///
/// Ref: Shi et al., "NDN-DPDK: NDN Forwarding at 100 Gbps on Commodity
/// Hardware" (ACM ICN 2020), §3.1.
#[derive(Clone, Debug)]
pub struct NameHashes {
    /// `prefix_hashes[i]` is the hash of the first `i+1` name components.
    pub prefix_hashes: SmallVec<[u64; 8]>,
}

/// FxHash-style multiplier for order-dependent accumulation.
const HASH_MIX: u64 = 0x517cc1b727220a95;

impl NameHashes {
    /// Compute cumulative prefix hashes for all prefixes of `name`.
    pub fn compute(name: &Name) -> Self {
        Self::from_components(name.components())
    }

    /// Compute from a component slice (avoids requiring a `Name` value).
    pub fn from_components(components: &[NameComponent]) -> Self {
        let mut prefix_hashes = SmallVec::with_capacity(components.len());
        let mut state: u64 = 0;
        for comp in components {
            state = Self::accumulate(state, comp);
            prefix_hashes.push(state);
        }
        Self { prefix_hashes }
    }

    /// Hash of the full name (all components).
    pub fn full_hash(&self) -> u64 {
        self.prefix_hashes.last().copied().unwrap_or(0)
    }

    /// Hash of the first `n` components. Returns 0 for the root name (n=0).
    pub fn prefix_hash(&self, n: usize) -> u64 {
        if n == 0 { 0 } else { self.prefix_hashes[n - 1] }
    }

    pub fn len(&self) -> usize {
        self.prefix_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefix_hashes.is_empty()
    }

    /// Compute the full-name hash without storing intermediates.
    pub fn full_name_hash(name: &Name) -> u64 {
        let mut state: u64 = 0;
        for comp in name.components() {
            state = Self::accumulate(state, comp);
        }
        state
    }

    fn accumulate(state: u64, comp: &NameComponent) -> u64 {
        let mut h = DefaultHasher::new();
        comp.hash(&mut h);
        let comp_hash = h.finish();
        state.wrapping_mul(HASH_MIX).wrapping_add(comp_hash)
    }
}

/// A stable, cheaply-copyable reference to a PIT entry.
///
/// Computed as a hash of (Name, Option<Selector>) — safe to copy across tasks
/// and `await` points without lifetime concerns.
///
/// Internally uses a two-phase hash: name components are hashed into a single
/// `u64` via [`NameHashes`], then combined with selector and forwarding-hint
/// hashes.  This lets [`NameHashes`] pre-compute the name hash once at decode
/// and reuse it across all PIT probes — eliminating per-probe re-hashing in
/// `PitMatchStage` (which may probe 5 + 3*(N-1) combinations).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PitToken(pub u64);

impl PitToken {
    /// Build a PIT token from Interest fields.
    ///
    /// Per RFC 8569 §4.2, PIT aggregation uses (Name, Selectors,
    /// ForwardingHint) as the key.
    pub fn from_interest(name: &Name, selector: Option<&Selector>) -> Self {
        Self::from_interest_full(name, selector, None)
    }

    /// Build a PIT token including ForwardingHint for correct aggregation.
    pub fn from_interest_full(
        name: &Name,
        selector: Option<&Selector>,
        forwarding_hint: Option<&[Arc<Name>]>,
    ) -> Self {
        let name_hash = NameHashes::full_name_hash(name);
        Self::from_name_hash(name_hash, selector, forwarding_hint)
    }

    /// Build a PIT token from a pre-computed name hash.
    ///
    /// Use with [`NameHashes::full_hash`] or [`NameHashes::prefix_hash`] to
    /// avoid re-hashing name components on every probe.
    pub fn from_name_hash(
        name_hash: u64,
        selector: Option<&Selector>,
        forwarding_hint: Option<&[Arc<Name>]>,
    ) -> Self {
        let mut h = DefaultHasher::new();
        name_hash.hash(&mut h);
        selector.hash(&mut h);
        if let Some(hints) = forwarding_hint {
            for hint in hints {
                hint.hash(&mut h);
            }
        }
        PitToken(h.finish())
    }
}

/// Record of an incoming Interest (consumer-facing side of the PIT entry).
#[derive(Clone, Debug)]
pub struct InRecord {
    /// Face the Interest arrived on (raw u32; mapped to FaceId by the engine).
    pub face_id: u32,
    pub nonce: u32,
    pub expires_at: u64,
    /// NDNLPv2 PIT token from the LP header on this face.
    /// Must be echoed back in the Data/Nack response.
    pub lp_pit_token: Option<bytes::Bytes>,
}

/// Record of an outgoing Interest (producer-facing side of the PIT entry).
#[derive(Clone, Debug)]
pub struct OutRecord {
    pub face_id: u32,
    pub last_nonce: u32,
    pub sent_at: u64,
}

/// A single PIT entry — one per pending (Name, Option<Selector>) pair.
pub struct PitEntry {
    pub name: Arc<Name>,
    pub selector: Option<Selector>,
    pub in_records: Vec<InRecord>,
    pub out_records: Vec<OutRecord>,
    /// Nonces seen so far — inline for the common case of ≤4 nonces.
    pub nonces_seen: SmallVec<[u32; 4]>,
    pub is_satisfied: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

impl PitEntry {
    pub fn new(name: Arc<Name>, selector: Option<Selector>, now: u64, lifetime_ms: u64) -> Self {
        Self {
            name,
            selector,
            in_records: Vec::new(),
            out_records: Vec::new(),
            nonces_seen: SmallVec::new(),
            is_satisfied: false,
            created_at: now,
            expires_at: now + lifetime_ms * 1_000_000,
        }
    }

    pub fn add_in_record(
        &mut self,
        face_id: u32,
        nonce: u32,
        expires_at: u64,
        lp_pit_token: Option<bytes::Bytes>,
    ) {
        self.in_records.push(InRecord {
            face_id,
            nonce,
            expires_at,
            lp_pit_token,
        });
        if !self.nonces_seen.contains(&nonce) {
            self.nonces_seen.push(nonce);
        }
    }

    pub fn add_out_record(&mut self, face_id: u32, nonce: u32, sent_at: u64) {
        self.out_records.push(OutRecord {
            face_id,
            last_nonce: nonce,
            sent_at,
        });
    }

    /// Returns the face IDs of all in-records (for Data fan-back).
    pub fn in_record_faces(&self) -> impl Iterator<Item = u32> + '_ {
        self.in_records.iter().map(|r| r.face_id)
    }
}

/// The Pending Interest Table.
///
/// On native targets uses `DashMap` for sharded concurrent access with no
/// global lock on the forwarding hot path. On `wasm32` uses a
/// `Mutex<HashMap>` (single-threaded WASM has no contention).
pub struct Pit {
    #[cfg(not(target_arch = "wasm32"))]
    entries: DashMap<PitToken, PitEntry>,
    #[cfg(target_arch = "wasm32")]
    entries: std::sync::Mutex<std::collections::HashMap<PitToken, PitEntry>>,
}

impl Pit {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            entries: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            entries: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn clear(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.entries.clear();
        #[cfg(target_arch = "wasm32")]
        self.entries.lock().unwrap().clear();
    }

    pub fn insert(&self, token: PitToken, entry: PitEntry) {
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.entries.insert(token, entry);
        }
        #[cfg(target_arch = "wasm32")]
        {
            self.entries.lock().unwrap().insert(token, entry);
        }
    }

    /// Returns `true` if the PIT contains an entry for `token`.
    pub fn contains(&self, token: &PitToken) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.contains_key(token);
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().contains_key(token);
    }

    /// Apply `f` to the entry for `token`, returning the closure's result.
    /// Returns `None` if no entry exists.
    pub fn with_entry<R, F: FnOnce(&PitEntry) -> R>(&self, token: &PitToken, f: F) -> Option<R> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.get(token).map(|e| f(&e));
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().get(token).map(f);
    }

    /// Apply `f` to the mutable entry for `token`, returning the closure's result.
    /// Returns `None` if no entry exists.
    pub fn with_entry_mut<R, F: FnOnce(&mut PitEntry) -> R>(
        &self,
        token: &PitToken,
        f: F,
    ) -> Option<R> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.get_mut(token).map(|mut e| f(&mut e));
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().get_mut(token).map(f);
    }

    /// Look up an entry by reference. Prefer `contains()` or `with_entry()` for new code.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get(
        &self,
        token: &PitToken,
    ) -> Option<dashmap::mapref::one::Ref<'_, PitToken, PitEntry>> {
        self.entries.get(token)
    }

    /// Look up a mutable entry. Prefer `with_entry_mut()` for new code.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_mut(
        &self,
        token: &PitToken,
    ) -> Option<dashmap::mapref::one::RefMut<'_, PitToken, PitEntry>> {
        self.entries.get_mut(token)
    }

    pub fn remove(&self, token: &PitToken) -> Option<(PitToken, PitEntry)> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.remove(token);
        #[cfg(target_arch = "wasm32")]
        return self
            .entries
            .lock()
            .unwrap()
            .remove(token)
            .map(|v| (*token, v));
    }

    pub fn len(&self) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.len();
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().len();
    }

    pub fn is_empty(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.is_empty();
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().is_empty();
    }

    /// Remove all entries whose `expires_at` ≤ `now_ns`.
    /// Returns the tokens of expired entries.
    pub fn drain_expired(&self, now_ns: u64) -> Vec<PitToken> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let expired: Vec<PitToken> = self
                .entries
                .iter()
                .filter(|r| r.expires_at <= now_ns)
                .map(|r| *r.key())
                .collect();
            for token in &expired {
                self.entries.remove(token);
            }
            expired
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let expired: Vec<PitToken> = entries
                .iter()
                .filter(|(_, e)| e.expires_at <= now_ns)
                .map(|(k, _)| *k)
                .collect();
            for token in &expired {
                entries.remove(token);
            }
            expired
        }
    }

    /// Remove PIT entries whose **only** in-record face is `face_id`.
    ///
    /// Entries that also have in-records from other faces are kept (with the
    /// dead face's records removed). This prevents stale PIT entries from
    /// suppressing Interests after a face disconnects.
    pub fn remove_face(&self, face_id: u32) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        {
            // First pass: identify entries to remove entirely (sole consumer was this face).
            let mut to_remove = Vec::new();
            let mut to_prune = Vec::new();

            for entry in self.entries.iter() {
                let all_on_face = entry.in_records.iter().all(|r| r.face_id == face_id);
                let any_on_face = entry.in_records.iter().any(|r| r.face_id == face_id);

                if all_on_face && !entry.in_records.is_empty() {
                    to_remove.push(*entry.key());
                } else if any_on_face {
                    to_prune.push(*entry.key());
                }
            }

            let removed = to_remove.len();

            for token in &to_remove {
                self.entries.remove(token);
            }

            // Second pass: prune in-records for the dead face from multi-consumer entries.
            for token in &to_prune {
                if let Some(mut entry) = self.entries.get_mut(token) {
                    entry.in_records.retain(|r| r.face_id != face_id);
                }
            }

            removed
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let mut to_remove = Vec::new();
            let mut to_prune = Vec::new();

            for (token, entry) in entries.iter() {
                let all_on_face = entry.in_records.iter().all(|r| r.face_id == face_id);
                let any_on_face = entry.in_records.iter().any(|r| r.face_id == face_id);

                if all_on_face && !entry.in_records.is_empty() {
                    to_remove.push(*token);
                } else if any_on_face {
                    to_prune.push(*token);
                }
            }

            let removed = to_remove.len();

            for token in &to_remove {
                entries.remove(token);
            }

            for token in &to_prune {
                if let Some(entry) = entries.get_mut(token) {
                    entry.in_records.retain(|r| r.face_id != face_id);
                }
            }

            removed
        }
    }
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::encode::{encode_data_unsigned, encode_interest};
    use ndn_packet::{Data, Interest, NameComponent, Selector};

    fn make_name(comps: &[&str]) -> Name {
        Name::from_components(
            comps
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        )
    }

    /// Verify PIT token matching for iperf-style Interest/Data flow.
    ///
    /// This reproduces the exact path used in the pipeline:
    /// - PitCheckStage creates token with `from_interest_full(name, Some(selectors), fwd_hint)`
    /// - PitMatchStage tries `from_interest(data.name, None)` then `from_interest(data.name, Some(default))`
    #[test]
    fn pit_token_iperf_interest_data_match() {
        let name = make_name(&["iperf", "0"]);

        // Encode Interest the same way iperf does.
        let interest_wire = encode_interest(&name, None);
        let interest = Interest::decode(interest_wire.clone()).unwrap();

        // PitCheckStage creates token:
        let check_token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );

        // Server responds with Data using the Interest's name.
        let data_wire = encode_data_unsigned(&interest.name, &[0xAAu8; 100]);
        let data = Data::decode(data_wire).unwrap();

        // PitMatchStage first try:
        let match_token1 = PitToken::from_interest(&data.name, None);
        // PitMatchStage second try:
        let default_sel = Selector::default();
        let match_token2 = PitToken::from_interest(&data.name, Some(&default_sel));

        // The second try MUST match the check token.
        assert_ne!(
            check_token, match_token1,
            "first try should NOT match (None vs Some selector)"
        );
        assert_eq!(
            check_token, match_token2,
            "second try MUST match (Same default selector)"
        );
    }

    /// Verify that source_face_id computation matches PitCheck for management Interests.
    ///
    /// This simulates the rib/register flow where source_face_id decodes
    /// the Interest from raw bytes forwarded through the pipeline.
    #[test]
    fn pit_token_management_interest_source_face() {
        // Build a rib/register command name (simplified).
        let name = make_name(&["localhost", "nfd", "rib", "register", "params"]);
        let interest_wire = encode_interest(&name, None);
        let interest = Interest::decode(interest_wire.clone()).unwrap();

        // PitCheckStage creates token from decoded Interest:
        let check_token = PitToken::from_interest_full(
            &interest.name,
            Some(interest.selectors()),
            interest.forwarding_hint(),
        );

        // After ensure_nonce (no-op since nonce already present), the same bytes
        // are forwarded to the management face. Management handler decodes them:
        let mgmt_interest = Interest::decode(interest_wire).unwrap();

        // source_face_id computes:
        let source_token = PitToken::from_interest_full(
            &mgmt_interest.name,
            Some(mgmt_interest.selectors()),
            mgmt_interest.forwarding_hint(),
        );

        assert_eq!(
            check_token, source_token,
            "source_face_id must match PitCheck token"
        );
    }

    #[test]
    fn pit_insert_and_remove_basic() {
        let pit = Pit::new();
        let name = Arc::new(make_name(&["test"]));
        let token = PitToken::from_interest(&name, None);
        let entry = PitEntry::new(name, None, 0, 4000);
        pit.insert(token, entry);
        assert_eq!(pit.len(), 1);
        assert!(pit.remove(&token).is_some());
        assert!(pit.is_empty());
    }

    #[test]
    fn remove_face_drains_sole_consumer() {
        let pit = Pit::new();

        // Entry with sole consumer on face 1.
        let name1 = Arc::new(make_name(&["a"]));
        let token1 = PitToken::from_interest(&name1, None);
        let mut entry1 = PitEntry::new(name1, None, 0, 4000);
        entry1.add_in_record(1, 100, 999, None);
        pit.insert(token1, entry1);

        // Entry with consumers on face 1 AND face 2.
        let name2 = Arc::new(make_name(&["b"]));
        let token2 = PitToken::from_interest(&name2, None);
        let mut entry2 = PitEntry::new(name2, None, 0, 4000);
        entry2.add_in_record(1, 200, 999, None);
        entry2.add_in_record(2, 201, 999, None);
        pit.insert(token2, entry2);

        // Entry with sole consumer on face 3 (unrelated).
        let name3 = Arc::new(make_name(&["c"]));
        let token3 = PitToken::from_interest(&name3, None);
        let mut entry3 = PitEntry::new(name3, None, 0, 4000);
        entry3.add_in_record(3, 300, 999, None);
        pit.insert(token3, entry3);

        assert_eq!(pit.len(), 3);

        // Remove face 1: should remove entry1 entirely, prune face 1 from entry2.
        let removed = pit.remove_face(1);
        assert_eq!(removed, 1);
        assert_eq!(pit.len(), 2); // entry2 and entry3 remain

        // entry2 should still exist but only have face 2's in-record.
        pit.with_entry(&token2, |entry2| {
            assert_eq!(entry2.in_records.len(), 1);
            assert_eq!(entry2.in_records[0].face_id, 2);
        })
        .expect("entry2 should exist");

        // entry3 is untouched.
        assert!(pit.contains(&token3));
    }
}
