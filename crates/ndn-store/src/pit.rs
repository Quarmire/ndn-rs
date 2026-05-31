use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
use smallvec::SmallVec;

use ndn_packet::lp::TraceId;
use ndn_packet::{Name, NameComponent, Selector};

/// Pre-computed cumulative name-prefix hashes, hashed once at TLV decode and
/// reused across PIT check/match/nack without re-hashing components.
///
/// Ref: Shi et al., "NDN-DPDK: NDN Forwarding at 100 Gbps on Commodity
/// Hardware" (ACM ICN 2020), §3.1.
#[derive(Clone, Debug)]
pub struct NameHashes {
    pub prefix_hashes: SmallVec<[u64; 8]>,
}

const HASH_MIX: u64 = 0x517cc1b727220a95;

impl NameHashes {
    pub fn compute(name: &Name) -> Self {
        Self::from_components(name.components())
    }

    pub fn from_components(components: &[NameComponent]) -> Self {
        let mut prefix_hashes = SmallVec::with_capacity(components.len());
        let mut state: u64 = 0;
        for comp in components {
            state = Self::accumulate(state, comp);
            prefix_hashes.push(state);
        }
        Self { prefix_hashes }
    }

    pub fn full_hash(&self) -> u64 {
        self.prefix_hashes.last().copied().unwrap_or(0)
    }

    pub fn prefix_hash(&self, n: usize) -> u64 {
        if n == 0 { 0 } else { self.prefix_hashes[n - 1] }
    }

    pub fn len(&self) -> usize {
        self.prefix_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prefix_hashes.is_empty()
    }

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
/// Hash of `(Name, ForwardingHint)`. Selectors are *not* part of the key —
/// they live on each [`InRecord`] so heterogeneous downstreams aggregate into
/// a single entry. Mirrors NFD `daemon/table/pit-entry.cpp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PitToken(pub u64);

/// Discriminator that keeps marker-bearing (persistent-attach) Interests in a
/// separate PIT entry from classical Interests at the same logical name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum PitKeyDiscriminator {
    #[default]
    Classical,
    PersistentAttach,
}

impl PitToken {
    pub fn from_interest(name: &Name) -> Self {
        Self::from_interest_full(name, None)
    }

    pub fn from_interest_full(name: &Name, forwarding_hint: Option<&[Arc<Name>]>) -> Self {
        let name_hash = NameHashes::full_name_hash(name);
        Self::from_name_hash(name_hash, forwarding_hint)
    }

    pub fn from_name_hash(name_hash: u64, forwarding_hint: Option<&[Arc<Name>]>) -> Self {
        Self::from_name_hash_keyed(name_hash, forwarding_hint, PitKeyDiscriminator::Classical)
    }

    pub fn from_name_hash_keyed(
        name_hash: u64,
        forwarding_hint: Option<&[Arc<Name>]>,
        disc: PitKeyDiscriminator,
    ) -> Self {
        let mut h = DefaultHasher::new();
        name_hash.hash(&mut h);
        if let Some(hints) = forwarding_hint {
            for hint in hints {
                hint.hash(&mut h);
            }
        }
        disc.hash(&mut h);
        PitToken(h.finish())
    }

    pub fn persistent_attach(name: &Name) -> Self {
        Self::from_name_hash_keyed(
            NameHashes::full_name_hash(name),
            None,
            PitKeyDiscriminator::PersistentAttach,
        )
    }

    pub fn persistent_attach_full(name: &Name, forwarding_hint: Option<&[Arc<Name>]>) -> Self {
        Self::from_name_hash_keyed(
            NameHashes::full_name_hash(name),
            forwarding_hint,
            PitKeyDiscriminator::PersistentAttach,
        )
    }
}

/// State for a persistent PIT in-record (one that survives multiple Data
/// matches). Per-in-record credit lets multiple persistent-attach subscribers
/// aggregate into one entry while owning independent ACL, expiry, and credit.
#[derive(Clone, Debug)]
pub struct PersistentState {
    /// Remaining Data packets before the in-record is reaped.
    pub data_count_remaining: u32,
    /// Absolute deadline (nanoseconds since UNIX_EPOCH).
    pub reap_at: u64,
}

#[derive(Clone, Debug)]
pub struct InRecord {
    pub face_id: u64,
    pub nonce: u32,
    pub expires_at: u64,
    /// NDNLPv2 PIT token from the LP header; must be echoed back in Data/Nack.
    pub lp_pit_token: Option<bytes::Bytes>,
    /// Originator's selectors. Stored per-in-record so the match stage can
    /// filter per-downstream (e.g. apply `MustBeFresh` only to the in-records
    /// that asked for it). Mirrors NFD `pit-in-record.hpp` `m_lastInterest`.
    pub selector: Selector,
    /// `Some` when this in-record came in via a validated substrate-marker
    /// Interest.
    pub persistent: Option<PersistentState>,
    /// Trace IDs observed on this in-record's Interest; emitted as one span
    /// per aggregated consumer on Data fan-out.
    pub trace_ids: SmallVec<[TraceId; 1]>,
}

#[derive(Clone, Debug)]
pub struct OutRecord {
    pub face_id: u64,
    pub last_nonce: u32,
    pub sent_at: u64,
}

pub struct PitEntry {
    pub name: Arc<Name>,
    pub in_records: Vec<InRecord>,
    pub out_records: Vec<OutRecord>,
    pub nonces_seen: SmallVec<[u32; 4]>,
    pub is_satisfied: bool,
    pub created_at: u64,
    pub expires_at: u64,
    /// Entry-level persistent state. New code installs persistent state on
    /// each in-record (see [`InRecord::persistent`]); the match stage falls
    /// back to this only when no in-record carries one.
    pub persistent: Option<PersistentState>,
    /// Overhear-cancel flag for a *scheduled* forward (CCLF election). Set when
    /// a neighbor is observed forwarding the same Interest instance (duplicate
    /// nonce) while this node has a `ForwardAfter` pending; the timer task
    /// checks it on wake and skips the redundant transmission. Inert for
    /// strategies that forward immediately.
    pub forward_cancelled: bool,
}

impl PitEntry {
    pub fn new(name: Arc<Name>, now: u64, lifetime_ms: u64) -> Self {
        Self {
            name,
            in_records: Vec::new(),
            out_records: Vec::new(),
            nonces_seen: SmallVec::new(),
            is_satisfied: false,
            created_at: now,
            expires_at: now + lifetime_ms * 1_000_000,
            persistent: None,
            forward_cancelled: false,
        }
    }

    pub fn add_in_record(
        &mut self,
        face_id: u64,
        nonce: u32,
        expires_at: u64,
        lp_pit_token: Option<bytes::Bytes>,
        selector: Selector,
    ) {
        self.add_in_record_with_persistent(face_id, nonce, expires_at, lp_pit_token, selector, None)
    }

    /// Add an in-record with optional persistent state. When `persistent` is
    /// `Some`, the entry survives until every persistent in-record exhausts
    /// its credit or the reaper fires.
    pub fn add_in_record_with_persistent(
        &mut self,
        face_id: u64,
        nonce: u32,
        expires_at: u64,
        lp_pit_token: Option<bytes::Bytes>,
        selector: Selector,
        persistent: Option<PersistentState>,
    ) {
        self.add_in_record_inner(
            face_id,
            nonce,
            expires_at,
            lp_pit_token,
            selector,
            persistent,
            SmallVec::new(),
        )
    }

    /// Add an in-record carrying the trace IDs of its originating Interest;
    /// emitted as one OTel span per in-record on Data fan-out.
    #[allow(clippy::too_many_arguments)]
    pub fn add_in_record_with_trace_ids(
        &mut self,
        face_id: u64,
        nonce: u32,
        expires_at: u64,
        lp_pit_token: Option<bytes::Bytes>,
        selector: Selector,
        persistent: Option<PersistentState>,
        trace_ids: SmallVec<[TraceId; 1]>,
    ) {
        self.add_in_record_inner(
            face_id,
            nonce,
            expires_at,
            lp_pit_token,
            selector,
            persistent,
            trace_ids,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_in_record_inner(
        &mut self,
        face_id: u64,
        nonce: u32,
        expires_at: u64,
        lp_pit_token: Option<bytes::Bytes>,
        selector: Selector,
        persistent: Option<PersistentState>,
        trace_ids: SmallVec<[TraceId; 1]>,
    ) {
        self.in_records.push(InRecord {
            face_id,
            nonce,
            expires_at,
            lp_pit_token,
            selector,
            persistent,
            trace_ids,
        });
        if !self.nonces_seen.contains(&nonce) {
            self.nonces_seen.push(nonce);
        }
    }

    pub fn is_persistent(&self) -> bool {
        self.persistent.is_some() || self.in_records.iter().any(|r| r.persistent.is_some())
    }

    pub fn add_out_record(&mut self, face_id: u64, nonce: u32, sent_at: u64) {
        self.out_records.push(OutRecord {
            face_id,
            last_nonce: nonce,
            sent_at,
        });
    }

    pub fn in_record_faces(&self) -> impl Iterator<Item = u64> + '_ {
        self.in_records.iter().map(|r| r.face_id)
    }
}

/// The Pending Interest Table.
///
/// Backed by `DashMap` on native (sharded — no global lock on the hot path)
/// and `Mutex<HashMap>` on `wasm32` (single-threaded).
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

    pub fn contains(&self, token: &PitToken) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.contains_key(token);
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().contains_key(token);
    }

    pub fn with_entry<R, F: FnOnce(&PitEntry) -> R>(&self, token: &PitToken, f: F) -> Option<R> {
        #[cfg(not(target_arch = "wasm32"))]
        return self.entries.get(token).map(|e| f(&e));
        #[cfg(target_arch = "wasm32")]
        return self.entries.lock().unwrap().get(token).map(f);
    }

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

    /// Look up the PIT entry at `name` under `disc` and call `f` on it.
    pub fn with_named_entry<R, F: FnOnce(&PitEntry) -> R>(
        &self,
        name: &Name,
        disc: PitKeyDiscriminator,
        f: F,
    ) -> Option<R> {
        let token = PitToken::from_name_hash_keyed(NameHashes::full_name_hash(name), None, disc);
        self.with_entry(&token, f)
    }

    /// Atomic check-and-insert under the per-shard write lock. Use this in
    /// any check-then-act pattern reachable from the parallel pipeline.
    pub fn with_entry_or_insert<R, FOcc, FNew>(
        &self,
        token: PitToken,
        on_existing: FOcc,
        on_new: FNew,
    ) -> R
    where
        FOcc: FnOnce(&mut PitEntry) -> R,
        FNew: FnOnce() -> (PitEntry, R),
    {
        #[cfg(not(target_arch = "wasm32"))]
        {
            use dashmap::mapref::entry::Entry;
            match self.entries.entry(token) {
                Entry::Occupied(mut e) => on_existing(e.get_mut()),
                Entry::Vacant(v) => {
                    let (entry, ret) = on_new();
                    v.insert(entry);
                    ret
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            use std::collections::hash_map::Entry;
            let mut guard = self.entries.lock().unwrap();
            match guard.entry(token) {
                Entry::Occupied(mut e) => on_existing(e.get_mut()),
                Entry::Vacant(v) => {
                    let (entry, ret) = on_new();
                    v.insert(entry);
                    ret
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn get(
        &self,
        token: &PitToken,
    ) -> Option<dashmap::mapref::one::Ref<'_, PitToken, PitEntry>> {
        self.entries.get(token)
    }

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

    /// Drain expired PIT entries with their full entry state. Forwarders use
    /// this when erasure needs more than the in-record face IDs, such as
    /// populating the Dead Nonce List.
    pub fn drain_expired_entries(&self, now_ns: u64) -> Vec<(PitToken, PitEntry)> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let expired: Vec<PitToken> = self
                .entries
                .iter()
                .filter(|r| r.expires_at <= now_ns)
                .map(|r| *r.key())
                .collect();
            let mut out: Vec<(PitToken, PitEntry)> = Vec::with_capacity(expired.len());
            for token in &expired {
                if let Some((_, entry)) = self.entries.remove(token) {
                    out.push((*token, entry));
                }
            }
            out
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut entries = self.entries.lock().unwrap();
            let expired: Vec<PitToken> = entries
                .iter()
                .filter(|(_, e)| e.expires_at <= now_ns)
                .map(|(k, _)| *k)
                .collect();
            let mut out: Vec<(PitToken, PitEntry)> = Vec::with_capacity(expired.len());
            for token in &expired {
                if let Some(entry) = entries.remove(token) {
                    out.push((*token, entry));
                }
            }
            out
        }
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

    /// Drain expired PIT entries; returns each entry's token paired with the
    /// list of in-record face IDs so the expiry task can credit
    /// `NUnsatisfiedInterests` per upstream face.
    pub fn drain_expired(&self, now_ns: u64) -> Vec<(PitToken, smallvec::SmallVec<[u64; 4]>)> {
        self.drain_expired_entries(now_ns)
            .into_iter()
            .map(|(token, entry)| {
                let faces: smallvec::SmallVec<[u64; 4]> =
                    entry.in_records.iter().map(|r| r.face_id).collect();
                (token, faces)
            })
            .collect()
    }

    /// Remove PIT entries whose only in-record face is `face_id`. Entries
    /// with other in-records are kept with the dead face's records pruned,
    /// so a disconnect doesn't suppress Interests from other consumers.
    pub fn remove_face(&self, face_id: u64) -> usize {
        #[cfg(not(target_arch = "wasm32"))]
        {
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

    #[test]
    fn pit_token_iperf_interest_data_match() {
        let name = make_name(&["iperf", "0"]);

        let interest_wire = encode_interest(&name, None);
        let interest = Interest::decode(interest_wire.clone()).unwrap();

        let check_token = PitToken::from_interest_full(&interest.name, interest.forwarding_hint());

        let data_wire = encode_data_unsigned(&interest.name, &[0xAAu8; 100]);
        let data = Data::decode(data_wire).unwrap();
        let match_token = PitToken::from_interest(&data.name);

        assert_eq!(
            check_token, match_token,
            "PitMatchStage's name-only lookup must match PitCheckStage's token"
        );
    }

    #[test]
    fn pit_token_management_interest_source_face() {
        let name = make_name(&["localhost", "nfd", "rib", "register", "params"]);
        let interest_wire = encode_interest(&name, None);
        let interest = Interest::decode(interest_wire.clone()).unwrap();

        let check_token = PitToken::from_interest_full(&interest.name, interest.forwarding_hint());

        let mgmt_interest = Interest::decode(interest_wire).unwrap();
        let source_token =
            PitToken::from_interest_full(&mgmt_interest.name, mgmt_interest.forwarding_hint());

        assert_eq!(
            check_token, source_token,
            "source_face_id must match PitCheck token"
        );
    }

    /// PIT token must not factor selectors: two Interests for the same Name
    /// (one with `MustBeFresh`, one without) hash to the same token and
    /// aggregate into one entry. Mirrors NFD `daemon/table/pit-entry.cpp`.
    #[test]
    fn pit_token_does_not_factor_selector() {
        let name = make_name(&["foo", "bar"]);
        let token_a = PitToken::from_interest(&name);
        let token_b = PitToken::from_interest(&name);
        assert_eq!(token_a, token_b);
    }

    #[test]
    fn in_record_carries_originator_selector() {
        let name = Arc::new(make_name(&["foo"]));
        let mut entry = PitEntry::new(Arc::clone(&name), 0, 4000);
        let must_be_fresh = Selector {
            can_be_prefix: false,
            must_be_fresh: true,
        };
        entry.add_in_record(1, 100, 999, None, must_be_fresh.clone());
        entry.add_in_record(2, 101, 999, None, Selector::default());
        assert_eq!(entry.in_records[0].selector, must_be_fresh);
        assert_eq!(entry.in_records[1].selector, Selector::default());
    }

    /// Aggregation invariant: two Interests for the same Name from different
    /// consumers (different selectors) land in a single PIT entry with two
    /// in-records.
    #[test]
    fn aggregation_same_name_different_selectors() {
        let pit = Pit::new();
        let name = Arc::new(make_name(&["aggregate"]));

        let token_a = PitToken::from_interest(&name);
        let mut entry_a = PitEntry::new(Arc::clone(&name), 0, 4000);
        entry_a.add_in_record(
            1,
            10,
            999,
            None,
            Selector {
                can_be_prefix: false,
                must_be_fresh: true,
            },
        );
        pit.insert(token_a, entry_a);

        let token_b = PitToken::from_interest(&name);
        assert_eq!(token_a, token_b, "PIT tokens for same Name must match");
        pit.with_entry_mut(&token_b, |e| {
            e.add_in_record(2, 20, 999, None, Selector::default());
        })
        .expect("entry must exist after first insert");

        assert_eq!(
            pit.len(),
            1,
            "two same-Name Interests must aggregate into one entry"
        );
        pit.with_entry(&token_a, |e| {
            assert_eq!(e.in_records.len(), 2, "both in-records must be present");
        })
        .expect("entry must exist");
    }

    #[test]
    fn pit_insert_and_remove_basic() {
        let pit = Pit::new();
        let name = Arc::new(make_name(&["test"]));
        let token = PitToken::from_interest(&name);
        let entry = PitEntry::new(name, 0, 4000);
        pit.insert(token, entry);
        assert_eq!(pit.len(), 1);
        assert!(pit.remove(&token).is_some());
        assert!(pit.is_empty());
    }

    #[test]
    fn remove_face_drains_sole_consumer() {
        let pit = Pit::new();

        let name1 = Arc::new(make_name(&["a"]));
        let token1 = PitToken::from_interest(&name1);
        let mut entry1 = PitEntry::new(name1, 0, 4000);
        entry1.add_in_record(1, 100, 999, None, Selector::default());
        pit.insert(token1, entry1);

        let name2 = Arc::new(make_name(&["b"]));
        let token2 = PitToken::from_interest(&name2);
        let mut entry2 = PitEntry::new(name2, 0, 4000);
        entry2.add_in_record(1, 200, 999, None, Selector::default());
        entry2.add_in_record(2, 201, 999, None, Selector::default());
        pit.insert(token2, entry2);

        let name3 = Arc::new(make_name(&["c"]));
        let token3 = PitToken::from_interest(&name3);
        let mut entry3 = PitEntry::new(name3, 0, 4000);
        entry3.add_in_record(3, 300, 999, None, Selector::default());
        pit.insert(token3, entry3);

        assert_eq!(pit.len(), 3);

        let removed = pit.remove_face(1);
        assert_eq!(removed, 1);
        assert_eq!(pit.len(), 2);

        pit.with_entry(&token2, |entry2| {
            assert_eq!(entry2.in_records.len(), 1);
            assert_eq!(entry2.in_records[0].face_id, 2);
        })
        .expect("entry2 should exist");

        assert!(pit.contains(&token3));
    }

    #[test]
    fn drain_expired_reports_in_record_faces() {
        let pit = Pit::new();
        let token = PitToken(0xAB);
        let name = std::sync::Arc::new(make_name(&["e08"]));
        let mut entry = PitEntry::new(name, 0, 0);
        entry.add_in_record(11, 1, 100, None, Selector::default());
        entry.add_in_record(22, 2, 100, None, Selector::default());
        pit.insert(token, entry);

        let expired = pit.drain_expired(u64::MAX);
        assert_eq!(expired.len(), 1);
        let (drained_token, faces) = &expired[0];
        assert_eq!(*drained_token, token);
        let mut got: Vec<u64> = faces.iter().copied().collect();
        got.sort();
        assert_eq!(got, vec![11u64, 22]);
        assert!(!pit.contains(&token));
    }

    #[test]
    fn trace_ids_single_in_record_stores_one() {
        let name = std::sync::Arc::new(make_name(&["agg", "single"]));
        let mut entry = PitEntry::new(name, 0, 0);
        let id = TraceId([1; 16]);
        let mut ids = SmallVec::new();
        ids.push(id);
        entry.add_in_record_with_trace_ids(1, 42, 100, None, Selector::default(), None, ids);
        assert_eq!(entry.in_records.len(), 1);
        assert_eq!(entry.in_records[0].trace_ids.as_slice(), &[id]);
    }

    #[test]
    fn trace_ids_aggregate_two_consumers() {
        let name = std::sync::Arc::new(make_name(&["agg", "two"]));
        let mut entry = PitEntry::new(name, 0, 0);

        let id_a = TraceId([0xAA; 16]);
        let id_b = TraceId([0xBB; 16]);

        let mut ids_a = SmallVec::new();
        ids_a.push(id_a);
        entry.add_in_record_with_trace_ids(10, 1, 100, None, Selector::default(), None, ids_a);

        let mut ids_b = SmallVec::new();
        ids_b.push(id_b);
        entry.add_in_record_with_trace_ids(20, 2, 100, None, Selector::default(), None, ids_b);

        assert_eq!(entry.in_records.len(), 2);
        assert_eq!(entry.in_records[0].trace_ids.as_slice(), &[id_a]);
        assert_eq!(entry.in_records[1].trace_ids.as_slice(), &[id_b]);
    }

    #[test]
    fn trace_ids_default_path_leaves_empty() {
        let name = std::sync::Arc::new(make_name(&["agg", "default"]));
        let mut entry = PitEntry::new(name, 0, 0);
        entry.add_in_record(1, 1, 100, None, Selector::default());
        assert!(entry.in_records[0].trace_ids.is_empty());
    }

    /// Overhear-cancel (CCLF): a fresh entry is not cancelled, and the flag can
    /// be set via `with_entry_or_insert`'s on-existing path — the exact seam the
    /// engine's PIT stage uses on a duplicate-nonce (overheard) Interest.
    #[test]
    fn forward_cancelled_defaults_false_and_sets_on_existing() {
        let pit = Pit::new();
        let name = std::sync::Arc::new(make_name(&["cclf", "overhear"]));
        let token = PitToken(0x0CCF);
        let entry = PitEntry::new(name, 0, 1000);
        assert!(!entry.forward_cancelled, "new entry must not be cancelled");
        pit.insert(token, entry);

        // Simulate the duplicate-nonce path setting the cancel flag.
        pit.with_entry_or_insert(
            token,
            |e| {
                e.forward_cancelled = true;
            },
            || unreachable!("entry exists"),
        );
        assert_eq!(
            pit.with_entry(&token, |e| e.forward_cancelled),
            Some(true),
            "overhear must set the cancel flag the ForwardAfter task reads"
        );
    }
}
