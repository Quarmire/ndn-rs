use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;

use dashmap::DashMap;
use smallvec::SmallVec;

use ndn_packet::{Name, Selector};

/// A stable, cheaply-copyable reference to a PIT entry.
///
/// Computed as a hash of (Name, Option<Selector>) — safe to copy across tasks
/// and `await` points without lifetime concerns.
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
        let mut h = DefaultHasher::new();
        name.hash(&mut h);
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
    pub face_id:    u32,
    pub nonce:      u32,
    pub expires_at: u64,
}

/// Record of an outgoing Interest (producer-facing side of the PIT entry).
#[derive(Clone, Debug)]
pub struct OutRecord {
    pub face_id:    u32,
    pub last_nonce: u32,
    pub sent_at:    u64,
}

/// A single PIT entry — one per pending (Name, Option<Selector>) pair.
pub struct PitEntry {
    pub name:         Arc<Name>,
    pub selector:     Option<Selector>,
    pub in_records:   Vec<InRecord>,
    pub out_records:  Vec<OutRecord>,
    /// Nonces seen so far — inline for the common case of ≤4 nonces.
    pub nonces_seen:  SmallVec<[u32; 4]>,
    pub is_satisfied: bool,
    pub created_at:   u64,
    pub expires_at:   u64,
}

impl PitEntry {
    pub fn new(
        name: Arc<Name>,
        selector: Option<Selector>,
        now: u64,
        lifetime_ms: u64,
    ) -> Self {
        Self {
            name,
            selector,
            in_records:   Vec::new(),
            out_records:  Vec::new(),
            nonces_seen:  SmallVec::new(),
            is_satisfied: false,
            created_at:   now,
            expires_at:   now + lifetime_ms * 1_000_000,
        }
    }

    pub fn add_in_record(&mut self, face_id: u32, nonce: u32, expires_at: u64) {
        self.in_records.push(InRecord { face_id, nonce, expires_at });
        if !self.nonces_seen.contains(&nonce) {
            self.nonces_seen.push(nonce);
        }
    }

    pub fn add_out_record(&mut self, face_id: u32, nonce: u32, sent_at: u64) {
        self.out_records.push(OutRecord { face_id, last_nonce: nonce, sent_at });
    }

    /// Returns the face IDs of all in-records (for Data fan-back).
    pub fn in_record_faces(&self) -> impl Iterator<Item = u32> + '_ {
        self.in_records.iter().map(|r| r.face_id)
    }
}

/// The Pending Interest Table.
///
/// `DashMap` provides sharded concurrent access with no global lock on the
/// forwarding hot path.
pub struct Pit {
    entries: DashMap<PitToken, PitEntry>,
}

impl Pit {
    pub fn new() -> Self {
        Self { entries: DashMap::new() }
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn insert(&self, token: PitToken, entry: PitEntry) {
        self.entries.insert(token, entry);
    }

    pub fn get(&self, token: &PitToken)
        -> Option<dashmap::mapref::one::Ref<'_, PitToken, PitEntry>>
    {
        self.entries.get(token)
    }

    pub fn get_mut(&self, token: &PitToken)
        -> Option<dashmap::mapref::one::RefMut<'_, PitToken, PitEntry>>
    {
        self.entries.get_mut(token)
    }

    pub fn remove(&self, token: &PitToken) -> Option<(PitToken, PitEntry)> {
        self.entries.remove(token)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove all entries whose `expires_at` ≤ `now_ns`.
    /// Returns the tokens of expired entries.
    pub fn drain_expired(&self, now_ns: u64) -> Vec<PitToken> {
        let expired: Vec<PitToken> = self.entries
            .iter()
            .filter(|r| r.expires_at <= now_ns)
            .map(|r| *r.key())
            .collect();
        for token in &expired {
            self.entries.remove(token);
        }
        expired
    }
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}
