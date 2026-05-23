//! Signed-Interest replay guard.
//!
//! Maintains a per-signer-key LRU of recently-seen
//! `(sig_nonce, sig_time, sig_seq_num)` tuples and rejects replays before
//! they reach the PIT.  This is the integrity floor for universal
//! strip-at-insert: once PSDC is no longer a multiplexing key, two replayed
//! signed Interests with identical SignatureInfo would silently coalesce
//! into one PIT entry.  The guard prevents that.
//!
//! Scope: per-`KeyLocator` (or a shared "no-key" bucket for `DigestSha256`).
//! Anti-replay fields used: `sig_nonce`, `sig_time`, `sig_seq_num` from
//! NDN Packet Format v0.3 §5.4.  An Interest is a replay iff every field
//! present in both the recorded entry and the candidate agrees (AND semantics).
//! A random 64-bit nonce uniquely identifies a signed Interest; time and seq
//! are coarse supplementary fields that must not trigger rejection on their own.

use std::collections::VecDeque;
use std::sync::Mutex;

use bytes::Bytes;
#[cfg(not(target_arch = "wasm32"))]
use dashmap::DashMap;
#[cfg(target_arch = "wasm32")]
use std::collections::HashMap;

use ndn_packet::{KeyLocator, SignatureInfo};

/// Stable fingerprint of a signer key.
///
/// `Name` form is hashed by name component bytes; `KeyDigest` is the raw
/// digest; absent locator → `None` (treated as the shared DigestSha256
/// bucket).  Cheap to compute, cheap to hash.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct KeyFingerprint(Vec<u8>);

impl KeyFingerprint {
    pub fn no_key() -> Self {
        KeyFingerprint(vec![])
    }

    pub fn from_locator(locator: Option<&KeyLocator>) -> Self {
        match locator {
            None => KeyFingerprint::no_key(),
            Some(KeyLocator::Name(n)) => {
                // Concatenate component bytes with a delimiter that cannot
                // appear in a TLV-TYPE byte at the leading position.
                let mut buf = Vec::with_capacity(64);
                for c in n.components() {
                    buf.extend_from_slice(&c.typ.to_be_bytes());
                    buf.push(0xff);
                    buf.extend_from_slice(c.value.as_ref());
                    buf.push(0xff);
                }
                KeyFingerprint(buf)
            }
            Some(KeyLocator::KeyDigest(b)) => KeyFingerprint(b.to_vec()),
        }
    }
}

#[derive(Clone)]
struct NonceRecord {
    sig_nonce: Option<Bytes>,
    sig_time: Option<u64>,
    sig_seq_num: Option<u64>,
}

impl NonceRecord {
    fn from_sig_info(si: &SignatureInfo) -> Option<Self> {
        // Require at least one anti-replay field to be present, otherwise the
        // record has no distinguishing content and replay protection is
        // structurally impossible — the caller must decide whether to admit.
        if si.sig_nonce.is_none() && si.sig_time.is_none() && si.sig_seq_num.is_none() {
            return None;
        }
        Some(Self {
            sig_nonce: si.sig_nonce.clone(),
            sig_time: si.sig_time,
            sig_seq_num: si.sig_seq_num,
        })
    }

    fn matches(&self, si: &SignatureInfo) -> bool {
        // Replay iff every field present in BOTH this record and the candidate
        // agrees. A single mismatch on a shared field means these are distinct
        // signed Interests. If they share no anti-replay field at all, there is
        // no comparable evidence — treat as non-match.
        let mut compared_any = false;

        if let (Some(a), Some(b)) = (self.sig_nonce.as_ref(), si.sig_nonce.as_ref()) {
            compared_any = true;
            if a != b {
                return false;
            }
        }
        if let (Some(a), Some(b)) = (self.sig_time, si.sig_time) {
            compared_any = true;
            if a != b {
                return false;
            }
        }
        if let (Some(a), Some(b)) = (self.sig_seq_num, si.sig_seq_num) {
            compared_any = true;
            if a != b {
                return false;
            }
        }

        compared_any
    }
}

struct KeyState {
    /// Bounded LRU of recently-seen records for this key.
    records: VecDeque<NonceRecord>,
    /// Monotonic floor for `sig_seq_num`; any equal-or-lower seq is a replay
    /// even after eviction from `records`.  Sticky.
    max_seq: Option<u64>,
    /// Monotonic floor for `sig_time`; any equal-or-lower timestamp is a
    /// replay if the policy is `Monotonic`.  Sticky.
    max_time: Option<u64>,
}

impl KeyState {
    fn new() -> Self {
        Self {
            records: VecDeque::with_capacity(16),
            max_seq: None,
            max_time: None,
        }
    }
}

/// Result of a guard check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayCheck {
    /// Fresh; record was admitted.
    Fresh,
    /// Replay; reject before PIT insert.
    Replay,
    /// SignatureInfo carried no anti-replay field; the guard cannot decide.
    /// Caller policy determines whether to admit such Interests.
    NoAntiReplayFields,
}

/// Per-key replay guard with bounded LRU.
pub struct ReplayGuard {
    #[cfg(not(target_arch = "wasm32"))]
    keys: DashMap<KeyFingerprint, Mutex<KeyState>>,
    #[cfg(target_arch = "wasm32")]
    keys: Mutex<HashMap<KeyFingerprint, KeyState>>,
    /// Maximum number of records retained per key (LRU bound).
    per_key_capacity: usize,
    /// If true, monotonic sig_seq_num and sig_time are enforced across the
    /// LRU window.  Disable for testbed callers that issue out-of-order
    /// signed Interests legitimately.
    monotonic: bool,
}

impl ReplayGuard {
    pub fn new(per_key_capacity: usize, monotonic: bool) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            keys: DashMap::new(),
            #[cfg(target_arch = "wasm32")]
            keys: Mutex::new(HashMap::new()),
            per_key_capacity: per_key_capacity.max(1),
            monotonic,
        }
    }

    pub fn check(&self, sig_info: &SignatureInfo) -> ReplayCheck {
        let Some(record) = NonceRecord::from_sig_info(sig_info) else {
            return ReplayCheck::NoAntiReplayFields;
        };
        let fp = KeyFingerprint::from_locator(sig_info.key_locator.as_ref());

        #[cfg(not(target_arch = "wasm32"))]
        let cell = self
            .keys
            .entry(fp)
            .or_insert_with(|| Mutex::new(KeyState::new()));
        #[cfg(not(target_arch = "wasm32"))]
        let mut state = cell.lock().expect("ReplayGuard mutex poisoned");

        #[cfg(target_arch = "wasm32")]
        let mut keys = self.keys.lock().expect("ReplayGuard map mutex poisoned");
        #[cfg(target_arch = "wasm32")]
        let state = keys.entry(fp).or_insert_with(KeyState::new);

        if self.monotonic {
            if let (Some(prev), Some(now)) = (state.max_seq, sig_info.sig_seq_num)
                && now <= prev
            {
                return ReplayCheck::Replay;
            }
            if let (Some(prev), Some(now)) = (state.max_time, sig_info.sig_time)
                && now <= prev
            {
                return ReplayCheck::Replay;
            }
        }

        for r in state.records.iter() {
            if r.matches(sig_info) {
                return ReplayCheck::Replay;
            }
        }

        if state.records.len() >= self.per_key_capacity {
            state.records.pop_front();
        }
        if let Some(t) = record.sig_time {
            state.max_time = Some(state.max_time.map_or(t, |p| p.max(t)));
        }
        if let Some(s) = record.sig_seq_num {
            state.max_seq = Some(state.max_seq.map_or(s, |p| p.max(s)));
        }
        state.records.push_back(record);
        ReplayCheck::Fresh
    }

    pub fn forget_all(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        self.keys.clear();
        #[cfg(target_arch = "wasm32")]
        self.keys.lock().unwrap().clear();
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(64, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::SignatureType;

    fn si_with_nonce(n: &[u8]) -> SignatureInfo {
        SignatureInfo {
            sig_type: SignatureType::SignatureEd25519,
            key_locator: Some(KeyLocator::KeyDigest(Bytes::from_static(b"key-A"))),
            sig_nonce: Some(Bytes::copy_from_slice(n)),
            sig_time: None,
            sig_seq_num: None,
        }
    }

    fn si_with_time(t: u64) -> SignatureInfo {
        SignatureInfo {
            sig_type: SignatureType::SignatureEd25519,
            key_locator: Some(KeyLocator::KeyDigest(Bytes::from_static(b"key-A"))),
            sig_nonce: None,
            sig_time: Some(t),
            sig_seq_num: None,
        }
    }

    fn si_with_seq(s: u64) -> SignatureInfo {
        SignatureInfo {
            sig_type: SignatureType::SignatureEd25519,
            key_locator: Some(KeyLocator::KeyDigest(Bytes::from_static(b"key-A"))),
            sig_nonce: None,
            sig_time: None,
            sig_seq_num: Some(s),
        }
    }

    fn si_with_nonce_time(nonce: &[u8], t: u64) -> SignatureInfo {
        SignatureInfo {
            sig_type: SignatureType::SignatureEd25519,
            key_locator: Some(KeyLocator::KeyDigest(Bytes::from_static(b"key-A"))),
            sig_nonce: Some(Bytes::copy_from_slice(nonce)),
            sig_time: Some(t),
            sig_seq_num: None,
        }
    }

    #[test]
    fn fresh_nonce_admitted() {
        let g = ReplayGuard::new(16, false);
        assert_eq!(g.check(&si_with_nonce(b"n1")), ReplayCheck::Fresh);
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let g = ReplayGuard::new(16, false);
        g.check(&si_with_nonce(b"n1"));
        assert_eq!(g.check(&si_with_nonce(b"n1")), ReplayCheck::Replay);
    }

    #[test]
    fn different_keys_isolated() {
        let g = ReplayGuard::new(16, false);
        let a = si_with_nonce(b"shared");
        let mut b = si_with_nonce(b"shared");
        b.key_locator = Some(KeyLocator::KeyDigest(Bytes::from_static(b"key-B")));
        assert_eq!(g.check(&a), ReplayCheck::Fresh);
        assert_eq!(g.check(&b), ReplayCheck::Fresh);
    }

    #[test]
    fn lru_evicts_oldest() {
        let g = ReplayGuard::new(2, false);
        g.check(&si_with_nonce(b"n1"));
        g.check(&si_with_nonce(b"n2"));
        g.check(&si_with_nonce(b"n3"));
        // n1 was evicted → no longer a replay.
        assert_eq!(g.check(&si_with_nonce(b"n1")), ReplayCheck::Fresh);
        // n3 is still in the window.
        assert_eq!(g.check(&si_with_nonce(b"n3")), ReplayCheck::Replay);
    }

    #[test]
    fn no_anti_replay_fields_returns_sentinel() {
        let g = ReplayGuard::new(16, false);
        let si = SignatureInfo {
            sig_type: SignatureType::DigestSha256,
            key_locator: None,
            sig_nonce: None,
            sig_time: None,
            sig_seq_num: None,
        };
        assert_eq!(g.check(&si), ReplayCheck::NoAntiReplayFields);
    }

    #[test]
    fn monotonic_seq_blocks_lower() {
        let g = ReplayGuard::new(16, true);
        assert_eq!(g.check(&si_with_seq(10)), ReplayCheck::Fresh);
        assert_eq!(g.check(&si_with_seq(11)), ReplayCheck::Fresh);
        assert_eq!(g.check(&si_with_seq(11)), ReplayCheck::Replay);
        assert_eq!(g.check(&si_with_seq(5)), ReplayCheck::Replay);
    }

    #[test]
    fn monotonic_time_blocks_lower() {
        let g = ReplayGuard::new(16, true);
        assert_eq!(g.check(&si_with_time(1000)), ReplayCheck::Fresh);
        assert_eq!(g.check(&si_with_time(2000)), ReplayCheck::Fresh);
        assert_eq!(g.check(&si_with_time(500)), ReplayCheck::Replay);
    }

    #[test]
    fn distinct_nonces_with_same_time_are_not_replays() {
        let g = ReplayGuard::new(16, false);
        let t = 1_700_000_000_000u64;
        let a = si_with_nonce_time(b"nonce-a", t);
        let b = si_with_nonce_time(b"nonce-b", t);
        assert_eq!(g.check(&a), ReplayCheck::Fresh);
        assert_eq!(
            g.check(&b),
            ReplayCheck::Fresh,
            "distinct nonces must not collide on shared timestamp (AND-semantics)"
        );
    }

    #[test]
    fn same_nonce_same_time_is_replay() {
        let g = ReplayGuard::new(16, false);
        let t = 1_700_000_000_000u64;
        let a = si_with_nonce_time(b"nonce-x", t);
        let b = si_with_nonce_time(b"nonce-x", t);
        assert_eq!(g.check(&a), ReplayCheck::Fresh);
        assert_eq!(g.check(&b), ReplayCheck::Replay);
    }
}
