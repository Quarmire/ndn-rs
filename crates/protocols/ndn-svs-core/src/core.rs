//! [`SvsCore`] — the synchronous, lock-free State Vector Sync node.
//!
//! A `NodeID → (boot, seq)` map plus the integer rules over it. ndn-sync's
//! `SvsNode` is this type inside a `tokio::sync::RwLock`; a constrained device
//! drives it directly. The collection is a [`BTreeMap`] (was a `std::HashMap`
//! in the fused version) keyed by [`Name`] (which is `Ord`) — the merge
//! semantics are identical because gaps are produced in *input* order and every
//! comparison is per-key, never iteration-order dependent.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ndn_packet::Name;

use crate::codec::StateEntry;

/// Default ceiling on distinct producers tracked in the local state vector
/// besides the node itself (audit SY-1). Under the accept-all default
/// validator a peer can pack a Sync Interest with fabricated producer names;
/// this bounds the map, and with it every Sync Interest the node sends,
/// which carries the whole vector. An application that knows its group's
/// members sets a tighter one ([`SvsCore::bound`]).
pub const MAX_TRACKED_PRODUCERS: usize = 16_384;

/// Whether the application vouches for a producer ([`SvsCore::bound`]): one
/// it vouches for is never displaced by one it does not.
pub type Vouch = Box<dyn Fn(&Name) -> bool + Send + Sync>;

/// Maximum publications a single `merge` will advertise as a gap for one
/// producer (audit SY-2). A forged state-vector entry with `SeqNo = u64::MAX`
/// would otherwise yield an unbounded `(1, u64::MAX)` fetch range. Catch-up to a
/// legitimately-large seq still completes — it just proceeds in bounded chunks
/// across successive sync rounds (the slot advances only to the clamped high).
pub const MAX_GAP_SPAN: u64 = 1 << 16;

/// Clamp a `[low, high]` fetch range so it spans at most [`MAX_GAP_SPAN`].
fn clamp_gap_high(low: u64, high: u64) -> u64 {
    high.min(low.saturating_add(MAX_GAP_SPAN - 1))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVectorEntry {
    /// URI rendering of the node's NDN name.
    pub node: String,
    /// Bootstrap timestamp (SVS v3); 0 under the v2 dialect.
    pub boot: u64,
    pub seq: u64,
}

/// State Vector Sync — synchronous core.
///
/// Each node maintains a `Name → highest-seq` map per peer; an incoming
/// peer seq higher than the local entry is recorded as a gap to fetch.
/// Keys are component-wise canonical `Name` values (mirrors ndn-svs
/// `common.hpp:41` `using NodeID = ndn::Name` /
/// `version-vector.hpp:83`); two NodeIDs with identical wire bytes but
/// different `Display` renderings aggregate into one entry. The
/// `String`-keyed methods (`merge`, `snapshot`, `seq_for`) parse
/// `String → Name` at the boundary so callers see the same
/// canonicalisation.
pub struct SvsCore {
    local_name: Name,
    local_boot: u64,
    vector: BTreeMap<Name, (u64, u64)>,
    /// When each producer besides this node last brought something to
    /// fetch (a tick), and the producers by that tick: the order they are
    /// displaced in ([`Self::bound`]).
    heard: BTreeMap<Name, u64>,
    order: BTreeMap<u64, Name>,
    /// The tick of the newest producer heard bringing something.
    tick: u64,
    /// The most producers tracked besides this node ([`Self::bound`]).
    cap: usize,
    /// The producers the application vouches for ([`Self::bound`]).
    vouch: Option<Vouch>,
    /// The producers displaced since [`Self::take_displaced`] last ran.
    displaced: Vec<Name>,
}

impl SvsCore {
    /// Create a node with bootstrap timestamp `local_boot` (0 under the
    /// v2 dialect, the startup time in ms under v3) and initial local seq 0.
    pub fn with_boot(local_name: &Name, local_boot: u64) -> Self {
        Self::with_boot_seq(local_name, local_boot, 0)
    }

    /// Like [`with_boot`](Self::with_boot) but seeds the local sequence number
    /// to `local_seq` — for restart recovery, so the node advertises its
    /// resumed sequence space rather than restarting at 0 (NS-8). Only the
    /// local entry is seeded; peers are still learned from the wire.
    pub fn with_boot_seq(local_name: &Name, local_boot: u64, local_seq: u64) -> Self {
        let mut map = BTreeMap::new();
        map.insert(local_name.clone(), (local_boot, local_seq));
        Self {
            local_name: local_name.clone(),
            local_boot,
            vector: map,
            heard: BTreeMap::new(),
            order: BTreeMap::new(),
            tick: 0,
            cap: MAX_TRACKED_PRODUCERS,
            vouch: None,
            displaced: Vec::new(),
        }
    }

    /// Track at most `cap` producers besides this node. Past it, a new
    /// producer bringing something to fetch displaces the producer that
    /// brought something longest ago that `vouch` does not vouch for — the
    /// new one itself is refused when every other one is vouched for and it
    /// is not — else the one longest ago. So a Sync Interest naming many
    /// producers leaves the vector, and every Sync Interest carrying it,
    /// bounded, and never displaces a producer the application vouches for
    /// with one it does not. Without `vouch`, the one longest ago goes.
    pub fn bound(&mut self, cap: usize, vouch: Option<Vouch>) {
        self.cap = cap;
        self.vouch = vouch;
    }

    /// The producers displaced from the vector since the last call
    /// ([`Self::bound`]).
    pub fn take_displaced(&mut self) -> Vec<Name> {
        core::mem::take(&mut self.displaced)
    }

    /// Whether `name` is tracked in the vector (this node included).
    pub fn tracks(&self, name: &Name) -> bool {
        self.vector.contains_key(name)
    }

    /// Make room for `name`, a producer not tracked yet ([`Self::bound`]):
    /// whether it may be tracked. The producers are read from the one that
    /// brought something longest ago, until one `vouch` does not vouch for.
    fn admit(&mut self, name: &Name) -> bool {
        if self.vector.len() <= self.cap {
            return true;
        }
        let vouched = |n: &Name| self.vouch.as_ref().is_some_and(|v| v(n));
        let victim = match self.order.values().find(|n| !vouched(n)) {
            Some(n) => n.clone(),
            None if !vouched(name) => return false,
            None => match self.order.values().next() {
                Some(n) => n.clone(),
                None => return false,
            },
        };
        self.vector.remove(&victim);
        if let Some(t) = self.heard.remove(&victim) {
            self.order.remove(&t);
        }
        self.displaced.push(victim);
        true
    }

    /// Note that `name` brought something to fetch now.
    fn heard_now(&mut self, name: &Name) {
        self.tick += 1;
        if let Some(t) = self.heard.insert(name.clone(), self.tick) {
            self.order.remove(&t);
        }
        self.order.insert(self.tick, name.clone());
    }

    /// v2 convenience: boot = 0.
    pub fn new(local_name: &Name) -> Self {
        Self::with_boot(local_name, 0)
    }

    pub fn local_name(&self) -> &Name {
        &self.local_name
    }

    pub fn local_boot(&self) -> u64 {
        self.local_boot
    }

    /// URI-string rendering of [`Self::local_name`].
    pub fn local_key(&self) -> String {
        self.local_name.to_string()
    }

    pub fn local_seq(&self) -> u64 {
        self.vector
            .get(&self.local_name)
            .map(|(_, s)| *s)
            .unwrap_or(0)
    }

    /// Increment the local sequence by 1 and return the new value.
    pub fn advance(&mut self) -> u64 {
        let entry = self
            .vector
            .entry(self.local_name.clone())
            .or_insert((self.local_boot, 0));
        entry.1 += 1;
        entry.1
    }

    /// Merge received state-vector entries, returning
    /// `(canonical_node_string, gap_from, gap_to)` seq ranges to fetch.
    ///
    /// Comparison is boot-aware: an entry supersedes the local view when
    /// its `(boot, seq)` is lexicographically greater. A higher `boot`
    /// (a peer that restarted, SVS v3) reopens the full `[1, seq]` range
    /// even though the raw seq dropped — the v2 dialect always passes
    /// `boot = 0`, so this reduces to plain seq comparison there.
    pub fn merge(&mut self, received: &[StateEntry]) -> Vec<(String, u64, u64)> {
        self.merge_inner(received, true)
    }

    /// Like [`merge`](Self::merge) but for **two-phase commit** (D-44 / N-3): gaps are detected and a
    /// peer's *boot* is adopted (a restart is a fact, not content to validate), yet the tracked *seq*
    /// is **not** advanced. The node keeps advertising the lower seq, so the gap stays visible until
    /// the app calls [`ack`](Self::ack) for the seqs it has validated and stored. This is the
    /// anti-poison half of the chain-replication contract: a delivered item the consumer *rejects*
    /// (a fork, a bad signature) never silently marks the node caught-up. The eager
    /// [`merge`](Self::merge) is the default; the SVS driver selects this when `auto_ack` is off.
    pub fn merge_deferred(&mut self, received: &[StateEntry]) -> Vec<(String, u64, u64)> {
        self.merge_inner(received, false)
    }

    fn merge_inner(&mut self, received: &[StateEntry], advance: bool) -> Vec<(String, u64, u64)> {
        let mut gaps = Vec::new();
        for entry in received {
            // Authoritative-for-self guard: a remote entry must never
            // raise our own (boot, seq) (gap #3, self-seq poisoning).
            // Only `advance()` moves it.
            if entry.name == self.local_name {
                continue;
            }
            // SY-1: bound the number of tracked producers ([`Self::bound`]).
            // A new producer whose entry brings nothing to fetch (counter 0)
            // is not tracked: it adds nothing a later entry of it would not.
            if !self.vector.contains_key(&entry.name)
                && (entry.seq == 0 || !self.admit(&entry.name))
            {
                continue;
            }
            let before = gaps.len();
            let slot = self.vector.entry(entry.name.clone()).or_insert((0, 0));
            let (lb, ls) = *slot;
            if entry.boot > lb {
                // Peer (re)started with a newer boot: fetch its whole run, but
                // clamp the advertised span (SY-2) and advance the slot only to
                // the clamped high so legit catch-up continues next round.
                if entry.seq >= 1 {
                    let high = clamp_gap_high(1, entry.seq);
                    gaps.push((entry.name.to_string(), 1, high));
                    // Adopt the new boot either way (restart detection is not gated on validation).
                    // In deferred mode the seq stays 0 so the gap re-emits until acked.
                    *slot = (entry.boot, if advance { high } else { 0 });
                } else {
                    *slot = (entry.boot, entry.seq);
                }
            } else if entry.boot == lb && entry.seq > ls {
                let high = clamp_gap_high(ls + 1, entry.seq);
                gaps.push((entry.name.to_string(), ls + 1, high));
                // Eager: advance now. Deferred: leave the seq at `ls`; `ack()` advances it once the
                // app has validated + stored the fetched publication.
                if advance {
                    slot.1 = high;
                }
            }
            if gaps.len() > before {
                self.heard_now(&entry.name);
            }
        }
        gaps
    }

    /// Two-phase commit (D-44 / N-3): raise the tracked seq for peer `node_key` to `seq` after the app
    /// has validated and stored that publication. Only *raises* (never lowers); ignores the local
    /// entry. Complements [`merge_deferred`](Self::merge_deferred) — together they let a consumer
    /// reject a delivered item without poisoning convergence.
    pub fn ack(&mut self, node_key: &str, seq: u64) {
        let Ok(name) = node_key.parse::<Name>() else {
            return;
        };
        if name == self.local_name {
            return;
        }
        if let Some(slot) = self.vector.get_mut(&name) {
            if seq > slot.1 {
                slot.1 = seq;
            }
        } else if seq > 0 && self.admit(&name) {
            self.vector.insert(name.clone(), (0, seq));
            self.heard_now(&name);
        }
    }

    pub fn snapshot(&self) -> Vec<StateVectorEntry> {
        self.vector
            .iter()
            .map(|(k, &(boot, seq))| StateVectorEntry {
                node: k.to_string(),
                boot,
                seq,
            })
            .collect()
    }

    /// State vector as [`StateEntry`]s (parsed names) for the wire codec.
    pub fn state_entries(&self) -> Vec<StateEntry> {
        self.vector
            .iter()
            .map(|(k, &(boot, seq))| StateEntry {
                name: k.clone(),
                boot,
                seq,
            })
            .collect()
    }

    /// Returns 0 for unknown keys.
    pub fn seq_for(&self, node_key: &str) -> u64 {
        let Ok(name) = node_key.parse::<Name>() else {
            return 0;
        };
        self.vector.get(&name).map(|(_, s)| *s).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn name(s: &'static str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::from_static(s.as_bytes()))])
    }

    /// v2-style entry (boot = 0).
    fn e(node: &str, seq: u64) -> StateEntry {
        StateEntry {
            name: node.parse().unwrap(),
            boot: 0,
            seq,
        }
    }

    // Proves the de-async'd core works with zero async and zero std: advance,
    // merge, snapshot, seq_for, ack — all synchronous over the BTreeMap.
    #[test]
    fn sync_core_advance_merge_snapshot() {
        let mut node = SvsCore::new(&name("a"));
        assert_eq!(node.local_seq(), 0);
        assert_eq!(node.advance(), 1);
        assert_eq!(node.advance(), 2);
        assert_eq!(node.local_seq(), 2);

        let gaps = node.merge(&[e("/b", 3), e("/c", 4)]);
        assert_eq!(gaps.len(), 2);
        assert_eq!(node.seq_for("/b"), 3);
        assert_eq!(node.seq_for("/c"), 4);

        // Snapshot lists local + both peers (BTreeMap => sorted, deterministic).
        let snap = node.snapshot();
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn merge_rejects_remote_raising_local_seq() {
        let mut node = SvsCore::new(&name("a"));
        node.advance(); // local seq = 1
        let local_key = node.local_key();
        let gaps = node.merge(&[e(&local_key, 9999)]);
        assert!(gaps.is_empty(), "self entry must not produce a gap");
        assert_eq!(node.local_seq(), 1, "self seq must stay authoritative");
        assert_eq!(
            node.advance(),
            2,
            "advance continues from local, not remote"
        );
    }

    #[test]
    fn sy2_forged_max_seq_yields_bounded_gap() {
        let mut node = SvsCore::new(&name("a"));
        let gaps = node.merge(&[e("/b", u64::MAX)]);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], ("/b".to_string(), 1, MAX_GAP_SPAN));
        let gaps2 = node.merge(&[e("/b", u64::MAX)]);
        assert_eq!(gaps2[0].1, MAX_GAP_SPAN + 1);
    }

    #[test]
    fn sy1_fabricated_producers_are_capped() {
        use alloc::format;
        let mut node = SvsCore::new(&name("a"));
        let flood: Vec<StateEntry> = (0..(MAX_TRACKED_PRODUCERS + 500))
            .map(|i| e(&format!("/p{i}"), 1))
            .collect();
        node.merge(&flood);
        assert!(node.snapshot().len() <= MAX_TRACKED_PRODUCERS + 1);
    }

    #[test]
    fn a_bounded_vector_displaces_unvouched_producers_first() {
        use alloc::format;
        let mut node = SvsCore::new(&name("a"));
        node.bound(4, Some(Box::new(|n: &Name| n.to_string() == "/v")));
        node.merge(&[e("/v", 3)]);
        let flood: Vec<StateEntry> = (0..100)
            .map(|i| e(&format!("/p{i}"), u64::from(i % 2 == 0)))
            .collect();
        node.merge(&flood);
        let snap = node.snapshot();
        assert!(
            snap.len() <= 5,
            "at most the bound and the node: {}",
            snap.len()
        );
        assert!(
            node.tracks(&"/v".parse().unwrap()),
            "a vouched producer stays"
        );
        assert!(
            snap.iter().all(|s| s.seq > 0 || s.node == node.local_key()),
            "a producer at counter 0 is never tracked"
        );
        assert_eq!(node.take_displaced().len(), 50 - 3);
    }

    #[test]
    fn v3_higher_boot_reopens_full_range() {
        let mut node = SvsCore::new(&name("a"));
        let peer: Name = "/b".parse().unwrap();
        let _ = node.merge(&[StateEntry {
            name: peer.clone(),
            boot: 100,
            seq: 9,
        }]);
        let gaps = node.merge(&[StateEntry {
            name: peer.clone(),
            boot: 200,
            seq: 2,
        }]);
        assert_eq!(gaps, alloc::vec![("/b".to_string(), 1, 2)]);
        assert_eq!(node.seq_for("/b"), 2);
    }

    #[test]
    fn merge_deferred_holds_gap_until_ack() {
        let mut node = SvsCore::new(&name("local"));
        assert_eq!(
            node.merge_deferred(&[e("/a", 3)]),
            alloc::vec![("/a".to_string(), 1, 3)]
        );
        assert_eq!(
            node.merge_deferred(&[e("/a", 3)]),
            alloc::vec![("/a".to_string(), 1, 3)]
        );
        assert_eq!(node.seq_for("/a"), 0);
        node.ack("/a", 3);
        assert!(node.merge_deferred(&[e("/a", 3)]).is_empty());
        assert_eq!(node.seq_for("/a"), 3);
    }
}
