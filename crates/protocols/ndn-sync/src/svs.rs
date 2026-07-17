//! `SvsNode` — the async, `tokio::sync::RwLock`-guarded face of the SVS state
//! vector. All the state-vector *logic* (advance, boot-aware merge, gap
//! detection, the SY-1/SY-2 clamps) now lives in the no_std
//! [`ndn_svs_core::SvsCore`]; this type is the thin re-wrap that restores
//! ndn-sync's historical async API. Every method is `async` only because it
//! awaits the lock, then delegates to the synchronous core — the same reason
//! it was `async` before the extraction. The public surface (method names,
//! signatures, `StateEntry` / `StateVectorEntry` / `MAX_TRACKED_PRODUCERS`
//! re-exports) is unchanged, so no caller and no wire byte moved.

use tokio::sync::RwLock;

use ndn_packet::Name;

pub use ndn_svs_core::{MAX_TRACKED_PRODUCERS, StateVectorEntry, SvsCore};
// `StateEntry` continues to be reachable as `crate::svs::StateEntry` (its
// canonical home moved to the core crate's codec module).
pub use ndn_svs_core::StateEntry;
// SY-2 gap span — only the async `svs.rs` tests below reference it (it was
// `pub(crate)`, never part of ndn-sync's public API), so gate it to test builds
// to stay warning-clean under `-D warnings`.
#[cfg(test)]
use ndn_svs_core::MAX_GAP_SPAN;

/// State Vector Sync — async wrapper.
///
/// Each node maintains a `Name → highest-seq` map per peer (inside
/// [`SvsCore`]); an incoming peer seq higher than the local entry is recorded
/// as a gap to fetch. Keys are component-wise canonical `Name` values (mirrors
/// ndn-svs `common.hpp:41` `using NodeID = ndn::Name` /
/// `version-vector.hpp:83`); two NodeIDs with identical wire bytes but
/// different `Display` renderings aggregate into one entry. The `String`-keyed
/// methods (`merge`, `local_key`, `snapshot`, `seq_for`) parse `String → Name`
/// at the boundary so callers see the same canonicalisation.
///
/// `local_name` / `local_boot` are mirrored out of the lock so the
/// synchronous accessors ([`Self::local_name`], [`Self::local_boot`],
/// [`Self::local_key`]) keep their non-`async` signatures.
pub struct SvsNode {
    local_name: Name,
    local_boot: u64,
    core: RwLock<SvsCore>,
}

impl SvsNode {
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
        Self {
            local_name: local_name.clone(),
            local_boot,
            core: RwLock::new(SvsCore::with_boot_seq(local_name, local_boot, local_seq)),
        }
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

    pub async fn local_seq(&self) -> u64 {
        self.core.read().await.local_seq()
    }

    /// Increment the local sequence by 1 and return the new value.
    pub async fn advance(&self) -> u64 {
        self.core.write().await.advance()
    }

    /// Merge received state-vector entries, returning
    /// `(canonical_node_string, gap_from, gap_to)` seq ranges to fetch.
    ///
    /// Comparison is boot-aware: an entry supersedes the local view when
    /// its `(boot, seq)` is lexicographically greater. A higher `boot`
    /// (a peer that restarted, SVS v3) reopens the full `[1, seq]` range
    /// even though the raw seq dropped — the v2 dialect always passes
    /// `boot = 0`, so this reduces to plain seq comparison there.
    pub async fn merge(&self, received: &[StateEntry]) -> Vec<(String, u64, u64)> {
        self.core.write().await.merge(received)
    }

    /// Like [`merge`](Self::merge) but for **two-phase commit** (D-44 / N-3): gaps are detected and a
    /// peer's *boot* is adopted (a restart is a fact, not content to validate), yet the tracked *seq*
    /// is **not** advanced. The node keeps advertising the lower seq, so the gap stays visible until
    /// the app calls [`ack`](Self::ack) for the seqs it has validated and stored. This is the
    /// anti-poison half of the chain-replication contract: a delivered item the consumer *rejects*
    /// (a fork, a bad signature) never silently marks the node caught-up. The eager
    /// [`merge`](Self::merge) is the default; the SVS driver selects this when `auto_ack` is off.
    pub async fn merge_deferred(&self, received: &[StateEntry]) -> Vec<(String, u64, u64)> {
        self.core.write().await.merge_deferred(received)
    }

    /// Two-phase commit (D-44 / N-3): raise the tracked seq for peer `node_key` to `seq` after the app
    /// has validated and stored that publication. Only *raises* (never lowers); ignores the local
    /// entry. Complements [`merge_deferred`](Self::merge_deferred) — together they let a consumer
    /// reject a delivered item without poisoning convergence.
    pub async fn ack(&self, node_key: &str, seq: u64) {
        self.core.write().await.ack(node_key, seq)
    }

    pub async fn snapshot(&self) -> Vec<StateVectorEntry> {
        self.core.read().await.snapshot()
    }

    /// State vector as [`StateEntry`]s (parsed names) for the wire codec.
    pub async fn state_entries(&self) -> Vec<StateEntry> {
        self.core.read().await.state_entries()
    }

    /// Returns 0 for unknown keys.
    pub async fn seq_for(&self, node_key: &str) -> u64 {
        self.core.read().await.seq_for(node_key)
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

    #[tokio::test]
    async fn new_node_starts_at_seq_zero() {
        let node = SvsNode::new(&name("a"));
        assert_eq!(node.local_seq().await, 0);
    }

    #[tokio::test]
    async fn advance_increments_seq() {
        let node = SvsNode::new(&name("a"));
        assert_eq!(node.advance().await, 1);
        assert_eq!(node.advance().await, 2);
        assert_eq!(node.local_seq().await, 2);
    }

    #[tokio::test]
    async fn sy2_forged_max_seq_yields_bounded_gap() {
        let node = SvsNode::new(&name("a"));
        let gaps = node.merge(&[e("/b", u64::MAX)]).await;
        assert_eq!(gaps.len(), 1);
        // The advertised range is clamped to MAX_GAP_SPAN, not (1, u64::MAX).
        assert_eq!(gaps[0], ("/b".to_string(), 1, MAX_GAP_SPAN));
        // Next round continues from the clamped high (incremental catch-up).
        let gaps2 = node.merge(&[e("/b", u64::MAX)]).await;
        assert_eq!(gaps2[0].1, MAX_GAP_SPAN + 1);
    }

    #[tokio::test]
    async fn sy1_fabricated_producers_are_capped() {
        let node = SvsNode::new(&name("a"));
        let flood: Vec<StateEntry> = (0..(MAX_TRACKED_PRODUCERS + 500))
            .map(|i| e(&format!("/p{i}"), 1))
            .collect();
        node.merge(&flood).await;
        // local ("a") + at most MAX_TRACKED_PRODUCERS foreign producers.
        assert!(node.snapshot().await.len() <= MAX_TRACKED_PRODUCERS + 1);
    }

    #[tokio::test]
    async fn merge_updates_higher_seq() {
        let node = SvsNode::new(&name("a"));
        let gaps = node.merge(&[e("/b", 3)]).await;
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], ("/b".to_string(), 1, 3));
        assert_eq!(node.seq_for("/b").await, 3);
    }

    #[tokio::test]
    async fn merge_ignores_equal_or_lower_seq() {
        let node = SvsNode::new(&name("a"));
        node.merge(&[e("/b", 5)]).await;
        let gaps = node.merge(&[e("/b", 3)]).await;
        assert!(gaps.is_empty());
        assert_eq!(node.seq_for("/b").await, 5);
    }

    #[tokio::test]
    async fn merge_does_not_downgrade_local_seq() {
        let node = SvsNode::new(&name("a"));
        node.advance().await;
        let local_key = node.local_key();
        let gaps = node.merge(&[e(&local_key, 0)]).await;
        assert!(gaps.is_empty());
        assert_eq!(node.local_seq().await, 1);
    }

    #[tokio::test]
    async fn merge_rejects_remote_raising_local_seq() {
        // gap #3: a peer claiming a high seq for *our* NodeID must not
        // hijack our sequence space. `advance()` must still continue
        // from the locally-known value, not the attacker's.
        let node = SvsNode::new(&name("a"));
        node.advance().await; // local seq = 1
        let local_key = node.local_key();
        let gaps = node.merge(&[e(&local_key, 9999)]).await;
        assert!(gaps.is_empty(), "self entry must not produce a gap");
        assert_eq!(
            node.local_seq().await,
            1,
            "self seq must stay authoritative"
        );
        assert_eq!(
            node.advance().await,
            2,
            "advance continues from local, not remote"
        );
    }

    #[tokio::test]
    async fn snapshot_contains_local_entry() {
        let node = SvsNode::new(&name("a"));
        let snap = node.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].seq, 0);
        assert_eq!(snap[0].boot, 0);
    }

    #[tokio::test]
    async fn merge_multiple_peers() {
        let node = SvsNode::new(&name("a"));
        let gaps = node.merge(&[e("/b", 2), e("/c", 4)]).await;
        assert_eq!(gaps.len(), 2);
        assert_eq!(node.seq_for("/b").await, 2);
        assert_eq!(node.seq_for("/c").await, 4);
    }

    #[tokio::test]
    async fn v3_higher_boot_reopens_full_range() {
        // A peer that restarts (higher boot) with a *lower* raw seq must
        // reopen [1, seq], not be dismissed as stale — the v3 restart
        // recovery the boot timestamp exists for.
        let node = SvsNode::new(&name("a"));
        let peer: Name = "/b".parse().unwrap();
        let _ = node
            .merge(&[StateEntry {
                name: peer.clone(),
                boot: 100,
                seq: 9,
            }])
            .await;
        // Reboot: boot jumps, seq resets to 2.
        let gaps = node
            .merge(&[StateEntry {
                name: peer.clone(),
                boot: 200,
                seq: 2,
            }])
            .await;
        assert_eq!(
            gaps,
            vec![("/b".to_string(), 1, 2)],
            "reboot reopens [1, seq]"
        );
        assert_eq!(node.seq_for("/b").await, 2);
    }

    #[tokio::test]
    async fn v3_stale_boot_is_ignored() {
        let node = SvsNode::new(&name("a"));
        let peer: Name = "/b".parse().unwrap();
        let _ = node
            .merge(&[StateEntry {
                name: peer.clone(),
                boot: 200,
                seq: 5,
            }])
            .await;
        // An older boot must not regress us.
        let gaps = node
            .merge(&[StateEntry {
                name: peer.clone(),
                boot: 100,
                seq: 9,
            }])
            .await;
        assert!(gaps.is_empty(), "older boot is stale");
        assert_eq!(node.seq_for("/b").await, 5);
    }

    #[tokio::test]
    async fn typed_components_canonicalize_to_single_entry() {
        let node = SvsNode::new(&name("local"));
        let _ = node.merge(&[e("/v=3", 5)]).await;
        let _ = node.merge(&[e("/v=3", 7)]).await;
        let snap = node.snapshot().await;
        assert_eq!(snap.len(), 2, "local + one peer (no duplicates)");
        assert_eq!(node.seq_for("/v=3").await, 7);
    }

    // ── two-phase commit (D-44 / N-3) ──

    #[tokio::test]
    async fn merge_deferred_holds_gap_until_ack() {
        let node = SvsNode::new(&name("local"));
        // deferred merge detects the gap but does NOT advance our tracked seq
        assert_eq!(node.merge_deferred(&[e("/a", 3)]).await, vec![("/a".to_string(), 1, 3)]);
        // re-merging re-emits the SAME gap — it stays visible (no poison) until acked
        assert_eq!(node.merge_deferred(&[e("/a", 3)]).await, vec![("/a".to_string(), 1, 3)]);
        assert_eq!(node.seq_for("/a").await, 0, "deferred merge did not advance the vector");
        // ack up to seq 3 → the gap no longer re-emits, and our vector now advertises seq 3
        node.ack("/a", 3).await;
        assert!(node.merge_deferred(&[e("/a", 3)]).await.is_empty(), "acked seqs stop re-emitting");
        assert_eq!(node.seq_for("/a").await, 3);
    }

    #[tokio::test]
    async fn auto_ack_merge_advances_eagerly_as_before() {
        // The default eager path is byte-for-byte the legacy behaviour.
        let node = SvsNode::new(&name("local"));
        assert_eq!(node.merge(&[e("/a", 3)]).await, vec![("/a".to_string(), 1, 3)]);
        assert!(node.merge(&[e("/a", 3)]).await.is_empty(), "eager merge already advanced");
        assert_eq!(node.seq_for("/a").await, 3);
    }

    #[tokio::test]
    async fn ack_only_raises_and_ignores_local() {
        let node = SvsNode::new(&name("local"));
        node.merge_deferred(&[e("/a", 5)]).await;
        node.ack("/a", 3).await; // partial ack of a 5-deep gap
        assert_eq!(node.seq_for("/a").await, 3);
        node.ack("/a", 2).await; // a lower ack never lowers
        assert_eq!(node.seq_for("/a").await, 3);
        node.ack(&node.local_key(), 9).await; // acking self is ignored (only advance() moves local)
        assert_eq!(node.local_seq().await, 0);
    }
}
