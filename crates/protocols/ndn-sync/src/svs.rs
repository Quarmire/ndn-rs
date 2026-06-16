use std::collections::HashMap;

use tokio::sync::RwLock;

use ndn_packet::Name;

pub use crate::svs_local::StateEntry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVectorEntry {
    /// URI rendering of the node's NDN name.
    pub node: String,
    /// Bootstrap timestamp (SVS v3); 0 under the v2 dialect.
    pub boot: u64,
    pub seq: u64,
}

/// State Vector Sync.
///
/// Each node maintains a `Name → highest-seq` map per peer; an incoming
/// peer seq higher than the local entry is recorded as a gap to fetch.
/// Keys are component-wise canonical `Name` values (mirrors ndn-svs
/// `common.hpp:41` `using NodeID = ndn::Name` /
/// `version-vector.hpp:83`); two NodeIDs with identical wire bytes but
/// different `Display` renderings aggregate into one entry. The
/// `String`-keyed methods (`merge`, `local_key`, `snapshot`, `seq_for`)
/// parse `String → Name` at the boundary so callers see the same
/// canonicalisation.
pub struct SvsNode {
    local_name: Name,
    local_boot: u64,
    vector: RwLock<HashMap<Name, (u64, u64)>>,
}

impl SvsNode {
    /// Create a node with bootstrap timestamp `local_boot` (0 under the
    /// v2 dialect, the startup time in ms under v3).
    pub fn with_boot(local_name: &Name, local_boot: u64) -> Self {
        let mut map = HashMap::new();
        map.insert(local_name.clone(), (local_boot, 0u64));
        Self {
            local_name: local_name.clone(),
            local_boot,
            vector: RwLock::new(map),
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
        self.vector
            .read()
            .await
            .get(&self.local_name)
            .map(|(_, s)| *s)
            .unwrap_or(0)
    }

    /// Increment the local sequence by 1 and return the new value.
    pub async fn advance(&self) -> u64 {
        let mut map = self.vector.write().await;
        let entry = map.entry(self.local_name.clone()).or_insert((self.local_boot, 0));
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
    pub async fn merge(&self, received: &[StateEntry]) -> Vec<(String, u64, u64)> {
        let mut gaps = Vec::new();
        let mut map = self.vector.write().await;
        for entry in received {
            // Authoritative-for-self guard: a remote entry must never
            // raise our own (boot, seq) (gap #3, self-seq poisoning).
            // Only `advance()` moves it.
            if entry.name == self.local_name {
                continue;
            }
            let slot = map.entry(entry.name.clone()).or_insert((0, 0));
            let (lb, ls) = *slot;
            if entry.boot > lb {
                // Peer (re)started with a newer boot: fetch its whole run.
                if entry.seq >= 1 {
                    gaps.push((entry.name.to_string(), 1, entry.seq));
                }
                *slot = (entry.boot, entry.seq);
            } else if entry.boot == lb && entry.seq > ls {
                gaps.push((entry.name.to_string(), ls + 1, entry.seq));
                slot.1 = entry.seq;
            }
        }
        gaps
    }

    pub async fn snapshot(&self) -> Vec<StateVectorEntry> {
        self.vector
            .read()
            .await
            .iter()
            .map(|(k, &(boot, seq))| StateVectorEntry {
                node: k.to_string(),
                boot,
                seq,
            })
            .collect()
    }

    /// State vector as [`StateEntry`]s (parsed names) for the wire codec.
    pub async fn state_entries(&self) -> Vec<StateEntry> {
        self.vector
            .read()
            .await
            .iter()
            .map(|(k, &(boot, seq))| StateEntry {
                name: k.clone(),
                boot,
                seq,
            })
            .collect()
    }

    /// Returns 0 for unknown keys.
    pub async fn seq_for(&self, node_key: &str) -> u64 {
        let Ok(name) = node_key.parse::<Name>() else {
            return 0;
        };
        self.vector.read().await.get(&name).map(|(_, s)| *s).unwrap_or(0)
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
        assert_eq!(node.local_seq().await, 1, "self seq must stay authoritative");
        assert_eq!(node.advance().await, 2, "advance continues from local, not remote");
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
            .merge(&[StateEntry { name: peer.clone(), boot: 100, seq: 9 }])
            .await;
        // Reboot: boot jumps, seq resets to 2.
        let gaps = node
            .merge(&[StateEntry { name: peer.clone(), boot: 200, seq: 2 }])
            .await;
        assert_eq!(gaps, vec![("/b".to_string(), 1, 2)], "reboot reopens [1, seq]");
        assert_eq!(node.seq_for("/b").await, 2);
    }

    #[tokio::test]
    async fn v3_stale_boot_is_ignored() {
        let node = SvsNode::new(&name("a"));
        let peer: Name = "/b".parse().unwrap();
        let _ = node
            .merge(&[StateEntry { name: peer.clone(), boot: 200, seq: 5 }])
            .await;
        // An older boot must not regress us.
        let gaps = node
            .merge(&[StateEntry { name: peer.clone(), boot: 100, seq: 9 }])
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
}
