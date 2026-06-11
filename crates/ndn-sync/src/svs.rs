use std::collections::HashMap;
use std::str::FromStr;

use tokio::sync::RwLock;

use ndn_packet::Name;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVectorEntry {
    /// URI rendering of the node's NDN name.
    pub node: String,
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
    vector: RwLock<HashMap<Name, u64>>,
}

impl SvsNode {
    pub fn new(local_name: &Name) -> Self {
        let mut map = HashMap::new();
        map.insert(local_name.clone(), 0u64);
        Self {
            local_name: local_name.clone(),
            vector: RwLock::new(map),
        }
    }

    pub fn local_name(&self) -> &Name {
        &self.local_name
    }

    /// URI-string rendering of [`Self::local_name`].
    pub fn local_key(&self) -> String {
        self.local_name.to_string()
    }

    pub async fn local_seq(&self) -> u64 {
        *self.vector.read().await.get(&self.local_name).unwrap_or(&0)
    }

    /// Increment the local sequence by 1 and return the new value.
    pub async fn advance(&self) -> u64 {
        let mut map = self.vector.write().await;
        let seq = map.entry(self.local_name.clone()).or_insert(0);
        *seq += 1;
        *seq
    }

    /// Returns `(canonical_node_string, gap_from, gap_to)` tuples; the
    /// rendered string is `Name::to_string()` so downstream consumers
    /// see a normalised peer id (not the caller's original input).
    /// Unparseable inputs are skipped.
    pub async fn merge(&self, received: &[(String, u64)]) -> Vec<(String, u64, u64)> {
        let mut gaps = Vec::new();
        let mut map = self.vector.write().await;
        for (node_str, remote_seq) in received {
            let Ok(name) = Name::from_str(node_str) else {
                continue;
            };
            // The node is authoritative for its own sequence number: a
            // remote entry must never raise the local entry (gap #3,
            // self-seq poisoning). Mirrors ndn-svs SVSyncCore, which
            // skips the producer's own NodeID when merging a received
            // state vector. `advance()` is the only path that moves it.
            if name == self.local_name {
                continue;
            }
            let local_seq = map.entry(name.clone()).or_insert(0);
            if *remote_seq > *local_seq {
                gaps.push((name.to_string(), *local_seq + 1, *remote_seq));
                *local_seq = *remote_seq;
            }
        }
        gaps
    }

    /// Name-keyed merge for callers that already have parsed `Name`s.
    pub async fn merge_names(&self, received: &[(Name, u64)]) -> Vec<(Name, u64, u64)> {
        let mut gaps = Vec::new();
        let mut map = self.vector.write().await;
        for (name, remote_seq) in received {
            // Authoritative-for-self guard, as in [`Self::merge`].
            if *name == self.local_name {
                continue;
            }
            let local_seq = map.entry(name.clone()).or_insert(0);
            if *remote_seq > *local_seq {
                gaps.push((name.clone(), *local_seq + 1, *remote_seq));
                *local_seq = *remote_seq;
            }
        }
        gaps
    }

    pub async fn snapshot(&self) -> Vec<StateVectorEntry> {
        self.vector
            .read()
            .await
            .iter()
            .map(|(k, &seq)| StateVectorEntry {
                node: k.to_string(),
                seq,
            })
            .collect()
    }

    /// Returns 0 for unknown or unparseable keys.
    pub async fn seq_for(&self, node_key: &str) -> u64 {
        let Ok(name) = Name::from_str(node_key) else {
            return 0;
        };
        *self.vector.read().await.get(&name).unwrap_or(&0)
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
        let gaps = node.merge(&[("/b".to_string(), 3)]).await;
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], ("/b".to_string(), 1, 3));
        assert_eq!(node.seq_for("/b").await, 3);
    }

    #[tokio::test]
    async fn merge_ignores_equal_or_lower_seq() {
        let node = SvsNode::new(&name("a"));
        node.merge(&[("/b".to_string(), 5)]).await;
        let gaps = node.merge(&[("/b".to_string(), 3)]).await;
        assert!(gaps.is_empty());
        assert_eq!(node.seq_for("/b").await, 5);
    }

    #[tokio::test]
    async fn merge_does_not_downgrade_local_seq() {
        let node = SvsNode::new(&name("a"));
        node.advance().await;
        let local_key = node.local_key().to_string();
        let gaps = node.merge(&[(local_key, 0)]).await;
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
        let local_key = node.local_key().to_string();
        let gaps = node.merge(&[(local_key, 9999)]).await;
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
    }

    #[tokio::test]
    async fn merge_multiple_peers() {
        let node = SvsNode::new(&name("a"));
        let gaps = node
            .merge(&[("/b".to_string(), 2), ("/c".to_string(), 4)])
            .await;
        assert_eq!(gaps.len(), 2);
        assert_eq!(node.seq_for("/b").await, 2);
        assert_eq!(node.seq_for("/c").await, 4);
    }

    #[tokio::test]
    async fn typed_components_canonicalize_to_single_entry() {
        let node = SvsNode::new(&name("local"));

        let n1: Name = "/v=3".parse().expect("parse v= shorthand");
        let n2: Name = "/v=3".parse().expect("parse v= shorthand");
        assert_eq!(n1, n2, "fixture sanity");

        let _ = node.merge(&[("/v=3".to_string(), 5)]).await;
        let _ = node.merge(&[("/v=3".to_string(), 7)]).await;

        let snap = node.snapshot().await;
        assert_eq!(
            snap.len(),
            2,
            "two equivalent renderings must aggregate into one peer entry"
        );

        assert_eq!(node.seq_for("/v=3").await, 7);
    }

    #[tokio::test]
    async fn merge_names_aggregates_equal_name_keys() {
        let node = SvsNode::new(&name("local"));
        let peer: Name = "/edu/ucla/peer".parse().unwrap();
        let _ = node.merge_names(&[(peer.clone(), 1)]).await;
        let _ = node.merge_names(&[(peer.clone(), 5)]).await;

        let snap = node.snapshot().await;
        assert_eq!(snap.len(), 2, "local + one peer (no duplicates)");
    }
}
