use std::collections::HashMap;

use tokio::sync::RwLock;

use ndn_packet::Name;

/// A node's entry in the state vector: its name key and current sequence number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateVectorEntry {
    /// Canonical string key for the node (typically its NDN name rendered as a URI).
    pub node: String,
    pub seq:  u64,
}

/// State Vector Sync (SVS).
///
/// Each node maintains a state vector — a map from node-name key to the
/// highest sequence number the local node has seen for that peer. When a peer's
/// sequence number in a received sync Interest is higher than the local entry,
/// the gap is recorded as "missing data" that should be fetched.
///
/// Node names are stored as canonical string keys so the vector can be compared
/// across the network without re-encoding `Name` objects on every merge.
pub struct SvsNode {
    local_key: String,
    vector:    RwLock<HashMap<String, u64>>,
}

impl SvsNode {
    pub fn new(local_name: &Name) -> Self {
        let key = local_name.to_string();
        let mut map = HashMap::new();
        map.insert(key.clone(), 0u64);
        Self {
            local_key: key,
            vector:    RwLock::new(map),
        }
    }

    pub fn local_key(&self) -> &str {
        &self.local_key
    }

    /// Return the current sequence number for the local node.
    pub async fn local_seq(&self) -> u64 {
        *self.vector.read().await.get(&self.local_key).unwrap_or(&0)
    }

    /// Increment the local sequence number by 1 and return the new value.
    pub async fn advance(&self) -> u64 {
        let mut map = self.vector.write().await;
        let seq = map.entry(self.local_key.clone()).or_insert(0);
        *seq += 1;
        *seq
    }

    /// Merge a received state vector into the local one.
    ///
    /// For each entry, if the received sequence number is higher than the
    /// locally known value the local entry is updated. Returns a list of
    /// `(node_key, gap_from, gap_to)` tuples describing missing data that
    /// should be fetched.
    pub async fn merge(&self, received: &[(String, u64)]) -> Vec<(String, u64, u64)> {
        let mut gaps = Vec::new();
        let mut map = self.vector.write().await;
        for (node, remote_seq) in received {
            let local_seq = map.entry(node.clone()).or_insert(0);
            if *remote_seq > *local_seq {
                gaps.push((node.clone(), *local_seq + 1, *remote_seq));
                *local_seq = *remote_seq;
            }
        }
        gaps
    }

    /// Return a snapshot of the current state vector.
    pub async fn snapshot(&self) -> Vec<StateVectorEntry> {
        self.vector
            .read()
            .await
            .iter()
            .map(|(k, &seq)| StateVectorEntry { node: k.clone(), seq })
            .collect()
    }

    /// Return the sequence number known for `node_key`, or 0 if unknown.
    pub async fn seq_for(&self, node_key: &str) -> u64 {
        *self.vector.read().await.get(node_key).unwrap_or(&0)
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
        let gaps = node.merge(&[("b".to_string(), 3)]).await;
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], ("b".to_string(), 1, 3));
        assert_eq!(node.seq_for("b").await, 3);
    }

    #[tokio::test]
    async fn merge_ignores_equal_or_lower_seq() {
        let node = SvsNode::new(&name("a"));
        node.merge(&[("b".to_string(), 5)]).await;
        let gaps = node.merge(&[("b".to_string(), 3)]).await;
        assert!(gaps.is_empty());
        assert_eq!(node.seq_for("b").await, 5);
    }

    #[tokio::test]
    async fn merge_does_not_downgrade_local_seq() {
        let node = SvsNode::new(&name("a"));
        node.advance().await;
        let local_key = node.local_key().to_string();
        // Remote claims seq=0 for our own name — must not downgrade us.
        let gaps = node.merge(&[(local_key, 0)]).await;
        assert!(gaps.is_empty());
        assert_eq!(node.local_seq().await, 1);
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
        let gaps = node.merge(&[
            ("b".to_string(), 2),
            ("c".to_string(), 4),
        ]).await;
        assert_eq!(gaps.len(), 2);
        assert_eq!(node.seq_for("b").await, 2);
        assert_eq!(node.seq_for("c").await, 4);
    }
}
