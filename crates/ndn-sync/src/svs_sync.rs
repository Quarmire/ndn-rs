//! SVS (State Vector Sync) network protocol.
//!
//! Runs a background task that periodically multicasts Sync Interests containing
//! the local state vector, merges received vectors, and emits [`SyncUpdate`]s
//! for detected gaps.
//!
//! # Wire format
//!
//! Sync Interest name: `/<group-prefix>/svs/<encoded-state-vector>`
//!
//! The state vector is encoded as a series of TLV-like entries in the last
//! name component: `<node-name-hash:8><seq:8>` pairs, concatenated.
//! This is compact enough for typical group sizes (< 100 nodes).

use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::protocol::{SyncHandle, SyncUpdate};
use crate::svs::SvsNode;

/// Configuration for an SVS sync group.
#[derive(Clone, Debug)]
pub struct SvsConfig {
    /// Sync Interest interval (default: 1 second).
    pub sync_interval: Duration,
    /// Jitter range added to sync interval to avoid collisions (default: 200ms).
    pub jitter_ms: u64,
    /// Channel capacity for update notifications (default: 256).
    pub channel_capacity: usize,
}

impl Default for SvsConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(1),
            jitter_ms: 200,
            channel_capacity: 256,
        }
    }
}

/// Join an SVS sync group.
///
/// Spawns a background task that:
/// 1. Periodically sends Sync Interests with the local state vector
/// 2. Processes incoming Sync Interests, merging their state vectors
/// 3. Emits `SyncUpdate` for any detected gaps (new data to fetch)
///
/// The returned `SyncHandle` provides `recv()` for updates and `publish()` to
/// announce new local data.
///
/// # Arguments
///
/// * `group` — sync group prefix (e.g. `/ndn/svs/chat`)
/// * `local_name` — this node's name within the group
/// * `send` — channel to send outgoing packets (Interests)
/// * `recv` — channel to receive incoming packets (Interests from peers)
/// * `config` — SVS configuration
pub fn join_svs_group(
    group: Name,
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<Bytes>,
    config: SvsConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, publish_rx) = mpsc::channel(64);

    let task_cancel = cancel.clone();
    tokio::spawn(async move {
        svs_task(
            group,
            local_name,
            send,
            recv,
            publish_rx,
            update_tx,
            config,
            task_cancel,
        )
        .await;
    });

    SyncHandle::new(update_rx, publish_tx, cancel)
}

#[allow(clippy::too_many_arguments)]
async fn svs_task(
    group: Name,
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<Bytes>,
    mut publish_rx: mpsc::Receiver<Name>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: SvsConfig,
    cancel: CancellationToken,
) {
    let node = SvsNode::new(&local_name);
    let local_key = node.local_key().to_string();

    loop {
        // Jittered sync interval.
        let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
        let interval = config.sync_interval + jitter;

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = tokio::time::sleep(interval) => {
                // Send periodic Sync Interest with current state vector.
                let snapshot = node.snapshot().await;
                let sv_bytes = encode_state_vector(&snapshot);
                let sync_name = group.clone()
                    .append("svs")
                    .append(sv_bytes);
                let wire = InterestBuilder::new(sync_name)
                    .lifetime(Duration::from_millis(1000))
                    .build();
                let _ = send.send(wire).await;
            }

            Some(raw) = recv.recv() => {
                // Parse incoming Sync Interest and merge.
                if let Some(remote_sv) = parse_sync_interest(&group, &raw) {
                    let gaps = node.merge(&remote_sv).await;
                    for (peer_key, low, high) in gaps {
                        if peer_key == local_key { continue; }
                        let update = SyncUpdate {
                            publisher: peer_key.clone(),
                            name: group.clone().append(&peer_key),
                            low_seq: low,
                            high_seq: high,
                        };
                        let _ = update_tx.send(update).await;
                    }
                }
            }

            Some(_pub_name) = publish_rx.recv() => {
                // Local publication: advance sequence and immediately send
                // a Sync Interest so peers learn quickly.
                node.advance().await;
                let snapshot = node.snapshot().await;
                let sv_bytes = encode_state_vector(&snapshot);
                let sync_name = group.clone()
                    .append("svs")
                    .append(sv_bytes);
                let wire = InterestBuilder::new(sync_name)
                    .lifetime(Duration::from_millis(1000))
                    .build();
                let _ = send.send(wire).await;
            }
        }
    }
}

// ─── State vector wire encoding ─────────────────────────────────────────────

use crate::svs::StateVectorEntry;

/// Encode a state vector as concatenated `<name-hash:8><seq:8>` pairs.
fn encode_state_vector(entries: &[StateVectorEntry]) -> Bytes {
    let mut buf = BytesMut::with_capacity(entries.len() * 16);
    for e in entries {
        buf.put_u64(hash_node_key(&e.node));
        buf.put_u64(e.seq);
    }
    buf.freeze()
}

/// Decode a state vector from wire bytes.
fn decode_state_vector(data: &[u8]) -> Vec<(u64, u64)> {
    let mut pairs = Vec::new();
    let mut cursor = data;
    while cursor.remaining() >= 16 {
        let hash = cursor.get_u64();
        let seq = cursor.get_u64();
        pairs.push((hash, seq));
    }
    pairs
}

/// Parse an incoming Sync Interest: check prefix, extract state vector.
///
/// Returns `Vec<(node_key_string, seq)>` for merge.
/// Since we only have the hash on the wire, we return the hash as a hex string.
/// In a full implementation, a node registry would map hashes back to names.
fn parse_sync_interest(group: &Name, raw: &[u8]) -> Option<Vec<(String, u64)>> {
    let interest = ndn_packet::Interest::decode(Bytes::copy_from_slice(raw)).ok()?;
    let components = interest.name.components();

    // Verify the interest is under our group prefix + "svs".
    let group_len = group.components().len();
    if components.len() < group_len + 2 {
        return None;
    }

    // Check "svs" component.
    let svs_comp = &components[group_len];
    if svs_comp.value.as_ref() != b"svs" {
        return None;
    }

    // The next component is the encoded state vector.
    let sv_comp = &components[group_len + 1];
    let pairs = decode_state_vector(&sv_comp.value);

    Some(
        pairs
            .into_iter()
            .map(|(hash, seq)| (format!("{hash:016x}"), seq))
            .collect(),
    )
}

/// Hash a node key string to a 64-bit value for compact wire encoding.
fn hash_node_key(key: &str) -> u64 {
    // FNV-1a 64-bit.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in key.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_vector_roundtrip() {
        let entries = vec![
            StateVectorEntry {
                node: "alice".into(),
                seq: 5,
            },
            StateVectorEntry {
                node: "bob".into(),
                seq: 12,
            },
        ];
        let encoded = encode_state_vector(&entries);
        let decoded = decode_state_vector(&encoded);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (hash_node_key("alice"), 5));
        assert_eq!(decoded[1], (hash_node_key("bob"), 12));
    }

    #[test]
    fn hash_node_key_distinct() {
        assert_ne!(hash_node_key("alice"), hash_node_key("bob"));
    }

    #[test]
    fn decode_empty_state_vector() {
        assert!(decode_state_vector(&[]).is_empty());
    }

    #[tokio::test]
    async fn join_and_leave() {
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-a".parse().unwrap();

        let handle = join_svs_group(group, local, send_tx, recv_rx, SvsConfig::default());
        // Dropping the handle should cancel the task cleanly.
        handle.leave();
    }
}
