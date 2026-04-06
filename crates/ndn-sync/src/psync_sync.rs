//! PSync network protocol — wires `PSyncNode` + `Ibf` to Interest/Data exchange.
//!
//! # Wire format
//!
//! **Sync Interest:** `/<group-prefix>/psync/<ibf-encoded>`
//!
//! The IBF is encoded as a series of `<xor_sum:8><hash_sum:8><count:8>` triples.
//!
//! **Sync Data:** response carries the list of name hashes the responder has
//! that the requester lacks, encoded as concatenated `<hash:8>` values.
//!
//! # Protocol flow
//!
//! 1. Periodically send a Sync Interest carrying the local IBF.
//! 2. When a peer receives it, subtract against local IBF, decode the difference.
//! 3. Reply with Data containing hashes the requester is missing.
//! 4. On receiving the Data, emit `SyncUpdate` for each missing hash.

use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::protocol::{SyncHandle, SyncUpdate};
use crate::psync::{Ibf, PSyncNode};

/// Configuration for a PSync group.
#[derive(Clone, Debug)]
pub struct PSyncConfig {
    /// Sync Interest interval (default: 1 second).
    pub sync_interval: Duration,
    /// Jitter range in ms (default: 200).
    pub jitter_ms: u64,
    /// IBF size (default: 80 cells).
    pub ibf_size: usize,
    /// Channel capacity for update notifications (default: 256).
    pub channel_capacity: usize,
}

impl Default for PSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(1),
            jitter_ms: 200,
            ibf_size: 80,
            channel_capacity: 256,
        }
    }
}

/// Join a PSync group.
///
/// Spawns a background task that:
/// 1. Periodically sends Sync Interests carrying the local IBF
/// 2. Processes incoming Sync Interests (subtracts IBFs, replies with diff)
/// 3. Processes incoming Sync Data (emits `SyncUpdate` for missing hashes)
///
/// # Arguments
///
/// * `group` — sync group prefix (e.g. `/ndn/psync/chat`)
/// * `send` — channel to send outgoing packets (Interests and Data)
/// * `recv` — channel to receive incoming packets from the network
/// * `config` — PSync configuration
pub fn join_psync_group(
    group: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<Bytes>,
    config: PSyncConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, publish_rx) = mpsc::channel(64);

    let task_cancel = cancel.clone();
    tokio::spawn(async move {
        psync_task(
            group,
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

/// Background task driving the PSync protocol loop.
///
/// On each tick: send a Sync Interest with the local IBF. On incoming
/// Interest: subtract IBFs, decode the difference, reply with missing hashes.
/// On incoming Data: emit `SyncUpdate` for each missing hash.
async fn psync_task(
    group: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<Bytes>,
    mut publish_rx: mpsc::Receiver<Name>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: PSyncConfig,
    cancel: CancellationToken,
) {
    let mut node = PSyncNode::new(config.ibf_size);

    loop {
        let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
        let interval = config.sync_interval + jitter;

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = tokio::time::sleep(interval) => {
                // Send Sync Interest with local IBF.
                let ibf = node.build_ibf();
                let ibf_bytes = encode_ibf(&ibf);
                let sync_name = group.clone()
                    .append("psync")
                    .append(ibf_bytes);
                let wire = InterestBuilder::new(sync_name)
                    .lifetime(Duration::from_millis(1000))
                    .build();
                let _ = send.send(wire).await;
            }

            Some(raw) = recv.recv() => {
                // Could be a Sync Interest (IBF from peer) or Sync Data (diff response).
                if raw.len() > 2 && raw[0] == 0x06 {
                    // Data packet — contains hashes we're missing.
                    if let Some(hashes) = parse_sync_data(&raw) {
                        for hash in hashes {
                            let update = SyncUpdate {
                                publisher: format!("{hash:016x}"),
                                name: group.clone().append(format!("{hash:016x}")),
                                low_seq: 0,
                                high_seq: 0,
                            };
                            let _ = update_tx.send(update).await;
                        }
                    }
                } else if raw.len() > 2 && raw[0] == 0x05 {
                    // Interest — peer's IBF. Subtract, decode, reply with diff.
                    if let Some(peer_ibf) = parse_sync_interest(&group, &raw)
                        && let Some((we_have, _they_have)) = node.reconcile(&peer_ibf)
                        && !we_have.is_empty()
                    {
                        let data_bytes = encode_hash_set(&we_have);
                        let _ = send.send(data_bytes).await;
                    }
                }
            }

            Some(_pub_name) = publish_rx.recv() => {
                // Local publication: hash the name and insert into the IBF.
                let hash = hash_name(&_pub_name);
                node.insert(hash);
                // Immediately send updated IBF.
                let ibf = node.build_ibf();
                let ibf_bytes = encode_ibf(&ibf);
                let sync_name = group.clone()
                    .append("psync")
                    .append(ibf_bytes);
                let wire = InterestBuilder::new(sync_name)
                    .lifetime(Duration::from_millis(1000))
                    .build();
                let _ = send.send(wire).await;
            }
        }
    }
}

// ─── Wire encoding helpers ─────────────────────────────────────────────────

/// Encode an IBF as concatenated `<xor_sum:8><hash_sum:8><count:8>` triples.
fn encode_ibf(ibf: &Ibf) -> Bytes {
    let cells = ibf.cells();
    let mut buf = BytesMut::with_capacity(cells.len() * 24);
    for cell in cells {
        buf.put_u64(cell.0); // xor_sum
        buf.put_u64(cell.1); // hash_sum
        buf.put_i64(cell.2); // count
    }
    buf.freeze()
}

/// Decode an IBF from wire bytes.
fn decode_ibf(data: &[u8], ibf_size: usize) -> Option<Ibf> {
    if data.len() < ibf_size * 24 {
        return None;
    }
    let mut cursor = data;
    let mut cells = Vec::with_capacity(ibf_size);
    for _ in 0..ibf_size {
        let xor_sum = cursor.get_u64();
        let hash_sum = cursor.get_u64();
        let count = cursor.get_i64();
        cells.push((xor_sum, hash_sum, count));
    }
    Some(Ibf::from_cells(cells))
}

/// Encode a set of hashes as concatenated `<hash:8>` values.
fn encode_hash_set(hashes: &std::collections::HashSet<u64>) -> Bytes {
    let mut buf = BytesMut::with_capacity(hashes.len() * 8);
    for &h in hashes {
        buf.put_u64(h);
    }
    buf.freeze()
}

/// Parse a Sync Interest: verify prefix, extract peer IBF.
fn parse_sync_interest(group: &Name, raw: &[u8]) -> Option<Ibf> {
    let interest = ndn_packet::Interest::decode(Bytes::copy_from_slice(raw)).ok()?;
    let components = interest.name.components();

    let group_len = group.components().len();
    if components.len() < group_len + 2 {
        return None;
    }

    let psync_comp = &components[group_len];
    if psync_comp.value.as_ref() != b"psync" {
        return None;
    }

    let ibf_comp = &components[group_len + 1];
    // Infer IBF size from the component length.
    let ibf_size = ibf_comp.value.len() / 24;
    if ibf_size == 0 {
        return None;
    }

    decode_ibf(&ibf_comp.value, ibf_size)
}

/// Parse a Sync Data response: extract list of hashes we're missing.
fn parse_sync_data(raw: &[u8]) -> Option<Vec<u64>> {
    let data = ndn_packet::Data::decode(Bytes::copy_from_slice(raw)).ok()?;
    let content = data.content()?;
    let mut hashes = Vec::new();
    let mut cursor = content.as_ref();
    while cursor.remaining() >= 8 {
        hashes.push(cursor.get_u64());
    }
    Some(hashes)
}

/// Hash an NDN name to a `u64` for IBF insertion.
///
/// Uses FNV-1a over the concatenated component values, with a `0xFF`
/// separator between components to avoid collisions between names
/// like `/a/bc` and `/ab/c`.
fn hash_name(name: &Name) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for comp in name.components() {
        for b in comp.value.iter() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // Separator to distinguish /a/bc from /ab/c.
        h ^= 0xff;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibf_encode_decode_roundtrip() {
        let mut ibf = Ibf::new(8, 3);
        ibf.insert(42);
        ibf.insert(99);
        let encoded = encode_ibf(&ibf);
        let decoded = decode_ibf(&encoded, 8).unwrap();
        // Subtracting should yield zero diff.
        let diff = ibf.subtract(&decoded);
        let (a, b) = diff.decode().unwrap();
        assert!(a.is_empty());
        assert!(b.is_empty());
    }

    #[test]
    fn hash_name_distinct() {
        let a: Name = "/a/b".parse().unwrap();
        let b: Name = "/a/c".parse().unwrap();
        assert_ne!(hash_name(&a), hash_name(&b));
    }

    #[tokio::test]
    async fn join_and_leave() {
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/psync".parse().unwrap();
        let handle = join_psync_group(group, send_tx, recv_rx, PSyncConfig::default());
        handle.leave();
    }
}
