//! ndnSVS-compatible State Vector Sync. Background task multicasts
//! Sync Interests carrying the local state vector, merges received
//! vectors, and emits [`SyncUpdate`]s for detected gaps.
//!
//! Wire shape — Sync Interest name `/<group-prefix>/svs`, state
//! vector in ApplicationParameters (0x24):
//!
//! ```text
//! AppParameters    ::= StateVector [MappingData]
//! StateVector      ::= 0xC9 LEN StateVectorEntry*
//! StateVectorEntry ::= 0xCA LEN NodeID SeqNo
//! NodeID           ::= Name (0x07)
//! SeqNo            ::= 0xCC LEN NonNegativeInteger
//! MappingData      ::= 0xCD LEN MappingEntry*
//! MappingEntry     ::= 0xCE LEN NodeID SeqNo AppData
//! ```
//!
//! When a peer's Sync Interest fully covers the local vector, the
//! local periodic timer is reset to a fresh `[interval±jitter]` window
//! — Interest-storm suppression for large groups.

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::protocol::{SyncHandle, SyncUpdate};
use crate::svs::SvsNode;

// TLV codes per ndn-svs/ndn-svs/tlv.hpp.
const TLV_STATE_VECTOR: u64 = 201;
const TLV_SV_ENTRY: u64 = 202;
const TLV_SV_SEQ_NO: u64 = 204;
const TLV_MAPPING_DATA: u64 = 205;
const TLV_MAPPING_ENTRY: u64 = 206;
const TLV_NDN_NAME: u64 = 7;

/// Exponential back-off for gap-fetch Interests. Defaults to the
/// ndnSVS reference: 4 retries, 1 s base, 2× factor.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub backoff_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 4,
            base_delay: Duration::from_secs(1),
            backoff_factor: 2.0,
        }
    }
}

/// On each failure the delay doubles (capped at 60 s). The closure
/// receives the 0-based attempt index.
pub async fn fetch_with_retry<F, Fut, T, E>(policy: RetryPolicy, mut fetch: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = policy.base_delay;
    for attempt in 0..=policy.max_retries {
        match fetch(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt == policy.max_retries {
                    return Err(e);
                }
                tokio::time::sleep(delay).await;
                delay = Duration::from_secs_f64(
                    (delay.as_secs_f64() * policy.backoff_factor).min(60.0),
                );
            }
        }
    }
    unreachable!()
}

#[derive(Clone, Debug)]
pub struct SvsConfig {
    /// Default 30 s (ndnSVS reference).
    pub sync_interval: Duration,
    /// Default 3000 ms (≈±10 %).
    pub jitter_ms: u64,
    pub channel_capacity: usize,
    /// Not consumed by the SVS task itself; passed to [`fetch_with_retry`]
    /// by application-side gap fetchers.
    pub retry_policy: RetryPolicy,
}

impl Default for SvsConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(30),
            jitter_ms: 3000,
            channel_capacity: 256,
            retry_policy: RetryPolicy::default(),
        }
    }
}

/// Spawn the SVS background task: periodic Sync Interests, merge of
/// incoming vectors, and gap [`SyncUpdate`]s on the returned handle.
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
    mut publish_rx: mpsc::Receiver<(Name, Option<Bytes>)>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: SvsConfig,
    cancel: CancellationToken,
) {
    let node = SvsNode::new(&local_name);
    let local_key = node.local_key().to_string();

    let mut current_mapping: Option<Bytes> = None;

    let mut next_send = Instant::now() + jitter_interval(&config);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = tokio::time::sleep_until(next_send) => {
                send_sync_interest(&group, &node, &send, current_mapping.clone()).await;
                next_send = Instant::now() + jitter_interval(&config);
            }

            Some(raw) = recv.recv() => {
                if let Some((remote_sv, peer_mappings)) = parse_sync_interest(&group, &raw) {
                    let snapshot = node.snapshot().await;
                    let covers_local = remote_covers_local(&snapshot, &remote_sv);

                    let gaps = node.merge(&remote_sv).await;
                    for (peer_key, low, high) in gaps {
                        if peer_key == local_key { continue; }
                        let mapping = peer_mappings.get(&peer_key).cloned();
                        let update = SyncUpdate {
                            publisher: peer_key.clone(),
                            name: group.clone().append(&peer_key),
                            low_seq: low,
                            high_seq: high,
                            mapping,
                        };
                        let _ = update_tx.send(update).await;
                    }

                    if covers_local {
                        next_send = Instant::now() + jitter_interval(&config);
                    }
                }
            }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                current_mapping = mapping;
                node.advance().await;
                let _ = pub_name;
                send_sync_interest(&group, &node, &send, current_mapping.clone()).await;
                next_send = Instant::now() + jitter_interval(&config);
            }
        }
    }
}

/// `mapping` adds a `MappingData` (0xCD) TLV after the `StateVector`.
async fn send_sync_interest(
    group: &Name,
    node: &SvsNode,
    send: &mpsc::Sender<Bytes>,
    mapping: Option<Bytes>,
) {
    let snapshot = node.snapshot().await;
    let mut app_params = encode_state_vector(&snapshot);

    if let Some(mapping_bytes) = mapping {
        let local_key = node.local_key();
        let local_name: Name = local_key.parse().unwrap_or_else(|_| Name::root());
        let seq = node.local_seq().await;
        let mapping_tlv = encode_mapping_data(&local_name, seq, &mapping_bytes);
        app_params.extend_from_slice(&mapping_tlv);
    }

    let sync_name = group.clone().append("svs");
    let wire = InterestBuilder::new(sync_name)
        .lifetime(Duration::from_millis(1000))
        .app_parameters(app_params)
        .build();
    let _ = send.send(wire).await;
}

fn jitter_interval(config: &SvsConfig) -> Duration {
    let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
    config.sync_interval + jitter
}

fn remote_covers_local(
    local_snapshot: &[crate::svs::StateVectorEntry],
    remote_sv: &[(String, u64)],
) -> bool {
    let remote_map: HashMap<&str, u64> = remote_sv.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    local_snapshot
        .iter()
        .all(|e| remote_map.get(e.node.as_str()).copied().unwrap_or(0) >= e.seq)
}

fn write_varnumber(buf: &mut BytesMut, n: u64) {
    if n < 0xFD {
        buf.put_u8(n as u8);
    } else if n <= 0xFFFF {
        buf.put_u8(0xFD);
        buf.put_u16(n as u16);
    } else if n <= 0xFFFF_FFFF {
        buf.put_u8(0xFE);
        buf.put_u32(n as u32);
    } else {
        buf.put_u8(0xFF);
        buf.put_u64(n);
    }
}

fn write_tlv(buf: &mut BytesMut, typ: u64, value: &[u8]) {
    write_varnumber(buf, typ);
    write_varnumber(buf, value.len() as u64);
    buf.put_slice(value);
}

fn encode_nni(v: u64) -> Vec<u8> {
    if v <= 0xFF {
        vec![v as u8]
    } else if v <= 0xFFFF {
        (v as u16).to_be_bytes().to_vec()
    } else if v <= 0xFFFF_FFFF {
        (v as u32).to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}

fn encode_name_tlv(name: &Name) -> Vec<u8> {
    let mut inner = BytesMut::new();
    for comp in name.components() {
        write_tlv(&mut inner, comp.typ, &comp.value);
    }
    let mut outer = BytesMut::new();
    write_tlv(&mut outer, TLV_NDN_NAME, &inner);
    outer.to_vec()
}

use crate::svs::StateVectorEntry;

fn encode_state_vector(entries: &[StateVectorEntry]) -> Vec<u8> {
    let mut sv_inner = BytesMut::new();
    for e in entries {
        let name: Name = e.node.parse().unwrap_or_else(|_| Name::root());
        let name_bytes = encode_name_tlv(&name);
        let seq_bytes = encode_nni(e.seq);

        let mut entry_inner = BytesMut::new();
        entry_inner.put_slice(&name_bytes);
        write_tlv(&mut entry_inner, TLV_SV_SEQ_NO, &seq_bytes);

        write_tlv(&mut sv_inner, TLV_SV_ENTRY, &entry_inner);
    }

    let mut buf = BytesMut::new();
    write_tlv(&mut buf, TLV_STATE_VECTOR, &sv_inner);
    buf.to_vec()
}

/// Single `MappingData` (0xCD) wrapping one `MappingEntry` (0xCE)
/// with NodeID, SeqNo, and application-defined `app_data`.
fn encode_mapping_data(node_name: &Name, seq: u64, app_data: &[u8]) -> Vec<u8> {
    let name_bytes = encode_name_tlv(node_name);
    let seq_bytes = encode_nni(seq);

    let mut entry_inner = BytesMut::new();
    entry_inner.put_slice(&name_bytes);
    write_tlv(&mut entry_inner, TLV_SV_SEQ_NO, &seq_bytes);
    entry_inner.put_slice(app_data);

    let mut mapping_inner = BytesMut::new();
    write_tlv(&mut mapping_inner, TLV_MAPPING_ENTRY, &entry_inner);

    let mut buf = BytesMut::new();
    write_tlv(&mut buf, TLV_MAPPING_DATA, &mapping_inner);
    buf.to_vec()
}

fn read_tlv(cursor: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (typ, rest) = read_varnumber(cursor)?;
    let (len, rest) = read_varnumber(rest)?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some((typ, &rest[..len], &rest[len..]))
}

fn read_varnumber(cursor: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = cursor.split_first()?;
    match first {
        0xFF => {
            if rest.len() < 8 {
                return None;
            }
            let v = u64::from_be_bytes(rest[..8].try_into().ok()?);
            Some((v, &rest[8..]))
        }
        0xFE => {
            if rest.len() < 4 {
                return None;
            }
            let v = u32::from_be_bytes(rest[..4].try_into().ok()?) as u64;
            Some((v, &rest[4..]))
        }
        0xFD => {
            if rest.len() < 2 {
                return None;
            }
            let v = u16::from_be_bytes(rest[..2].try_into().ok()?) as u64;
            Some((v, &rest[2..]))
        }
        b => Some((b as u64, rest)),
    }
}

fn decode_nni(bytes: &[u8]) -> u64 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes(bytes.try_into().unwrap_or_default()) as u64,
        4 => u32::from_be_bytes(bytes.try_into().unwrap_or_default()) as u64,
        8 => u64::from_be_bytes(bytes.try_into().unwrap_or_default()),
        _ => {
            let mut arr = [0u8; 8];
            let start = 8usize.saturating_sub(bytes.len());
            let copy_len = bytes.len().min(8);
            arr[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
            u64::from_be_bytes(arr)
        }
    }
}

fn decode_name_key(name_tlv: &[u8]) -> Option<String> {
    let (typ, value, _) = read_tlv(name_tlv)?;
    if typ != TLV_NDN_NAME {
        return None;
    }
    let name = Name::decode(Bytes::copy_from_slice(value)).ok()?;
    Some(name.to_string())
}

fn decode_state_vector(sv_tlv: &[u8]) -> Option<Vec<(String, u64)>> {
    let (typ, mut body, _) = read_tlv(sv_tlv)?;
    if typ != TLV_STATE_VECTOR {
        return None;
    }

    let mut entries = Vec::new();
    while !body.is_empty() {
        let (entry_typ, mut entry_body, rest) = read_tlv(body)?;
        body = rest;
        if entry_typ != TLV_SV_ENTRY {
            continue;
        }

        let (name_typ, name_val, after_name) = read_tlv(entry_body)?;
        if name_typ != TLV_NDN_NAME {
            continue;
        }
        let mut name_bytes = BytesMut::new();
        write_tlv(&mut name_bytes, name_typ, name_val);
        let Some(node_key) = decode_name_key(&name_bytes) else {
            continue;
        };

        entry_body = after_name;

        let (seq_typ, seq_val, _) = read_tlv(entry_body)?;
        if seq_typ != TLV_SV_SEQ_NO {
            continue;
        }
        entries.push((node_key, decode_nni(seq_val)));
    }

    Some(entries)
}

/// `MappingData` (0xCD) → `node_key → app_data`. `app_data` is
/// everything after `NodeID` and `SeqNo` inside each `MappingEntry`.
fn decode_mapping_data(md_tlv: &[u8]) -> HashMap<String, Bytes> {
    let mut result = HashMap::new();
    let Some((typ, mut body, _)) = read_tlv(md_tlv) else {
        return result;
    };
    if typ != TLV_MAPPING_DATA {
        return result;
    }

    while !body.is_empty() {
        let Some((entry_typ, mut entry_body, rest)) = read_tlv(body) else {
            break;
        };
        body = rest;
        if entry_typ != TLV_MAPPING_ENTRY {
            continue;
        }

        // NodeID.
        let Some((name_typ, name_val, after_name)) = read_tlv(entry_body) else {
            continue;
        };
        if name_typ != TLV_NDN_NAME {
            continue;
        }
        let mut name_bytes = BytesMut::new();
        write_tlv(&mut name_bytes, name_typ, name_val);
        let Some(node_key) = decode_name_key(&name_bytes) else {
            continue;
        };

        entry_body = after_name;

        // SeqNo — read and discard (we match by node_key, not seq).
        let Some((seq_typ, _, after_seq)) = read_tlv(entry_body) else {
            continue;
        };
        if seq_typ != TLV_SV_SEQ_NO {
            continue;
        }

        // Remaining bytes are the application-defined AppData.
        let app_data = Bytes::copy_from_slice(after_seq);
        result.insert(node_key, app_data);
    }

    result
}

/// `(state_vector, mapping_map)` where `mapping_map` is empty when no
/// MappingData TLV is present.
type ParsedSyncInterest = (Vec<(String, u64)>, HashMap<String, Bytes>);

fn parse_sync_interest(group: &Name, raw: &[u8]) -> Option<ParsedSyncInterest> {
    let interest = ndn_packet::Interest::decode(Bytes::copy_from_slice(raw)).ok()?;
    let components = interest.name.components();

    let group_len = group.components().len();
    if components.len() < group_len + 1 {
        return None;
    }
    if components[group_len].value.as_ref() != b"svs" {
        return None;
    }

    let app_params = interest.app_parameters()?;

    let mut sv: Option<Vec<(String, u64)>> = None;
    let mut mappings: HashMap<String, Bytes> = HashMap::new();
    let mut cursor: &[u8] = app_params;

    while !cursor.is_empty() {
        let Some((typ, _value, rest)) = read_tlv(cursor) else {
            break;
        };
        let consumed = cursor.len() - rest.len();
        let full_tlv = &cursor[..consumed];

        match typ {
            TLV_STATE_VECTOR => {
                sv = decode_state_vector(full_tlv);
            }
            TLV_MAPPING_DATA => {
                mappings = decode_mapping_data(full_tlv);
            }
            _ => {}
        }

        cursor = rest;
    }

    sv.map(|v| (v, mappings))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_vector_roundtrip() {
        let entries = vec![
            StateVectorEntry {
                node: "/alice".to_string(),
                seq: 5,
            },
            StateVectorEntry {
                node: "/bob".to_string(),
                seq: 12,
            },
        ];
        let encoded = encode_state_vector(&entries);
        let decoded = decode_state_vector(&encoded).expect("decode should succeed");
        assert_eq!(decoded.len(), 2);
        let alice = decoded.iter().find(|(k, _)| k == "/alice");
        let bob = decoded.iter().find(|(k, _)| k == "/bob");
        assert_eq!(alice.map(|(_, s)| *s), Some(5));
        assert_eq!(bob.map(|(_, s)| *s), Some(12));
    }

    #[test]
    fn decode_empty_state_vector() {
        let entries: Vec<StateVectorEntry> = vec![];
        let encoded = encode_state_vector(&entries);
        let decoded = decode_state_vector(&encoded).expect("decode empty sv");
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_uses_tlv_type_201() {
        let entries = vec![StateVectorEntry {
            node: "/n".to_string(),
            seq: 1,
        }];
        let encoded = encode_state_vector(&entries);
        assert_eq!(encoded[0], 0xC9, "StateVector type must be 201 (0xC9)");
    }

    #[test]
    fn mapping_data_roundtrip() {
        let name: Name = "/alice".parse().unwrap();
        let app_data = Bytes::from_static(b"hello-mapping");
        let encoded = encode_mapping_data(&name, 42, &app_data);

        assert_eq!(encoded[0], 0xCD, "MappingData type must be 205 (0xCD)");

        let decoded = decode_mapping_data(&encoded);
        let got = decoded.get("/alice").cloned().expect("entry for /alice");
        assert_eq!(got, app_data);
    }

    #[test]
    fn mapping_data_multiple_entries_roundtrip() {
        let a = encode_mapping_data(&"/a".parse().unwrap(), 1, b"data-a");
        let b = encode_mapping_data(&"/b".parse().unwrap(), 2, b"data-b");

        let da = decode_mapping_data(&a);
        let db = decode_mapping_data(&b);
        assert_eq!(da["/a"].as_ref(), b"data-a");
        assert_eq!(db["/b"].as_ref(), b"data-b");
    }

    #[test]
    fn remote_covers_local_true() {
        let local = vec![
            StateVectorEntry {
                node: "/a".to_string(),
                seq: 3,
            },
            StateVectorEntry {
                node: "/b".to_string(),
                seq: 1,
            },
        ];
        let remote = vec![("/a".to_string(), 3u64), ("/b".to_string(), 5)];
        assert!(remote_covers_local(&local, &remote));
    }

    #[test]
    fn remote_covers_local_false_when_behind() {
        let local = vec![StateVectorEntry {
            node: "/a".to_string(),
            seq: 5,
        }];
        let remote = vec![("/a".to_string(), 3u64)];
        assert!(!remote_covers_local(&local, &remote));
    }

    #[test]
    fn remote_covers_local_false_when_missing_node() {
        let local = vec![StateVectorEntry {
            node: "/a".to_string(),
            seq: 1,
        }];
        let remote: Vec<(String, u64)> = vec![];
        assert!(!remote_covers_local(&local, &remote));
    }

    #[tokio::test]
    async fn fetch_with_retry_succeeds_on_first_try() {
        let result = fetch_with_retry(RetryPolicy::default(), |_attempt| async {
            Ok::<_, &str>("ok")
        })
        .await;
        assert_eq!(result, Ok("ok"));
    }

    #[tokio::test]
    async fn fetch_with_retry_retries_on_failure() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();

        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            backoff_factor: 1.0,
        };

        let result: Result<(), &str> = fetch_with_retry(policy, move |_| {
            let c = calls2.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 { Err("fail") } else { Ok(()) }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fetch_with_retry_exhausts_retries() {
        let policy = RetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(1),
            backoff_factor: 1.0,
        };

        let result: Result<(), &str> =
            fetch_with_retry(policy, |_| async { Err("always fail") }).await;
        assert_eq!(result, Err("always fail"));
    }

    #[tokio::test]
    async fn join_and_leave() {
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-a".parse().unwrap();

        let handle = join_svs_group(group, local, send_tx, recv_rx, SvsConfig::default());
        handle.leave();
    }

    #[tokio::test]
    async fn sync_interest_carries_app_params() {
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/node-a".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_millis(10),
            jitter_ms: 0,
            ..Default::default()
        };

        let _handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        let raw = tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        let interest = ndn_packet::Interest::decode(raw).expect("decode interest");
        let ap = interest.app_parameters().expect("must have AppParameters");
        let sv = decode_state_vector(ap).expect("must decode StateVector");
        assert!(!sv.is_empty(), "state vector should contain local node");
    }

    #[tokio::test]
    async fn sync_interest_carries_mapping_after_publish_with_mapping() {
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/node-m".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            ..Default::default()
        };

        let handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        handle
            .publish_with_mapping(local.clone(), Bytes::from_static(b"test-mapping"))
            .await
            .expect("publish_with_mapping");

        let raw = tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        let interest = ndn_packet::Interest::decode(raw).expect("decode interest");
        let ap = interest.app_parameters().expect("AppParameters present");

        let mut found_mapping = false;
        let mut cursor: &[u8] = ap;
        while !cursor.is_empty() {
            let Some((typ, _val, rest)) = read_tlv(cursor) else {
                break;
            };
            let consumed = cursor.len() - rest.len();
            if typ == TLV_MAPPING_DATA {
                let mappings = decode_mapping_data(&cursor[..consumed]);
                let key = local.to_string();
                if let Some(data) = mappings.get(&key) {
                    assert_eq!(data.as_ref(), b"test-mapping");
                    found_mapping = true;
                }
            }
            cursor = rest;
        }
        assert!(found_mapping, "MappingData TLV not found in AppParameters");
    }
}
