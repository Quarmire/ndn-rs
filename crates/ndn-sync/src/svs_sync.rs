//! ndnSVS-compatible State Vector Sync. Background task multicasts
//! Sync Interests carrying the local state vector, merges received
//! vectors, and emits [`SyncUpdate`]s for detected gaps.
//!
//! Wire shape — Sync Interest name `/<group-prefix>/v=2` (a typed
//! VERSION component, TLV-TYPE `0x36`, value 2), matching ndn-svs
//! `core.cpp:351` `Interest(Name(m_syncPrefix).appendVersion(2))`. This
//! is the v2 dialect; ndnd's v3 uses `v=3`. (Earlier revisions of this
//! file appended a *generic* `"svs"` component, which no C++/Go peer
//! recognises — see `testbed/fixtures/svs/README.md`, gap #9.) State
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
//! Timer model — the driver is a two-state machine (ndn-svs
//! `SVSyncCore`):
//!
//! * **Steady state.** A jittered periodic timer fires every
//!   `[sync_interval ± jitter_ms]`, emitting one Sync Interest. When a
//!   peer's Interest *covers* the local vector, this timer is reset to a
//!   fresh window — Interest-storm suppression, so a large group emits
//!   ≈ one Interest per interval rather than one per member.
//! * **Suppression (reply-to-stale).** When an incoming Interest is
//!   *behind* local state (a peer is missing data we hold), the node
//!   does **not** wait for the next periodic tick. It schedules a
//!   catch-up Interest after a short, exponentially-jittered
//!   [`SvsConfig::suppression_period`] (~200 ms) and, while that timer
//!   runs, records every peer vector it sees. When the timer fires it
//!   sends *only if* the union of recorded vectors still does not cover
//!   us — i.e. no other member already corrected the laggard. This is
//!   what gives a partitioned/rejoining node sub-second recovery instead
//!   of a full periodic wait, and what keeps the group to a single
//!   corrective Interest.
//!
//! **Authoritative-for-self (deliberate behaviour change, gap #3).**
//! [`SvsNode::merge`](crate::svs::SvsNode::merge) ignores any received
//! entry naming the local node: a remote peer can never raise our own
//! sequence number, only [`advance`](crate::svs::SvsNode::advance) can.
//! This closes a state-injection / seq-hijack hole. The one legitimate
//! case it used to (accidentally) serve — a node that restarted with no
//! persistence relearning its own seq from peers — is instead solved
//! correctly by the SVS v3 boot-timestamp dialect in
//! [`svs_local`](crate::svs_local), which disambiguates pre- and
//! post-restart sequence spaces.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::rt::{self, Instant};

use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::protocol::{SyncHandle, SyncUpdate};
use crate::security::{SyncSigner, SyncValidator};
use crate::svs::SvsNode;

// TLV codes per ndn-svs/ndn-svs/tlv.hpp.
const TLV_STATE_VECTOR: u64 = 201;
const TLV_SV_ENTRY: u64 = 202;
const TLV_SV_SEQ_NO: u64 = 204;
const TLV_MAPPING_DATA: u64 = 205;
const TLV_MAPPING_ENTRY: u64 = 206;
const TLV_NDN_NAME: u64 = 7;

/// v2 Sync Interest name version (ndn-svs `core.cpp:351`
/// `appendVersion(2)`). ndnd's v3 dialect uses 3.
const SVS_SYNC_VERSION_V2: u64 = 2;

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
                rt::sleep(delay).await;
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
    /// Reply-to-stale suppression window. When an incoming Sync Interest
    /// is *behind* local state (a peer is missing data we have), the
    /// node schedules its catch-up reply after an exponentially-jittered
    /// delay with this mean, then sends only if no other member has
    /// already corrected the laggard. This is half of the SVS protocol
    /// (ndn-svs `SVSyncCore`): in steady state the group emits ≈ one
    /// Sync Interest per [`Self::sync_interval`] rather than one per
    /// member, and a rejoining/partitioned node recovers in
    /// sub-`suppression_period` time instead of a full periodic wait.
    /// Default 200 ms.
    pub suppression_period: Duration,
    pub channel_capacity: usize,
    /// Not consumed by the SVS task itself; passed to [`fetch_with_retry`]
    /// by application-side gap fetchers.
    pub retry_policy: RetryPolicy,
    /// Signs every outgoing Sync Interest. Defaults to
    /// [`Insecure`](crate::security::Insecure) (unsigned), the
    /// closed-link posture; set an
    /// [`HmacKey`](crate::security::HmacKey) for authenticated groups.
    pub signer: Arc<dyn SyncSigner>,
    /// Gates every inbound Sync Interest before merge. Defaults to
    /// [`Insecure`](crate::security::Insecure) (accept-all); pair it with
    /// the same key as [`Self::signer`] for an HMAC group.
    pub validator: Arc<dyn SyncValidator>,
}

impl Default for SvsConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(30),
            jitter_ms: 3000,
            suppression_period: Duration::from_millis(200),
            channel_capacity: 256,
            retry_policy: RetryPolicy::default(),
            signer: crate::security::default_signer(),
            validator: crate::security::default_validator(),
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
    rt::spawn(async move {
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

    // Suppression state (ndn-svs `SVSyncCore`). When `suppressing` is set,
    // `next_send` is a *short* reply-to-stale deadline rather than the
    // steady periodic one, and `recorded` accumulates every peer vector
    // seen during the window so the timer can check — at fire time —
    // whether someone else already corrected the laggard.
    let mut suppressing = false;
    let mut recorded: HashMap<String, u64> = HashMap::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,

            // Portable equivalent of `sleep_until(next_send)` — recomputed each
            // loop iteration, so a reset of `next_send` reschedules correctly.
            _ = rt::sleep(next_send.saturating_duration_since(Instant::now())) => {
                if suppressing {
                    // Reply-to-stale: only emit if the union of vectors
                    // recorded during the window still does not cover us —
                    // i.e. nobody else has announced our data yet.
                    suppressing = false;
                    let snapshot = node.snapshot().await;
                    let recorded_sv: Vec<(String, u64)> =
                        recorded.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    recorded.clear();
                    if !remote_covers_local(&snapshot, &recorded_sv) {
                        send_sync_interest(&group, &node, &send, current_mapping.clone(), &config.signer).await;
                    }
                    next_send = Instant::now() + jitter_interval(&config);
                } else {
                    send_sync_interest(&group, &node, &send, current_mapping.clone(), &config.signer).await;
                    next_send = Instant::now() + jitter_interval(&config);
                }
            }

            Some(raw) = recv.recv() => {
                // Authenticate before touching the state vector — an
                // unsigned/forged Interest must never reach `merge`
                // (gap #2). `Insecure` accepts everything.
                if let Err(reason) = config.validator.validate(&raw) {
                    tracing::trace!(?reason, "svs: rejected inbound sync interest");
                    continue;
                }
                if let Some((remote_sv, peer_mappings)) = parse_sync_interest(&group, &raw) {
                    let snapshot = node.snapshot().await;
                    let covers_local = remote_covers_local(&snapshot, &remote_sv);
                    // The peer is missing data we already hold (we are ahead
                    // on at least one entry). `covers_local == false` is
                    // necessary but not sufficient — they could be ahead on a
                    // *different* entry — so test strict local-ahead directly.
                    let local_ahead = local_ahead_of_remote(&snapshot, &remote_sv);

                    let gaps = node.merge(&remote_sv).await;
                    for (peer_key, low, high) in gaps {
                        if peer_key == local_key { continue; }
                        let mapping = peer_mappings.get(&peer_key).cloned();
                        // `peer_key` is the publisher's full NDN name rendered
                        // as a URI; parse it back into a component-wise Name so
                        // consumers can append a segment/seq to form a real
                        // fetch prefix (not one opaque component holding "/a").
                        let fetch_name = peer_key
                            .parse::<Name>()
                            .unwrap_or_else(|_| group.clone().append(&peer_key));
                        let update = SyncUpdate {
                            publisher: peer_key.clone(),
                            name: fetch_name,
                            low_seq: low,
                            high_seq: high,
                            mapping,
                        };
                        let _ = update_tx.send(update).await;
                    }

                    if local_ahead {
                        // Schedule (or extend) a suppressed catch-up reply.
                        record_vector(&mut recorded, &remote_sv);
                        if !suppressing {
                            suppressing = true;
                            next_send = Instant::now() + suppression_delay(&config);
                        }
                    } else if covers_local {
                        // Peer is at least as new as us: steady-state
                        // suppression — defer our next periodic Interest.
                        suppressing = false;
                        recorded.clear();
                        next_send = Instant::now() + jitter_interval(&config);
                    }
                    // else: incomparable with no local-ahead entry (we were
                    // strictly behind); we merged and will fetch — stay on the
                    // existing schedule.
                }
            }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                current_mapping = mapping;
                node.advance().await;
                let _ = pub_name;
                // A fresh local publication is authoritative: leave any
                // suppression window and announce immediately.
                suppressing = false;
                recorded.clear();
                send_sync_interest(&group, &node, &send, current_mapping.clone(), &config.signer).await;
                next_send = Instant::now() + jitter_interval(&config);
            }
        }
    }
}

/// Exponentially-jittered suppression delay with mean
/// [`SvsConfig::suppression_period`], capped at 4× the mean. The
/// exponential shape makes one member of a large group statistically
/// fire well before the others, who then observe its reply and stay
/// quiet (ndn-svs suppression timer).
fn suppression_delay(config: &SvsConfig) -> Duration {
    let mean = config.suppression_period.as_secs_f64();
    if mean <= 0.0 {
        return Duration::ZERO;
    }
    let u = fastrand::f64().clamp(f64::MIN_POSITIVE, 1.0);
    let sampled = (-mean * u.ln()).min(mean * 4.0);
    Duration::from_secs_f64(sampled)
}

/// True if local state is strictly ahead of `remote_sv` on at least one
/// node — i.e. the peer is missing a publication we already hold.
fn local_ahead_of_remote(
    local_snapshot: &[crate::svs::StateVectorEntry],
    remote_sv: &[(String, u64)],
) -> bool {
    let remote_map: HashMap<&str, u64> = remote_sv.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    local_snapshot
        .iter()
        .any(|e| e.seq > remote_map.get(e.node.as_str()).copied().unwrap_or(0))
}

/// Merge a received vector into the suppression record, keeping the
/// highest seq seen per node across the window.
fn record_vector(recorded: &mut HashMap<String, u64>, remote_sv: &[(String, u64)]) {
    for (node, seq) in remote_sv {
        let slot = recorded.entry(node.clone()).or_insert(0);
        if *seq > *slot {
            *slot = *seq;
        }
    }
}

/// `mapping` adds a `MappingData` (0xCD) TLV after the `StateVector`.
/// The Interest is signed by `signer` ([`Insecure`](crate::security::Insecure)
/// leaves it unsigned).
async fn send_sync_interest(
    group: &Name,
    node: &SvsNode,
    send: &mpsc::Sender<Bytes>,
    mapping: Option<Bytes>,
    signer: &Arc<dyn SyncSigner>,
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

    let sync_name = group.clone().append_version(SVS_SYNC_VERSION_V2);
    let builder = InterestBuilder::new(sync_name)
        .lifetime(Duration::from_millis(1000))
        .app_parameters(app_params);
    let wire = signer.sign(builder);
    let _ = send.send(wire).await;
}

fn jitter_interval(config: &SvsConfig) -> Duration {
    let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
    config.sync_interval + jitter
}

use crate::tlv::{decode_nni, encode_nni, read_tlv, write_tlv};

fn remote_covers_local(
    local_snapshot: &[crate::svs::StateVectorEntry],
    remote_sv: &[(String, u64)],
) -> bool {
    let remote_map: HashMap<&str, u64> = remote_sv.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    local_snapshot
        .iter()
        .all(|e| remote_map.get(e.node.as_str()).copied().unwrap_or(0) >= e.seq)
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
    // The component after the group prefix must be the typed v2 version
    // (ndn-svs `appendVersion(2)`), not a generic component.
    if components[group_len].as_version() != Some(SVS_SYNC_VERSION_V2) {
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

    /// Build a raw Sync Interest carrying `entries` as its state vector,
    /// as a peer on the wire would send it.
    fn peer_sync_interest(group: &Name, entries: &[(&str, u64)]) -> Bytes {
        let sv: Vec<StateVectorEntry> = entries
            .iter()
            .map(|(n, s)| StateVectorEntry {
                node: n.to_string(),
                seq: *s,
            })
            .collect();
        let app_params = encode_state_vector(&sv);
        InterestBuilder::new(group.clone().append_version(SVS_SYNC_VERSION_V2))
            .lifetime(Duration::from_millis(1000))
            .app_parameters(app_params)
            .build()
    }

    /// gap #9 golden: the v2 Sync Interest name appends a typed VERSION
    /// component (`0x36`) = 2, matching ndn-svs `core.cpp:351`
    /// `appendVersion(2)` — byte-for-byte against
    /// `testbed/fixtures/svs/sync_interest_v2_name.hex`.
    #[test]
    fn sync_interest_name_matches_ndn_svs_v2() {
        let group: Name = "/ndn/svs".parse().unwrap();
        let name = group.clone().append_version(SVS_SYNC_VERSION_V2);

        // Reconstruct the NAME TLV inner bytes and compare to the fixture.
        let mut inner = BytesMut::new();
        for comp in name.components() {
            write_tlv(&mut inner, comp.typ, &comp.value);
        }
        let mut name_tlv = BytesMut::new();
        write_tlv(&mut name_tlv, TLV_NDN_NAME, &inner);

        let fixture = "070d08036e646e0803737673360102";
        let actual: String = name_tlv.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, fixture,
            "v2 Sync Interest name must match ndn-svs appendVersion(2)"
        );

        // And the structural accessor agrees.
        assert_eq!(
            name.components().last().unwrap().as_version(),
            Some(2),
            "trailing component must be VERSION=2"
        );
    }

    #[test]
    fn parser_rejects_legacy_generic_svs_component() {
        // A peer (or our own old code) appending a generic "svs"
        // component must no longer be accepted as a v2 Sync Interest.
        let group: Name = "/ndn/svs".parse().unwrap();
        let sv = vec![StateVectorEntry {
            node: "/ndn/svs/a".to_string(),
            seq: 1,
        }];
        let legacy = InterestBuilder::new(group.clone().append("svs"))
            .app_parameters(encode_state_vector(&sv))
            .build();
        assert!(
            parse_sync_interest(&group, &legacy).is_none(),
            "generic 'svs' component must be rejected"
        );

        let good = peer_sync_interest(&group, &[("/ndn/svs/a", 1)]);
        assert!(
            parse_sync_interest(&group, &good).is_some(),
            "v=2 component must parse"
        );
    }

    #[tokio::test]
    async fn reply_to_stale_fires_within_suppression_window() {
        // A node that is *ahead* of an incoming (stale) peer vector must
        // reply well before the steady periodic interval — this is the
        // sub-second partition/rejoin recovery the suppression FSM exists
        // for. We set the periodic interval to 60 s so any reply we see
        // can only come from the suppression path.
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-ahead".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            suppression_period: Duration::from_millis(40),
            ..Default::default()
        };

        let handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        // Publish so we advance to seq 1 (now ahead of any peer at 0).
        handle.publish(local.clone()).await.expect("publish");
        // Drain the immediate post-publish announcement.
        let _ = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("post-publish interest")
            .expect("channel open");

        // Feed a stale peer vector that does not know our seq=1.
        let stale = peer_sync_interest(&group, &[("/test/svs/node-behind", 0)]);
        recv_tx.send(stale).await.expect("send stale");

        // The suppressed reply must arrive far sooner than 60 s.
        let replied = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
        assert!(
            replied.is_ok() && replied.unwrap().is_some(),
            "node should emit a suppressed catch-up Interest for the stale peer"
        );
    }

    #[tokio::test]
    async fn steady_state_suppression_defers_periodic_interest() {
        // When a peer's vector already covers us, our next periodic
        // Interest is pushed out (interest-storm suppression). With a
        // short interval but a covering peer arriving each round, the
        // node should stay quiet rather than emit back-to-back.
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-q".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_millis(120),
            jitter_ms: 0,
            suppression_period: Duration::from_millis(40),
            ..Default::default()
        };

        let _handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        // Drain the first periodic Interest.
        let _ = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("first interest")
            .expect("channel open");

        // A peer that already covers us (knows our seq=0) arrives — should
        // reset our periodic timer, so no Interest in the next ~80 ms.
        let covering = peer_sync_interest(&group, &[("/test/svs/node-q", 0)]);
        recv_tx.send(covering).await.expect("send covering");

        let quiet = tokio::time::timeout(Duration::from_millis(80), send_rx.recv()).await;
        assert!(
            quiet.is_err(),
            "covering peer should defer our periodic Interest"
        );
    }

    #[tokio::test]
    async fn sync_update_name_is_publisher_components() {
        // Regression for the `group.append(peer_key)` smell: the fetch
        // prefix handed to consumers must be the publisher's real
        // component-wise Name, not one opaque component holding the URI.
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/me".parse().unwrap();

        let mut handle = join_svs_group(
            group.clone(),
            local.clone(),
            send_tx,
            recv_rx,
            SvsConfig::default(),
        );

        let peer = "/test/svs/peer-x";
        recv_tx
            .send(peer_sync_interest(&group, &[(peer, 3)]))
            .await
            .expect("send peer interest");

        let update = tokio::time::timeout(Duration::from_secs(2), handle.recv())
            .await
            .expect("timed out")
            .expect("update");

        let expected: Name = peer.parse().unwrap();
        assert_eq!(update.name, expected, "fetch name must be the publisher Name");
        assert_eq!(
            update.name.components().len(),
            expected.components().len(),
            "publisher name must not collapse into one opaque component"
        );
    }

    #[tokio::test]
    async fn validator_drops_unsigned_then_accepts_signed() {
        use crate::security::HmacKey;
        let group: Name = "/ndn/svs".parse().unwrap();
        let local: Name = "/ndn/svs/me".parse().unwrap();
        let key = HmacKey::new(b"group-key".to_vec(), "/keys/g".parse::<Name>().unwrap());

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            signer: Arc::new(key.clone()),
            validator: Arc::new(key.clone()),
            ..Default::default()
        };
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);
        let mut handle = join_svs_group(group.clone(), local, send_tx, recv_rx, config);

        // Unsigned peer Interest → validator drops it, no SyncUpdate.
        let unsigned = peer_sync_interest(&group, &[("/ndn/svs/peer", 4)]);
        recv_tx.send(unsigned).await.unwrap();
        let none = tokio::time::timeout(Duration::from_millis(300), handle.recv()).await;
        assert!(none.is_err(), "unsigned interest must not produce an update");

        // Correctly HMAC-signed peer Interest → accepted, update emitted.
        let sv = vec![StateVectorEntry {
            node: "/ndn/svs/peer".to_string(),
            seq: 4,
        }];
        let signed = key.sign(
            InterestBuilder::new(group.clone().append_version(SVS_SYNC_VERSION_V2))
                .lifetime(Duration::from_millis(1000))
                .app_parameters(encode_state_vector(&sv)),
        );
        recv_tx.send(signed).await.unwrap();
        let upd = tokio::time::timeout(Duration::from_secs(2), handle.recv())
            .await
            .expect("timed out")
            .expect("update");
        assert_eq!(upd.publisher, "/ndn/svs/peer");
        assert_eq!(upd.high_seq, 4);
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
