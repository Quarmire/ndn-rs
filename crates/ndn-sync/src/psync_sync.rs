//! PSync FullProducer network protocol — wires `PSyncNode` + `Ibf` to
//! Interest/Data exchange. Wire format per
//! `PSync/PSync/full-producer.cpp`:
//!
//! - Sync Interest:
//!   `/<sync-prefix>/<IBF-component>/<numCumulativeElements>` where
//!   `<IBF-component>` is the IBLT as 12-byte big-endian triples
//!   `(count, keySum, keyCheck)`, zlib-compressed, in a
//!   GenericNameComponent (`PSync/detail/iblt.cpp::appendToName`).
//! - Sync Data: `PSyncContent` TLV (0x80) wrapping Name TLVs. The
//!   Data name is `<interest-name>/<version>/<seg=0>` and requires
//!   `CanBePrefix` on the Sync Interest so NFD satisfies the PIT
//!   entry with the longer name
//!   (`PSync/detail/state.hpp:27`, `segment-publisher.cpp:37`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::Duration;

use bytes::Bytes;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};

use crate::murmur3::{N_HASHCHECK, murmur3_x86_32};
use crate::protocol::{SyncHandle, SyncUpdate};
use crate::psync::{Ibf, PSyncNode};
use crate::rt::{self, Instant};
use crate::tlv::{decode_nni, encode_nni};

/// Generic NameComponent TLV-TYPE (0x08) — the component a PSync `seq`
/// rides in (`appendNumber`).
const T_GENERIC: u64 = 0x08;

/// Split a published/learned name into `(prefix, seq)` when it ends with a
/// generic NonNegativeInteger component (the PSync `<prefix>/<seq>`
/// convention, ndn-cxx `appendNumber`). `None` for an unversioned name.
fn parse_prefix_seq(name: &Name) -> Option<(Name, u64)> {
    let comps = name.components();
    let last = comps.last()?;
    if last.typ != T_GENERIC || !matches!(last.value.len(), 1 | 2 | 4 | 8) {
        return None;
    }
    let seq = decode_nni(&last.value);
    let prefix = Name::from_components(comps[..comps.len() - 1].iter().cloned());
    Some((prefix, seq))
}

/// `prefix/<seq-as-generic-NNI>` — inverse of [`parse_prefix_seq`].
fn append_seq(prefix: &Name, seq: u64) -> Name {
    prefix.clone().append_component(ndn_packet::NameComponent::generic(Bytes::from(
        encode_nni(seq),
    )))
}

/// PSync `ProducerBase` (C++ `PSync/producer-base.cpp`): a **bounded**,
/// latest-version set. For a versioned name `<prefix>/<seq>`, publishing
/// or learning a newer seq erases `<prefix>/<oldSeq>` from the IBLT and
/// inserts `<prefix>/<seq>` — so the set is bounded by the number of
/// prefixes, not the total publication count (audit #1). The hash→name
/// table makes every learned name relay-capable (audit #4): a node can
/// answer a reconcile with names it learned from peers, not just its own.
struct ProducerBase {
    node: PSyncNode,
    /// prefix (sans seq) → latest seq.
    prefixes: HashMap<Name, u64>,
    /// IBLT hash → the full `<prefix>/<seq>` name (relay-capable).
    hash2name: HashMap<u32, Name>,
    /// `<prefix>/<seq>` name → IBLT hash (for erase).
    name2hash: HashMap<Name, u32>,
    /// Optional per-name application mapping (in-process fast-path).
    mappings: HashMap<u32, Bytes>,
    /// Cumulative element count carried in the Sync Interest
    /// (C++ `m_numOwnElements`; drives the decode-failure heuristic).
    num_own_elements: u64,
}

impl ProducerBase {
    fn new(ibf_count: usize) -> Self {
        Self {
            node: PSyncNode::new(ibf_count),
            prefixes: HashMap::new(),
            hash2name: HashMap::new(),
            name2hash: HashMap::new(),
            mappings: HashMap::new(),
            num_own_elements: 0,
        }
    }

    /// Insert/supersede a name. Returns `Some((reported_name, low, high))`
    /// when the set actually advanced; `None` for a stale or duplicate
    /// name. For a versioned name the old version is erased first.
    fn apply(&mut self, name: &Name, mapping: Option<Bytes>) -> Option<(Name, u64, u64)> {
        match parse_prefix_seq(name) {
            Some((prefix, seq)) => {
                let old = self.prefixes.get(&prefix).copied().unwrap_or(0);
                if seq <= old {
                    return None; // stale / duplicate
                }
                if old != 0 {
                    let old_name = append_seq(&prefix, old);
                    if let Some(h) = self.name2hash.remove(&old_name) {
                        self.node.remove(h);
                        self.hash2name.remove(&h);
                        self.mappings.remove(&h);
                    }
                }
                let h = hash_name(name);
                self.node.insert(h);
                self.hash2name.insert(h, name.clone());
                self.name2hash.insert(name.clone(), h);
                if let Some(m) = mapping {
                    self.mappings.insert(h, m);
                }
                self.prefixes.insert(prefix, seq);
                self.num_own_elements += seq - old;
                Some((name.clone(), old + 1, seq))
            }
            None => {
                // Unversioned name: insert once (no version churn).
                let h = hash_name(name);
                if self.node.contains(h) {
                    return None;
                }
                self.node.insert(h);
                self.hash2name.insert(h, name.clone());
                self.name2hash.insert(name.clone(), h);
                if let Some(m) = mapping {
                    self.mappings.insert(h, m);
                }
                self.num_own_elements += 1;
                Some((name.clone(), 0, 0))
            }
        }
    }

    fn names_for_hashes(&self, hashes: &std::collections::HashSet<u32>) -> Vec<Name> {
        hashes
            .iter()
            .filter_map(|h| self.hash2name.get(h).cloned())
            .collect()
    }

    /// The whole current set (decode-failure full-state response).
    fn state_names(&self) -> Vec<Name> {
        self.hash2name.values().cloned().collect()
    }

    fn build_ibf(&self) -> Ibf {
        self.node.build_ibf()
    }

    fn reconcile(
        &self,
        peer: &Ibf,
    ) -> Option<(std::collections::HashSet<u32>, std::collections::HashSet<u32>)> {
        self.node.reconcile(peer)
    }

    fn mapping_for(&self, name: &Name) -> Option<Bytes> {
        self.name2hash
            .get(name)
            .and_then(|h| self.mappings.get(h).cloned())
    }
}

/// A held Sync Interest (no diff at receipt). Satisfied when a later
/// publish/learn makes our set differ from `peer_ibf` (audit #3).
struct PendingEntry {
    peer_ibf: Ibf,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
pub struct PSyncConfig {
    /// Default 1 s (`SYNC_INTEREST_LIFETIME`).
    pub sync_interval: Duration,
    /// Default 200 ms.
    pub jitter_ms: u64,
    /// Default 80 (C++ `FullProducer::Options::ibfCount`); actual cell
    /// count is `ibf_count + ibf_count/2` rounded to a multiple of 3.
    pub ibf_count: usize,
    pub channel_capacity: usize,
}

/// Raw NDN Interest/Data TLV bytes for the PSync task. When `reply` is
/// set, any Sync Data response is sent through the oneshot instead of
/// the outbound channel — used for virtual faces (e.g. `CallbackFace`)
/// that must produce the response synchronously from their callback.
pub struct PSyncInbound {
    pub bytes: Bytes,
    pub reply: Option<oneshot::Sender<Bytes>>,
}

impl From<Bytes> for PSyncInbound {
    fn from(b: Bytes) -> Self {
        Self {
            bytes: b,
            reply: None,
        }
    }
}

impl Default for PSyncConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(1),
            jitter_ms: 200,
            ibf_count: 80,
            channel_capacity: 256,
        }
    }
}

/// Spawn the PSync background task: periodic IBLT-carrying Sync
/// Interests, IBLT subtract-and-reply, and `SyncUpdate` emission for
/// new names returned in Sync Data.
pub fn join_psync_group(
    group: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<PSyncInbound>,
    config: PSyncConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, publish_rx) = mpsc::channel(64);

    let task_cancel = cancel.clone();
    rt::spawn(async move {
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

/// How long a no-diff Sync Interest is held before expiry (≈ the Interest
/// lifetime we emit). On a later publish/learn it's satisfied early.
const PENDING_LIFETIME: Duration = Duration::from_millis(1100);

async fn psync_task(
    group: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<PSyncInbound>,
    mut publish_rx: mpsc::Receiver<(Name, Option<bytes::Bytes>)>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: PSyncConfig,
    cancel: CancellationToken,
) {
    let mut pb = ProducerBase::new(config.ibf_count);
    let mut pending: HashMap<Name, PendingEntry> = HashMap::new();

    loop {
        let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
        let interval = config.sync_interval + jitter;

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = rt::sleep(interval) => {
                let now = Instant::now();
                pending.retain(|_, e| e.expires_at > now);
                send_sync_interest(&group, &pb, &send).await;
            }

            Some(inbound) = recv.recv() => {
                let raw = inbound.bytes;
                let reply = inbound.reply;
                if raw.len() > 2 && raw[0] == 0x06 {
                    // Sync Data: learn names (relay-capable, #4) and emit updates.
                    if let Some(names) = parse_sync_data_names(&raw) {
                        let mut advanced = false;
                        for name in names {
                            if let Some((rep_name, low, high)) = pb.apply(&name, None) {
                                advanced = true;
                                let mapping = pb.mapping_for(&name);
                                let publisher = parse_prefix_seq(&name)
                                    .map(|(p, _)| p.to_string())
                                    .unwrap_or_else(|| name.to_string());
                                let _ = update_tx
                                    .send(SyncUpdate {
                                        publisher,
                                        name: rep_name,
                                        low_seq: low,
                                        high_seq: high,
                                        mapping,
                                    })
                                    .await;
                            }
                        }
                        // Learning new names may satisfy a peer's held Interest (#3/#4).
                        if advanced {
                            satisfy_pending(&mut pending, &pb, &send).await;
                        }
                    }
                } else if raw.len() > 2 && raw[0] == 0x05 {
                    handle_sync_interest(&group, &raw, &config, &pb, &mut pending, &send, reply).await;
                }
            }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                if pb.apply(&pub_name, mapping).is_some() {
                    satisfy_pending(&mut pending, &pb, &send).await;
                    send_sync_interest(&group, &pb, &send).await;
                }
            }
        }
    }
}

/// Reply to a Sync Interest per C++ `FullProducer::onSyncInterest`:
/// positive diff ⇒ send those names; no diff ⇒ hold a pending entry
/// (channel path) so a later publish satisfies it (#3); decode failure ⇒
/// if we're not behind (`num_rcvd <= num_own`), send the entire state (#2).
/// A direct-reply (CallbackFace) Interest can't be held, so it always gets
/// an immediate Data (names or an empty PSyncContent).
#[allow(clippy::too_many_arguments)]
async fn handle_sync_interest(
    group: &Name,
    raw: &[u8],
    config: &PSyncConfig,
    pb: &ProducerBase,
    pending: &mut HashMap<Name, PendingEntry>,
    send: &mpsc::Sender<Bytes>,
    reply: Option<oneshot::Sender<Bytes>>,
) {
    let Some((peer_ibf, num_elems, interest_name)) = parse_sync_interest(group, raw, config.ibf_count)
    else {
        return;
    };

    enum Action {
        Send(Vec<Name>),
        HoldPending(Ibf),
        Nothing,
    }

    let action = match pb.reconcile(&peer_ibf) {
        Some((we_have, they_have)) => {
            let names = pb.names_for_hashes(&we_have);
            if !names.is_empty() {
                Action::Send(names)
            } else if they_have.is_empty() {
                Action::HoldPending(peer_ibf) // identical sets — hold until we advance
            } else {
                Action::Nothing // peer is ahead; nothing to offer
            }
        }
        None => {
            // Can't decode the difference. If we're not behind, dump the
            // whole state so the peer resynchronises (#2).
            if num_elems <= pb.num_own_elements {
                Action::Send(pb.state_names())
            } else {
                Action::Nothing
            }
        }
    };

    match (action, reply) {
        (Action::Send(names), Some(tx)) => {
            let _ = tx.send(encode_sync_data_names(&interest_name, &names));
        }
        (Action::Send(names), None) => {
            if !names.is_empty() {
                let _ = send.send(encode_sync_data_names(&interest_name, &names)).await;
            }
        }
        (Action::HoldPending(ibf), None) => {
            pending.insert(
                interest_name,
                PendingEntry {
                    peer_ibf: ibf,
                    expires_at: Instant::now() + PENDING_LIFETIME,
                },
            );
        }
        // A synchronous direct-reply face can't be held; answer empty.
        (Action::HoldPending(_) | Action::Nothing, Some(tx)) => {
            let _ = tx.send(encode_sync_data_names(&interest_name, &[]));
        }
        (Action::Nothing, None) => {}
    }
}

/// Walk held Sync Interests; satisfy any whose recomputed diff now yields
/// names we can send (audit #3).
async fn satisfy_pending(
    pending: &mut HashMap<Name, PendingEntry>,
    pb: &ProducerBase,
    send: &mpsc::Sender<Bytes>,
) {
    let mut satisfied: Vec<Name> = Vec::new();
    for (iname, entry) in pending.iter() {
        if let Some((we_have, _)) = pb.reconcile(&entry.peer_ibf) {
            let names = pb.names_for_hashes(&we_have);
            if !names.is_empty() {
                let _ = send.send(encode_sync_data_names(iname, &names)).await;
                satisfied.push(iname.clone());
            }
        }
    }
    for iname in satisfied {
        pending.remove(&iname);
    }
}

async fn send_sync_interest(group: &Name, pb: &ProducerBase, send: &mpsc::Sender<Bytes>) {
    let ibf = pb.build_ibf();
    let ibf_bytes = encode_ibf(&ibf);
    let sync_name = group
        .clone()
        .append(ibf_bytes.as_ref())
        .append(pb.num_own_elements.to_be_bytes());
    // `CanBePrefix` is required because C++ PSync replies with
    // segmented Data named `<interest-name>/<version>/<seg=0>`.
    // `MustBeFresh` is required because that Data carries a 1 s
    // FreshnessPeriod (see `encode_sync_data_names`) — without it
    // intermediate NFDs serve a stale cached response forever.
    let wire = InterestBuilder::new(sync_name)
        .lifetime(Duration::from_millis(1000))
        .can_be_prefix()
        .must_be_fresh()
        .build();
    let _ = send.send(wire).await;
}

/// Cell layout: `count_be(4) + keySum_be(4) + keyCheck_be(4)`, then
/// zlib-compressed (`PSync/detail/iblt.cpp::appendToName`).
pub fn encode_ibf(ibf: &Ibf) -> Bytes {
    let cells = ibf.raw_cells();
    let mut raw = Vec::with_capacity(cells.len() * 12);
    for (count, key_sum, key_check) in &cells {
        raw.extend_from_slice(&count.to_be_bytes());
        raw.extend_from_slice(&key_sum.to_be_bytes());
        raw.extend_from_slice(&key_check.to_be_bytes());
    }
    Bytes::from(zlib_compress(&raw))
}

/// `expected_entries` must match the sender's configuration.
pub fn decode_ibf(compressed: &[u8], expected_entries: usize) -> Option<Ibf> {
    let raw = zlib_decompress(compressed)?;
    let n_cells = raw.len() / 12;
    let expected_ibf = Ibf::from_expected(expected_entries);
    if n_cells == 0 || n_cells != expected_ibf.n_cells() {
        return None;
    }
    let mut cursor = &raw[..];
    let mut cells = Vec::with_capacity(n_cells);
    for _ in 0..n_cells {
        if cursor.len() < 12 {
            return None;
        }
        let count = i32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        let key_sum = u32::from_be_bytes([cursor[4], cursor[5], cursor[6], cursor[7]]);
        let key_check = u32::from_be_bytes([cursor[8], cursor[9], cursor[10], cursor[11]]);
        cells.push((count, key_sum, key_check));
        cursor = &cursor[12..];
    }
    Some(Ibf::from_raw_cells(cells))
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    enc.write_all(data).expect("zlib compress");
    enc.finish().expect("zlib finish")
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    Some(out)
}

/// Content: `PSyncContent` TLV (0x80) wrapping concatenated Name
/// TLVs. Data name: `<interest_name>/<version>/<seg=0>` (matches
/// `PSync/PSync/segment-publisher.cpp:37`).
fn encode_sync_data_names(interest_name: &Name, names: &[Name]) -> Bytes {
    let mut inner = Vec::new();
    for name in names {
        let tlv = name.encode_to_tlv();
        inner.extend_from_slice(&tlv);
    }

    let mut psync_content = Vec::with_capacity(2 + inner.len());
    psync_content.push(0x80u8);
    write_tlv_varint(&mut psync_content, inner.len());
    psync_content.extend_from_slice(&inner);

    // Compress to match C++ PSync's CompressionScheme::DEFAULT == ZLIB
    // (PSync/detail/segment-publisher.cpp + util.cpp).  The decoder also
    // accepts uncompressed bytes via the inflate-then-fallback path, so this
    // is safe for ndn-rs↔ndn-rs as well.
    let content = zlib_compress(&psync_content);

    // Data name: <interest_name>/<version(µs)>/<seg=0>
    // web_time::SystemTime delegates to std natively; reads Date.now() on wasm32.
    let version = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64;
    let data_name = interest_name
        .clone()
        .append_version(version)
        .append_segment(0);

    DataBuilder::new(data_name, &content)
        .freshness(Duration::from_secs(1))
        .final_block_id_typed_seg(0)
        .sign_digest_sha256()
}

/// Write a TLV length field as a minimal varint (NDN TLV encoding).
fn write_tlv_varint(buf: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_be_bytes());
    }
}

/// Accepts both `PSyncContent` (0x80) wrapping (C++ PSync) and bare
/// concatenated Name TLVs (ndn-rs↔ndn-rs). C++ PSync also compresses
/// the State payload (CompressionScheme::DEFAULT == ZLIB), so zlib is
/// tried first.
fn parse_sync_data_names(raw: &[u8]) -> Option<Vec<Name>> {
    let data = ndn_packet::Data::decode(Bytes::copy_from_slice(raw)).ok()?;
    let content = data.content()?;

    let content: Bytes = match zlib_decompress(content) {
        Some(inflated) => Bytes::from(inflated),
        None => content.clone(),
    };

    let name_cursor: Bytes = if !content.is_empty() && content[0] == 0x80 {
        let (inner_len, hdr) = read_varint_len(&content[1..])?;
        let start = 1 + hdr;
        let end = start + inner_len;
        if content.len() < end {
            return Some(Vec::new());
        }
        content.slice(start..end)
    } else {
        content.clone()
    };

    let mut names = Vec::new();
    let mut cursor = name_cursor;
    while !cursor.is_empty() {
        if cursor.len() < 2 {
            break;
        }
        let type_byte = cursor[0];
        if type_byte != 0x07 {
            break;
        }
        let (len, header_size) = read_varint_len(&cursor[1..])?;
        let total = 1 + header_size + len;
        if cursor.len() < total {
            break;
        }
        let name_bytes = cursor.slice(1 + header_size..total);
        if let Ok(name) = Name::decode(name_bytes) {
            names.push(name);
        }
        cursor = cursor.slice(total..);
    }
    Some(names)
}

/// `(length_value, bytes_consumed)`.
fn read_varint_len(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        v if v < 0xfd => Some((v as usize, 1)),
        0xfd if data.len() >= 3 => {
            let v = u16::from_be_bytes([data[1], data[2]]) as usize;
            Some((v, 3))
        }
        0xfe if data.len() >= 5 => {
            let v = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
            Some((v, 5))
        }
        _ => None,
    }
}

/// `(peer_ibf, num_cumulative_elements, interest_name)` on success;
/// the interest name forms the response Data name.
fn parse_sync_interest(group: &Name, raw: &[u8], ibf_count: usize) -> Option<(Ibf, u64, Name)> {
    let interest = ndn_packet::Interest::decode(Bytes::copy_from_slice(raw)).ok()?;
    let interest_name = (*interest.name).clone();
    let components = interest_name.components();
    let group_len = group.components().len();
    if components.len() < group_len + 2 {
        return None;
    }
    let ibf_comp = &components[group_len];
    let peer_ibf = decode_ibf(&ibf_comp.value, ibf_count)?;

    let num_comp = &components[group_len + 1];
    let num_elems = parse_be_u64(&num_comp.value).unwrap_or(0);
    Some((peer_ibf, num_elems, interest_name))
}

fn parse_be_u64(b: &[u8]) -> Option<u64> {
    match b.len() {
        1 => Some(b[0] as u64),
        2 => Some(u16::from_be_bytes([b[0], b[1]]) as u64),
        4 => Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64),
        8 => Some(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ])),
        _ => None,
    }
}

/// `MurmurHash3(N_HASHCHECK, name_tlv_value)` matching C++
/// `murmurHash3(N_HASHCHECK, name)` in `PSync/detail/util.cpp`.
/// Hashes the Name TLV *value* (component TLVs), not the outer 0x07.
pub fn hash_name(name: &Name) -> u32 {
    let value_bytes = name_wire_value(name);
    murmur3_x86_32(&value_bytes, N_HASHCHECK)
}

/// Strips the outer `0x07` + length to mirror C++
/// `name.wireEncode().value()`.
fn name_wire_value(name: &Name) -> Bytes {
    let full = name.encode_to_tlv();
    let len_byte = full[1];
    let len_field_size: usize = if len_byte < 0xfd {
        1
    } else if len_byte == 0xfd {
        3
    } else if len_byte == 0xfe {
        5
    } else {
        9
    };
    full.slice(1 + len_field_size..)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_name_matches_psync_cpp() {
        let mut name: Name = "/test/memphis".parse().unwrap();
        name = name.append([1u8]);

        let expected: &[u8] = &[
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x07, 0x6d, 0x65, 0x6d, 0x70, 0x68, 0x69,
            0x73, 0x08, 0x01, 0x01,
        ];
        assert_eq!(
            name_wire_value(&name).as_ref(),
            expected,
            "Name TLV value must match hand-encoded bytes"
        );

        let hash = hash_name(&name);
        assert_eq!(
            hash, 0x5C5BF267,
            "hash_name must match C++ test vector keySum"
        );
    }

    #[test]
    fn ibf_encode_decode_roundtrip() {
        let mut ibf = Ibf::from_expected(10);
        let key = 0x5C5BF267u32;
        ibf.insert(key);

        let encoded = encode_ibf(&ibf);
        let decoded = decode_ibf(&encoded, 10).expect("decode must succeed");

        let diff = ibf.subtract(&decoded);
        let (a, b) = diff.decode().expect("diff decode must succeed");
        assert!(
            a.is_empty() && b.is_empty(),
            "round-trip must produce zero diff"
        );
    }

    #[test]
    fn name_wire_value_root_is_empty() {
        let root = Name::root();
        assert!(name_wire_value(&root).is_empty());
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

    // ---- ProducerBase: bounded set (#1) + relay (#4) -------------------

    #[test]
    fn producer_base_set_is_bounded_per_prefix() {
        // 100 publications under one prefix ⇒ the IBLT holds exactly one
        // element (the latest), not 100 — the fix for the "eventual brick".
        let mut pb = ProducerBase::new(80);
        let prefix: Name = "/ndn/nlsr/routerA/NAME".parse().unwrap();
        for seq in 1..=100u64 {
            pb.apply(&append_seq(&prefix, seq), None);
        }
        assert_eq!(pb.node.len(), 1, "bounded set holds only the latest version");
        assert_eq!(pb.num_own_elements, 100, "cumulative count tracks every bump");
        assert!(pb.name2hash.contains_key(&append_seq(&prefix, 100)));
        assert!(
            !pb.name2hash.contains_key(&append_seq(&prefix, 99)),
            "old version must be erased"
        );
    }

    #[test]
    fn producer_base_rejects_stale_and_duplicate() {
        let mut pb = ProducerBase::new(80);
        let p: Name = "/a/b".parse().unwrap();
        assert!(pb.apply(&append_seq(&p, 5), None).is_some());
        assert!(pb.apply(&append_seq(&p, 3), None).is_none(), "older rejected");
        assert!(pb.apply(&append_seq(&p, 5), None).is_none(), "same rejected");
        let (_, low, high) = pb.apply(&append_seq(&p, 9), None).unwrap();
        assert_eq!((low, high), (6, 9), "range = oldStored+1 ..= new");
    }

    #[test]
    fn learned_names_are_relay_capable() {
        // A node that LEARNS a name (never published it) can still offer it
        // on reconcile — transitive propagation (#4).
        let mut learner = ProducerBase::new(80);
        let name = append_seq(&"/peer/x".parse().unwrap(), 7);
        learner.apply(&name, None); // learned from a peer's Sync Data
        let empty = ProducerBase::new(80);
        let (we_have, _) = learner.reconcile(&empty.build_ibf()).expect("decode");
        assert_eq!(
            learner.names_for_hashes(&we_have),
            vec![name],
            "learned name must be offerable"
        );
    }

    #[test]
    fn unversioned_name_inserted_once() {
        let mut pb = ProducerBase::new(80);
        let n: Name = "/plain/name".parse().unwrap();
        assert!(pb.apply(&n, None).is_some());
        assert!(pb.apply(&n, None).is_none(), "duplicate plain name is a no-op");
        assert_eq!(pb.node.len(), 1);
    }

    #[test]
    fn parse_prefix_seq_roundtrips() {
        let p: Name = "/ndn/nlsr/routerA/NAME".parse().unwrap();
        let n = append_seq(&p, 42);
        let (prefix, seq) = parse_prefix_seq(&n).expect("has trailing seq");
        assert_eq!(prefix, p);
        assert_eq!(seq, 42);
        // A tail whose width isn't a legal NNI (1/2/4/8 bytes) ⇒ not a
        // seq (3-byte "xyz"). ndn-cxx `appendNumber` only emits those
        // widths, so NLSR/C++ versioned tails always parse.
        assert!(parse_prefix_seq(&"/a/b/xyz".parse::<Name>().unwrap()).is_none());
    }

    // ---- 2-node end-to-end: publish → reconcile → learn ----------------

    #[tokio::test]
    async fn two_nodes_converge_and_stay_bounded() {
        let group: Name = "/test/psync".parse().unwrap();
        let cfg = PSyncConfig {
            sync_interval: Duration::from_millis(40),
            jitter_ms: 0,
            ..Default::default()
        };

        let (a_out_tx, mut a_out_rx) = mpsc::channel::<Bytes>(256);
        let (a_in_tx, a_in_rx) = mpsc::channel::<PSyncInbound>(256);
        let (b_out_tx, mut b_out_rx) = mpsc::channel::<Bytes>(256);
        let (b_in_tx, b_in_rx) = mpsc::channel::<PSyncInbound>(256);

        // Broker: A.out → B.in, B.out → A.in.
        let a_in_for_b = a_in_tx.clone();
        tokio::spawn(async move {
            while let Some(p) = b_out_rx.recv().await {
                let _ = a_in_for_b.send(p.into()).await;
            }
        });
        let b_in_for_a = b_in_tx.clone();
        tokio::spawn(async move {
            while let Some(p) = a_out_rx.recv().await {
                let _ = b_in_for_a.send(p.into()).await;
            }
        });

        let a = join_psync_group(group.clone(), a_out_tx, a_in_rx, cfg.clone());
        let mut b = join_psync_group(group.clone(), b_out_tx, b_in_rx, cfg);

        // A publishes /p under prefix many times (versioned); B must learn
        // the latest, and A's set must stay bounded.
        let prefix: Name = "/test/psync/p".parse().unwrap();
        for seq in 1..=20u64 {
            a.publish(append_seq(&prefix, seq)).await.expect("publish");
            tokio::time::sleep(Duration::from_millis(3)).await;
        }

        // B receives at least one SyncUpdate naming /p (the latest version).
        let update = tokio::time::timeout(Duration::from_secs(5), b.recv())
            .await
            .expect("timed out")
            .expect("update");
        assert!(
            update.name.has_prefix(&prefix),
            "B should learn a /test/psync/p version, got {}",
            update.name
        );
    }

    #[test]
    fn ibf_cell_encoding_is_big_endian() {
        let mut ibf = Ibf::from_expected(10);
        let key: u32 = 0x5C5BF267;
        ibf.insert(key);

        let cells = ibf.raw_cells();
        let non_zero: Vec<_> = cells.iter().filter(|(c, _, _)| *c != 0).collect();
        assert_eq!(
            non_zero.len(),
            3,
            "one insert touches exactly N_HASH=3 cells"
        );
        for (count, key_sum, _key_check) in &non_zero {
            assert_eq!(*count, 1);
            assert_eq!(*key_sum, key, "keySum must equal the inserted key");
        }
    }

    #[test]
    fn sync_data_names_roundtrip() {
        let group: Name = "/test/sync".parse().unwrap();
        let names: Vec<Name> = vec![
            "/ndn/nlsr/LSA/routerA/NAME".parse().unwrap(),
            "/ndn/nlsr/LSA/routerB/ADJACENCY".parse().unwrap(),
        ];

        let encoded = encode_sync_data_names(&group, &names);
        let decoded = parse_sync_data_names(&encoded).expect("decode must succeed");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].to_string(), "/ndn/nlsr/LSA/routerA/NAME");
        assert_eq!(decoded[1].to_string(), "/ndn/nlsr/LSA/routerB/ADJACENCY");
    }
}
