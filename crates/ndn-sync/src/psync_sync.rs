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
use crate::rt;

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

async fn psync_task(
    group: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<PSyncInbound>,
    mut publish_rx: mpsc::Receiver<(Name, Option<bytes::Bytes>)>,
    update_tx: mpsc::Sender<SyncUpdate>,
    config: PSyncConfig,
    cancel: CancellationToken,
) {
    let mut node = PSyncNode::new(config.ibf_count);
    let mut name_map: HashMap<u32, (Name, Option<Bytes>)> = HashMap::new();

    loop {
        let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
        let interval = config.sync_interval + jitter;

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = rt::sleep(interval) => {
                send_sync_interest(&group, &node, &send).await;
            }

            Some(inbound) = recv.recv() => {
                let raw = inbound.bytes;
                let reply = inbound.reply;
                tracing::trace!(target: "sync.psync", len=raw.len(), first_byte=format_args!("{:02x}", raw.first().copied().unwrap_or(0)), reply=reply.is_some(), "psync: recv");
                if raw.len() > 2 && raw[0] == 0x06 {
                    match parse_sync_data_names(&raw) {
                        Some(names) => {
                            tracing::debug!(target: "sync.psync", count=names.len(), "psync: parsed Sync Data names");
                            for name in names {
                                let hash = hash_name(&name);
                                if node.contains(hash) {
                                    tracing::trace!(target: "sync.psync", %name, "psync: skip already-known Sync Data name");
                                    continue;
                                }
                                node.insert(hash);
                                let mapping = name_map.get(&hash).and_then(|(_, m)| m.clone());
                                let seq_no = name
                                    .components()
                                    .last()
                                    .and_then(|c| c.as_sequence_num())
                                    .unwrap_or(0);
                                tracing::debug!(target: "sync.psync", %name, has_mapping=mapping.is_some(), "psync: emit SyncUpdate");
                                let update = SyncUpdate {
                                    publisher: name.to_string(),
                                    name: name.clone(),
                                    low_seq: seq_no,
                                    high_seq: seq_no,
                                    mapping,
                                };
                                let _ = update_tx.send(update).await;
                            }
                        }
                        None => tracing::debug!(target: "sync.psync", "psync: Sync Data parse failed"),
                    }
                } else if raw.len() > 2 && raw[0] == 0x05 {
                    let parsed = parse_sync_interest(&group, &raw, config.ibf_count);
                    let (interest_name_for_reply, names_to_send) = match &parsed {
                        Some((peer_ibf, num_elems, interest_name)) => {
                            tracing::debug!(target: "sync.psync", num_elems=*num_elems, %interest_name, "psync: parsed Sync Interest");
                            match node.reconcile(peer_ibf) {
                                Some((we_have, they_have)) => {
                                    tracing::debug!(target: "sync.psync", we_have=we_have.len(), they_have=they_have.len(), "psync: reconcile result");
                                    let names: Vec<Name> = we_have
                                        .iter()
                                        .filter_map(|&h| name_map.get(&h).map(|(n, _)| n.clone()))
                                        .collect();
                                    (Some(interest_name.clone()), names)
                                }
                                None => {
                                    tracing::debug!(target: "sync.psync", "psync: reconcile returned None (IBF mismatch?)");
                                    (Some(interest_name.clone()), Vec::new())
                                }
                            }
                        }
                        None => {
                            tracing::debug!(target: "sync.psync", "psync: Sync Interest parse failed (IBF decode?)");
                            (None, Vec::new())
                        }
                    };

                    // CallbackFace direct-reply Interests must receive
                    // *some* Data — otherwise the face returns NoRoute
                    // Nack and the C++ PSync peer stops sending us
                    // further Sync Interests. We send an empty
                    // PSyncContent when there's no positive diff.
                    if let Some(reply_tx) = reply {
                        if let Some(interest_name) = interest_name_for_reply {
                            tracing::debug!(target: "sync.psync", count=names_to_send.len(), "psync: direct-reply Sync Data");
                            let data_bytes = encode_sync_data_names(&interest_name, &names_to_send);
                            let _ = reply_tx.send(data_bytes);
                        }
                    } else if let (Some(interest_name), false) = (
                        interest_name_for_reply,
                        names_to_send.is_empty(),
                    ) {
                        tracing::debug!(target: "sync.psync", count=names_to_send.len(), "psync: sending Sync Data with names we_have");
                        let data_bytes = encode_sync_data_names(&interest_name, &names_to_send);
                        let _ = send.send(data_bytes).await;
                    }
                }
            }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                let hash = hash_name(&pub_name);
                node.insert(hash);
                name_map.insert(hash, (pub_name, mapping));
                send_sync_interest(&group, &node, &send).await;
            }
        }
    }
}

async fn send_sync_interest(group: &Name, node: &PSyncNode, send: &mpsc::Sender<Bytes>) {
    let ibf = node.build_ibf();
    let ibf_bytes = encode_ibf(&ibf);
    let sync_name = group
        .clone()
        .append(ibf_bytes.as_ref())
        .append((node.len() as u64).to_be_bytes());
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
