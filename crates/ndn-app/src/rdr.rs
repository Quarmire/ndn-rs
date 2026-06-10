//! RDR (Realtime Data Retrieval) metadata convention —
//! `<name>/32=metadata` discovery for segmented objects.
//!
//! Spec: <https://named-data.net/doc/ndn-cxx/current/specs/rdr.html>.
//! Mirrors ndnd `std/ndn/rdr_2024/definitions.go` +
//! `std/object/{client_consume.go, client_produce.go}`. Used by
//! [`Consumer::fetch_object`](crate::Consumer::fetch_object) and
//! [`Producer::publish_object`](crate::Producer::publish_object).

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, NameComponent};
use ndn_security::{SignWith, Signer};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::AppError;

pub const METADATA_KEYWORD: &[u8] = b"metadata";

const TLV_METADATA_NAME: u64 = 0x07;
const TLV_METADATA_FINAL_BLOCK_ID: u64 = 0x1a;
const TLV_METADATA_SEGMENT_SIZE: u64 = 0xf500;
const TLV_METADATA_SIZE: u64 = 0xf502;

/// `versioned_name` is the segment prefix (`<name>/v=<ver>`);
/// `final_block_id` is the last-segment NameComponent's wire bytes
/// (typically `0x32 <len> <NNI>`).
#[derive(Clone, Debug)]
pub struct MetaData {
    pub versioned_name: Name,
    pub final_block_id: Bytes,
    pub segment_size: Option<u64>,
    pub size: Option<u64>,
}

impl Default for MetaData {
    fn default() -> Self {
        Self {
            versioned_name: Name::root(),
            final_block_id: Bytes::new(),
            segment_size: None,
            size: None,
        }
    }
}

impl MetaData {
    pub fn encode(&self) -> Bytes {
        let name_tlv = self.versioned_name.encode_to_tlv();
        let mut w = TlvWriter::with_capacity(64 + name_tlv.len() + self.final_block_id.len());
        w.write_raw(&name_tlv);
        w.write_tlv(TLV_METADATA_FINAL_BLOCK_ID, &self.final_block_id);
        if let Some(seg_size) = self.segment_size {
            let nni = encode_nni_be(seg_size);
            w.write_tlv(TLV_METADATA_SEGMENT_SIZE, &nni);
        }
        if let Some(size) = self.size {
            let nni = encode_nni_be(size);
            w.write_tlv(TLV_METADATA_SIZE, &nni);
        }
        w.finish()
    }

    pub fn decode(bytes: Bytes) -> Result<Self, AppError> {
        let mut r = TlvReader::new(bytes);
        let mut versioned_name = None;
        let mut final_block_id = None;
        let mut segment_size = None;
        let mut size = None;
        while !r.is_empty() {
            let (typ, value) = r
                .read_tlv()
                .map_err(|e| AppError::Protocol(format!("metadata TLV: {e}")))?;
            match typ {
                TLV_METADATA_NAME => {
                    let n = Name::decode(value)
                        .map_err(|e| AppError::Protocol(format!("metadata Name: {e}")))?;
                    versioned_name = Some(n);
                }
                TLV_METADATA_FINAL_BLOCK_ID => {
                    final_block_id = Some(value);
                }
                TLV_METADATA_SEGMENT_SIZE => {
                    segment_size = Some(decode_nni(&value)?);
                }
                TLV_METADATA_SIZE => {
                    size = Some(decode_nni(&value)?);
                }
                _ => {}
            }
        }
        let versioned_name =
            versioned_name.ok_or_else(|| AppError::Protocol("metadata missing Name".into()))?;
        let final_block_id = final_block_id
            .ok_or_else(|| AppError::Protocol("metadata missing FinalBlockID".into()))?;
        Ok(Self {
            versioned_name,
            final_block_id,
            segment_size,
            size,
        })
    }

    /// Recognises `SegmentNameComponent` (0x32 + NNI) and generic
    /// `NameComponent` (0x08 + ASCII-decimal); `None` on malformed
    /// FinalBlockID.
    pub fn last_segment(&self) -> Option<u64> {
        let fbi = self.final_block_id.as_ref();
        if fbi.len() < 2 {
            return None;
        }
        let typ = fbi[0] as u64;
        let len = fbi[1] as usize;
        let value = fbi.get(2..2 + len)?;
        match typ {
            0x32 => Some(decode_nni_be(value)),
            0x08 => std::str::from_utf8(value).ok()?.parse::<u64>().ok(),
            _ => None,
        }
    }
}

/// `<name>/32=metadata`.
pub fn metadata_name(prefix: &Name) -> Name {
    prefix
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD)))
}

/// Encode a NonNegativeInteger per the NDN packet spec: the width is **1, 2, 4,
/// or 8 bytes** chosen by magnitude — *not* minimal-trimmed. A minimal encoding
/// can emit 3/5/6/7 bytes, which a conforming decoder (incl. [`decode_nni`] and
/// other NDN stacks) rejects as an invalid NNI length. This matches
/// `ndn-foundation-types`' name-component integer encoding byte-for-byte, so a
/// FinalBlockID segment number equals the corresponding segment name component.
pub(crate) fn encode_nni_be(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    match v {
        0..=0xFF => b[7..].to_vec(),
        0x100..=0xFFFF => b[6..].to_vec(),
        0x1_0000..=0xFFFF_FFFF => b[4..].to_vec(),
        _ => b.to_vec(),
    }
}

fn decode_nni_be(buf: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in buf {
        v = (v << 8) | (b as u64);
    }
    v
}

fn decode_nni(buf: &Bytes) -> Result<u64, AppError> {
    let len = buf.len();
    if !(len == 1 || len == 2 || len == 4 || len == 8) {
        return Err(AppError::Protocol(format!("invalid NNI length: {len}")));
    }
    let mut v = 0u64;
    for &b in buf.as_ref() {
        v = (v << 8) | (b as u64);
    }
    Ok(v)
}

/// Pre-segmented object so the [`Producer`](crate::Producer) serve
/// loop answers metadata and segment Interests without re-slicing.
#[doc(hidden)]
pub struct PreparedObject {
    pub object_name: Name,
    pub versioned_name: Name,
    pub metadata_data_name: Name,
    pub metadata_content: Bytes,
    pub last_seg: u64,
    pub segments: Vec<Bytes>,
}

impl PreparedObject {
    /// Version is the current Unix millis.
    pub fn build(object_name: Name, content: Bytes, chunk_size: usize) -> Self {
        // web_time::SystemTime delegates to std natively; on wasm32 it reads
        // Date.now() instead of panicking like std::time::SystemTime::now().
        let version = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        let versioned_name = object_name.clone().append_version(version);

        let segments: Vec<Bytes> = if content.is_empty() {
            vec![Bytes::new()]
        } else {
            let mut acc = Vec::with_capacity(content.len().div_ceil(chunk_size));
            let mut cursor = 0;
            while cursor < content.len() {
                let end = (cursor + chunk_size).min(content.len());
                acc.push(content.slice(cursor..end));
                cursor = end;
            }
            acc
        };
        let last_seg = (segments.len() as u64).saturating_sub(1);

        let mut fbi = BytesMut::with_capacity(2 + 8);
        let nni = encode_nni_be(last_seg);
        fbi.extend_from_slice(&[0x32u8, nni.len() as u8]);
        fbi.extend_from_slice(&nni);
        let meta = MetaData {
            versioned_name: versioned_name.clone(),
            final_block_id: fbi.freeze(),
            segment_size: Some(chunk_size as u64),
            size: Some(content.len() as u64),
        };
        let metadata_content = meta.encode();

        let metadata_data_name = object_name
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD)))
            .append_version(version)
            .append_segment(0);

        Self {
            object_name,
            versioned_name,
            metadata_data_name,
            metadata_content,
            last_seg,
            segments,
        }
    }

    /// Answer one RDR Interest against this prepared object: the
    /// `<name>/32=metadata` discovery Data, or a `<name>/v=<ver>/seg=<n>`
    /// segment, signed with `signer` (or `DigestSha256` if `None`). Returns
    /// `Ok(None)` when `interest_name` matches neither — the caller drops it.
    ///
    /// This is the per-Interest core shared by the [`Producer::publish_object`]
    /// serve loop and any demultiplexed serve (e.g. a node serving objects and
    /// fetching on one connection), so neither re-implements the matching.
    ///
    /// [`Producer::publish_object`]: crate::Producer::publish_object
    pub fn answer_interest(
        &self,
        interest_name: &Name,
        signer: Option<&dyn Signer>,
    ) -> Result<Option<Bytes>, AppError> {
        let finish = |builder: DataBuilder| -> Result<Bytes, AppError> {
            match signer {
                Some(s) => builder
                    .sign_with_sync(s)
                    .map_err(|e| AppError::Protocol(e.to_string())),
                None => Ok(builder.build()),
            }
        };

        // Metadata discovery: an Interest under the object name carrying the
        // `metadata` keyword component (CanBePrefix + MustBeFresh from the consumer).
        let metadata_keyword = NameComponent::keyword(Bytes::from_static(METADATA_KEYWORD));
        if interest_name.has_prefix(&self.object_name)
            && interest_name
                .components()
                .iter()
                .skip(self.object_name.len())
                .any(|c| c.typ == ndn_packet::tlv_type::KEYWORD && c.value == metadata_keyword.value)
        {
            let builder = DataBuilder::new(self.metadata_data_name.clone(), &self.metadata_content)
                .freshness(Duration::from_millis(1000))
                .final_block_id_typed_seg(0);
            return Ok(Some(finish(builder)?));
        }

        // Segment: `<name>/v=<ver>/seg=<n>`.
        if interest_name.has_prefix(&self.versioned_name)
            && let Some(last) = interest_name.components().last()
            && let Some(seg_idx) = last.as_segment()
        {
            let Some(payload) = self.segments.get(seg_idx as usize) else {
                return Ok(None);
            };
            let seg_name = self.versioned_name.clone().append_segment(seg_idx);
            let builder = if seg_idx == self.last_seg {
                DataBuilder::new(seg_name, payload.as_ref()).final_block_id_typed_seg(self.last_seg)
            } else {
                DataBuilder::new(seg_name, payload.as_ref())
            };
            return Ok(Some(finish(builder)?));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_roundtrip() {
        let versioned: Name = "/foo/bar".parse::<Name>().unwrap().append_version(42);
        let fbi_nni = encode_nni_be(3);
        let mut fbi = vec![0x32u8, fbi_nni.len() as u8];
        fbi.extend_from_slice(&fbi_nni);
        let m = MetaData {
            versioned_name: versioned.clone(),
            final_block_id: Bytes::from(fbi),
            segment_size: Some(8192),
            size: Some(24000),
        };
        let wire = m.encode();
        let m2 = MetaData::decode(wire).unwrap();
        assert_eq!(m2.versioned_name, versioned);
        assert_eq!(m2.last_segment(), Some(3));
        assert_eq!(m2.segment_size, Some(8192));
        assert_eq!(m2.size, Some(24000));
    }

    #[test]
    fn nni_encodes_to_legal_widths() {
        // NDN NonNegativeInteger must be 1/2/4/8 bytes — never minimal-trimmed.
        for (v, w) in [
            (0u64, 1usize),
            (0xFF, 1),
            (0x100, 2),
            (0xFFFF, 2),
            (0x1_0000, 4), // the regressing range: minimal would be 3 bytes
            (0x12_3456, 4),
            (0xFFFF_FFFF, 4),
            (0x1_0000_0000, 8),
        ] {
            assert_eq!(encode_nni_be(v).len(), w, "NNI width for {v:#x}");
        }
        // Byte-identical to the name-component integer encoding, so a
        // FinalBlockID segment number equals the segment name component.
        let seg = Name::root().append_segment(0x12_3456);
        assert_eq!(
            encode_nni_be(0x12_3456),
            seg.components().last().unwrap().value.as_ref()
        );
    }

    #[test]
    fn metadata_size_in_three_byte_range_round_trips() {
        // Regression: a ~1.2 MB file's `size` minimal-encodes to 3 bytes, which
        // the strict decoder rejected ("invalid NNI length: 3"). Must decode.
        let fbi_nni = encode_nni_be(0);
        let mut fbi = vec![0x32u8, fbi_nni.len() as u8];
        fbi.extend_from_slice(&fbi_nni);
        let m = MetaData {
            versioned_name: "/f".parse::<Name>().unwrap().append_version(1),
            final_block_id: Bytes::from(fbi),
            segment_size: Some(8192),
            size: Some(0x12_3456), // 1,193,046 bytes
        };
        let m2 = MetaData::decode(m.encode()).expect("3-byte-range size must decode");
        assert_eq!(m2.size, Some(0x12_3456));
    }

    #[test]
    fn prepared_object_segments_correctly() {
        let payload = Bytes::from(vec![0u8; 25_000]);
        let prep = PreparedObject::build("/obj".parse().unwrap(), payload, 8192);
        assert_eq!(prep.segments.len(), 4);
        assert_eq!(prep.last_seg, 3);
        assert!(
            prep.versioned_name
                .components()
                .last()
                .unwrap()
                .as_version()
                .is_some()
        );
    }

    #[test]
    fn metadata_name_appends_keyword() {
        let n: Name = "/a/b".parse().unwrap();
        let m = metadata_name(&n);
        let last = m.components().last().unwrap();
        assert_eq!(last.typ, ndn_packet::tlv_type::KEYWORD);
        assert_eq!(last.value.as_ref(), b"metadata");
    }
}
