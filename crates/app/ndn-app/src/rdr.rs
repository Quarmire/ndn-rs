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

/// Sign `builder` with `signer` asynchronously, or emit a bare `DigestSha256`
/// when there is no signer. The async path lets a remote/enclave/delegated
/// signer serve objects without the `sign_sync` panic.
async fn sign_or_digest(
    builder: DataBuilder,
    signer: Option<&dyn Signer>,
) -> Result<Bytes, AppError> {
    match signer {
        Some(s) => s_sign(builder, s).await,
        None => Ok(builder.build()),
    }
}

async fn s_sign(builder: DataBuilder, signer: &dyn Signer) -> Result<Bytes, AppError> {
    builder
        .sign_with(signer)
        .await
        .map_err(|e| AppError::Protocol(e.to_string()))
}

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
    /// Where segment payloads come from: a fully-in-memory slice list, or — for
    /// large files — the file on disk read positionally per segment, so the
    /// whole object is never resident in RAM.
    source: SegmentSource,
    /// Signed segment Data, cached by segment index so a retransmitted Interest
    /// is served from here instead of re-signing. Critical when the signer is a
    /// remote/delegated one (each sign is a seam round-trip): without this, a big
    /// file's retransmits re-sign every segment, pacing the whole transfer at the
    /// signing rate. The signer is fixed for a `PreparedObject`'s serve lifetime,
    /// so a cached Data stays valid.
    seg_cache: std::sync::Mutex<std::collections::HashMap<u64, Bytes>>,
    /// Signed metadata Data, cached likewise (the consumer may re-discover it).
    meta_cache: std::sync::Mutex<Option<Bytes>>,
}

/// Per-segment payload source for a [`PreparedObject`].
enum SegmentSource {
    /// All segments held in memory (small objects: cert, manifest, modest files).
    Memory(Vec<Bytes>),
    /// Read each segment from a file at its offset on demand (large files). Uses
    /// positioned reads (`read_at`), so concurrent segment Interests need no
    /// lock and the file is never fully loaded. Unix-only (Android target is).
    #[cfg(all(not(target_arch = "wasm32"), unix))]
    File(FileSource),
    /// No payload — only the segment *count* is known. Serves correct RDR
    /// metadata (version, FinalBlockID, size) while every segment read returns
    /// `None`. For a producer-of-record whose segment content is supplied out of
    /// band (e.g. an engine relay streaming + signing segments from a source),
    /// so it owns naming/metadata without ever holding the bytes.
    Phantom { count: u64 },
}

#[cfg(all(not(target_arch = "wasm32"), unix))]
struct FileSource {
    file: std::fs::File,
    size: u64,
    chunk: u64,
    count: u64,
}

impl SegmentSource {
    fn count(&self) -> u64 {
        match self {
            SegmentSource::Memory(v) => v.len() as u64,
            #[cfg(all(not(target_arch = "wasm32"), unix))]
            SegmentSource::File(f) => f.count,
            SegmentSource::Phantom { count } => *count,
        }
    }

    fn read(&self, idx: u64) -> Option<Bytes> {
        match self {
            SegmentSource::Memory(v) => v.get(idx as usize).cloned(),
            SegmentSource::Phantom { .. } => None,
            #[cfg(all(not(target_arch = "wasm32"), unix))]
            SegmentSource::File(f) => {
                use std::os::unix::fs::FileExt;
                if idx >= f.count {
                    return None;
                }
                let offset = idx * f.chunk;
                let len = f.chunk.min(f.size - offset) as usize;
                let mut buf = vec![0u8; len];
                f.file.read_exact_at(&mut buf, offset).ok()?;
                Some(Bytes::from(buf))
            }
        }
    }
}

impl PreparedObject {
    /// Version is the current Unix millis.
    pub fn build(object_name: Name, content: Bytes, chunk_size: usize) -> Self {
        let size = content.len() as u64;
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
        Self::assemble(object_name, SegmentSource::Memory(segments), size, chunk_size)
    }

    /// File-backed prepared object: segments are read from `file` on demand, so
    /// an arbitrarily large file is served without ever loading it into memory.
    /// `size` is the file's length in bytes. Unix-only (positioned reads).
    #[cfg(all(not(target_arch = "wasm32"), unix))]
    pub fn build_from_file(
        object_name: Name,
        file: std::fs::File,
        size: u64,
        chunk_size: usize,
    ) -> Self {
        let chunk = chunk_size.max(1) as u64;
        let count = if size == 0 { 1 } else { size.div_ceil(chunk) };
        let source = SegmentSource::File(FileSource {
            file,
            size,
            chunk,
            count,
        });
        Self::assemble(object_name, source, size, chunk_size)
    }

    /// Metadata-only prepared object: knows the segment count (from `size` /
    /// `chunk_size`) so it serves correct RDR metadata, but holds no segment
    /// content — every segment read returns `None`. For a producer-of-record
    /// (e.g. an engine relay) that names + signs the object and serves its
    /// metadata, while the segment bytes are supplied out of band (streamed from
    /// a content source and signed on the fly). `versioned_name` is the segment
    /// prefix the out-of-band producer must name its segments under.
    pub fn build_metadata(object_name: Name, size: u64, chunk_size: usize) -> Self {
        let chunk = if chunk_size == 0 {
            8192
        } else {
            chunk_size
        };
        let count = if size == 0 {
            1
        } else {
            size.div_ceil(chunk as u64)
        };
        Self::assemble(object_name, SegmentSource::Phantom { count }, size, chunk)
    }

    /// Shared assembly: derive the versioned name, FinalBlockID, and metadata
    /// from the segment `source` (its count) and the total `size`.
    fn assemble(
        object_name: Name,
        source: SegmentSource,
        size: u64,
        chunk_size: usize,
    ) -> Self {
        // web_time::SystemTime delegates to std natively; on wasm32 it reads
        // Date.now() instead of panicking like std::time::SystemTime::now().
        let version = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        let versioned_name = object_name.clone().append_version(version);
        let last_seg = source.count().saturating_sub(1);

        let mut fbi = BytesMut::with_capacity(2 + 8);
        let nni = encode_nni_be(last_seg);
        fbi.extend_from_slice(&[0x32u8, nni.len() as u8]);
        fbi.extend_from_slice(&nni);
        let meta = MetaData {
            versioned_name: versioned_name.clone(),
            final_block_id: fbi.freeze(),
            segment_size: Some(chunk_size as u64),
            size: Some(size),
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
            source,
            seg_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            meta_cache: std::sync::Mutex::new(None),
        }
    }

    /// Number of segments this object serves.
    pub fn segment_count(&self) -> u64 {
        self.source.count()
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
    pub async fn answer_interest(
        &self,
        interest_name: &Name,
        signer: Option<&dyn Signer>,
    ) -> Result<Option<Bytes>, AppError> {
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
            if let Some(cached) = self.meta_cache.lock().unwrap().clone() {
                return Ok(Some(cached));
            }
            let builder = DataBuilder::new(self.metadata_data_name.clone(), &self.metadata_content)
                .freshness(Duration::from_millis(1000))
                .final_block_id_typed_seg(0);
            let wire = sign_or_digest(builder, signer).await?;
            *self.meta_cache.lock().unwrap() = Some(wire.clone());
            return Ok(Some(wire));
        }

        // Segment: `<name>/v=<ver>/seg=<n>`.
        if interest_name.has_prefix(&self.versioned_name)
            && let Some(last) = interest_name.components().last()
            && let Some(seg_idx) = last.as_segment()
        {
            // Serve a previously-signed segment straight from cache — a
            // retransmit must not re-sign (a seam round-trip for a remote signer).
            if let Some(cached) = self.seg_cache.lock().unwrap().get(&seg_idx).cloned() {
                return Ok(Some(cached));
            }
            let Some(payload) = self.source.read(seg_idx) else {
                return Ok(None);
            };
            let seg_name = self.versioned_name.clone().append_segment(seg_idx);
            let builder = if seg_idx == self.last_seg {
                DataBuilder::new(seg_name, payload.as_ref()).final_block_id_typed_seg(self.last_seg)
            } else {
                DataBuilder::new(seg_name, payload.as_ref())
            };
            let wire = sign_or_digest(builder, signer).await?;
            self.seg_cache.lock().unwrap().insert(seg_idx, wire.clone());
            return Ok(Some(wire));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn file_backed_serves_correct_segment_bytes() {
        use std::io::Write;
        // 25 000 bytes → 4 segments at 8 KiB (last is short), distinct bytes so
        // any offset error shows up.
        let content: Vec<u8> = (0..25_000u32).map(|i| (i % 251) as u8).collect();
        let path = std::env::temp_dir().join("ndn_rdr_filebacked_test.bin");
        std::fs::File::create(&path).unwrap().write_all(&content).unwrap();
        let file = std::fs::File::open(&path).unwrap();

        let object: Name = "/obj".parse().unwrap();
        let prep = PreparedObject::build_from_file(object, file, content.len() as u64, 8192);
        assert_eq!(prep.segment_count(), 4);
        assert_eq!(prep.last_seg, 3);

        // Every segment served from disk equals the file's slice at that offset.
        for i in 0..=prep.last_seg {
            let seg_name = prep.versioned_name.clone().append_segment(i);
            let wire = prep.answer_interest(&seg_name, None).await.unwrap().expect("segment served");
            let data = ndn_packet::Data::decode(wire).unwrap();
            let start = (i * 8192) as usize;
            let end = (start + 8192).min(content.len());
            assert_eq!(data.content().unwrap(), &content[start..end], "segment {i} bytes");
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn prepared_object_segments_correctly() {
        let payload = Bytes::from(vec![0u8; 25_000]);
        let prep = PreparedObject::build("/obj".parse().unwrap(), payload, 8192);
        assert_eq!(prep.segment_count(), 4);
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
