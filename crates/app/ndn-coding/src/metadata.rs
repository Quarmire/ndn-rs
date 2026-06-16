//! `FecMetadata` — sub-TLV declaring FEC parameters of a Data segment.
//!
//! Carried at the head of `Content`, not inside `MetaInfo`, because
//! `ndn-packet::MetaInfo::decode` does not currently preserve unknown
//! sub-TLVs across a round-trip. Migrating into `MetaInfo` (restoring
//! systematic-compat for non-FEC consumers) waits on that property.
//!
//! Wire layout (draft, unregistered type codes in the 0xC8 block):
//!
//! ```text
//! FecMetadata = FEC-METADATA-TYPE TLV-LENGTH
//!                 GenerationId       ; u64, big-endian, length 1..8
//!                 Role               ; 1 byte: 0 = source, 1 = parity
//!                 Index              ; u16 big-endian
//!                 K                  ; u16 big-endian
//!                 N                  ; u16 big-endian
//!                 Field              ; 1 byte: 0 = GF(2^8)
//!                 [PaddingLen]       ; optional u32 BE — last source segment only
//! ```

use bytes::{BufMut, Bytes, BytesMut};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::policy::Field;
use crate::{CodingError, Result};

// Draft TLV type codes — even, non-critical, single-byte varu64 in the 0xC8..=0xD6 block.
pub(crate) const TYPE_FEC_METADATA: u64 = 0xC8;
pub(crate) const TYPE_FEC_GENERATION: u64 = 0xCA;
pub(crate) const TYPE_FEC_ROLE: u64 = 0xCC;
pub(crate) const TYPE_FEC_INDEX: u64 = 0xCE;
pub(crate) const TYPE_FEC_K: u64 = 0xD0;
pub(crate) const TYPE_FEC_N: u64 = 0xD2;
pub(crate) const TYPE_FEC_FIELD: u64 = 0xD4;
pub(crate) const TYPE_FEC_PADDING: u64 = 0xD6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentRole {
    Source,
    Parity,
}

impl SegmentRole {
    fn code(self) -> u8 {
        match self {
            SegmentRole::Source => 0,
            SegmentRole::Parity => 1,
        }
    }

    fn from_code(c: u8) -> Result<Self> {
        match c {
            0 => Ok(SegmentRole::Source),
            1 => Ok(SegmentRole::Parity),
            _ => Err(CodingError::MalformedMetadata),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecMetadata {
    pub generation_id: u64,
    pub role: SegmentRole,
    /// `0..k` for source, `k..n` for parity.
    pub index: u16,
    pub k: u16,
    pub n: u16,
    pub field: Field,
    /// Padding bytes in the last source segment of a short stream.
    pub padding_len: Option<u32>,
}

impl FecMetadata {
    pub fn to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_FEC_METADATA, |inner| {
            inner.write_tlv(TYPE_FEC_GENERATION, &encode_u64_be(self.generation_id));
            inner.write_tlv(TYPE_FEC_ROLE, &[self.role.code()]);
            inner.write_tlv(TYPE_FEC_INDEX, &self.index.to_be_bytes());
            inner.write_tlv(TYPE_FEC_K, &self.k.to_be_bytes());
            inner.write_tlv(TYPE_FEC_N, &self.n.to_be_bytes());
            inner.write_tlv(TYPE_FEC_FIELD, &[field_code(self.field)]);
            if let Some(p) = self.padding_len {
                inner.write_tlv(TYPE_FEC_PADDING, &p.to_be_bytes());
            }
        });
        w.finish()
    }

    /// Decode a `FecMetadata` from the head of `bytes`. Returns the metadata
    /// and the byte offset where the metadata TLV ends; the segment payload
    /// is `bytes[end..]`.
    pub fn from_tlv(bytes: &[u8]) -> Result<(Self, usize)> {
        let buf = Bytes::copy_from_slice(bytes);
        let mut r = TlvReader::new(buf);
        let (typ, value) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        if typ != TYPE_FEC_METADATA {
            return Err(CodingError::MalformedMetadata);
        }
        let consumed = r.position();
        let meta = decode_inner(value)?;
        Ok((meta, consumed))
    }
}

fn decode_inner(value: Bytes) -> Result<FecMetadata> {
    let mut r = TlvReader::new(value);
    let mut generation: Option<u64> = None;
    let mut role: Option<SegmentRole> = None;
    let mut index: Option<u16> = None;
    let mut k: Option<u16> = None;
    let mut n: Option<u16> = None;
    let mut field: Option<Field> = None;
    let mut padding: Option<u32> = None;

    while !r.is_empty() {
        let (typ, val) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        match typ {
            TYPE_FEC_GENERATION => generation = Some(decode_u64_be(&val)?),
            TYPE_FEC_ROLE => {
                if val.len() != 1 {
                    return Err(CodingError::MalformedMetadata);
                }
                role = Some(SegmentRole::from_code(val[0])?);
            }
            TYPE_FEC_INDEX => index = Some(decode_u16_be(&val)?),
            TYPE_FEC_K => k = Some(decode_u16_be(&val)?),
            TYPE_FEC_N => n = Some(decode_u16_be(&val)?),
            TYPE_FEC_FIELD => {
                if val.len() != 1 {
                    return Err(CodingError::MalformedMetadata);
                }
                field = Some(field_from_code(val[0])?);
            }
            TYPE_FEC_PADDING => padding = Some(decode_u32_be(&val)?),
            _ => {} // Unknown sub-TLV ignored for forward compatibility.
        }
    }

    Ok(FecMetadata {
        generation_id: generation.ok_or(CodingError::MalformedMetadata)?,
        role: role.ok_or(CodingError::MalformedMetadata)?,
        index: index.ok_or(CodingError::MalformedMetadata)?,
        k: k.ok_or(CodingError::MalformedMetadata)?,
        n: n.ok_or(CodingError::MalformedMetadata)?,
        field: field.ok_or(CodingError::MalformedMetadata)?,
        padding_len: padding,
    })
}

fn field_code(f: Field) -> u8 {
    match f {
        Field::Gf8 => 0,
    }
}

fn field_from_code(c: u8) -> Result<Field> {
    match c {
        0 => Ok(Field::Gf8),
        _ => Err(CodingError::MalformedMetadata),
    }
}

/// Big-endian with leading zeros trimmed; matches NDN's nonneg-int TLV convention.
fn encode_u64_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

fn decode_u64_be(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(CodingError::MalformedMetadata);
    }
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

fn decode_u16_be(bytes: &[u8]) -> Result<u16> {
    if bytes.len() != 2 {
        return Err(CodingError::MalformedMetadata);
    }
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn decode_u32_be(bytes: &[u8]) -> Result<u32> {
    if bytes.len() != 4 {
        return Err(CodingError::MalformedMetadata);
    }
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Prepend `metadata.to_tlv()` to `payload`; the result is `Data.Content`.
pub fn prepend_metadata(meta: &FecMetadata, payload: &[u8]) -> Bytes {
    let header = meta.to_tlv();
    let mut buf = BytesMut::with_capacity(header.len() + payload.len());
    buf.extend_from_slice(&header);
    buf.put_slice(payload);
    buf.freeze()
}

/// Inverse of [`prepend_metadata`].
pub fn split_metadata(content: &[u8]) -> Result<(FecMetadata, Bytes)> {
    let (meta, end) = FecMetadata::from_tlv(content)?;
    Ok((meta, Bytes::copy_from_slice(&content[end..])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(role: SegmentRole, index: u16, padding: Option<u32>) -> FecMetadata {
        FecMetadata {
            generation_id: 0x0102_0304_0506_0708,
            role,
            index,
            k: 16,
            n: 20,
            field: Field::Gf8,
            padding_len: padding,
        }
    }

    #[test]
    fn round_trip_source_no_padding() {
        let meta = sample(SegmentRole::Source, 0, None);
        let wire = meta.to_tlv();
        let (decoded, end) = FecMetadata::from_tlv(&wire).unwrap();
        assert_eq!(end, wire.len());
        assert_eq!(decoded, meta);
    }

    #[test]
    fn round_trip_parity() {
        let meta = sample(SegmentRole::Parity, 17, None);
        let wire = meta.to_tlv();
        let (decoded, _) = FecMetadata::from_tlv(&wire).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn round_trip_with_padding() {
        let meta = sample(SegmentRole::Source, 15, Some(1234));
        let wire = meta.to_tlv();
        let (decoded, _) = FecMetadata::from_tlv(&wire).unwrap();
        assert_eq!(decoded, meta);
        assert_eq!(decoded.padding_len, Some(1234));
    }

    #[test]
    fn round_trip_with_payload() {
        let meta = sample(SegmentRole::Source, 3, None);
        let payload = b"Hello, FEC world.";
        let content = prepend_metadata(&meta, payload);
        let (decoded, rest) = split_metadata(&content).unwrap();
        assert_eq!(decoded, meta);
        assert_eq!(rest.as_ref(), payload);
    }

    #[test]
    fn rejects_wrong_outer_type() {
        let mut w = TlvWriter::new();
        w.write_tlv(0xAA, b"x");
        let bad = w.finish();
        assert!(matches!(
            FecMetadata::from_tlv(&bad),
            Err(CodingError::MalformedMetadata)
        ));
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_FEC_METADATA, |inner| {
            inner.write_tlv(TYPE_FEC_ROLE, &[0]);
            inner.write_tlv(TYPE_FEC_INDEX, &0u16.to_be_bytes());
        });
        let bad = w.finish();
        assert!(matches!(
            FecMetadata::from_tlv(&bad),
            Err(CodingError::MalformedMetadata)
        ));
    }

    #[test]
    fn ignores_unknown_inner_tlv() {
        let meta = sample(SegmentRole::Source, 0, None);
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_FEC_METADATA, |inner| {
            inner.write_tlv(TYPE_FEC_GENERATION, &encode_u64_be(meta.generation_id));
            inner.write_tlv(TYPE_FEC_ROLE, &[meta.role.code()]);
            inner.write_tlv(TYPE_FEC_INDEX, &meta.index.to_be_bytes());
            inner.write_tlv(TYPE_FEC_K, &meta.k.to_be_bytes());
            inner.write_tlv(TYPE_FEC_N, &meta.n.to_be_bytes());
            inner.write_tlv(TYPE_FEC_FIELD, &[field_code(meta.field)]);
            inner.write_tlv(0xF0, b"opaque");
        });
        let wire = w.finish();
        let (decoded, _) = FecMetadata::from_tlv(&wire).unwrap();
        assert_eq!(decoded, meta);
    }
}
