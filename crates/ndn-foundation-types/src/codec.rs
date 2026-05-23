//! `TlvEncode` / `TlvDecode` — high-level encode/decode pair over `ndn-tlv`'s
//! `TlvReader` / `TlvWriter`.

use bytes::Bytes;
use ndn_tlv::{TlvError, TlvReader, TlvWriter};

#[derive(Debug, PartialEq, Eq)]
pub enum TlvCodecError {
    Tlv(TlvError),
    UnexpectedType { expected: u64, found: u64 },
    MissingField(u64),
    MalformedField(u64),
    UnrecognizedVariant(u8),
    TrailingBytes,
}

impl core::fmt::Display for TlvCodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlvCodecError::Tlv(e) => write!(f, "tlv error: {e:?}"),
            TlvCodecError::UnexpectedType { expected, found } => {
                write!(f, "expected TLV type {expected:#x}, found {found:#x}")
            }
            TlvCodecError::MissingField(t) => write!(f, "missing required field type {t:#x}"),
            TlvCodecError::MalformedField(t) => write!(f, "malformed field type {t:#x}"),
            TlvCodecError::UnrecognizedVariant(d) => {
                write!(f, "unrecognized variant discriminant: {d}")
            }
            TlvCodecError::TrailingBytes => write!(f, "trailing bytes after final field"),
        }
    }
}

impl From<TlvError> for TlvCodecError {
    fn from(e: TlvError) -> Self {
        TlvCodecError::Tlv(e)
    }
}

impl core::error::Error for TlvCodecError {}

/// Encode a value as a TLV record. Implementors write only the inner value
/// bytes; the outer T-L envelope is added by [`Self::encode_to_bytes`].
pub trait TlvEncode {
    const TYPE: u64;

    fn write_value(&self, w: &mut TlvWriter);

    fn encode_to_bytes(&self) -> Bytes {
        let mut outer = TlvWriter::new();
        outer.write_nested(Self::TYPE, |inner| self.write_value(inner));
        outer.finish()
    }
}

/// Decode a value from a TLV record.
pub trait TlvDecode: Sized {
    const TYPE: u64;

    fn decode_from(r: &mut TlvReader) -> Result<Self, TlvCodecError> {
        let typ = r.read_type()?;
        if typ != Self::TYPE {
            return Err(TlvCodecError::UnexpectedType {
                expected: Self::TYPE,
                found: typ,
            });
        }
        let len = r.read_length()?;
        let mut inner = r.scoped(len)?;
        let v = Self::decode_value(&mut inner)?;
        if !inner.is_empty() {
            return Err(TlvCodecError::TrailingBytes);
        }
        Ok(v)
    }

    fn decode_value(r: &mut TlvReader) -> Result<Self, TlvCodecError>;

    fn decode_from_bytes(bytes: Bytes) -> Result<Self, TlvCodecError> {
        let mut r = TlvReader::new(bytes);
        let v = Self::decode_from(&mut r)?;
        if !r.is_empty() {
            return Err(TlvCodecError::TrailingBytes);
        }
        Ok(v)
    }
}

/// Encode a u64 as minimum-width big-endian bytes (`0` → single zero byte).
pub fn nonneg_int_bytes_vec(value: u64) -> Bytes {
    if value == 0 {
        return Bytes::copy_from_slice(&[0u8]);
    }
    let b = value.to_be_bytes();
    let lead = b.iter().position(|&x| x != 0).unwrap_or(7);
    Bytes::copy_from_slice(&b[lead..])
}

pub fn read_nonneg_int(bytes: &[u8]) -> Result<u64, TlvCodecError> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(TlvCodecError::MalformedField(0));
    }
    let mut acc = 0u64;
    for &b in bytes {
        acc = (acc << 8) | b as u64;
    }
    Ok(acc)
}
