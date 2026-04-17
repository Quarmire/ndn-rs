//! # ndn-tlv -- TLV encoding foundation for NDN
//!
//! Implements the NDN Type-Length-Value wire format used by all other crates
//! in the ndn-rs workspace. Parsing is zero-copy over `bytes::Bytes` buffers.
//!
//! ## Key types
//!
//! - [`TlvReader`] -- zero-copy, streaming TLV parser over byte slices.
//! - [`TlvWriter`] -- growable encoder that produces wire-format `BytesMut`.
//! - [`read_varu64`] / [`write_varu64`] -- NDN variable-width integer codec.
//! - [`TlvError`] -- error type for malformed or truncated input.
//!
//! ## Feature flags
//!
//! - **`std`** (default) -- enables `std` support in `bytes`.
//!   Disable for `no_std` environments (an allocator is still required).

#![allow(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod error;
pub mod reader;
pub mod writer;

pub use error::TlvError;
pub use reader::TlvReader;
pub use writer::TlvWriter;

/// Read a variable-width unsigned integer (NDN varint encoding).
///
/// - 1 byte  if value < 253
/// - 3 bytes if value < 65536   (marker 0xFD + 2 bytes big-endian)
/// - 5 bytes if value < 2^32    (marker 0xFE + 4 bytes big-endian)
/// - 9 bytes otherwise          (marker 0xFF + 8 bytes big-endian)
pub fn read_varu64(buf: &[u8]) -> Result<(u64, usize), TlvError> {
    let first = *buf.first().ok_or(TlvError::UnexpectedEof)?;
    match first {
        0..=252 => Ok((first as u64, 1)),
        253 => {
            if buf.len() < 3 {
                return Err(TlvError::UnexpectedEof);
            }
            let v = u16::from_be_bytes([buf[1], buf[2]]);
            if v < 253 {
                return Err(TlvError::NonMinimalVarNumber);
            }
            Ok((v as u64, 3))
        }
        254 => {
            if buf.len() < 5 {
                return Err(TlvError::UnexpectedEof);
            }
            let v = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
            if v < 0x1_0000 {
                return Err(TlvError::NonMinimalVarNumber);
            }
            Ok((v as u64, 5))
        }
        255 => {
            if buf.len() < 9 {
                return Err(TlvError::UnexpectedEof);
            }
            let v = u64::from_be_bytes([
                buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
            ]);
            if v < 0x1_0000_0000 {
                return Err(TlvError::NonMinimalVarNumber);
            }
            Ok((v, 9))
        }
    }
}

/// Write a variable-width unsigned integer into `buf`.
/// Returns the number of bytes written.
pub fn write_varu64(buf: &mut [u8], value: u64) -> usize {
    if value < 253 {
        buf[0] = value as u8;
        1
    } else if value < 0x1_0000 {
        buf[0] = 0xFD;
        buf[1..3].copy_from_slice(&(value as u16).to_be_bytes());
        3
    } else if value < 0x1_0000_0000 {
        buf[0] = 0xFE;
        buf[1..5].copy_from_slice(&(value as u32).to_be_bytes());
        5
    } else {
        buf[0] = 0xFF;
        buf[1..9].copy_from_slice(&value.to_be_bytes());
        9
    }
}

/// Returns the number of bytes needed to encode `value` as a varint.
pub fn varu64_size(value: u64) -> usize {
    if value < 253 {
        1
    } else if value < 0x1_0000 {
        3
    } else if value < 0x1_0000_0000 {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varu64_size_boundaries() {
        assert_eq!(varu64_size(0), 1);
        assert_eq!(varu64_size(252), 1);
        assert_eq!(varu64_size(253), 3);
        assert_eq!(varu64_size(0xFFFF), 3);
        assert_eq!(varu64_size(0x1_0000), 5);
        assert_eq!(varu64_size(0xFFFF_FFFF), 5);
        assert_eq!(varu64_size(0x1_0000_0000), 9);
        assert_eq!(varu64_size(u64::MAX), 9);
    }

    fn roundtrip(value: u64) {
        let mut buf = [0u8; 9];
        let written = write_varu64(&mut buf, value);
        assert_eq!(written, varu64_size(value));
        let (decoded, read) = read_varu64(&buf[..written]).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(read, written);
    }

    #[test]
    fn varu64_roundtrip_1byte() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(252);
    }

    #[test]
    fn varu64_roundtrip_3byte() {
        roundtrip(253);
        roundtrip(254);
        roundtrip(0xFFFF);
    }

    #[test]
    fn varu64_roundtrip_5byte() {
        roundtrip(0x1_0000);
        roundtrip(0xFFFF_FFFF);
    }

    #[test]
    fn varu64_roundtrip_9byte() {
        roundtrip(0x1_0000_0000);
        roundtrip(u64::MAX);
    }

    #[test]
    fn read_varu64_eof_empty() {
        assert_eq!(read_varu64(&[]), Err(TlvError::UnexpectedEof));
    }

    #[test]
    fn read_varu64_eof_truncated_3byte() {
        assert_eq!(read_varu64(&[0xFD, 0x01]), Err(TlvError::UnexpectedEof));
    }

    #[test]
    fn read_varu64_eof_truncated_5byte() {
        assert_eq!(
            read_varu64(&[0xFE, 0x00, 0x01, 0x00]),
            Err(TlvError::UnexpectedEof)
        );
    }

    #[test]
    fn read_varu64_eof_truncated_9byte() {
        assert_eq!(
            read_varu64(&[0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
            Err(TlvError::UnexpectedEof)
        );
    }

    #[test]
    fn read_varu64_rejects_non_minimal_3byte() {
        // 0xFD marker but value 100 (< 253) — should use 1-byte form.
        assert_eq!(
            read_varu64(&[0xFD, 0x00, 0x64]),
            Err(TlvError::NonMinimalVarNumber)
        );
    }

    #[test]
    fn read_varu64_rejects_non_minimal_5byte() {
        // 0xFE marker but value 0x00FF (< 0x10000) — should use 3-byte form.
        assert_eq!(
            read_varu64(&[0xFE, 0x00, 0x00, 0x00, 0xFF]),
            Err(TlvError::NonMinimalVarNumber)
        );
    }

    #[test]
    fn read_varu64_rejects_non_minimal_9byte() {
        // 0xFF marker but value 0x0000_FFFF (< 0x1_0000_0000) — should use 5-byte form.
        assert_eq!(
            read_varu64(&[0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF]),
            Err(TlvError::NonMinimalVarNumber)
        );
    }

    #[test]
    fn read_varu64_ignores_trailing_bytes() {
        // Extra bytes after the value are not consumed and not an error.
        let (v, n) = read_varu64(&[0x2A, 0xFF, 0xFF]).unwrap();
        assert_eq!(v, 0x2A);
        assert_eq!(n, 1);
    }
}
