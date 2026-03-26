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
            Ok((v as u64, 3))
        }
        254 => {
            if buf.len() < 5 {
                return Err(TlvError::UnexpectedEof);
            }
            let v = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
            Ok((v as u64, 5))
        }
        255 => {
            if buf.len() < 9 {
                return Err(TlvError::UnexpectedEof);
            }
            let v = u64::from_be_bytes([
                buf[1], buf[2], buf[3], buf[4],
                buf[5], buf[6], buf[7], buf[8],
            ]);
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
    if value < 253 { 1 }
    else if value < 0x1_0000 { 3 }
    else if value < 0x1_0000_0000 { 5 }
    else { 9 }
}
