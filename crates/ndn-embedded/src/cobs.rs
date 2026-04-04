//! Consistent Overhead Byte Stuffing (COBS) framing for serial NDN links.
//!
//! COBS eliminates 0x00 bytes from the payload, allowing 0x00 to be used as
//! a reliable frame delimiter on UART/SPI/I²C links. This is the standard
//! framing used by `ndn-face-serial` in the desktop stack.
//!
//! These functions operate on `&[u8]` slices and require no heap allocation.
//! The implementation is algorithm-compatible with the COBS framing in
//! `ndn-face-serial/src/cobs.rs`.

/// Maximum overhead added by COBS encoding: ceil(n / 254) extra bytes.
///
/// Use this to size your output buffer:
/// `let mut out = [0u8; cobs_encoded_max_len(MTU) + 1]` (the +1 for delimiter).
pub const fn cobs_encoded_max_len(input_len: usize) -> usize {
    input_len + (input_len / 254) + 1
}

/// COBS encode `src` into `dst`.
///
/// `dst` must be at least [`cobs_encoded_max_len`]`(src.len())` bytes.
///
/// Returns the number of bytes written to `dst`, or `None` if `dst` is too
/// small.
///
/// The output does **not** include the 0x00 frame delimiter. Append it
/// manually after writing to the serial port.
pub fn encode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let max_out = cobs_encoded_max_len(src.len());
    if dst.len() < max_out {
        return None;
    }

    let mut write_pos = 0usize;
    let mut code_pos = 0usize; // position of the current overhead byte
    let mut code = 1u8; // distance to next 0x00 or end of block

    // Reserve space for the first overhead byte.
    write_pos += 1;

    for &byte in src {
        if byte == 0x00 {
            // Emit the overhead byte for the current block.
            dst[code_pos] = code;
            code_pos = write_pos;
            write_pos += 1;
            code = 1;
        } else {
            dst[write_pos] = byte;
            write_pos += 1;
            code += 1;
            if code == 0xFF {
                // Block is full (254 non-zero bytes); start a new block.
                dst[code_pos] = code;
                code_pos = write_pos;
                write_pos += 1;
                code = 1;
            }
        }
    }

    // Write the final overhead byte.
    dst[code_pos] = code;

    Some(write_pos)
}

/// COBS decode `src` into `dst`.
///
/// `src` must be a complete COBS-encoded frame **without** the 0x00 delimiter.
/// `dst` must be at least `src.len()` bytes (decoded output is always ≤ input).
///
/// Returns the number of bytes written to `dst`, or `None` if the input is
/// malformed (e.g. an unexpected 0x00 byte inside the encoded frame).
pub fn decode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    if src.is_empty() {
        return Some(0);
    }
    if dst.len() < src.len() {
        return None;
    }

    let mut read_pos = 0usize;
    let mut write_pos = 0usize;

    while read_pos < src.len() {
        let code = src[read_pos];
        read_pos += 1;

        if code == 0x00 {
            // 0x00 must not appear inside a COBS frame.
            return None;
        }

        // Copy `code - 1` non-zero bytes.
        let end = read_pos + (code as usize - 1);
        if end > src.len() {
            return None;
        }
        for &b in &src[read_pos..end] {
            if b == 0x00 {
                return None; // malformed
            }
            dst[write_pos] = b;
            write_pos += 1;
        }
        read_pos = end;

        // Emit a 0x00 unless this is the last block (code == 0xFF means no
        // trailing zero was present).
        if code != 0xFF && read_pos < src.len() {
            dst[write_pos] = 0x00;
            write_pos += 1;
        }
    }

    Some(write_pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(input: &[u8]) {
        let mut encoded = [0u8; 512];
        let enc_len = encode(input, &mut encoded).expect("encode");
        let mut decoded = [0u8; 512];
        let dec_len = decode(&encoded[..enc_len], &mut decoded).expect("decode");
        assert_eq!(&decoded[..dec_len], input, "roundtrip mismatch for {:?}", input);
    }

    #[test]
    fn empty() {
        roundtrip(&[]);
    }

    #[test]
    fn no_zeros() {
        roundtrip(b"hello world");
    }

    #[test]
    fn all_zeros() {
        roundtrip(&[0u8; 8]);
    }

    #[test]
    fn mixed() {
        roundtrip(&[0x01, 0x00, 0x02, 0x00, 0x03]);
    }

    #[test]
    fn full_block_254_bytes() {
        let data: [u8; 254] = core::array::from_fn(|i| (i as u8) + 1);
        roundtrip(&data);
    }

    #[test]
    fn encoded_contains_no_zeros() {
        let input = &[0u8; 32];
        let mut out = [0u8; 64];
        let n = encode(input, &mut out).unwrap();
        assert!(!out[..n].contains(&0x00));
    }

    #[test]
    fn invalid_zero_in_frame_rejected() {
        let encoded = [0x03u8, 0x01, 0x00, 0x01]; // 0x00 inside frame
        let mut out = [0u8; 8];
        assert!(decode(&encoded, &mut out).is_none());
    }

    #[test]
    fn buffer_too_small_returns_none() {
        let input = b"hello";
        let mut tiny = [0u8; 2]; // way too small
        assert!(encode(input, &mut tiny).is_none());
    }
}
