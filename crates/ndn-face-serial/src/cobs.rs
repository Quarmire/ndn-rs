//! COBS (Consistent Overhead Byte Stuffing) codec for serial framing.
//!
//! COBS encodes a byte stream so that `0x00` never appears in the payload,
//! making `0x00` a reliable frame delimiter.  After line noise or partial
//! reads, the decoder simply discards bytes until the next `0x00` and
//! resyncs — recovery is always at most one frame away.
//!
//! Overhead: at most 1 byte per 254 input bytes (~0.4%).
//!
//! # Wire format
//!
//! ```text
//! [ COBS-encoded payload ] [ 0x00 ]
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum NDN packet size (~8800 bytes) plus COBS overhead.
const DEFAULT_MAX_FRAME_LEN: usize = 8800;

/// COBS frame codec for `tokio_util::codec::Framed`.
#[derive(Clone)]
pub struct CobsCodec {
    max_frame_len: usize,
}

impl CobsCodec {
    pub fn new() -> Self {
        Self { max_frame_len: DEFAULT_MAX_FRAME_LEN }
    }

    pub fn with_max_frame_len(max_frame_len: usize) -> Self {
        Self { max_frame_len }
    }
}

impl Default for CobsCodec {
    fn default() -> Self { Self::new() }
}

// ─── COBS encode ────────────────────────────────────────────────────────────

/// COBS-encode `src` into `dst`.  The caller must append a `0x00` delimiter.
fn cobs_encode(src: &[u8], dst: &mut BytesMut) {
    // Reserve worst case: input_len + ceil(input_len/254) + 1
    let max_overhead = (src.len() / 254) + 2;
    dst.reserve(src.len() + max_overhead);

    let mut code_idx = dst.len();
    dst.put_u8(0); // placeholder for first code byte
    let mut code: u8 = 1;

    for &byte in src {
        if byte == 0x00 {
            // End of run — write the run length at code_idx.
            dst[code_idx] = code;
            code_idx = dst.len();
            dst.put_u8(0); // placeholder for next code byte
            code = 1;
        } else {
            dst.put_u8(byte);
            code += 1;
            if code == 0xFF {
                // Max run length (254 data bytes) — flush and start new run.
                dst[code_idx] = code;
                code_idx = dst.len();
                dst.put_u8(0); // placeholder
                code = 1;
            }
        }
    }
    // Final code byte.
    dst[code_idx] = code;
}

/// COBS-decode `src` into `dst`.  `src` must NOT include the trailing `0x00`.
fn cobs_decode(src: &[u8], dst: &mut BytesMut) -> Result<(), std::io::Error> {
    dst.reserve(src.len());
    let mut i = 0;
    while i < src.len() {
        let code = src[i] as usize;
        i += 1;
        if code == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected zero in COBS data",
            ));
        }
        let run_len = code - 1;
        if i + run_len > src.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "COBS run exceeds input",
            ));
        }
        dst.extend_from_slice(&src[i..i + run_len]);
        i += run_len;
        // If code < 0xFF there's an implicit zero (end of original zero-delimited run),
        // unless we've consumed all input.
        if code < 0xFF && i < src.len() {
            dst.put_u8(0x00);
        }
    }
    Ok(())
}

// ─── Decoder ────────────────────────────────────────────────────────────────

impl Decoder for CobsCodec {
    type Item = Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, std::io::Error> {
        // Scan for frame delimiter (0x00).
        let delim_pos = buf.iter().position(|&b| b == 0x00);
        let delim_pos = match delim_pos {
            Some(pos) => pos,
            None => {
                // No delimiter yet.  If the buffer is unreasonably large,
                // discard it (corrupt stream).
                if buf.len() > self.max_frame_len * 2 {
                    buf.clear();
                }
                return Ok(None);
            }
        };

        // Extract the encoded frame (excluding delimiter).
        let encoded = buf.split_to(delim_pos);
        buf.advance(1); // consume the 0x00 delimiter

        // Empty frame (consecutive delimiters) — skip.
        if encoded.is_empty() {
            return Ok(None);
        }

        // Decode.
        let mut decoded = BytesMut::new();
        match cobs_decode(&encoded, &mut decoded) {
            Ok(()) => {
                if decoded.len() > self.max_frame_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "COBS frame exceeds max length",
                    ));
                }
                Ok(Some(decoded.freeze()))
            }
            Err(_) => {
                // Corrupt frame — discard and wait for next delimiter.
                Ok(None)
            }
        }
    }
}

// ─── Encoder ────────────────────────────────────────────────────────────────

impl Encoder<Bytes> for CobsCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        cobs_encode(&item, dst);
        dst.put_u8(0x00); // frame delimiter
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut encoded = BytesMut::new();
        cobs_encode(data, &mut encoded);
        encoded.put_u8(0x00);

        // Verify no 0x00 in encoded payload (before delimiter).
        assert!(
            !encoded[..encoded.len() - 1].contains(&0x00),
            "encoded payload must not contain 0x00"
        );

        let mut codec = CobsCodec::new();
        let decoded = codec.decode(&mut encoded).unwrap().unwrap();
        decoded.to_vec()
    }

    #[test]
    fn empty_payload() {
        assert_eq!(roundtrip(&[]), Vec::<u8>::new());
    }

    #[test]
    fn single_byte() {
        assert_eq!(roundtrip(&[0x42]), vec![0x42]);
    }

    #[test]
    fn single_zero() {
        assert_eq!(roundtrip(&[0x00]), vec![0x00]);
    }

    #[test]
    fn multiple_zeros() {
        let data = vec![0x00; 10];
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn no_zeros() {
        let data: Vec<u8> = (1..=255).collect();
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn boundary_254_bytes() {
        let data: Vec<u8> = (1..=254).collect();
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn boundary_255_bytes() {
        let mut data: Vec<u8> = (1..=254).collect();
        data.push(0x01);
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn large_payload() {
        let data: Vec<u8> = (0..8000).map(|i| (i % 256) as u8).collect();
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn zeros_and_data_interleaved() {
        let data = vec![0x01, 0x00, 0x02, 0x00, 0x03];
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn codec_multiple_frames() {
        let mut codec = CobsCodec::new();
        let mut buf = BytesMut::new();

        // Encode two frames into the same buffer.
        let frame1 = Bytes::from_static(&[0x01, 0x02, 0x03]);
        let frame2 = Bytes::from_static(&[0xAA, 0x00, 0xBB]);
        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();

        // Decode both.
        let d1 = codec.decode(&mut buf).unwrap().unwrap();
        let d2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d1, frame1);
        assert_eq!(d2, frame2);
    }

    #[test]
    fn codec_resync_after_garbage() {
        let mut codec = CobsCodec::new();
        let mut buf = BytesMut::new();

        // Garbage bytes terminated by a delimiter (as if a partial/corrupt frame
        // was received, followed by its delimiter).
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        buf.put_u8(0x00); // delimiter ends the garbage
        // Then a valid frame.
        let frame = Bytes::from_static(&[0x42]);
        codec.encode(frame.clone(), &mut buf).unwrap();

        // First decode: garbage decoded as COBS → fails → returns None.
        let result1 = codec.decode(&mut buf).unwrap();
        assert_eq!(result1, None);
        // Second decode: valid frame.
        let result2 = codec.decode(&mut buf).unwrap();
        assert_eq!(result2, Some(frame));
    }

    #[test]
    fn consecutive_delimiters_skipped() {
        let mut codec = CobsCodec::new();
        let mut buf = BytesMut::new();

        // Two consecutive delimiters (empty frames).
        buf.put_u8(0x00);
        buf.put_u8(0x00);
        // Then a valid frame.
        let frame = Bytes::from_static(&[0x01]);
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Empty frames return None.
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        // Valid frame.
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(frame));
    }
}
