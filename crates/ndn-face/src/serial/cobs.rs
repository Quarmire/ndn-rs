//! COBS codec for serial framing: `0x00` never appears in encoded payload,
//! making it the frame delimiter; overhead is at most one byte per 254
//! input bytes.
//!
//! Wire format: `[ COBS-encoded payload ] [ 0x00 ]`.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// Maximum NDN packet size (~8800 bytes) plus COBS overhead.
const DEFAULT_MAX_FRAME_LEN: usize = 8800;

#[derive(Clone)]
pub struct CobsCodec {
    max_frame_len: usize,
}

impl CobsCodec {
    pub fn new() -> Self {
        Self {
            max_frame_len: DEFAULT_MAX_FRAME_LEN,
        }
    }

    pub fn with_max_frame_len(max_frame_len: usize) -> Self {
        Self { max_frame_len }
    }
}

impl Default for CobsCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller must append the trailing `0x00` delimiter.
fn cobs_encode(src: &[u8], dst: &mut BytesMut) {
    let max_overhead = (src.len() / 254) + 2;
    dst.reserve(src.len() + max_overhead);

    let mut code_idx = dst.len();
    dst.put_u8(0);
    let mut code: u8 = 1;

    for &byte in src {
        if byte == 0x00 {
            dst[code_idx] = code;
            code_idx = dst.len();
            dst.put_u8(0);
            code = 1;
        } else {
            dst.put_u8(byte);
            code += 1;
            if code == 0xFF {
                dst[code_idx] = code;
                code_idx = dst.len();
                dst.put_u8(0);
                code = 1;
            }
        }
    }
    dst[code_idx] = code;
}

/// `src` must NOT include the trailing `0x00`.
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
        if code < 0xFF && i < src.len() {
            dst.put_u8(0x00);
        }
    }
    Ok(())
}

impl Decoder for CobsCodec {
    type Item = Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Bytes>, std::io::Error> {
        let delim_pos = buf.iter().position(|&b| b == 0x00);
        let delim_pos = match delim_pos {
            Some(pos) => pos,
            None => {
                if buf.len() > self.max_frame_len * 2 {
                    buf.clear();
                }
                return Ok(None);
            }
        };

        let encoded = buf.split_to(delim_pos);
        buf.advance(1);
        if encoded.is_empty() {
            return Ok(None);
        }

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
            Err(_) => Ok(None),
        }
    }
}

impl Encoder<Bytes> for CobsCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), std::io::Error> {
        cobs_encode(&item, dst);
        dst.put_u8(0x00);
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

        let frame1 = Bytes::from_static(&[0x01, 0x02, 0x03]);
        let frame2 = Bytes::from_static(&[0xAA, 0x00, 0xBB]);
        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();

        let d1 = codec.decode(&mut buf).unwrap().unwrap();
        let d2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(d1, frame1);
        assert_eq!(d2, frame2);
    }

    #[test]
    fn codec_resync_after_garbage() {
        let mut codec = CobsCodec::new();
        let mut buf = BytesMut::new();

        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        buf.put_u8(0x00);
        let frame = Bytes::from_static(&[0x42]);
        codec.encode(frame.clone(), &mut buf).unwrap();

        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(frame));
    }

    #[test]
    fn consecutive_delimiters_skipped() {
        let mut codec = CobsCodec::new();
        let mut buf = BytesMut::new();

        buf.put_u8(0x00);
        buf.put_u8(0x00);
        let frame = Bytes::from_static(&[0x01]);
        codec.encode(frame.clone(), &mut buf).unwrap();

        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
        assert_eq!(codec.decode(&mut buf).unwrap(), Some(frame));
    }
}
