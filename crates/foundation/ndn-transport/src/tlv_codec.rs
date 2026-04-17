use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use ndn_tlv::read_varu64;

/// `tokio_util::codec` implementation for NDN TLV framing over byte streams.
///
/// NDN uses length-prefix framing: each frame is a complete TLV element
/// `[type | length | value]` where both type and length are `varu64`-encoded.
/// This codec reassembles frames from the byte stream and passes complete
/// TLV buffers up to the face.
///
/// ## Wire format
///
/// ```text
/// ┌──────────┬──────────┬─────────────────┐
/// │ type     │ length   │ value           │
/// │ (varu64) │ (varu64) │ (length bytes)  │
/// └──────────┴──────────┴─────────────────┘
/// ```
///
/// Both `TcpFace` and `SerialFace` (over COBS) use this codec for framing.
#[derive(Clone, Copy)]
pub struct TlvCodec;

impl Decoder for TlvCodec {
    type Item = Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let (_, type_len) = match read_varu64(src) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        if src.len() < type_len + 1 {
            return Ok(None);
        }
        let (value_len, len_len) = match read_varu64(&src[type_len..]) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        let header_len = type_len + len_len;
        let frame_len = header_len + value_len as usize;

        if src.len() < frame_len {
            src.reserve(frame_len - src.len());
            return Ok(None);
        }

        Ok(Some(src.split_to(frame_len).freeze()))
    }
}

impl Encoder<Bytes> for TlvCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.extend_from_slice(&item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use ndn_tlv::TlvWriter;

    fn make_tlv(typ: u8, value: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(typ as u64, value);
        w.finish()
    }

    fn decode_one(src: &mut BytesMut) -> Option<Bytes> {
        TlvCodec.decode(src).unwrap()
    }

    #[test]
    fn decode_complete_tlv() {
        let tlv = make_tlv(0x05, b"hello");
        let mut src = BytesMut::from(tlv.as_ref());
        let frame = decode_one(&mut src).unwrap();
        assert_eq!(frame.as_ref(), tlv.as_ref());
        assert!(src.is_empty());
    }

    #[test]
    fn decode_empty_value_tlv() {
        let tlv = make_tlv(0x21, &[]);
        let mut src = BytesMut::from(tlv.as_ref());
        let frame = decode_one(&mut src).unwrap();
        assert_eq!(frame.as_ref(), &[0x21, 0x00]);
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut src = BytesMut::from(&[0x05u8][..]);
        assert!(decode_one(&mut src).is_none());
    }

    #[test]
    fn decode_partial_value_returns_none() {
        let mut src = BytesMut::new();
        src.put_u8(0x08); // type
        src.put_u8(0x05); // length = 5
        src.put_slice(&[0xAA, 0xBB]); // only 2 value bytes
        assert!(decode_one(&mut src).is_none());
    }

    #[test]
    fn decode_two_sequential_frames() {
        let t1 = make_tlv(0x07, b"foo");
        let t2 = make_tlv(0x08, b"bar");
        let mut src = BytesMut::new();
        src.extend_from_slice(&t1);
        src.extend_from_slice(&t2);

        let f1 = decode_one(&mut src).unwrap();
        let f2 = decode_one(&mut src).unwrap();
        assert_eq!(f1.as_ref(), t1.as_ref());
        assert_eq!(f2.as_ref(), t2.as_ref());
        assert!(src.is_empty());
    }

    #[test]
    fn decode_large_value() {
        let value = vec![0xABu8; 300];
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &value);
        let tlv = w.finish();
        let mut src = BytesMut::from(tlv.as_ref());
        let frame = decode_one(&mut src).unwrap();
        assert_eq!(frame.as_ref(), tlv.as_ref());
    }

    #[test]
    fn encode_appends_bytes_as_is() {
        let pkt = Bytes::from_static(&[0x05, 0x03, b'a', b'b', b'c']);
        let mut dst = BytesMut::new();
        TlvCodec.encode(pkt.clone(), &mut dst).unwrap();
        assert_eq!(dst.as_ref(), pkt.as_ref());
    }

    #[test]
    fn encode_then_decode_roundtrip() {
        let tlv = make_tlv(0x15, b"content");
        let mut dst = BytesMut::new();
        TlvCodec.encode(tlv.clone(), &mut dst).unwrap();
        let frame = decode_one(&mut dst).unwrap();
        assert_eq!(frame.as_ref(), tlv.as_ref());
    }
}
