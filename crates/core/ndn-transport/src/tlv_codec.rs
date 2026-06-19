use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use ndn_tlv::read_varu64;

/// Maximum frame the stream decoder will buffer before declaring the peer
/// malformed. A single NDN packet (including its NDNLP wrapper) is an order of
/// magnitude smaller than this; the cap exists only to stop a peer's length
/// field from driving an unbounded `reserve` (audit D-4 — a ~10-byte header
/// claiming a multi-GiB length would otherwise force a giant allocation → OOM,
/// pre-authentication). NFD bounds the analogous path at `MAX_NDN_PACKET_SIZE`
/// (8800); this is deliberately generous (so it never drops a conformant frame,
/// including a full-MTU LP frame plus header overhead) while still hard-capping
/// memory. A deployment wanting strict NFD parity can tighten it.
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// `tokio_util::codec` for NDN TLV framing over byte streams.
///
/// Each frame is a complete TLV element `[type | length | value]` with
/// both type and length encoded as `varu64`. Used by `TcpFace` and
/// `SerialFace` (over COBS).
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

        // Reject an oversize frame BEFORE reserving (audit D-4). `value_len` is
        // attacker-controlled; without this a huge value drives an unbounded
        // `reserve` and `header_len + value_len as usize` can also overflow.
        // Erroring tears down the connection, matching NFD's behaviour.
        if value_len > MAX_FRAME_SIZE as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TLV frame exceeds maximum size",
            ));
        }

        let header_len = type_len + len_len;
        // `value_len` is now bounded by MAX_FRAME_SIZE, so this cannot overflow;
        // `checked_add` documents the invariant.
        let frame_len = match header_len.checked_add(value_len as usize) {
            Some(f) => f,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TLV frame length overflow",
                ));
            }
        };

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
        src.put_u8(0x08);
        src.put_u8(0x05);
        src.put_slice(&[0xAA, 0xBB]);
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

    // --- D-4 regression: an oversize length must error, never OOM-reserve ----

    #[test]
    fn decode_rejects_oversize_length() {
        // TLV-TYPE=0x06, then a 9-byte length far above MAX_FRAME_SIZE
        // (0xFF + 8 bytes encoding 4 GiB). Must error, not reserve.
        let mut src = BytesMut::new();
        src.put_u8(0x06);
        src.put_u8(0xFF); // 9-byte length form
        src.put_u64(4 * 1024 * 1024 * 1024); // 4 GiB
        let err = TlvCodec.decode(&mut src).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_rejects_u64_max_length() {
        // The audit's weaponizable case: a tiny header claiming ~u64::MAX.
        let mut src = BytesMut::new();
        src.put_u8(0x06);
        src.put_u8(0xFF);
        src.put_u64(u64::MAX);
        let err = TlvCodec.decode(&mut src).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_accepts_frame_at_capacity_boundary() {
        // A frame whose value is just under the cap decodes fine when present.
        let value = vec![0xCDu8; 8800];
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, &value);
        let tlv = w.finish();
        let mut src = BytesMut::from(tlv.as_ref());
        let frame = decode_one(&mut src).unwrap();
        assert_eq!(frame.len(), tlv.len());
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
