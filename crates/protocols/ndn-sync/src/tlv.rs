//! Shared TLV / NonNegativeInteger helpers for the SVS dialects.
//!
//! Both the v2 multi-peer codec ([`svs_sync`](crate::svs_sync)) and the
//! v3 self-only codec ([`svs_local`](crate::svs_local)) — and the new
//! data-plane layers built on them — encode NDN NonNegativeIntegers and
//! walk raw TLV cursors. Before this module each carried its own copy of
//! `encode_nni` and a private var-number reader; this is the single home
//! so a third layer never adds a fourth copy.
//!
//! Heavier structured parsing should prefer [`ndn_tlv::TlvReader`] /
//! [`ndn_tlv::TlvWriter`]; these byte-cursor helpers exist for the
//! tolerant, allocation-light walks the v2 path already relied on.

use bytes::{BufMut, BytesMut};

/// Encode `n` as an NDN NonNegativeInteger at the minimal legal width
/// (1, 2, 4, or 8 octets), big-endian. Matches ndn-svs / ndnd.
pub(crate) fn encode_nni(n: u64) -> Vec<u8> {
    if n <= 0xFF {
        vec![n as u8]
    } else if n <= 0xFFFF {
        (n as u16).to_be_bytes().to_vec()
    } else if n <= 0xFFFF_FFFF {
        (n as u32).to_be_bytes().to_vec()
    } else {
        n.to_be_bytes().to_vec()
    }
}

/// Lenient NonNegativeInteger decode: accepts the four legal widths and,
/// for forward-compat, zero-pads any other length rather than erroring.
/// (The v2 SVS path historically tolerated odd widths; the strict
/// 1/2/4/8 decoder lives in `ndn_packet::decode_nni`.)
pub(crate) fn decode_nni(bytes: &[u8]) -> u64 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes(bytes.try_into().unwrap_or_default()) as u64,
        4 => u32::from_be_bytes(bytes.try_into().unwrap_or_default()) as u64,
        8 => u64::from_be_bytes(bytes.try_into().unwrap_or_default()),
        _ => {
            let mut arr = [0u8; 8];
            let start = 8usize.saturating_sub(bytes.len());
            let copy_len = bytes.len().min(8);
            arr[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
            u64::from_be_bytes(arr)
        }
    }
}

/// Append a TLV var-number (TLV-TYPE or TLV-LENGTH) to `buf`.
pub(crate) fn write_varnumber(buf: &mut BytesMut, n: u64) {
    if n < 0xFD {
        buf.put_u8(n as u8);
    } else if n <= 0xFFFF {
        buf.put_u8(0xFD);
        buf.put_u16(n as u16);
    } else if n <= 0xFFFF_FFFF {
        buf.put_u8(0xFE);
        buf.put_u32(n as u32);
    } else {
        buf.put_u8(0xFF);
        buf.put_u64(n);
    }
}

/// Append a complete `TYPE LENGTH VALUE` triple to `buf`.
pub(crate) fn write_tlv(buf: &mut BytesMut, typ: u64, value: &[u8]) {
    write_varnumber(buf, typ);
    write_varnumber(buf, value.len() as u64);
    buf.put_slice(value);
}

/// Read one `(type, value, rest)` triple from the front of `cursor`,
/// or `None` if it is truncated.
pub(crate) fn read_tlv(cursor: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (typ, rest) = read_varnumber(cursor)?;
    let (len, rest) = read_varnumber(rest)?;
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some((typ, &rest[..len], &rest[len..]))
}

/// Read one TLV var-number from the front of `cursor`.
pub(crate) fn read_varnumber(cursor: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = cursor.split_first()?;
    match first {
        0xFF => {
            if rest.len() < 8 {
                return None;
            }
            let v = u64::from_be_bytes(rest[..8].try_into().ok()?);
            Some((v, &rest[8..]))
        }
        0xFE => {
            if rest.len() < 4 {
                return None;
            }
            let v = u32::from_be_bytes(rest[..4].try_into().ok()?) as u64;
            Some((v, &rest[4..]))
        }
        0xFD => {
            if rest.len() < 2 {
                return None;
            }
            let v = u16::from_be_bytes(rest[..2].try_into().ok()?) as u64;
            Some((v, &rest[2..]))
        }
        b => Some((b as u64, rest)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nni_widths() {
        assert_eq!(encode_nni(0), vec![0x00]);
        assert_eq!(encode_nni(0xFF), vec![0xFF]);
        assert_eq!(encode_nni(0x100), vec![0x01, 0x00]);
        assert_eq!(encode_nni(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(encode_nni(0x1_0000), vec![0x00, 0x01, 0x00, 0x00]);
        assert_eq!(encode_nni(0xFFFF_FFFF), vec![0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            encode_nni(0x1_0000_0000),
            vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
    }

    #[test]
    fn nni_roundtrip() {
        for v in [
            0u64,
            1,
            0xFE,
            0xFF,
            0x100,
            0xFFFF,
            0x1_0000,
            u32::MAX as u64,
            u64::MAX,
        ] {
            assert_eq!(decode_nni(&encode_nni(v)), v);
        }
    }

    #[test]
    fn tlv_roundtrip() {
        let mut buf = BytesMut::new();
        write_tlv(&mut buf, 201, &[1, 2, 3]);
        let (typ, val, rest) = read_tlv(&buf).expect("read");
        assert_eq!(typ, 201);
        assert_eq!(val, &[1, 2, 3]);
        assert!(rest.is_empty());
    }

    #[test]
    fn varnumber_three_octet_form() {
        let mut buf = BytesMut::new();
        write_varnumber(&mut buf, 0x1234);
        assert_eq!(&buf[..], &[0xFD, 0x12, 0x34]);
        let (v, rest) = read_varnumber(&buf).expect("read");
        assert_eq!(v, 0x1234);
        assert!(rest.is_empty());
    }
}
