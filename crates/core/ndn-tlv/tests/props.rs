//! Property-based tests for the TLV codec: the wire surface parses hostile
//! network input, so the two properties enforced here are "never panic" and
//! "roundtrip identity" (plus minimal-form VAR-NUMBER encoding).

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter, read_varu64, varu64_size, write_varu64};
use proptest::prelude::*;

proptest! {
    /// write_varu64 → read_varu64 is the identity for every u64, and the
    /// encoded width follows the minimal-form rule (1/3/5/9 bytes at the
    /// 253 / 2^16 / 2^32 boundaries).
    #[test]
    fn varu64_roundtrip_with_minimal_width(value in any::<u64>()) {
        let mut buf = [0u8; 9];
        let written = write_varu64(&mut buf, value);

        let expected_width = if value < 253 {
            1
        } else if value < 0x1_0000 {
            3
        } else if value < 0x1_0000_0000 {
            5
        } else {
            9
        };
        prop_assert_eq!(written, expected_width);
        prop_assert_eq!(varu64_size(value), expected_width);

        let (decoded, consumed) = read_varu64(&buf[..written]).unwrap();
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(consumed, written);
    }

    /// A value that fits in 1 byte, deliberately widened to the 3-byte form,
    /// must be rejected as non-minimal.
    #[test]
    fn varu64_rejects_non_minimal_3byte(value in 0u64..253) {
        let mut buf = vec![0xFDu8];
        buf.extend_from_slice(&(value as u16).to_be_bytes());
        prop_assert!(read_varu64(&buf).is_err());
    }

    /// A value that fits in <= 3 bytes, deliberately widened to the 5-byte
    /// form, must be rejected as non-minimal.
    #[test]
    fn varu64_rejects_non_minimal_5byte(value in 0u64..0x1_0000) {
        let mut buf = vec![0xFEu8];
        buf.extend_from_slice(&(value as u32).to_be_bytes());
        prop_assert!(read_varu64(&buf).is_err());
    }

    /// A value that fits in <= 5 bytes, deliberately widened to the 9-byte
    /// form, must be rejected as non-minimal.
    #[test]
    fn varu64_rejects_non_minimal_9byte(value in 0u64..0x1_0000_0000) {
        let mut buf = vec![0xFFu8];
        buf.extend_from_slice(&value.to_be_bytes());
        prop_assert!(read_varu64(&buf).is_err());
    }

    /// read_varu64 never panics on arbitrary (possibly truncated) input.
    #[test]
    fn read_varu64_never_panics(data in prop::collection::vec(any::<u8>(), 0..16)) {
        let _ = read_varu64(&data);
    }

    /// TlvReader::read_tlv never panics on arbitrary byte vectors (up to
    /// ~64KiB): loop reading until Err or the buffer is exhausted, with a
    /// fuel counter as a belt-and-braces bound.
    #[test]
    fn read_tlv_never_panics(data in prop::collection::vec(any::<u8>(), 0..65536)) {
        let mut reader = TlvReader::new(Bytes::from(data));
        // Every successful read_tlv consumes >= 2 bytes, so 64KiB needs at
        // most ~32k iterations; the fuel bound only exists to guarantee the
        // test terminates even if that invariant were broken.
        let mut fuel = 40_000u32;
        while !reader.is_empty() && fuel > 0 {
            if reader.read_tlv().is_err() {
                break;
            }
            fuel -= 1;
        }
        prop_assert!(fuel > 0, "read_tlv looped without consuming input");
    }

    /// TlvWriter → TlvReader roundtrip: an arbitrary sequence of
    /// (type in the valid u32 range, value bytes) records reads back exactly.
    #[test]
    fn write_read_roundtrip(
        records in prop::collection::vec(
            (any::<u32>(), prop::collection::vec(any::<u8>(), 0..256)),
            0..16,
        )
    ) {
        let mut w = TlvWriter::new();
        for (typ, value) in &records {
            w.write_tlv(u64::from(*typ), value);
        }
        let mut r = TlvReader::new(w.finish());
        for (typ, value) in &records {
            let (t, v) = r.read_tlv().unwrap();
            prop_assert_eq!(t, u64::from(*typ));
            prop_assert_eq!(v.as_ref(), value.as_slice());
        }
        prop_assert!(r.is_empty());
    }
}
