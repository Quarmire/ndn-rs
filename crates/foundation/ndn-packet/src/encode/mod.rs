mod data;
mod interest;

pub use data::DataBuilder;
pub use interest::{InterestBuilder, encode_interest, ensure_nonce};

use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use ndn_tlv::TlvWriter;

use crate::{Name, tlv_type};


/// `FreshnessPeriod` is set to 0 so management responses are never served
/// from cache.
#[cfg(feature = "std")]
pub fn encode_data_unsigned(name: &Name, content: &[u8]) -> Bytes {
    DataBuilder::new(name.clone(), content)
        .freshness(std::time::Duration::ZERO)
        .sign_digest_sha256()
}

pub fn encode_nack(reason: crate::NackReason, interest_wire: &[u8]) -> Bytes {
    crate::lp::encode_lp_nack(reason, interest_wire)
}


/// Per NDN Packet Format v0.3 §1.2, a NonNegativeInteger is 1, 2, 4, or 8
/// bytes in network byte order using the shortest valid encoding.
pub(crate) fn nni(val: u64) -> ([u8; 8], usize) {
    let be = val.to_be_bytes();
    if val <= 0xFF {
        ([be[7], 0, 0, 0, 0, 0, 0, 0], 1)
    } else if val <= 0xFFFF {
        ([be[6], be[7], 0, 0, 0, 0, 0, 0], 2)
    } else if val <= 0xFFFF_FFFF {
        ([be[4], be[5], be[6], be[7], 0, 0, 0, 0], 4)
    } else {
        (be, 8)
    }
}

pub(super) fn write_nni(w: &mut TlvWriter, typ: u64, val: u64) {
    let (buf, len) = nni(val);
    w.write_tlv(typ, &buf[..len]);
}

pub(super) fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

/// Per-process-unique 4-byte nonce. Sufficient for loop detection; not
/// cryptographically random.
pub(super) fn next_nonce() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    (std::process::id() << 16).wrapping_add(seq)
}

pub(super) fn rand_nonce_bytes() -> [u8; 8] {
    let mut buf = [0u8; 8];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf)
        .expect("system RNG failed");
    buf
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Data, NameComponent};
    use bytes::Bytes;
    use std::time::Duration;

    pub(super) fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    #[test]
    fn data_roundtrip_name_and_content() {
        let n = name(&[b"localhost", b"ndn-ctl", b"get-stats"]);
        let content = br#"{"status":"ok","pit_size":42}"#;
        let bytes = encode_data_unsigned(&n, content);
        let data = Data::decode(bytes).unwrap();
        assert_eq!(*data.name, n);
        assert_eq!(data.content().map(|b| b.as_ref()), Some(content.as_ref()));
    }

    #[test]
    fn data_freshness_is_zero() {
        let n = name(&[b"test"]);
        let bytes = encode_data_unsigned(&n, b"hello");
        let data = Data::decode(bytes).unwrap();
        let mi = data.meta_info().expect("meta_info present");
        assert_eq!(mi.freshness_period, Some(Duration::from_millis(0)));
    }

    #[test]
    fn nack_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"test", b"nack"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::NoRoute, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(*nack.interest.name, n);
    }

    #[test]
    fn nack_congestion_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"hello"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::Congestion, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::Congestion);
    }


    #[test]
    fn nni_minimal_encoding() {
        assert_eq!(nni(0), ([0, 0, 0, 0, 0, 0, 0, 0], 1));
        assert_eq!(nni(255), ([0xFF, 0, 0, 0, 0, 0, 0, 0], 1));

        assert_eq!(nni(256), ([0x01, 0x00, 0, 0, 0, 0, 0, 0], 2));
        assert_eq!(nni(4000), ([0x0F, 0xA0, 0, 0, 0, 0, 0, 0], 2));
        assert_eq!(nni(65535), ([0xFF, 0xFF, 0, 0, 0, 0, 0, 0], 2));

        assert_eq!(nni(65536), ([0x00, 0x01, 0x00, 0x00, 0, 0, 0, 0], 4));
        assert_eq!(nni(1_000_000), ([0x00, 0x0F, 0x42, 0x40, 0, 0, 0, 0], 4));

        let big: u64 = 0x1_0000_0000;
        let (buf, len) = nni(big);
        assert_eq!(len, 8);
        assert_eq!(buf, big.to_be_bytes());
    }


    pub(super) fn assert_bytes_eq(actual: &[u8], expected: &[u8], msg: &str) {
        if actual != expected {
            panic!(
                "{msg}\n  actual:   {}\n  expected: {}",
                hex(actual),
                hex(expected),
            );
        }
    }

    pub(super) fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn wire_data_unsigned_structure() {
        let wire = encode_data_unsigned(&name(&[b"A"]), b"X");

        assert_eq!(wire[0], 0x06);
        assert_bytes_eq(&wire[2..7], &[0x07, 0x03, 0x08, 0x01, 0x41], "Name /A");
        assert_bytes_eq(&wire[7..12], &[0x14, 0x03, 0x19, 0x01, 0x00], "MetaInfo");
        assert_bytes_eq(&wire[12..15], &[0x15, 0x01, 0x58], "Content");
        assert_bytes_eq(&wire[15..20], &[0x16, 0x03, 0x1B, 0x01, 0x00], "SigInfo");
        assert_eq!(wire[20], 0x17);
        assert_eq!(wire[21], 0x20, "SigValue length should be 32");
        assert!(
            !wire[22..54].iter().all(|&b| b == 0),
            "SigValue should be a real SHA-256, not zeros"
        );

        assert_eq!(wire.len(), 54, "total Data length");
    }

    #[test]
    fn wire_nack_reason_nni() {
        use crate::{Nack, NackReason};
        let n = name(&[b"A"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::NoRoute, &interest_wire);

        let nack = Nack::decode(nack_wire.clone()).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);

        let needle = [0xFD, 0x03, 0x21, 0x01, 0x96];
        assert!(
            nack_wire.windows(5).any(|w| w == needle),
            "NackReason TLV should be FD 03 21 01 96, got: {}",
            hex(&nack_wire),
        );
    }

    #[test]
    fn wire_ndnd_data_decode() {
        let ndnd_wire: &[u8] = &[
            0x06, 0x1D, // Data, length=29
            0x07, 0x06, // Name, length=6
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
            0x14, 0x04, // MetaInfo, length=4
            0x19, 0x02, 0x27, 0x10, //   FreshnessPeriod=10000
            0x15, 0x02, 0x68, 0x69, // Content "hi"
            0x16, 0x03, // SignatureInfo, length=3
            0x1B, 0x01, 0x00, //   SignatureType=0 (DigestSha256)
            0x17, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // SignatureValue (4 bytes)
        ];
        let data = Data::decode(Bytes::from_static(ndnd_wire)).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"hi".as_ref()));
        let mi = data.meta_info().expect("meta_info");
        assert_eq!(mi.freshness_period, Some(Duration::from_secs(10)));
    }

    #[test]
    fn wire_ndnd_data_no_metainfo_decode() {
        let ndnd_wire: &[u8] = &[
            0x06, 0x15, // Data, length=21
            0x07, 0x06, // Name
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
            0x15, 0x02, 0x68, 0x69, // Content "hi"
            0x16, 0x03, // SignatureInfo
            0x1B, 0x01, 0x00, //   DigestSha256
            0x17, 0x04, 0x00, 0x00, 0x00, 0x00, // SignatureValue
        ];
        let data = Data::decode(Bytes::from_static(ndnd_wire)).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert!(data.meta_info().is_none());
    }
}
