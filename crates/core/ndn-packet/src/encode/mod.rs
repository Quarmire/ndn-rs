mod data;
mod interest;

pub use data::DataBuilder;
pub use interest::{InterestBuilder, encode_interest, ensure_nonce, random_reflexive_name};

use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use ndn_tlv::TlvWriter;

use crate::{Name, tlv_type};

/// Encode a Data packet with `DigestSha256` signature (32-byte SHA-256 over
/// the signed region) and `FreshnessPeriod = 0` so management responses are
/// never served from cache.
#[cfg(feature = "std")]
pub fn encode_data_digest_sha256(name: &Name, content: &[u8]) -> Bytes {
    DataBuilder::new(name.clone(), content)
        .freshness(std::time::Duration::ZERO)
        .sign_digest_sha256()
}

/// Misnamed alias for [`encode_data_digest_sha256`] (the output is signed
/// Data, not unsigned); kept for call-site stability.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn encode_data_unsigned(name: &Name, content: &[u8]) -> Bytes {
    encode_data_digest_sha256(name, content)
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

/// Per-process-unique 4-byte nonce: a per-process base plus a counter.
/// Sufficient for loop detection; not cryptographically random. The base is
/// `pid << 16` on native targets (deterministic per process, which the
/// simulator relies on); on wasm32, which has no process id, it is drawn from
/// the host's RNG once per instance, so two instances do not run the same
/// sequence (nonces that a stranger could predict would let it forge a
/// duplicate-nonce Nack, and the jitter of Congestion retries derives from
/// the nonce).
pub(crate) fn next_nonce() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    nonce_at(nonce_base(), COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn nonce_at(base: u32, seq: u32) -> u32 {
    base.wrapping_add(seq)
}

#[cfg(not(target_arch = "wasm32"))]
fn nonce_base() -> u32 {
    std::process::id() << 16
}

#[cfg(target_arch = "wasm32")]
fn nonce_base() -> u32 {
    static BASE: std::sync::LazyLock<u32> = std::sync::LazyLock::new(|| {
        let mut bytes = [0u8; 4];
        let entropy = getrandom::getrandom(&mut bytes).ok().map(|()| bytes);
        let clock_ns = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        wasm_nonce_base(entropy, clock_ns)
    });
    *BASE
}

/// Where a wasm instance starts its nonce sequence: from the host's RNG
/// (`entropy`) when it has one, else from its clock (a host with neither
/// still gets instances that differ, though predictably).
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn wasm_nonce_base(entropy: Option<[u8; 4]>, clock_ns: u128) -> u32 {
    match entropy {
        Some(bytes) => u32::from_le_bytes(bytes),
        None => (clock_ns ^ (clock_ns >> 32) ^ (clock_ns >> 64)) as u32,
    }
}

pub(super) fn rand_nonce_bytes() -> [u8; 8] {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).expect("system RNG failed");
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
        assert_eq!(nack.reason, Some(NackReason::NoRoute));
        assert_eq!(*nack.interest.name, n);
    }

    #[test]
    fn nack_congestion_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"hello"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::Congestion, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, Some(NackReason::Congestion));
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
        assert_eq!(nack.reason, Some(NackReason::NoRoute));

        let needle = [0xFD, 0x03, 0x21, 0x01, 0x96];
        assert!(
            nack_wire.windows(5).any(|w| w == needle),
            "NackReason TLV should be FD 03 21 01 96, got: {}",
            hex(&nack_wire),
        );
    }

    #[test]
    fn wire_ndnd_data_decode() {
        let mut ndnd_wire: Vec<u8> = vec![
            0x06,
            0x39, // Data, length = 57 (Name 8 + MetaInfo 6 + Content 4 + SigInfo 5 + SigValue 34)
            0x07, 0x06, // Name
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
            0x14, 0x04, // MetaInfo
            0x19, 0x02, 0x27, 0x10, //   FreshnessPeriod=10000
            0x15, 0x02, 0x68, 0x69, // Content "hi"
            0x16, 0x03, // SignatureInfo
            0x1B, 0x01, 0x00, //   SignatureType=0 (DigestSha256)
            0x17, 0x20, // SignatureValue, length=32
        ];
        ndnd_wire.extend_from_slice(&[0u8; 32]);
        let data = Data::decode(Bytes::copy_from_slice(&ndnd_wire)).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert_eq!(data.content().map(|b| b.as_ref()), Some(b"hi".as_ref()));
        let mi = data.meta_info().expect("meta_info");
        assert_eq!(mi.freshness_period, Some(Duration::from_secs(10)));
    }

    #[test]
    fn wire_ndnd_data_no_metainfo_decode() {
        let mut ndnd_wire: Vec<u8> = vec![
            0x06, 0x33, // Data, length = 51 (Name 8 + Content 4 + SigInfo 5 + SigValue 34)
            0x07, 0x06, // Name
            0x08, 0x04, 0x74, 0x65, 0x73, 0x74, // "test"
            0x15, 0x02, 0x68, 0x69, // Content "hi"
            0x16, 0x03, // SignatureInfo
            0x1B, 0x01, 0x00, //   DigestSha256
            0x17, 0x20, // SignatureValue, length=32
        ];
        ndnd_wire.extend_from_slice(&[0u8; 32]);
        let data = Data::decode(Bytes::copy_from_slice(&ndnd_wire)).unwrap();
        assert_eq!(data.name.to_string(), "/test");
        assert!(data.meta_info().is_none());
    }

    /// Two sequences from different bases never meet (the wasm instances
    /// that used to run the identical sequence from 0).
    #[test]
    fn nonce_sequences_from_different_bases_differ() {
        let (a, b) = (0x1111_0000u32, 0x2222_0000u32);
        for seq in 0..64 {
            assert_ne!(nonce_at(a, seq), nonce_at(b, seq));
        }
        assert_eq!(nonce_at(a, 3), a + 3, "a base plus the counter");
        assert_eq!(nonce_at(u32::MAX, 1), 0, "wraps, never panics");
    }

    /// A wasm instance's base is the host RNG's draw: different draws, different
    /// bases (the base is a pure function of its inputs, so this runs natively).
    #[test]
    fn wasm_base_is_the_hosts_random_draw() {
        let a = wasm_nonce_base(Some([1, 2, 3, 4]), 7);
        let b = wasm_nonce_base(Some([5, 6, 7, 8]), 7);
        assert_eq!(a, u32::from_le_bytes([1, 2, 3, 4]));
        assert_ne!(a, b);
        assert_eq!(
            wasm_nonce_base(Some([1, 2, 3, 4]), 7),
            wasm_nonce_base(Some([1, 2, 3, 4]), 9),
            "with an RNG, the clock does not enter"
        );
    }

    /// A host with no RNG still starts instances apart, by their clocks.
    #[test]
    fn wasm_base_without_an_rng_follows_the_clock() {
        let a = wasm_nonce_base(None, 1_700_000_000_000_000_000);
        let b = wasm_nonce_base(None, 1_700_000_000_123_456_789);
        assert_ne!(a, b);
        assert_ne!(
            wasm_nonce_base(None, 1_700_000_000_000_000_000),
            wasm_nonce_base(None, 1_700_000_000_000_000_001)
        );
    }

    /// Native nonces are unchanged: `pid << 16` plus the counter, so the
    /// simulator and every native process keep the sequence they had.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_base_is_the_process_id_shifted() {
        assert_eq!(nonce_base(), std::process::id() << 16);
    }
}
