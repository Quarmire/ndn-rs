//! W-1 / W-2 regression: a malformed packet whose TLV-LENGTH is near `u64::MAX`
//! must make `decode` return `Err`, never panic. (Audit finding W-1, S0 — a
//! remote DoS reachable from the first byte of any decode.)
//!
//! Gated on `std` because the decoders need the hashing/codec features.
#![cfg(feature = "std")]

use bytes::Bytes;

/// The exact 10-byte proof-of-concept from the audit report:
/// TLV-TYPE = 0x05 (Interest), TLV-LENGTH = 9-byte form 0xFF + 8×0xFF = u64::MAX.
fn huge_length_packet(type_byte: u8) -> Bytes {
    Bytes::from(vec![
        type_byte, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ])
}

#[test]
fn interest_decode_huge_length_does_not_panic() {
    let pkt = huge_length_packet(0x05); // Interest
    assert!(ndn_packet::Interest::decode(pkt).is_err());
}

#[test]
fn data_decode_huge_length_does_not_panic() {
    let pkt = huge_length_packet(0x06); // Data
    assert!(ndn_packet::Data::decode(pkt).is_err());
}

#[test]
fn lp_decode_huge_length_does_not_panic() {
    let pkt = huge_length_packet(0x64); // LpPacket
    assert!(ndn_packet::lp::LpPacket::decode(pkt).is_err());
}

/// Also exercise a huge length nested *inside* a well-formed outer length, so the
/// overflow is reached after the reader has advanced (the scoped-reader path).
#[test]
fn nested_huge_length_does_not_panic() {
    // Interest, outer length 10, then Name TLV-TYPE 0x07 with a u64::MAX length.
    let pkt = Bytes::from(vec![
        0x05, 0x0A, 0x07, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ]);
    assert!(ndn_packet::Interest::decode(pkt).is_err());
}
