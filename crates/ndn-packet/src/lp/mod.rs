//! NDNLPv2 Link Protocol Packet framing.
//!
//! An `LpPacket` (TLV 0x64) wraps a network-layer packet (Interest or Data)
//! with optional link-layer header fields:
//!
//! - **Nack** (0x0320): carries a NackReason; the fragment is the nacked Interest
//! - **CongestionMark** (0x0340): hop-by-hop congestion signal
//! - **Sequence / FragIndex / FragCount**: fragmentation (decode only)
//!
//! Bare Interest/Data packets (not wrapped in LpPacket) are still valid on the
//! wire — LpPacket framing is only required when link-layer fields are present.

mod decode;
mod encode;
mod fragment;

pub use decode::LpPacket;
pub use encode::{
    encode_lp_acks, encode_lp_nack, encode_lp_packet, encode_lp_reliable, encode_lp_with_headers,
};
pub use fragment::{FragmentHeader, extract_acks, extract_fragment};

/// Cache policy type for NDNLPv2 CachePolicy header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicyType {
    NoCache,
    Other(u64),
}

/// Optional LP header fields for encoding.
pub struct LpHeaders {
    pub pit_token: Option<bytes::Bytes>,
    pub congestion_mark: Option<u64>,
    pub incoming_face_id: Option<u64>,
    pub cache_policy: Option<CachePolicyType>,
}

/// Check if raw bytes start with an LpPacket TLV type (0x64).
pub fn is_lp_packet(raw: &[u8]) -> bool {
    raw.first() == Some(&0x64)
}

/// Encode a u64 as a NonNegativeInteger (minimal big-endian, 1/2/4/8 bytes).
/// Returns the buffer and the number of bytes written.
pub(super) fn nni(val: u64) -> ([u8; 8], usize) {
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

/// Decode a big-endian unsigned integer from variable-length bytes.
pub(super) fn decode_be_u64(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | b as u64;
    }
    val
}
