//! NDNLPv2 Link Protocol Packet framing.

mod decode;
mod encode;
mod fragment;

pub use decode::LpPacket;
pub use encode::{
    encode_lp_acks, encode_lp_nack, encode_lp_packet, encode_lp_reliable, encode_lp_with_headers,
};
pub use fragment::{FragmentHeader, extract_acks, extract_fragment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicyType {
    NoCache,
    Other(u64),
}

pub struct LpHeaders {
    pub pit_token: Option<bytes::Bytes>,
    pub congestion_mark: Option<u64>,
    pub incoming_face_id: Option<u64>,
    pub cache_policy: Option<CachePolicyType>,
}

pub fn is_lp_packet(raw: &[u8]) -> bool {
    raw.first() == Some(&0x64)
}

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

pub(super) fn decode_be_u64(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | b as u64;
    }
    val
}
