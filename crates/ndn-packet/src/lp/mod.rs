//! NDNLPv2 Link Protocol Packet framing.

mod decode;
mod encode;
mod fragment;
pub mod trace_context;

pub use decode::LpPacket;
pub use encode::{
    encode_lp_acks, encode_lp_nack, encode_lp_nack_with_pit_token, encode_lp_packet,
    encode_lp_reliable, encode_lp_with_headers,
};
pub use fragment::{FragmentHeader, extract_acks, extract_fragment};
pub use trace_context::{SpanId, TLV_TRACE_CONTEXT, TraceContext, TraceFlags, TraceId};
#[cfg(feature = "std")]
pub use trace_context::{extract_from_lp_wire, splice_into_lp_wire};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicyType {
    NoCache,
    Other(u64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LpHeaders {
    pub pit_token: Option<bytes::Bytes>,
    pub congestion_mark: Option<u64>,
    pub incoming_face_id: Option<u64>,
    /// `NextHopFaceId` (TLV 0x0330): when set on an outbound Interest, asks
    /// the next-hop forwarder to bypass FIB lookup and send directly on the
    /// named face. Honored by ndn-rs via `NextHopOverride` in the strategy stage.
    pub next_hop_face_id: Option<u64>,
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
