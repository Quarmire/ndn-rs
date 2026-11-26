//! NDNLPv2 Link Protocol Packet framing.

pub mod al_lal;
mod decode;
mod encode;
mod fragment;
pub mod trace_context;

pub use al_lal::{GeoFix, TLV_AL_DATA_LOC, TLV_AL_PRESENCE, TLV_AL_PREV_HOP_LOC};
#[cfg(feature = "std")]
pub use al_lal::{extract_lp_header, splice_lp_header};
pub use decode::LpPacket;
pub use encode::{
    encode_lp_acks, encode_lp_nack, encode_lp_nack_with_pit_token, encode_lp_packet,
    encode_lp_reliable, encode_lp_with_headers,
};
pub use fragment::{
    FragmentHeader, PeekedName, extract_acks, extract_fragment, lp_ndn_packet_bytes, peek_lp_name,
};
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
    /// `SideRoute` (0x0370): the fan-out label of a channel session Data.
    pub side_route: Option<SideRoute>,
}

/// The `SideRoute` LP header (TLV 0x0370): the label a session Data carries so
/// every forwarder on its reverse path installs a route for the channel frames
/// that follow (see `ndn-engine`'s `SideTable`). The value is exactly 10
/// octets: `id` (8, big-endian) then `ttl_secs` (2, big-endian); any other
/// length makes the whole LP packet a decode error (fail closed). The type is
/// even, so a forwarder that predates it skips it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideRoute {
    /// The opaque channel id the frames carry in octets 2..10.
    pub id: u64,
    /// Seconds a sink lapses after its last refresh; the receiving forwarder
    /// clamps it to its own maximum.
    pub ttl_secs: u16,
}

impl SideRoute {
    /// Length of the encoded value.
    pub const VALUE_LEN: usize = 10;

    /// The 10-octet value.
    pub fn to_value(self) -> [u8; Self::VALUE_LEN] {
        let mut v = [0u8; Self::VALUE_LEN];
        v[..8].copy_from_slice(&self.id.to_be_bytes());
        v[8..].copy_from_slice(&self.ttl_secs.to_be_bytes());
        v
    }

    /// Parse the value; `None` unless it is exactly 10 octets.
    pub fn from_value(value: &[u8]) -> Option<Self> {
        let value: &[u8; Self::VALUE_LEN] = value.try_into().ok()?;
        Some(Self {
            id: u64::from_be_bytes(value[..8].try_into().ok()?),
            ttl_secs: u16::from_be_bytes(value[8..].try_into().ok()?),
        })
    }
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
