use std::sync::Arc;

use bytes::Bytes;
use smallvec::SmallVec;

use ndn_packet::{Data, Interest, Nack, Name};
use ndn_store::{NameHashes, PitToken};
use ndn_transport::{AnyMap, FaceId};

pub enum DecodedPacket {
    Raw,
    Interest(Box<Interest>),
    Data(Box<Data>),
    Nack(Box<Nack>),
}

/// Per-packet state passed by value through pipeline stages so the compiler
/// enforces short-circuits at every hand-off.
pub struct PacketContext {
    pub raw_bytes: Bytes,
    pub face_id: FaceId,
    /// `None` until `TlvDecodeStage` runs.
    pub name: Option<Arc<Name>>,
    pub packet: DecodedPacket,
    pub name_hashes: Option<NameHashes>,
    /// `None` before `PitCheckStage` runs.
    pub pit_token: Option<PitToken>,
    /// NDNLPv2 hop-by-hop PIT token from the incoming LP header (distinct
    /// from the internal hash-based `pit_token`).
    pub lp_pit_token: Option<Bytes>,
    pub out_faces: SmallVec<[FaceId; 4]>,
    /// Per-egress NDNLPv2 PitToken to echo on the return path. Parallel to
    /// `out_faces`; `None` at index `i` means no LP wrap for that face.
    pub out_pit_tokens: SmallVec<[Option<Bytes>; 4]>,
    /// Link-layer sender id (from `InboundMeta`), used to key NDNLPv2
    /// reassembly per-sender on a multi-access face. `0` = unicast / no source.
    pub endpoint_id: u64,
    pub cs_hit: bool,
    pub verified: bool,
    /// Set by `PitMatchStage` when an incoming Data matched no PIT entry. Such
    /// Data is never forwarded (`out_faces` stays empty); whether it is cached
    /// is decided by the engine's `UnsolicitedDataPolicy`.
    pub unsolicited: bool,
    pub arrival: u64,
    pub tags: AnyMap,
}

impl PacketContext {
    pub fn new(raw_bytes: Bytes, face_id: FaceId, arrival: u64) -> Self {
        Self {
            raw_bytes,
            face_id,
            name: None,
            packet: DecodedPacket::Raw,
            name_hashes: None,
            pit_token: None,
            lp_pit_token: None,
            out_faces: SmallVec::new(),
            out_pit_tokens: SmallVec::new(),
            endpoint_id: 0,
            cs_hit: false,
            verified: false,
            unsolicited: false,
            arrival,
            tags: AnyMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::FaceId;

    #[test]
    fn packet_context_new_defaults() {
        let raw = Bytes::from_static(b"\x05\x01\x00");
        let ctx = PacketContext::new(raw.clone(), FaceId(7), 12345);
        assert_eq!(ctx.raw_bytes, raw);
        assert_eq!(ctx.face_id, FaceId(7));
        assert_eq!(ctx.arrival, 12345);
        assert!(ctx.name.is_none());
        assert!(ctx.pit_token.is_none());
        assert!(ctx.out_faces.is_empty());
        assert!(!ctx.cs_hit);
        assert!(!ctx.verified);
        assert!(matches!(ctx.packet, DecodedPacket::Raw));
    }
}
