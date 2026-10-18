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
    /// The Interest of each classical (one-shot) downstream the Data
    /// consumed, kept by `PitMatchStage` only when
    /// [`record_downstream`](Self::record_downstream) is set (empty
    /// otherwise), so a refusal Nack can echo each local downstream's own
    /// Interest. Persistent subscriptions are not listed: their in-records
    /// outlive the Data, and a Nack would end them.
    pub out_interests: SmallVec<[DownstreamInterest; 1]>,
    /// Set by the dispatcher before PIT match on a Data it will validate:
    /// PIT match then fills [`out_interests`](Self::out_interests). Data that
    /// is never validated pays nothing for it.
    pub record_downstream: bool,
    /// Link-layer sender id (from `InboundMeta`), used to key NDNLPv2
    /// reassembly per-sender on a multi-access face. `0` = unicast / no source.
    pub endpoint_id: u64,
    pub cs_hit: bool,
    /// Signature was CHECKED and passed. Never set when a validator is
    /// configured and the check fails.
    pub verified: bool,
    /// No validator is configured, so this Data was never SUBJECT to
    /// validation. Distinct from `verified == false`, which also covers "a
    /// validator ran and rejected it". Conflating the two made
    /// `CsInsertStage` refuse every network packet whenever
    /// `[security] profile = "disabled"`, silently disabling the Content
    /// Store: measured 0.17% hit rate and 37 retained entries against NFD's
    /// 7.33% and 12033 on the same workload.
    pub validation_not_configured: bool,
    /// The validator keyring's [revocation epoch] read just before
    /// `ValidationStage` judged this Data valid; `None` if no validator ran.
    /// `CsInsertStage` stamps the cached entry with it, and `CsLookupStage`
    /// re-checks the entry against the revocations once the epoch has moved.
    ///
    /// [revocation epoch]: ndn_security::Keyring::revocation_epoch
    pub revocation_epoch: Option<u64>,
    /// Set by `PitMatchStage` when an incoming Data matched no PIT entry. Such
    /// Data is never forwarded (`out_faces` stays empty); whether it is cached
    /// is decided by the engine's `UnsolicitedDataPolicy`.
    pub unsolicited: bool,
    pub arrival: u64,
    pub tags: AnyMap,
}

/// A downstream's Interest as a refusal Nack must carry it: consumers
/// (ndn-cxx's `Face`, `ndn-app`) match a Nack to their pending Interest by
/// name and selectors.
#[derive(Clone, Debug)]
pub struct DownstreamInterest {
    pub face: FaceId,
    /// The NDNLPv2 PitToken the downstream sent, to echo.
    pub lp_pit_token: Option<Bytes>,
    /// The PIT entry's name: the Interest's, which for a `CanBePrefix`
    /// downstream is a prefix of the Data's.
    pub name: Arc<Name>,
    pub selector: ndn_packet::Selector,
    pub nonce: u32,
    /// The Interest's parameters portion, when it is parameterized
    /// (`ndn_store::InRecord::parameters`).
    pub parameters: Option<Bytes>,
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
            out_interests: SmallVec::new(),
            record_downstream: false,
            endpoint_id: 0,
            cs_hit: false,
            verified: false,
            validation_not_configured: false,
            revocation_epoch: None,
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
