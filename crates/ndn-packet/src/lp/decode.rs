#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::format;
#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::vec::Vec;

use bytes::Bytes;
use ndn_tlv::TlvReader;

use super::{CachePolicyType, decode_be_u64};
use crate::nack::NackReason;
use crate::tlv_type;

#[derive(Debug)]
pub struct LpPacket {
    pub fragment: Option<Bytes>,
    pub nack: Option<NackReason>,
    pub congestion_mark: Option<u64>,
    pub sequence: Option<u64>,
    pub frag_index: Option<u64>,
    pub frag_count: Option<u64>,
    pub acks: Vec<u64>,
    pub pit_token: Option<Bytes>,
    pub incoming_face_id: Option<u64>,
    pub next_hop_face_id: Option<u64>,
    pub cache_policy: Option<CachePolicyType>,
    /// Reliability TxSequence (0x0348) — distinct from fragmentation Sequence (0x51).
    pub tx_sequence: Option<u64>,
    pub non_discovery: bool,
    pub prefix_announcement: Option<Bytes>,
    /// A-LAL presence: the forwarding node's encoded Name wire (network-layer
    /// neighbor identity for CCLF density). See [`super::al_lal`].
    pub al_presence: Option<Bytes>,
    /// A-LAL previous-hop location (12-byte [`super::GeoFix`]) for Location Score.
    pub al_prev_hop_loc: Option<Bytes>,
    /// A-LAL destination/data location (12-byte [`super::GeoFix`]) for Location Score.
    pub al_data_loc: Option<Bytes>,
}

impl LpPacket {
    pub fn decode(raw: Bytes) -> Result<Self, crate::PacketError> {
        let mut reader = TlvReader::new(raw);
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::LP_PACKET {
            return Err(crate::PacketError::UnknownPacketType(typ));
        }

        let mut inner = TlvReader::new(value);
        let mut fragment = None;
        let mut nack = None;
        let mut congestion_mark = None;
        let mut sequence = None;
        let mut frag_index = None;
        let mut frag_count = None;
        let mut acks = Vec::new();
        let mut pit_token = None;
        let mut incoming_face_id = None;
        let mut next_hop_face_id = None;
        let mut cache_policy = None;
        let mut tx_sequence = None;
        let mut non_discovery = false;
        let mut prefix_announcement = None;
        let mut al_presence = None;
        let mut al_prev_hop_loc = None;
        let mut al_data_loc = None;

        // Enforce NDNLPv2 §"Element Order": LP headers ascend by TLV-TYPE,
        // only `Ack` (0x0344) is repeatable, and `Fragment` (0x50) is last.
        let mut last_typ: Option<u64> = None;
        let mut fragment_seen = false;

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv()?;

            // NDNLPv2 wraps the network packet in `LpFragment` (0x50); bare
            // Interest/Data inside an LpPacket body is rejected below.
            let is_terminator = matches!(t, tlv_type::LP_FRAGMENT);

            if fragment_seen {
                return Err(crate::PacketError::MalformedPacket(
                    "LP header appears after Fragment (NDNLPv2 §Element Order)".into(),
                ));
            }

            if !is_terminator {
                if let Some(prev) = last_typ {
                    let repeatable_repeat = t == prev && t == tlv_type::LP_ACK;
                    if t < prev || (t == prev && !repeatable_repeat) {
                        return Err(crate::PacketError::MalformedPacket(
                            "LP headers out of TLV-TYPE order or non-repeatable header duplicated"
                                .into(),
                        ));
                    }
                }
                last_typ = Some(t);
            } else {
                fragment_seen = true;
            }

            match t {
                tlv_type::LP_FRAGMENT => {
                    fragment = Some(v);
                }
                tlv_type::NACK => {
                    nack = Some(decode_nack_header(v)?);
                }
                tlv_type::LP_CONGESTION_MARK => {
                    congestion_mark = Some(decode_be_u64(&v));
                }
                tlv_type::LP_SEQUENCE => {
                    sequence = Some(decode_be_u64(&v));
                }
                tlv_type::LP_FRAG_INDEX => {
                    frag_index = Some(decode_be_u64(&v));
                }
                tlv_type::LP_FRAG_COUNT => {
                    frag_count = Some(decode_be_u64(&v));
                }
                tlv_type::LP_ACK => {
                    acks.push(decode_be_u64(&v));
                }
                tlv_type::LP_PIT_TOKEN => {
                    // NDNLPv2 specifies "one or more bytes" with no upper bound.
                    if v.is_empty() {
                        return Err(crate::PacketError::MalformedPacket(
                            "PitToken must be at least 1 byte (NDNLPv2)".into(),
                        ));
                    }
                    pit_token = Some(v);
                }
                tlv_type::LP_INCOMING_FACE_ID => {
                    incoming_face_id = Some(decode_be_u64(&v));
                }
                tlv_type::LP_NEXT_HOP_FACE_ID => {
                    next_hop_face_id = Some(decode_be_u64(&v));
                }
                tlv_type::LP_CACHE_POLICY => {
                    let mut cp_reader = TlvReader::new(v);
                    while !cp_reader.is_empty() {
                        let (ct, cv) = cp_reader.read_tlv()?;
                        if ct == tlv_type::LP_CACHE_POLICY_TYPE {
                            let code = decode_be_u64(&cv);
                            cache_policy = Some(if code == 1 {
                                CachePolicyType::NoCache
                            } else {
                                CachePolicyType::Other(code)
                            });
                        }
                    }
                }
                tlv_type::LP_TX_SEQUENCE => {
                    tx_sequence = Some(decode_be_u64(&v));
                }
                tlv_type::LP_NON_DISCOVERY => {
                    non_discovery = true;
                }
                tlv_type::LP_PREFIX_ANNOUNCEMENT => {
                    prefix_announcement = Some(v);
                }
                super::al_lal::TLV_AL_PRESENCE => {
                    al_presence = Some(v);
                }
                super::al_lal::TLV_AL_PREV_HOP_LOC => {
                    al_prev_hop_loc = Some(v);
                }
                super::al_lal::TLV_AL_DATA_LOC => {
                    al_data_loc = Some(v);
                }
                tlv_type::INTEREST | tlv_type::DATA => {
                    // NDNLPv2 requires the network-layer packet to be wrapped
                    // in `LpFragment` (0x50). Bare Interest/Data is not spec.
                    let _ = v;
                    return Err(crate::PacketError::MalformedPacket(format!(
                        "bare top-level TLV-TYPE 0x{t:x} inside LpPacket body \
                         is not spec-defined; NDNLPv2 requires LpFragment (0x50)"
                    )));
                }
                _ => {
                    if crate::is_critical_tlv_type(t) {
                        return Err(crate::PacketError::MalformedPacket(format!(
                            "unknown critical LP TLV-TYPE 0x{t:x}"
                        )));
                    }
                }
            }
        }

        if fragment.is_none() && acks.is_empty() {
            return Err(crate::PacketError::MalformedPacket(
                "LpPacket has neither fragment nor acks".into(),
            ));
        }

        Ok(Self {
            fragment,
            nack,
            congestion_mark,
            sequence,
            frag_index,
            frag_count,
            acks,
            pit_token,
            incoming_face_id,
            next_hop_face_id,
            cache_policy,
            tx_sequence,
            non_discovery,
            prefix_announcement,
            al_presence,
            al_prev_hop_loc,
            al_data_loc,
        })
    }
}

impl LpPacket {
    pub fn is_fragmented(&self) -> bool {
        self.frag_count.is_some_and(|c| c > 1)
    }

    pub fn is_ack_only(&self) -> bool {
        self.fragment.is_none() && !self.acks.is_empty()
    }
}

fn decode_nack_header(value: Bytes) -> Result<NackReason, crate::PacketError> {
    if value.is_empty() {
        return Ok(NackReason::Other(0));
    }
    let mut reader = TlvReader::new(value);
    while !reader.is_empty() {
        let (t, v) = reader.read_tlv()?;
        if t == tlv_type::NACK_REASON {
            let mut code = 0u64;
            for &b in v.iter() {
                code = (code << 8) | b as u64;
            }
            return Ok(NackReason::from_code(code));
        }
    }
    Ok(NackReason::Other(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_interest;
    use crate::lp::{
        LpHeaders, encode_lp_acks, encode_lp_nack, encode_lp_packet, encode_lp_reliable,
        encode_lp_with_headers, is_lp_packet, nni,
    };
    use crate::{Interest, Name, NameComponent};
    use bytes::Bytes;
    use ndn_tlv::TlvWriter;

    fn name(comps: &[&[u8]]) -> Name {
        Name::from_components(
            comps
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    fn build_lp_wire(headers: &[(u64, &[u8])], fragment: Option<&[u8]>) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            for (typ, val) in headers {
                w.write_tlv(*typ, val);
            }
            if let Some(frag) = fragment {
                w.write_tlv(tlv_type::LP_FRAGMENT, frag);
            }
        });
        w.finish()
    }

    fn fixture_interest_wire() -> Bytes {
        encode_interest(&name(&[b"audit", b"n03"]), None)
    }

    /// Unknown critical LP TLV-TYPE must abort decoding (NFD rejects via
    /// `Detail::onUnknownFieldType`).
    #[test]
    fn b02_lp_decode_rejects_unknown_critical_lp_field() {
        let interest = fixture_interest_wire();
        let wire = build_lp_wire(&[(0x99, b"x")], Some(&interest));
        let err = LpPacket::decode(wire).expect_err("unknown critical LP TLV must be rejected");
        match err {
            crate::PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Unknown non-critical LP TLV must decode (forward compatibility).
    #[test]
    fn b02_lp_decode_accepts_unknown_non_critical_lp_field() {
        let interest = fixture_interest_wire();
        let wire = build_lp_wire(&[(0x98, b"x")], Some(&interest));
        let lp = LpPacket::decode(wire).expect("unknown non-critical LP TLV must decode");
        assert!(lp.fragment.is_some());
    }

    /// Duplicate non-repeatable header (`IncomingFaceId`) must be rejected.
    #[test]
    fn n03_lp_decode_rejects_duplicate_incoming_face_id() {
        let interest = fixture_interest_wire();
        let id1 = nni(7);
        let id2 = nni(11);
        let wire = build_lp_wire(
            &[
                (tlv_type::LP_INCOMING_FACE_ID, &id1.0[..id1.1]),
                (tlv_type::LP_INCOMING_FACE_ID, &id2.0[..id2.1]),
            ],
            Some(&interest),
        );
        let err = LpPacket::decode(wire).expect_err("duplicate IncomingFaceId must be rejected");
        match err {
            crate::PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Non-repeatable headers must appear in ascending TLV-TYPE order.
    /// `IncomingFaceId` (812) before `Nack` (800) violates the rule.
    #[test]
    fn n03_lp_decode_rejects_out_of_order_headers() {
        let interest = fixture_interest_wire();
        let id = nni(3);
        let mut nack_inner = TlvWriter::new();
        let r = nni(NackReason::NoRoute.code());
        nack_inner.write_tlv(tlv_type::NACK_REASON, &r.0[..r.1]);
        let nack_value = nack_inner.finish();

        let wire = build_lp_wire(
            &[
                (tlv_type::LP_INCOMING_FACE_ID, &id.0[..id.1]),
                (tlv_type::NACK, &nack_value),
            ],
            Some(&interest),
        );
        let err = LpPacket::decode(wire).expect_err("out-of-order LP headers must be rejected");
        match err {
            crate::PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// `Ack` (TLV-TYPE 0x0344) is the only repeatable LP header.
    #[test]
    fn n03_lp_decode_accepts_repeated_acks() {
        let a1 = nni(100);
        let a2 = nni(101);
        let a3 = nni(102);
        let wire = build_lp_wire(
            &[
                (tlv_type::LP_ACK, &a1.0[..a1.1]),
                (tlv_type::LP_ACK, &a2.0[..a2.1]),
                (tlv_type::LP_ACK, &a3.0[..a3.1]),
            ],
            None,
        );
        let lp = LpPacket::decode(wire).expect("repeated Ack headers must decode");
        assert_eq!(lp.acks, vec![100, 101, 102]);
    }

    /// Fragment is the last element; a header after it is malformed.
    #[test]
    fn n03_lp_decode_rejects_header_after_fragment() {
        let interest = fixture_interest_wire();
        let id = nni(7);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest);
            w.write_tlv(tlv_type::LP_INCOMING_FACE_ID, &id.0[..id.1]);
        });
        let wire = w.finish();
        let err = LpPacket::decode(wire).expect_err("header after Fragment must be rejected");
        match err {
            crate::PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    #[test]
    fn encode_decode_lp_nack_roundtrip() {
        let n = name(&[b"test", b"nack"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_nack(NackReason::NoRoute, &interest_wire);

        assert!(is_lp_packet(&lp_wire));

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert_eq!(lp.nack, Some(NackReason::NoRoute));
        assert!(lp.congestion_mark.is_none());

        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn encode_decode_congestion_nack() {
        let n = name(&[b"hello"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_nack(NackReason::Congestion, &interest_wire);

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert_eq!(lp.nack, Some(NackReason::Congestion));
    }

    #[test]
    fn decode_lp_packet_without_nack() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp_wire = w.finish();

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert!(lp.nack.is_none());
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn decode_lp_packet_with_congestion_mark() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_CONGESTION_MARK, &1u64.to_be_bytes());
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp_wire = w.finish();

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert_eq!(lp.congestion_mark, Some(1));
    }

    #[test]
    fn decode_wrong_type_errors() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[]);
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn decode_missing_fragment_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_nested(crate::tlv_type::NACK, |w| {
                w.write_tlv(crate::tlv_type::NACK_REASON, &[150]);
            });
        });
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn decode_fragmentation_fields() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_SEQUENCE, &42u64.to_be_bytes());
            w.write_tlv(crate::tlv_type::LP_FRAG_INDEX, &[0]);
            w.write_tlv(crate::tlv_type::LP_FRAG_COUNT, &[3]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert_eq!(lp.sequence, Some(42));
        assert_eq!(lp.frag_index, Some(0));
        assert_eq!(lp.frag_count, Some(3));
        assert!(lp.is_fragmented());
    }

    #[test]
    fn unfragmented_packet_not_fragmented() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert!(!lp.is_fragmented());
        assert!(lp.sequence.is_none());
        assert!(lp.frag_index.is_none());
        assert!(lp.frag_count.is_none());
    }

    #[test]
    fn encode_decode_lp_reliable_roundtrip() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let wire = encode_lp_reliable(&interest_wire, 42, None, &[10, 20]);
        let lp = LpPacket::decode(wire).unwrap();
        assert_eq!(lp.tx_sequence, Some(42));
        assert!(lp.sequence.is_none());
        assert!(lp.frag_index.is_none());
        assert!(lp.frag_count.is_none());
        assert_eq!(lp.acks, vec![10, 20]);
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn encode_decode_lp_reliable_with_frag_info() {
        // tx_sequence = 100 (per-LP), shared net-packet sequence = 7,
        // frag_index = 1, frag_count = 3.
        let wire = encode_lp_reliable(&[0x05, 0x00], 100, Some((7, 1, 3)), &[]);
        let lp = LpPacket::decode(wire).unwrap();
        assert_eq!(lp.tx_sequence, Some(100));
        assert_eq!(lp.sequence, Some(7));
        assert_eq!(lp.frag_index, Some(1));
        assert_eq!(lp.frag_count, Some(3));
        assert!(lp.acks.is_empty());
    }

    /// Fragmented + reliably-tracked LP packet carries both `Sequence`
    /// (0x51) shared by fragments and `TxSequence` (0x0348) per transmission.
    #[test]
    fn b01_b09_fragmented_reliable_carries_both_sequences() {
        let wire = encode_lp_reliable(&[0x05, 0x00], 100, Some((7, 1, 3)), &[]);
        // Sequence = `0x51 0x08 <8-byte big-endian>`. TxSequence = `FD 03 48 <len> <bytes>`.
        assert!(
            wire.windows(10)
                .any(|w| w == [0x51, 0x08, 0, 0, 0, 0, 0, 0, 0, 0x07]),
            "Sequence (0x51) must be 8-byte big-endian; header missing or wrong: {wire:02x?}"
        );
        assert!(
            wire.windows(5).any(|w| w == [0xFD, 0x03, 0x48, 0x01, 0x64]),
            "TxSequence (0x0348) header missing or wrong value: {wire:02x?}"
        );
    }

    #[test]
    fn encode_decode_lp_acks_roundtrip() {
        let wire = encode_lp_acks(&[5, 6, 7]);
        let lp = LpPacket::decode(wire).unwrap();
        assert!(lp.fragment.is_none());
        assert_eq!(lp.acks, vec![5, 6, 7]);
        assert!(lp.is_ack_only());
    }

    #[test]
    fn decode_bare_ack_no_fragment_ok() {
        let wire = encode_lp_acks(&[99]);
        assert!(LpPacket::decode(wire).is_ok());
    }

    #[test]
    fn decode_empty_lp_packet_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |_| {});
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn decode_pit_token_valid() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_PIT_TOKEN, &[0xAB, 0xCD, 0xEF, 0x01]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert_eq!(lp.pit_token.as_deref(), Some(&[0xAB, 0xCD, 0xEF, 0x01][..]));
    }

    /// PitToken length per NDNLPv2 is "one or more bytes" with no upper bound.
    #[test]
    fn decode_pit_token_long_is_accepted_post_b04() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_PIT_TOKEN, &[0u8; 33]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).expect("33-byte PitToken must decode");
        assert_eq!(lp.pit_token.as_ref().map(|t| t.len()), Some(33));
    }

    #[test]
    fn decode_pit_token_empty_rejected() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_PIT_TOKEN, &[]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn decode_cache_policy_no_cache() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_nested(crate::tlv_type::LP_CACHE_POLICY, |w| {
                w.write_tlv(crate::tlv_type::LP_CACHE_POLICY_TYPE, &[1]);
            });
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert_eq!(lp.cache_policy, Some(CachePolicyType::NoCache));
    }

    #[test]
    fn decode_incoming_and_next_hop_face_id() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            let (buf, len) = nni(42);
            w.write_tlv(crate::tlv_type::LP_INCOMING_FACE_ID, &buf[..len]);
            let (buf, len) = nni(99);
            w.write_tlv(crate::tlv_type::LP_NEXT_HOP_FACE_ID, &buf[..len]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert_eq!(lp.incoming_face_id, Some(42));
        assert_eq!(lp.next_hop_face_id, Some(99));
    }

    #[test]
    fn decode_non_discovery_flag() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_NON_DISCOVERY, &[]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert!(lp.non_discovery);
    }

    #[test]
    fn decode_tx_sequence() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            let (buf, len) = nni(12345);
            w.write_tlv(crate::tlv_type::LP_TX_SEQUENCE, &buf[..len]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert_eq!(lp.tx_sequence, Some(12345));
    }

    #[test]
    fn decode_without_new_fields_still_works() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_packet(&interest_wire);

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert!(lp.pit_token.is_none());
        assert!(lp.incoming_face_id.is_none());
        assert!(lp.next_hop_face_id.is_none());
        assert!(lp.cache_policy.is_none());
        assert!(lp.tx_sequence.is_none());
        assert!(!lp.non_discovery);
        assert!(lp.prefix_announcement.is_none());
        assert!(lp.al_presence.is_none());
        assert!(lp.al_prev_hop_loc.is_none());
        assert!(lp.al_data_loc.is_none());
    }

    #[test]
    fn encode_lp_with_headers_roundtrip() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let headers = LpHeaders {
            pit_token: Some(Bytes::from_static(&[0x01, 0x02, 0x03])),
            congestion_mark: Some(5),
            incoming_face_id: Some(42),
            next_hop_face_id: None,
            cache_policy: Some(CachePolicyType::NoCache),
        };
        let wire = encode_lp_with_headers(&interest_wire, &headers);
        let lp = LpPacket::decode(wire).unwrap();

        assert_eq!(lp.pit_token.as_deref(), Some(&[0x01, 0x02, 0x03][..]));
        assert_eq!(lp.congestion_mark, Some(5));
        assert_eq!(lp.incoming_face_id, Some(42));
        assert_eq!(lp.cache_policy, Some(CachePolicyType::NoCache));
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    /// Bare top-level `Interest` (0x05) inside an LpPacket body is non-spec.
    #[test]
    fn b03_lp_decode_rejects_bare_interest_in_body() {
        use ndn_tlv::TlvWriter;
        let inner = encode_interest(&name(&[b"test"]), None);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_raw(&inner);
        });
        let wire = w.finish();
        let err = LpPacket::decode(wire).expect_err("bare Interest must reject");
        match err {
            crate::PacketError::MalformedPacket(ref m) => {
                assert!(m.contains("LpFragment"), "wrong error: {m}");
            }
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Same for bare `Data` (0x06).
    #[test]
    fn b03_lp_decode_rejects_bare_data_in_body() {
        use ndn_tlv::TlvWriter;
        let mut d = TlvWriter::new();
        d.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::CONTENT, b"x");
            w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
            });
            w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
        });
        let inner = d.finish();
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_raw(&inner);
        });
        let wire = w.finish();
        let err = LpPacket::decode(wire).expect_err("bare Data must reject");
        assert!(matches!(err, crate::PacketError::MalformedPacket(_)));
    }

    /// PitToken length is "one or more bytes" with no upper bound.
    #[test]
    fn b04_lp_decode_accepts_long_pit_token() {
        use ndn_tlv::TlvWriter;
        let inner = encode_interest(&name(&[b"test"]), None);
        let big_token: Vec<u8> = (0u8..=99).collect();
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_PIT_TOKEN, &big_token);
            w.write_tlv(tlv_type::LP_FRAGMENT, &inner);
        });
        let lp = LpPacket::decode(w.finish()).expect("100-byte PitToken must decode");
        assert_eq!(lp.pit_token.as_deref(), Some(&big_token[..]));
    }

    /// Empty PitToken (length 0) is still rejected.
    #[test]
    fn b04_lp_decode_still_rejects_empty_pit_token() {
        use ndn_tlv::TlvWriter;
        let inner = encode_interest(&name(&[b"test"]), None);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_PIT_TOKEN, &[]);
            w.write_tlv(tlv_type::LP_FRAGMENT, &inner);
        });
        let err = LpPacket::decode(w.finish()).expect_err("empty PitToken must reject");
        assert!(matches!(err, crate::PacketError::MalformedPacket(_)));
    }

    #[test]
    fn encode_lp_with_headers_empty_headers() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let headers = LpHeaders {
            pit_token: None,
            congestion_mark: None,
            incoming_face_id: None,
            next_hop_face_id: None,
            cache_policy: None,
        };
        let wire = encode_lp_with_headers(&interest_wire, &headers);
        let lp = LpPacket::decode(wire).unwrap();

        assert!(lp.pit_token.is_none());
        assert!(lp.congestion_mark.is_none());
        assert!(lp.incoming_face_id.is_none());
        assert!(lp.cache_policy.is_none());
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }
}
