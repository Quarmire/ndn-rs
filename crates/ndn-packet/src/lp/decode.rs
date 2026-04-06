#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use bytes::Bytes;
use ndn_tlv::TlvReader;

use super::{CachePolicyType, decode_be_u64};
use crate::nack::NackReason;
use crate::tlv_type;

/// A decoded NDNLPv2 LpPacket.
#[derive(Debug)]
pub struct LpPacket {
    /// The network-layer fragment (Interest or Data wire bytes).
    /// `None` for bare Ack-only packets (no payload).
    pub fragment: Option<Bytes>,
    /// Nack header — present when this LpPacket carries a Nack.
    pub nack: Option<NackReason>,
    /// Hop-by-hop congestion mark (0 = no congestion).
    pub congestion_mark: Option<u64>,
    /// Fragment sequence number (for reassembly ordering).
    pub sequence: Option<u64>,
    /// Zero-based index of this fragment within the original packet.
    pub frag_index: Option<u64>,
    /// Total number of fragments the original packet was split into.
    pub frag_count: Option<u64>,
    /// Piggybacked Ack TxSequences (NDNLPv2 reliability).
    pub acks: Vec<u64>,
    /// PIT token (opaque, 1-32 bytes).
    pub pit_token: Option<Bytes>,
    /// Incoming face ID (local control header).
    pub incoming_face_id: Option<u64>,
    /// Next-hop face ID (local control header).
    pub next_hop_face_id: Option<u64>,
    /// Cache policy.
    pub cache_policy: Option<CachePolicyType>,
    /// Reliability TxSequence (0x0348) — distinct from fragmentation Sequence (0x51).
    pub tx_sequence: Option<u64>,
    /// NonDiscovery flag (presence = true).
    pub non_discovery: bool,
    /// Prefix announcement (raw Data bytes).
    pub prefix_announcement: Option<Bytes>,
}

impl LpPacket {
    /// Decode an LpPacket from raw wire bytes.
    ///
    /// The input must start with TLV type 0x64 (LP_PACKET).
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

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv()?;
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
                    if v.is_empty() || v.len() > 32 {
                        return Err(crate::PacketError::MalformedPacket(
                            "PitToken length must be 1-32".into(),
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
                tlv_type::INTEREST | tlv_type::DATA => {
                    let mut w = ndn_tlv::TlvWriter::new();
                    w.write_tlv(t, &v);
                    fragment = Some(w.finish());
                }
                _ => {}
            }
        }

        // A valid LpPacket must have either a fragment or at least one Ack.
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
        })
    }
}

impl LpPacket {
    /// Returns `true` if this LpPacket is a fragment of a larger packet.
    pub fn is_fragmented(&self) -> bool {
        self.frag_count.is_some_and(|c| c > 1)
    }

    /// Returns `true` if this LpPacket is a bare Ack (no payload fragment).
    pub fn is_ack_only(&self) -> bool {
        self.fragment.is_none() && !self.acks.is_empty()
    }
}

/// Decode the Nack header field value to extract the NackReason.
fn decode_nack_header(value: Bytes) -> Result<NackReason, crate::PacketError> {
    if value.is_empty() {
        // Nack with no reason = unspecified.
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

    #[test]
    fn encode_decode_lp_nack_roundtrip() {
        let n = name(&[b"test", b"nack"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_nack(NackReason::NoRoute, &interest_wire);

        assert!(is_lp_packet(&lp_wire));

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert_eq!(lp.nack, Some(NackReason::NoRoute));
        assert!(lp.congestion_mark.is_none());

        // Fragment should be the original Interest.
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
        assert_eq!(lp.sequence, Some(42));
        assert_eq!(lp.frag_index, None);
        assert_eq!(lp.frag_count, None);
        assert_eq!(lp.acks, vec![10, 20]);
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn encode_decode_lp_reliable_with_frag_info() {
        let wire = encode_lp_reliable(&[0x05, 0x00], 100, Some((1, 3)), &[]);
        let lp = LpPacket::decode(wire).unwrap();
        assert_eq!(lp.sequence, Some(100));
        assert_eq!(lp.frag_index, Some(1));
        assert_eq!(lp.frag_count, Some(3));
        assert!(lp.acks.is_empty());
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

    // ─── NDNLPv2 header field tests ──────────────────────────────────────────

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

    #[test]
    fn decode_pit_token_too_long_rejected() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(crate::tlv_type::LP_PACKET, |w| {
            w.write_tlv(crate::tlv_type::LP_PIT_TOKEN, &[0u8; 33]);
            w.write_tlv(crate::tlv_type::LP_FRAGMENT, &interest_wire);
        });
        assert!(LpPacket::decode(w.finish()).is_err());
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
    }

    #[test]
    fn encode_lp_with_headers_roundtrip() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let headers = LpHeaders {
            pit_token: Some(Bytes::from_static(&[0x01, 0x02, 0x03])),
            congestion_mark: Some(5),
            incoming_face_id: Some(42),
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

    #[test]
    fn encode_lp_with_headers_empty_headers() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let headers = LpHeaders {
            pit_token: None,
            congestion_mark: None,
            incoming_face_id: None,
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
