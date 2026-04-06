use bytes::Bytes;
use ndn_tlv::TlvWriter;

use super::{CachePolicyType, LpHeaders, is_lp_packet, nni};
use crate::tlv_type;

/// Encode a Nack as an NDNLPv2 LpPacket.
///
/// The resulting packet is:
/// ```text
/// LpPacket (0x64)
///   Nack (0x0320)
///     NackReason (0x0321) = reason code
///   Fragment (0x50)
///     <original Interest wire bytes>
/// ```
pub fn encode_lp_nack(reason: crate::nack::NackReason, interest_wire: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        // Nack header field.
        w.write_nested(tlv_type::NACK, |w| {
            let (buf, len) = nni(reason.code());
            w.write_tlv(tlv_type::NACK_REASON, &buf[..len]);
        });
        // Fragment: the original Interest.
        w.write_tlv(tlv_type::LP_FRAGMENT, interest_wire);
    });
    w.finish()
}

/// Wrap a bare Interest or Data in a minimal NDNLPv2 LpPacket.
///
/// If the packet is already an LpPacket (starts with 0x64), returns it unchanged.
///
/// ```text
/// LpPacket (0x64)
///   Fragment (0x50)
///     <original packet wire bytes>
/// ```
pub fn encode_lp_packet(packet: &[u8]) -> Bytes {
    if is_lp_packet(packet) {
        return Bytes::copy_from_slice(packet);
    }
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        w.write_tlv(tlv_type::LP_FRAGMENT, packet);
    });
    w.finish()
}

/// Encode a reliability-enabled LpPacket with TxSequence, optional fragmentation,
/// and piggybacked Acks.
///
/// `frag_info` is `Some((frag_index, frag_count))` for fragmented packets.
/// `acks` contains TxSequences to acknowledge.
pub fn encode_lp_reliable(
    fragment: &[u8],
    sequence: u64,
    frag_info: Option<(u64, u64)>,
    acks: &[u64],
) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        let (buf, len) = nni(sequence);
        w.write_tlv(tlv_type::LP_SEQUENCE, &buf[..len]);
        if let Some((idx, count)) = frag_info {
            let (buf, len) = nni(idx);
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &buf[..len]);
            let (buf, len) = nni(count);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &buf[..len]);
        }
        for &ack in acks {
            let (buf, len) = nni(ack);
            w.write_tlv(tlv_type::LP_ACK, &buf[..len]);
        }
        w.write_tlv(tlv_type::LP_FRAGMENT, fragment);
    });
    w.finish()
}

/// Encode a bare Ack-only LpPacket (no fragment payload).
pub fn encode_lp_acks(acks: &[u64]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        for &ack in acks {
            let (buf, len) = nni(ack);
            w.write_tlv(tlv_type::LP_ACK, &buf[..len]);
        }
    });
    w.finish()
}

/// Encode an LpPacket with optional header fields.
///
/// LP header fields are written in increasing TLV-TYPE order as required by the spec.
pub fn encode_lp_with_headers(fragment: &[u8], headers: &LpHeaders) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        // Fields must appear in increasing TLV-TYPE order.
        // 0x62 PitToken
        if let Some(ref token) = headers.pit_token {
            w.write_tlv(tlv_type::LP_PIT_TOKEN, token);
        }
        // 0x032C IncomingFaceId
        if let Some(id) = headers.incoming_face_id {
            let (buf, len) = nni(id);
            w.write_tlv(tlv_type::LP_INCOMING_FACE_ID, &buf[..len]);
        }
        // 0x0334 CachePolicy
        if let Some(ref cp) = headers.cache_policy {
            w.write_nested(tlv_type::LP_CACHE_POLICY, |w| {
                let code = match cp {
                    CachePolicyType::NoCache => 1u64,
                    CachePolicyType::Other(c) => *c,
                };
                let (buf, len) = nni(code);
                w.write_tlv(tlv_type::LP_CACHE_POLICY_TYPE, &buf[..len]);
            });
        }
        // 0x0340 CongestionMark
        if let Some(mark) = headers.congestion_mark {
            let (buf, len) = nni(mark);
            w.write_tlv(tlv_type::LP_CONGESTION_MARK, &buf[..len]);
        }
        // 0x50 Fragment (last)
        w.write_tlv(tlv_type::LP_FRAGMENT, fragment);
    });
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_interest;
    use crate::lp::{LpPacket, is_lp_packet};
    use crate::nack::NackReason;
    use crate::{Interest, Name, NameComponent};
    use bytes::Bytes;

    fn name(comps: &[&[u8]]) -> Name {
        Name::from_components(
            comps
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    #[test]
    fn is_lp_packet_checks_first_byte() {
        assert!(is_lp_packet(&[0x64, 0x00]));
        assert!(!is_lp_packet(&[0x05, 0x00]));
        assert!(!is_lp_packet(&[]));
    }

    #[test]
    fn encode_lp_packet_wraps_bare_interest() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let lp_wire = encode_lp_packet(&interest_wire);
        assert!(is_lp_packet(&lp_wire));

        let lp = LpPacket::decode(lp_wire).unwrap();
        assert!(lp.nack.is_none());
        let interest = Interest::decode(lp.fragment.unwrap()).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn encode_lp_packet_passthrough_existing_lp() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_nack(NackReason::NoRoute, &interest_wire);

        // Wrapping an existing LpPacket should return it unchanged.
        let rewrapped = encode_lp_packet(&lp_wire);
        assert_eq!(rewrapped, lp_wire);
    }
}
