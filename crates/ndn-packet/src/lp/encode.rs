use bytes::Bytes;
use ndn_tlv::TlvWriter;

use super::{CachePolicyType, LpHeaders, is_lp_packet, nni};
use crate::tlv_type;

pub fn encode_lp_nack(reason: crate::nack::NackReason, interest_wire: &[u8]) -> Bytes {
    encode_lp_nack_with_pit_token(reason, interest_wire, None)
}

/// Encode an LP-framed Nack with an optional `PitToken` header echoed back
/// to the consumer (the forwarder MUST echo the upstream `PitToken` on the
/// return path). Headers are written in ascending TLV-TYPE order per
/// NDNLPv2 §3: PitToken (0x62) before Nack (0x0320), then Fragment (0x50)
/// as the terminator.
pub fn encode_lp_nack_with_pit_token(
    reason: crate::nack::NackReason,
    interest_wire: &[u8],
    pit_token: Option<&[u8]>,
) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        if let Some(token) = pit_token {
            w.write_tlv(tlv_type::LP_PIT_TOKEN, token);
        }
        w.write_nested(tlv_type::NACK, |w| {
            let (buf, len) = nni(reason.code());
            w.write_tlv(tlv_type::NACK_REASON, &buf[..len]);
        });
        w.write_tlv(tlv_type::LP_FRAGMENT, interest_wire);
    });
    w.finish()
}

/// Wrap a bare Interest or Data in a minimal LpPacket. Returns unchanged
/// if already an LpPacket.
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

/// Encode an NDNLPv2 reliability-tracked LP packet. Every reliability frame
/// carries a per-LP `TxSequence` (0x0348); fragments additionally share a
/// `Sequence` (0x51) plus `FragIndex` / `FragCount`. Acks reference peer
/// `TxSequence` values. `frag_info` is `Some((seq, idx, count))` for
/// fragments, `None` otherwise.
pub fn encode_lp_reliable(
    fragment: &[u8],
    tx_sequence: u64,
    frag_info: Option<(u64, u64, u64)>,
    acks: &[u64],
) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        // Ascending TLV-TYPE order: Sequence(81), FragIndex(82), FragCount(83),
        // Ack(836), TxSequence(840), Fragment(80) at end.
        if let Some((seq, idx, count)) = frag_info {
            // NDNLPv2 §6.3: Sequence/FragIndex/FragCount MUST be exactly
            // 8-byte NonNegativeInteger (NFD rejects shorter encodings).
            w.write_tlv(tlv_type::LP_SEQUENCE, &seq.to_be_bytes());
            let (buf, len) = nni(idx);
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &buf[..len]);
            let (buf, len) = nni(count);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &buf[..len]);
        }
        for &ack in acks {
            let (buf, len) = nni(ack);
            w.write_tlv(tlv_type::LP_ACK, &buf[..len]);
        }
        let (buf, len) = nni(tx_sequence);
        w.write_tlv(tlv_type::LP_TX_SEQUENCE, &buf[..len]);
        w.write_tlv(tlv_type::LP_FRAGMENT, fragment);
    });
    w.finish()
}

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

/// LP header fields are written in increasing TLV-TYPE order per spec.
pub fn encode_lp_with_headers(fragment: &[u8], headers: &LpHeaders) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        if let Some(ref token) = headers.pit_token {
            w.write_tlv(tlv_type::LP_PIT_TOKEN, token);
        }
        if let Some(id) = headers.incoming_face_id {
            let (buf, len) = nni(id);
            w.write_tlv(tlv_type::LP_INCOMING_FACE_ID, &buf[..len]);
        }
        if let Some(id) = headers.next_hop_face_id {
            let (buf, len) = nni(id);
            w.write_tlv(tlv_type::LP_NEXT_HOP_FACE_ID, &buf[..len]);
        }
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
        if let Some(mark) = headers.congestion_mark {
            let (buf, len) = nni(mark);
            w.write_tlv(tlv_type::LP_CONGESTION_MARK, &buf[..len]);
        }
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

        let rewrapped = encode_lp_packet(&lp_wire);
        assert_eq!(rewrapped, lp_wire);
    }

    /// `encode_lp_nack_with_pit_token` echoes the upstream `PitToken` header.
    #[test]
    fn d07_encode_lp_nack_with_pit_token_emits_token() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let token: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let lp_wire =
            encode_lp_nack_with_pit_token(NackReason::NoRoute, &interest_wire, Some(token));

        let lp = LpPacket::decode(lp_wire).expect("LpPacket must decode");
        assert_eq!(
            lp.nack,
            Some(NackReason::NoRoute),
            "Nack reason must round-trip"
        );
        assert_eq!(
            lp.pit_token.as_deref(),
            Some(token),
            "PitToken bytes must round-trip exactly"
        );
    }

    /// Plain `encode_lp_nack` omits the PitToken header.
    #[test]
    fn d07_encode_lp_nack_omits_pit_token_when_absent() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_nack(NackReason::NoRoute, &interest_wire);
        let lp = LpPacket::decode(lp_wire).expect("LpPacket must decode");
        assert!(lp.pit_token.is_none());
        assert_eq!(lp.nack, Some(NackReason::NoRoute));
    }

    /// `encode_lp_reliable` must emit `TxSequence` (0x0348) for per-link
    /// reliability tracking, not `Sequence` (0x51, reserved for fragmentation).
    #[test]
    fn b01_b09_reliable_wire_uses_tx_sequence() {
        let wire = encode_lp_reliable(&[0x05, 0x00], 7, None, &[]);
        let needle: &[u8] = &[0xFD, 0x03, 0x48];
        let found = wire.windows(needle.len()).any(|w| w == needle);
        assert!(
            found,
            "encode_lp_reliable must emit TxSequence (TLV-TYPE 0x0348). Wire bytes: {wire:02x?}"
        );
    }
}
