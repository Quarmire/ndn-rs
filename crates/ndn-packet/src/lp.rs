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

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

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
                tlv_type::INTEREST | tlv_type::DATA => {
                    let mut w = TlvWriter::new();
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

/// Decode a big-endian unsigned integer from variable-length bytes.
fn decode_be_u64(bytes: &[u8]) -> u64 {
    let mut val = 0u64;
    for &b in bytes {
        val = (val << 8) | b as u64;
    }
    val
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
pub fn encode_lp_nack(reason: NackReason, interest_wire: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::LP_PACKET, |w| {
        // Nack header field.
        w.write_nested(tlv_type::NACK, |w| {
            let (buf, len) = crate::encode::nni(reason.code());
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
        let (buf, len) = crate::encode::nni(sequence);
        w.write_tlv(tlv_type::LP_SEQUENCE, &buf[..len]);
        if let Some((idx, count)) = frag_info {
            let (buf, len) = crate::encode::nni(idx);
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &buf[..len]);
            let (buf, len) = crate::encode::nni(count);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &buf[..len]);
        }
        for &ack in acks {
            let (buf, len) = crate::encode::nni(ack);
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
            let (buf, len) = crate::encode::nni(ack);
            w.write_tlv(tlv_type::LP_ACK, &buf[..len]);
        }
    });
    w.finish()
}

/// Fast-path extraction of Sequence and Ack fields from a raw LpPacket.
///
/// Scans for Sequence (0x51) and Ack (0x0344) TLVs without allocating `Bytes`.
/// Returns `(tx_sequence, acks)`. Used only for reliability-enabled faces.
pub fn extract_acks(raw: &[u8]) -> (Option<u64>, smallvec::SmallVec<[u64; 8]>) {
    let mut tx_seq = None;
    let mut acks = smallvec::SmallVec::new();

    if raw.first() != Some(&0x64) {
        return (tx_seq, acks);
    }
    let Some((_, type_len)) = ndn_tlv::read_varu64(raw).ok() else { return (tx_seq, acks) };
    let Some((outer_len, len_len)) = ndn_tlv::read_varu64(&raw[type_len..]).ok() else { return (tx_seq, acks) };
    let header_len = type_len + len_len;
    let Some(inner) = raw.get(header_len..header_len + outer_len as usize) else { return (tx_seq, acks) };

    let mut pos = 0;
    while pos < inner.len() {
        let Some((t, tn)) = ndn_tlv::read_varu64(&inner[pos..]).ok() else { break };
        pos += tn;
        let Some((l, ln)) = ndn_tlv::read_varu64(&inner[pos..]).ok() else { break };
        pos += ln;
        let l = l as usize;
        if pos + l > inner.len() { break; }
        match t {
            0x51 => tx_seq = Some(decode_be_u64(&inner[pos..pos + l])),
            0x0344 => acks.push(decode_be_u64(&inner[pos..pos + l])),
            _ => {}
        }
        pos += l;
    }
    (tx_seq, acks)
}

/// Check if raw bytes start with an LpPacket TLV type (0x64).
pub fn is_lp_packet(raw: &[u8]) -> bool {
    raw.first() == Some(&0x64)
}

/// Result of lightweight fragment extraction.
///
/// Returned by [`extract_fragment`] for packets that carry fragmentation fields
/// (`FragCount > 1`).  Holds the minimum information needed for reassembly
/// without parsing Nack, CongestionMark, or other LpPacket headers.
pub struct FragmentHeader {
    pub sequence:   u64,
    pub frag_index: u64,
    pub frag_count: u64,
    /// Byte range of the Fragment TLV value within the original raw buffer.
    pub frag_start: usize,
    pub frag_end:   usize,
}

/// Lightweight fragment extraction from an LpPacket.
///
/// Scans the TLV fields for Sequence, FragIndex, FragCount, and Fragment
/// **without** creating `Bytes` sub-slices, parsing Nack headers, or allocating.
/// Returns `Some` only if the packet is a multi-fragment LpPacket (`frag_count > 1`).
///
/// This is the hot-path parser for the fragment sieve — unfragmented LpPackets,
/// Nacks, and bare Interest/Data fall through to the full `LpPacket::decode`.
pub fn extract_fragment(raw: &[u8]) -> Option<FragmentHeader> {
    if raw.first() != Some(&0x64) {
        return None;
    }
    // Read outer TLV: type (0x64) + length.
    let (_, type_len) = ndn_tlv::read_varu64(raw).ok()?;
    let (outer_len, len_len) = ndn_tlv::read_varu64(&raw[type_len..]).ok()?;
    let header_len = type_len + len_len;
    let inner = raw.get(header_len..header_len + outer_len as usize)?;

    let mut pos = 0;
    let mut sequence = None;
    let mut frag_index = None;
    let mut frag_count = None;
    let mut frag_start = 0;
    let mut frag_end = 0;

    while pos < inner.len() {
        let (t, tn) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
        pos += tn;
        let (l, ln) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
        pos += ln;
        let l = l as usize;
        if pos + l > inner.len() {
            return None;
        }
        match t {
            0x51 => sequence   = Some(decode_be_u64(&inner[pos..pos + l])),
            0x52 => frag_index = Some(decode_be_u64(&inner[pos..pos + l])),
            0x53 => {
                let c = decode_be_u64(&inner[pos..pos + l]);
                if c <= 1 { return None; } // Not fragmented — let full decode handle it.
                frag_count = Some(c);
            }
            0x50 => {
                frag_start = header_len + (pos - 0) + 0;
                // Adjust: frag_start relative to raw, not inner.
                frag_start = header_len + pos;
                frag_end   = frag_start + l;
            }
            _ => {}
        }
        pos += l;
    }

    Some(FragmentHeader {
        sequence:   sequence?,
        frag_index: frag_index?,
        frag_count: frag_count?,
        frag_start,
        frag_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encode_interest;
    use crate::{Interest, Name, NameComponent};

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
        // LpPacket wrapping a plain Interest (no Nack header).
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
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
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_CONGESTION_MARK, &1u64.to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
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
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_nested(tlv_type::NACK, |w| {
                w.write_tlv(tlv_type::NACK_REASON, &[150]);
            });
            // No fragment.
        });
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn decode_fragmentation_fields() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_SEQUENCE, &42u64.to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &[0]);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &[3]);
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
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
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let lp = LpPacket::decode(w.finish()).unwrap();
        assert!(!lp.is_fragmented());
        assert!(lp.sequence.is_none());
        assert!(lp.frag_index.is_none());
        assert!(lp.frag_count.is_none());
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

    #[test]
    fn extract_fragment_returns_correct_fields() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_SEQUENCE, &42u64.to_be_bytes());
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &[1]);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &[3]);
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
        });
        let raw = w.finish();

        let hdr = extract_fragment(&raw).unwrap();
        assert_eq!(hdr.sequence, 42);
        assert_eq!(hdr.frag_index, 1);
        assert_eq!(hdr.frag_count, 3);
        assert_eq!(&raw[hdr.frag_start..hdr.frag_end], &interest_wire[..]);
    }

    #[test]
    fn extract_fragment_returns_none_for_unfragmented() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let lp_wire = encode_lp_packet(&interest_wire);
        assert!(extract_fragment(&lp_wire).is_none());
    }

    #[test]
    fn extract_fragment_returns_none_for_single_fragment() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_tlv(tlv_type::LP_SEQUENCE, &[0]);
            w.write_tlv(tlv_type::LP_FRAG_INDEX, &[0]);
            w.write_tlv(tlv_type::LP_FRAG_COUNT, &[1]); // count=1, not fragmented
            w.write_tlv(tlv_type::LP_FRAGMENT, &[0x05, 0x00]);
        });
        assert!(extract_fragment(&w.finish()).is_none());
    }

    #[test]
    fn extract_fragment_matches_full_decode() {
        // Ensure extract_fragment and LpPacket::decode agree on fragment content.
        use crate::fragment::fragment_packet;
        let data: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let frags = fragment_packet(&data, 500, 99);
        for frag_bytes in &frags {
            let hdr = extract_fragment(frag_bytes).unwrap();
            let lp = LpPacket::decode(Bytes::copy_from_slice(frag_bytes)).unwrap();
            assert_eq!(hdr.sequence, lp.sequence.unwrap());
            assert_eq!(hdr.frag_index, lp.frag_index.unwrap());
            assert_eq!(hdr.frag_count, lp.frag_count.unwrap());
            assert_eq!(&frag_bytes[hdr.frag_start..hdr.frag_end], &lp.fragment.unwrap()[..]);
        }
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
        // LpPacket with neither fragment nor acks.
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |_| {});
        assert!(LpPacket::decode(w.finish()).is_err());
    }

    #[test]
    fn extract_acks_from_reliable_packet() {
        let wire = encode_lp_reliable(&[0x05, 0x00], 42, None, &[10, 20, 30]);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, Some(42));
        assert_eq!(&acks[..], &[10, 20, 30]);
    }

    #[test]
    fn extract_acks_from_ack_only() {
        let wire = encode_lp_acks(&[7, 8]);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, None);
        assert_eq!(&acks[..], &[7, 8]);
    }

    #[test]
    fn extract_acks_from_plain_lp() {
        let n = name(&[b"test"]);
        let interest_wire = encode_interest(&n, None);
        let wire = encode_lp_packet(&interest_wire);
        let (seq, acks) = extract_acks(&wire);
        assert_eq!(seq, None);
        assert!(acks.is_empty());
    }
}
