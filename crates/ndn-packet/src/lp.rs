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
    pub fragment: Bytes,
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
                tlv_type::INTEREST | tlv_type::DATA => {
                    let mut w = TlvWriter::new();
                    w.write_tlv(t, &v);
                    fragment = Some(w.finish());
                }
                _ => {}
            }
        }

        let fragment = fragment.ok_or_else(|| {
            crate::PacketError::MalformedPacket("LpPacket missing fragment".into())
        })?;

        Ok(Self {
            fragment,
            nack,
            congestion_mark,
            sequence,
            frag_index,
            frag_count,
        })
    }
}

impl LpPacket {
    /// Returns `true` if this LpPacket is a fragment of a larger packet.
    pub fn is_fragmented(&self) -> bool {
        self.frag_count.is_some_and(|c| c > 1)
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

/// Check if raw bytes start with an LpPacket TLV type (0x64).
pub fn is_lp_packet(raw: &[u8]) -> bool {
    raw.first() == Some(&0x64)
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
        let interest = Interest::decode(lp.fragment).unwrap();
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
        let interest = Interest::decode(lp.fragment).unwrap();
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
}
