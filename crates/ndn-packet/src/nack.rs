use bytes::Bytes;

use crate::{Interest, PacketError};
use ndn_tlv::{TlvReader, TlvWriter};
use crate::tlv_type;

/// Reason codes carried in a Nack packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NackReason {
    /// The forwarder has no route for this Interest.
    NoRoute,
    /// The Interest is a duplicate (loop detected).
    Duplicate,
    /// The forwarder is congested.
    Congestion,
    /// The data does not yet exist; consumer may retry after a hint.
    NotYet,
    /// Unknown/vendor-specific reason code.
    Other(u64),
}

impl NackReason {
    pub fn code(&self) -> u64 {
        match self {
            NackReason::Congestion => 50,
            NackReason::Duplicate  => 100,
            NackReason::NoRoute    => 150,
            NackReason::NotYet     => 160,
            NackReason::Other(c)   => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            50  => NackReason::Congestion,
            100 => NackReason::Duplicate,
            150 => NackReason::NoRoute,
            160 => NackReason::NotYet,
            c   => NackReason::Other(c),
        }
    }
}

/// An NDN Nack — a negative acknowledgement wrapping the rejected Interest.
#[derive(Debug)]
pub struct Nack {
    pub reason:   NackReason,
    pub interest: Interest,
}

impl Nack {
    pub fn new(interest: Interest, reason: NackReason) -> Self {
        Self { reason, interest }
    }

    /// Decode a Nack from wire bytes.
    ///
    /// Accepts both NDNLPv2 format (LpPacket 0x64 with Nack header) and the
    /// legacy bare Nack TLV (0x0320). Prefer LpPacket format for new code.
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let first = *raw.first().ok_or(PacketError::Tlv(ndn_tlv::TlvError::UnexpectedEof))?;

        // NDNLPv2 LpPacket format.
        if first as u64 == tlv_type::LP_PACKET {
            let lp = crate::lp::LpPacket::decode(raw)?;
            let reason = lp.nack.ok_or_else(|| {
                PacketError::MalformedPacket("LpPacket has no Nack header".into())
            })?;
            let fragment = lp.fragment.ok_or_else(|| {
                PacketError::MalformedPacket("Nack LpPacket has no fragment".into())
            })?;
            let interest = Interest::decode(fragment)?;
            return Ok(Self { reason, interest });
        }

        // Legacy bare Nack TLV (0x0320).
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::NACK {
            return Err(PacketError::UnknownPacketType(typ));
        }
        let mut inner = TlvReader::new(value);

        let mut reason = NackReason::Other(0);
        let mut interest_raw: Option<Bytes> = None;

        while !inner.is_empty() {
            let (t, v) = inner.read_tlv()?;
            match t {
                t if t == tlv_type::NACK_REASON => {
                    let mut code = 0u64;
                    for &b in v.iter() {
                        code = (code << 8) | b as u64;
                    }
                    reason = NackReason::from_code(code);
                }
                t if t == tlv_type::INTEREST => {
                    let mut w = TlvWriter::new();
                    w.write_tlv(tlv_type::INTEREST, &v);
                    interest_raw = Some(w.finish());
                }
                _ => {}
            }
        }

        let interest_bytes = interest_raw.ok_or(
            PacketError::Tlv(ndn_tlv::TlvError::MissingField("Interest inside Nack"))
        )?;
        let interest = Interest::decode(interest_bytes)?;
        Ok(Self { reason, interest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;
    use crate::{Name, NameComponent};
    use bytes::Bytes;

    fn build_nack(reason_code: u8, name_components: &[&[u8]]) -> Bytes {
        // Build the Interest inner content (Name TLV value).
        let mut interest_inner = TlvWriter::new();
        interest_inner.write_nested(tlv_type::NAME, |w| {
            for comp in name_components {
                w.write_tlv(tlv_type::NAME_COMPONENT, comp);
            }
        });

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NACK, |w| {
            w.write_tlv(tlv_type::NACK_REASON, &[reason_code]);
            // Embed the Interest's inner content as a child TLV with INTEREST type.
            // Nack::decode reconstructs the full Interest wire bytes from this.
            w.write_tlv(tlv_type::INTEREST, &interest_inner.finish());
        });
        w.finish()
    }

    // ── NackReason round-trips ────────────────────────────────────────────────

    #[test]
    fn nack_reason_known_codes() {
        let cases = [
            (NackReason::Congestion, 50),
            (NackReason::Duplicate,  100),
            (NackReason::NoRoute,    150),
            (NackReason::NotYet,     160),
        ];
        for (reason, code) in cases {
            assert_eq!(reason.code(), code);
            assert_eq!(NackReason::from_code(code), reason);
        }
    }

    #[test]
    fn nack_reason_unknown_code_roundtrip() {
        let reason = NackReason::Other(42);
        assert_eq!(reason.code(), 42);
        assert_eq!(NackReason::from_code(42), NackReason::Other(42));
    }

    // ── Nack::new ─────────────────────────────────────────────────────────────

    #[test]
    fn nack_new_stores_fields() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"test")),
        ]);
        let interest = Interest::new(name.clone());
        let nack = Nack::new(interest, NackReason::NoRoute);
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(*nack.interest.name, name);
    }

    // ── Nack::decode ─────────────────────────────────────────────────────────

    #[test]
    fn decode_nack_reason_and_name() {
        let raw = build_nack(150, &[b"edu", b"ucla"]);  // NoRoute = 150
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(nack.interest.name.len(), 2);
        assert_eq!(nack.interest.name.components()[0].value.as_ref(), b"edu");
    }

    #[test]
    fn decode_nack_congestion() {
        let raw = build_nack(50, &[b"test"]);
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, NackReason::Congestion);
    }

    #[test]
    fn decode_nack_wrong_outer_type_errors() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[]);  // INTEREST type, not NACK
        assert!(matches!(
            Nack::decode(w.finish()).unwrap_err(),
            crate::PacketError::UnknownPacketType(0x05)
        ));
    }

    #[test]
    fn decode_nack_missing_interest_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NACK, |w| {
            w.write_tlv(tlv_type::NACK_REASON, &[50]);
            // No Interest TLV embedded.
        });
        assert!(Nack::decode(w.finish()).is_err());
    }
}
