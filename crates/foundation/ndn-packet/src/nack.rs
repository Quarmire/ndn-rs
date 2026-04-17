use bytes::Bytes;

use crate::tlv_type;
use crate::{Interest, PacketError};
use ndn_tlv::{TlvReader, TlvWriter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NackReason {
    NoRoute,
    Duplicate,
    Congestion,
    NotYet,
    Other(u64),
}

impl NackReason {
    pub fn code(&self) -> u64 {
        match self {
            NackReason::Congestion => 50,
            NackReason::Duplicate => 100,
            NackReason::NoRoute => 150,
            NackReason::NotYet => 160,
            NackReason::Other(c) => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            50 => NackReason::Congestion,
            100 => NackReason::Duplicate,
            150 => NackReason::NoRoute,
            160 => NackReason::NotYet,
            c => NackReason::Other(c),
        }
    }
}

#[derive(Debug)]
pub struct Nack {
    pub reason: NackReason,
    pub interest: Interest,
}

impl Nack {
    pub fn new(interest: Interest, reason: NackReason) -> Self {
        Self { reason, interest }
    }

    /// Accepts both NDNLPv2 format (LpPacket with Nack header) and the
    /// legacy bare Nack TLV (0x0320).
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let first = *raw
            .first()
            .ok_or(PacketError::Tlv(ndn_tlv::TlvError::UnexpectedEof))?;

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

        let interest_bytes = interest_raw.ok_or(PacketError::Tlv(
            ndn_tlv::TlvError::MissingField("Interest inside Nack"),
        ))?;
        let interest = Interest::decode(interest_bytes)?;
        Ok(Self { reason, interest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Name, NameComponent};
    use bytes::Bytes;
    use ndn_tlv::TlvWriter;

    fn build_nack(reason_code: u8, name_components: &[&[u8]]) -> Bytes {
        let mut interest_inner = TlvWriter::new();
        interest_inner.write_nested(tlv_type::NAME, |w| {
            for comp in name_components {
                w.write_tlv(tlv_type::NAME_COMPONENT, comp);
            }
        });

        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NACK, |w| {
            w.write_tlv(tlv_type::NACK_REASON, &[reason_code]);
            w.write_tlv(tlv_type::INTEREST, &interest_inner.finish());
        });
        w.finish()
    }


    #[test]
    fn nack_reason_known_codes() {
        let cases = [
            (NackReason::Congestion, 50),
            (NackReason::Duplicate, 100),
            (NackReason::NoRoute, 150),
            (NackReason::NotYet, 160),
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


    #[test]
    fn nack_new_stores_fields() {
        let name = Name::from_components([NameComponent::generic(Bytes::from_static(b"test"))]);
        let interest = Interest::new(name.clone());
        let nack = Nack::new(interest, NackReason::NoRoute);
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(*nack.interest.name, name);
    }


    #[test]
    fn decode_nack_reason_and_name() {
        let raw = build_nack(150, &[b"edu", b"ucla"]); // NoRoute = 150
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
        w.write_tlv(0x05, &[]);
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
        });
        assert!(Nack::decode(w.finish()).is_err());
    }
}
