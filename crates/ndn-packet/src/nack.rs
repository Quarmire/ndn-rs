use bytes::Bytes;

use crate::{Interest, PacketError, tlv_type};

/// NDNLPv2 `NackReason` (NFD wiki "NDNLPv2"). Only `NoRoute=150`,
/// `Duplicate=100`, and `Congestion=50` are registered; `NotYet=160` is an
/// ndn-rs-private extension and peers will decode it as `Other(160)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NackReason {
    NoRoute,
    Duplicate,
    Congestion,
    /// ndn-rs-private; not in the NDNLPv2 registry.
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

    /// True iff this reason is in the NDNLPv2 registry. Excludes `NotYet`.
    pub fn is_registered(&self) -> bool {
        matches!(
            self,
            NackReason::NoRoute | NackReason::Duplicate | NackReason::Congestion
        )
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

    /// Decode a Nack from NDNLPv2 wire format: an `LpPacket` (type 0x64)
    /// carrying a `Nack` header (type 0x0320) and a `Fragment` (type 0x50)
    /// whose value is the encoded `Interest`. Per NDNLPv2 §3.5.
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let first = *raw
            .first()
            .ok_or(PacketError::Tlv(ndn_tlv::TlvError::UnexpectedEof))?;

        if first as u64 != tlv_type::LP_PACKET {
            return Err(PacketError::UnknownPacketType(first as u64));
        }

        let lp = crate::lp::LpPacket::decode(raw)?;
        let reason = lp
            .nack
            .ok_or_else(|| PacketError::MalformedPacket("LpPacket has no Nack header".into()))?;
        let fragment = lp
            .fragment
            .ok_or_else(|| PacketError::MalformedPacket("Nack LpPacket has no fragment".into()))?;
        let interest = Interest::decode(fragment)?;
        Ok(Self { reason, interest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Name, NameComponent, encode::encode_interest, lp::encode_lp_nack};
    use bytes::Bytes;
    use ndn_tlv::TlvWriter;

    fn make_nack_lp(reason: NackReason, name_components: &[&[u8]]) -> Bytes {
        let name = Name::from_components(
            name_components
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        );
        let interest_wire = encode_interest(&name, None);
        encode_lp_nack(reason, &interest_wire)
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
        let raw = make_nack_lp(NackReason::NoRoute, &[b"edu", b"ucla"]);
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(nack.interest.name.len(), 2);
        assert_eq!(nack.interest.name.components()[0].value.as_ref(), b"edu");
    }

    #[test]
    fn decode_nack_congestion() {
        let raw = make_nack_lp(NackReason::Congestion, &[b"test"]);
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

    /// LpPacket that carries a Nack header but no Fragment must be rejected.
    #[test]
    fn decode_nack_lp_no_fragment_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_nested(tlv_type::NACK, |w| {
                w.write_tlv(tlv_type::NACK_REASON, &[50u8]);
            });
        });
        let err = Nack::decode(w.finish()).unwrap_err();
        assert!(
            matches!(err, crate::PacketError::MalformedPacket(_)),
            "expected MalformedPacket, got {err:?}"
        );
    }

    /// A bare Nack TLV (0x0320 as outer type) must be rejected; only the
    /// NDNLPv2 LpPacket-wrapped form is valid.
    #[test]
    fn a12_nack_lp_only_decode() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::NACK, |w| {
            w.write_tlv(tlv_type::NACK_REASON, &[150u8]);
        });
        assert!(
            Nack::decode(w.finish()).is_err(),
            "bare Nack TLV (0x0320 outer) must not decode"
        );

        let raw = make_nack_lp(NackReason::NoRoute, &[b"ndn", b"test"]);
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(nack.interest.name.len(), 2);
    }
}
