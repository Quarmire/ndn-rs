use bytes::Bytes;

use crate::{Interest, Name, PacketError, Selector, tlv_type};

/// NDNLPv2 `NackReason` (NFD wiki "NDNLPv2"). Only `NoRoute=150`,
/// `Duplicate=100`, and `Congestion=50` are registered; `NotYet=160` and the
/// [`Refusal`] codes `170..=176` are ndn-rs-private extensions. A receiver
/// that does not know a code treats the Nack as one without a reason
/// (NDNLPv2: "MUST treat this NACK as a NACK without reason, and MUST NOT drop
/// the packet"); ndn-rs peers that predate a code decode it as `Other(code)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NackReason {
    NoRoute,
    Duplicate,
    Congestion,
    /// ndn-rs-private; not in the NDNLPv2 registry.
    NotYet,
    /// ndn-rs-private; not in the NDNLPv2 registry. The forwarder refused the
    /// Data that answered the Interest (see [`Refusal`]).
    Refused(Refusal),
    Other(u64),
}

impl NackReason {
    pub fn code(&self) -> u64 {
        match self {
            NackReason::Congestion => 50,
            NackReason::Duplicate => 100,
            NackReason::NoRoute => 150,
            NackReason::NotYet => 160,
            NackReason::Refused(r) => r.code(),
            NackReason::Other(c) => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            50 => NackReason::Congestion,
            100 => NackReason::Duplicate,
            150 => NackReason::NoRoute,
            160 => NackReason::NotYet,
            c => Refusal::from_code(c).map_or(NackReason::Other(c), NackReason::Refused),
        }
    }

    /// True iff this reason is in the NDNLPv2 registry. Excludes `NotYet`
    /// and `Refused`.
    pub fn is_registered(&self) -> bool {
        matches!(
            self,
            NackReason::NoRoute | NackReason::Duplicate | NackReason::Congestion
        )
    }

    /// The refusal this Nack reports, if it reports one.
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            NackReason::Refused(r) => Some(*r),
            _ => None,
        }
    }
}

/// Why a validating forwarder refused the Data that answered an Interest. A
/// forwarder sends it as a Nack ([`NackReason::Refused`]) to its **local**
/// downstreams only — apps and its own internal consumers — so they learn at
/// once why nothing came instead of waiting out the Interest lifetime. A
/// non-local downstream gets nothing, as NDN specifies for Data a forwarder
/// drops.
///
/// Every refusal but one is a final verdict on that Data
/// ([`is_final`](Self::is_final)): asking again gets the same answer.
/// [`Unverifiable`](Self::Unverifiable) is "refused for now": the signing
/// certificate was definitely not to be had when the forwarder fetched it,
/// which can change (a route converges, the producer comes back), so a
/// consumer asks again after the forwarder's certificate-fetch back-off.
/// [`next_step`](Self::next_step) says what to do about each.
///
/// The codes are ndn-rs-private (`170..=176`); [`as_str`](Self::as_str) is a
/// stable token for logs, spans and tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The certificate chain was rejected for another reason (too deep, a
    /// cycle, an unsupported signature type, a key store error).
    Chain,
    /// A certificate on the chain is revoked in the governing trust context.
    Revoked,
    /// The signature does not verify: forged, or altered in transit; or the
    /// Data names no usable signing key (no SignatureInfo, no KeyLocator, a
    /// KeyDigest this forwarder has no certificate of). Retrying cannot
    /// change any of these.
    BadSignature,
    /// The trust schema or trust context does not authorize the signer for
    /// the name.
    Schema,
    /// The chain ends at a self-signed certificate that is no trust anchor.
    UntrustedRoot,
    /// A trust context arrived for a namespace being adopted or updated and
    /// failed that expectation (a foreign fingerprint, or an update not
    /// signed by an anchor of the held version).
    Context,
    /// The Data cannot be verified now: every source the forwarder asked for
    /// its signing certificate — the routes and the face that delivered the
    /// Data — answered that none is to be had there (NoRoute) or refused
    /// what it served. Not final ([`is_final`](Refusal::is_final)).
    Unverifiable,
}

impl Refusal {
    pub const ALL: [Refusal; 7] = [
        Refusal::Chain,
        Refusal::Revoked,
        Refusal::BadSignature,
        Refusal::Schema,
        Refusal::UntrustedRoot,
        Refusal::Context,
        Refusal::Unverifiable,
    ];

    /// The NackReason code.
    pub fn code(self) -> u64 {
        match self {
            Refusal::Chain => 170,
            Refusal::Revoked => 171,
            Refusal::BadSignature => 172,
            Refusal::Schema => 173,
            Refusal::UntrustedRoot => 174,
            Refusal::Context => 175,
            Refusal::Unverifiable => 176,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }

    /// Stable token: `chain`, `revoked`, `bad-signature`, `schema`,
    /// `untrusted-root`, `context`, `unverifiable`.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Chain => "chain",
            Refusal::Revoked => "revoked",
            Refusal::BadSignature => "bad-signature",
            Refusal::Schema => "schema",
            Refusal::UntrustedRoot => "untrusted-root",
            Refusal::Context => "context",
            Refusal::Unverifiable => "unverifiable",
        }
    }

    /// The token back ([`as_str`](Self::as_str)).
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == token)
    }

    /// Whether asking again gets the same answer. `false` only for
    /// [`Unverifiable`](Self::Unverifiable): a certificate absent now may be
    /// reachable once the forwarder's certificate-fetch back-off has passed,
    /// so a consumer retries it within its retry budget. Every other refusal
    /// is a verdict on what the Data is, and retrying it is pointless.
    pub fn is_final(self) -> bool {
        !matches!(self, Refusal::Unverifiable)
    }

    /// What to do about this refusal, in one user-facing line.
    pub fn next_step(self) -> &'static str {
        match self {
            Refusal::Chain => {
                "the signer's certificate chain is unusable (too deep, a cycle, an unsupported \
                 signature type): the publisher must sign with a certificate issued in the \
                 namespace"
            }
            Refusal::Revoked => {
                "the signer's certificate was revoked: the publisher must enroll again"
            }
            Refusal::BadSignature => {
                "the signature does not verify (forged or altered in transit): fetch it over \
                 another path, or ask the publisher to publish it again"
            }
            Refusal::Schema => {
                "the trust schema does not let this signer publish under this name: publish \
                 under a name the signer is authorized for, or have an admin change the schema"
            }
            Refusal::UntrustedRoot => {
                "the signer chains to a root this node does not trust: adopt the namespace's \
                 anchor link"
            }
            Refusal::Context => {
                "the trust context is not the one expected (a foreign fingerprint, or an update \
                 not signed by an anchor of the held version): check the anchor link or \
                 fingerprint you adopted"
            }
            Refusal::Unverifiable => {
                "retry later: the signing certificate could not be fetched (if it never can, the \
                 publisher has no certificate)"
            }
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// NDNLPv2 Nack header. `NackReason` is optional in the wire format;
/// absence means the upstream did not state why it rejected the Interest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct NackHeader {
    pub reason: Option<NackReason>,
}

impl NackHeader {
    pub fn new(reason: Option<NackReason>) -> Self {
        Self { reason }
    }
}

#[derive(Debug)]
pub struct Nack {
    pub reason: Option<NackReason>,
    pub interest: Interest,
}

impl Nack {
    pub fn new(interest: Interest, reason: NackReason) -> Self {
        Self {
            reason: Some(reason),
            interest,
        }
    }

    pub fn new_with_reason(interest: Interest, reason: Option<NackReason>) -> Self {
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
        let header = lp
            .nack
            .ok_or_else(|| PacketError::MalformedPacket("LpPacket has no Nack header".into()))?;
        let fragment = lp
            .fragment
            .ok_or_else(|| PacketError::MalformedPacket("Nack LpPacket has no fragment".into()))?;
        let interest = Interest::decode(fragment)?;
        Ok(Self {
            reason: header.reason,
            interest,
        })
    }

    /// The Interest a Nack to one downstream carries, rebuilt from what the
    /// forwarder kept of it (name, selectors, nonce, and for a parameterized
    /// Interest its [`parameters_portion`](Interest::parameters_portion))
    /// once the Interest itself is gone: a consumer matches the Nack to its
    /// pending Interest by name and selectors (ndn-cxx's `Face`, `ndn-app`),
    /// and a name ending in a `ParametersSha256DigestComponent` comes with
    /// the parameters that digest covers, so a strict decoder accepts it.
    pub fn interest_wire(
        name: &Name,
        selector: &Selector,
        nonce: u32,
        parameters: Option<&Bytes>,
    ) -> Bytes {
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_raw(&name.encode_to_tlv());
            if selector.can_be_prefix {
                w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
            }
            if selector.must_be_fresh {
                w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
            }
            w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
            if let Some(parameters) = parameters {
                w.write_raw(parameters);
            }
        });
        w.finish()
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

    /// Every refusal round-trips through its NackReason code and its token,
    /// and no refusal code collides with a registered or other private one.
    #[test]
    fn refusal_codes_and_tokens_roundtrip() {
        for r in Refusal::ALL {
            let reason = NackReason::Refused(r);
            assert_eq!(NackReason::from_code(reason.code()), reason);
            assert_eq!(Refusal::from_token(r.as_str()), Some(r));
            assert!(!reason.is_registered());
            assert!(![50, 100, 150, 160].contains(&r.code()));
        }
        assert_eq!(NackReason::from_code(169), NackReason::Other(169));
        assert_eq!(NackReason::from_code(177), NackReason::Other(177));
    }

    /// Only a definite certificate absence is refused for now (a consumer
    /// retries it); every other refusal is final.
    #[test]
    fn only_unverifiable_is_refused_for_now() {
        for r in Refusal::ALL {
            assert_eq!(r.is_final(), r != Refusal::Unverifiable, "{r}");
        }
    }

    /// The Interest a refusal encloses for a parameterized downstream keeps
    /// the parameters its ParametersSha256DigestComponent covers, so the
    /// name and the parameters stay consistent for a strict decoder.
    #[test]
    fn a_rebuilt_parameterized_interest_keeps_its_parameters() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"ca");
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[7u8; 32]);
            });
            w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
            w.write_tlv(tlv_type::NONCE, &[1, 2, 3, 4]);
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &[0x0F, 0xA0]);
            w.write_tlv(tlv_type::APP_PARAMETERS, b"params");
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_INFO, &[0x1B, 0x01, 0x00]);
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, &[0u8; 32]);
        });
        let original = Interest::decode(w.finish()).unwrap();
        let portion = original.parameters_portion().expect("parameterized");

        let wire = Nack::interest_wire(&original.name, original.selectors(), 0x0102_0304, Some(&portion));
        let rebuilt = Interest::decode(wire).unwrap();
        assert_eq!(rebuilt.name, original.name);
        assert_eq!(rebuilt.selectors(), original.selectors());
        assert_eq!(rebuilt.app_parameters(), original.app_parameters());
        assert_eq!(rebuilt.parameters_portion(), Some(portion), "the digest covers the same bytes");
        assert!(rebuilt.sig_value().is_some());

        let name = Name::from_components([NameComponent::generic(Bytes::from_static(b"x"))]);
        let unparameterized = Interest::decode(encode_interest(&name, None)).unwrap();
        assert_eq!(unparameterized.parameters_portion(), None);
    }

    #[test]
    fn nack_new_stores_fields() {
        let name = Name::from_components([NameComponent::generic(Bytes::from_static(b"test"))]);
        let interest = Interest::new(name.clone());
        let nack = Nack::new(interest, NackReason::NoRoute);
        assert_eq!(nack.reason, Some(NackReason::NoRoute));
        assert_eq!(*nack.interest.name, name);
    }

    #[test]
    fn decode_nack_reason_and_name() {
        let raw = make_nack_lp(NackReason::NoRoute, &[b"edu", b"ucla"]);
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, Some(NackReason::NoRoute));
        assert_eq!(nack.interest.name.len(), 2);
        assert_eq!(nack.interest.name.components()[0].value.as_ref(), b"edu");
    }

    #[test]
    fn decode_nack_congestion() {
        let raw = make_nack_lp(NackReason::Congestion, &[b"test"]);
        let nack = Nack::decode(raw).unwrap();
        assert_eq!(nack.reason, Some(NackReason::Congestion));
    }

    #[test]
    fn n05_decode_nack_without_reason_as_none() {
        let name = Name::from_components([NameComponent::generic(Bytes::from_static(b"n05"))]);
        let interest_wire = encode_interest(&name, None);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::LP_PACKET, |w| {
            w.write_nested(tlv_type::NACK, |_w| {});
            w.write_tlv(tlv_type::LP_FRAGMENT, &interest_wire);
        });

        let nack = Nack::decode(w.finish()).unwrap();
        assert_eq!(nack.reason, None);
        assert_eq!(*nack.interest.name, name);
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
        assert_eq!(nack.reason, Some(NackReason::NoRoute));
        assert_eq!(nack.interest.name.len(), 2);
    }
}
