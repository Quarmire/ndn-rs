//! NDNLPv2 PrefixAnnouncement — a **signed** object (a Data) by which a
//! producer announces a reachable name prefix, used by self-learning to install
//! a route. The Data name is `/<announced-prefix>/32=PA/<version>...`; the
//! Content carries an `ExpirationPeriod` (route TTL). The Data MUST be
//! signature-/trust-validated before its route is acted on — this type only
//! parses; it does not verify.

use core::time::Duration;

use bytes::Bytes;
use ndn_tlv::TlvReader;

use crate::{Data, Name, PacketError, tlv_type};

/// NFD `ExpirationPeriod` TLV (`tlv-nfd.hpp` = 109), NonNegativeInteger ms.
const TLV_NFD_EXPIRATION_PERIOD: u64 = 109;
/// The `KeywordNameComponent` value identifying a PrefixAnnouncement
/// (ndn-cxx `PrefixAnnouncement::getKeywordComponent` = keyword `PA`).
const PA_KEYWORD: &[u8] = b"PA";

/// A parsed PrefixAnnouncement. `data` is the signed object to validate.
pub struct PrefixAnnouncement {
    /// The announced (routable) prefix — the Data name minus the trailing
    /// `32=PA/<version>...` suffix.
    pub announced_prefix: Name,
    /// Route lifetime from the announcement's `ExpirationPeriod`, if present.
    pub expiration: Option<Duration>,
    /// The signed announcement object; validate before installing the route.
    pub data: Data,
}

impl PrefixAnnouncement {
    /// Parse PrefixAnnouncement wire bytes (a Data). Does **not** verify the
    /// signature — the caller must validate `data` against its trust anchors
    /// before installing a route for `announced_prefix`.
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let data = Data::decode(raw)?;
        let comps = data.name.components();
        let pa_idx = comps
            .iter()
            .position(|c| c.typ == tlv_type::KEYWORD && c.value.as_ref() == PA_KEYWORD)
            .ok_or_else(|| {
                PacketError::MalformedPacket("PrefixAnnouncement: missing 'PA' keyword".into())
            })?;
        if pa_idx == 0 {
            return Err(PacketError::MalformedPacket(
                "PrefixAnnouncement: empty announced prefix".into(),
            ));
        }
        let announced_prefix = Name::from_components(comps[..pa_idx].iter().cloned());
        let expiration = data.content().and_then(parse_expiration);
        Ok(Self {
            announced_prefix,
            expiration,
            data,
        })
    }
}

fn parse_expiration(content: &Bytes) -> Option<Duration> {
    let mut r = TlvReader::new(content.clone());
    while let Ok((typ, val)) = r.read_tlv() {
        if typ == TLV_NFD_EXPIRATION_PERIOD {
            let ms = val.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            return Some(Duration::from_millis(ms));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NameComponent;
    use crate::encode::DataBuilder;

    #[test]
    fn decodes_announced_prefix_before_pa_keyword() {
        // /app/svc/32=PA/v=1
        let announced: Name = "/app/svc".parse().unwrap();
        let pa_name = announced
            .clone()
            .append_component(NameComponent::keyword(Bytes::from_static(b"PA")))
            .append_version(1);
        let data = DataBuilder::new(pa_name, b"").sign_digest_sha256();
        let pa = PrefixAnnouncement::decode(data).expect("decode");
        assert_eq!(pa.announced_prefix, announced);
    }

    #[test]
    fn rejects_data_without_pa_keyword() {
        let data = DataBuilder::new("/app/svc/data", b"x").sign_digest_sha256();
        assert!(PrefixAnnouncement::decode(data).is_err());
    }
}
