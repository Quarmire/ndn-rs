use core::time::Duration;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(not(feature = "std"))]
use core::cell::OnceCell as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

use bytes::Bytes;

use crate::tlv_type;
use crate::{Name, PacketError, SignatureInfo};
use ndn_tlv::TlvReader;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Selector {
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
}

/// An NDN Interest packet.
///
/// Fields beyond the name are lazily decoded via `OnceLock` so that pipeline
/// stages that short-circuit (e.g., CS hit) pay no decode cost for fields
/// they never access.
#[derive(Debug)]
pub struct Interest {
    pub(crate) raw: Bytes,
    pub name: Arc<Name>,
    selectors: OnceLock<Selector>,
    nonce: OnceLock<Option<u32>>,
    lifetime: OnceLock<Option<Duration>>,
    app_params: OnceLock<Option<Bytes>>,
    hop_limit: OnceLock<Option<u8>>,
    forwarding_hint: OnceLock<Option<Vec<Arc<Name>>>>,
    sig_info: OnceLock<Option<SignatureInfo>>,
    sig_value: OnceLock<Option<Bytes>>,
}

impl Interest {
    pub fn new(name: Name) -> Self {
        Self {
            raw: Bytes::new(),
            name: Arc::new(name),
            selectors: OnceLock::new(),
            nonce: OnceLock::new(),
            lifetime: OnceLock::new(),
            app_params: OnceLock::new(),
            hop_limit: OnceLock::new(),
            forwarding_hint: OnceLock::new(),
            sig_info: OnceLock::new(),
            sig_value: OnceLock::new(),
        }
    }

    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::INTEREST {
            return Err(PacketError::UnknownPacketType(typ));
        }
        let mut inner = TlvReader::new(value);

        let (name_typ, name_val) = inner.read_tlv()?;
        if name_typ != tlv_type::NAME {
            return Err(PacketError::UnknownPacketType(name_typ));
        }
        let name = Name::decode(name_val)?;

        // NDN Packet Format v0.3 §2: Interest/Data must have at least one
        // name component.
        if name.is_empty() {
            return Err(PacketError::MalformedPacket(
                "Interest Name must have at least one component".into(),
            ));
        }

        // ParametersSha256DigestComponent digest validation is an
        // application-layer trust concern, not a routing concern.  Forwarders
        // must accept and forward Signed Interests (NDNts v0.3, ndn-cxx) without
        // validating the digest — rejecting them would silently drop management
        // commands.  Applications that need integrity checking should call a
        // dedicated verify method.

        Ok(Self {
            raw,
            name: Arc::new(name),
            selectors: OnceLock::new(),
            nonce: OnceLock::new(),
            lifetime: OnceLock::new(),
            app_params: OnceLock::new(),
            hop_limit: OnceLock::new(),
            forwarding_hint: OnceLock::new(),
            sig_info: OnceLock::new(),
            sig_value: OnceLock::new(),
        })
    }

    pub fn selectors(&self) -> &Selector {
        self.selectors
            .get_or_init(|| decode_selectors(&self.raw).unwrap_or_default())
    }

    pub fn nonce(&self) -> Option<u32> {
        *self
            .nonce
            .get_or_init(|| decode_nonce(&self.raw).ok().flatten())
    }

    pub fn lifetime(&self) -> Option<Duration> {
        *self
            .lifetime
            .get_or_init(|| decode_lifetime(&self.raw).ok().flatten())
    }

    pub fn app_parameters(&self) -> Option<&Bytes> {
        self.app_params
            .get_or_init(|| decode_app_params(&self.raw).ok().flatten())
            .as_ref()
    }

    /// Per NDN Packet Format v0.3 §5.2, ForwardingHint contains one or more
    /// delegation Name TLVs a forwarder can use to reach the Data producer.
    pub fn forwarding_hint(&self) -> Option<&[Arc<Name>]> {
        self.forwarding_hint
            .get_or_init(|| decode_forwarding_hint(&self.raw).ok().flatten())
            .as_deref()
    }

    /// Per NDN Packet Format v0.3 §5.2, the forwarder must decrement before
    /// forwarding and drop if zero.
    pub fn hop_limit(&self) -> Option<u8> {
        *self
            .hop_limit
            .get_or_init(|| decode_hop_limit(&self.raw).ok().flatten())
    }

    pub fn sig_info(&self) -> Option<&SignatureInfo> {
        self.sig_info
            .get_or_init(|| decode_interest_sig_info(&self.raw).ok().flatten())
            .as_ref()
    }

    pub fn sig_value(&self) -> Option<&Bytes> {
        self.sig_value
            .get_or_init(|| decode_interest_sig_value(&self.raw).ok().flatten())
            .as_ref()
    }

    /// Per NDN Packet Format v0.3 §5.4, the signed region spans from the
    /// start of the Name TLV through the end of InterestSignatureInfo TLV.
    pub fn signed_region(&self) -> Option<&[u8]> {
        compute_interest_signed_region(&self.raw).ok().flatten()
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}

fn decode_selectors(raw: &Bytes) -> Result<Selector, PacketError> {
    let mut sel = Selector::default();
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, _) = inner.read_tlv()?;
        match typ {
            t if t == tlv_type::CAN_BE_PREFIX => sel.can_be_prefix = true,
            t if t == tlv_type::MUST_BE_FRESH => sel.must_be_fresh = true,
            _ => {}
        }
    }
    Ok(sel)
}

fn decode_nonce(raw: &Bytes) -> Result<Option<u32>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::NONCE {
            if val.len() != 4 {
                return Ok(None);
            }
            let n = u32::from_be_bytes([val[0], val[1], val[2], val[3]]);
            return Ok(Some(n));
        }
    }
    Ok(None)
}

fn decode_app_params(raw: &Bytes) -> Result<Option<Bytes>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::APP_PARAMETERS {
            return Ok(Some(val));
        }
    }
    Ok(None)
}

fn decode_forwarding_hint(raw: &Bytes) -> Result<Option<Vec<Arc<Name>>>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::FORWARDING_HINT {
            let mut hint_reader = TlvReader::new(val);
            let mut names = Vec::new();
            while !hint_reader.is_empty() {
                let (t, v) = hint_reader.read_tlv()?;
                if t == tlv_type::NAME {
                    names.push(Arc::new(Name::decode(v)?));
                }
            }
            if names.is_empty() {
                return Ok(None);
            }
            return Ok(Some(names));
        }
    }
    Ok(None)
}

fn decode_hop_limit(raw: &Bytes) -> Result<Option<u8>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::HOP_LIMIT {
            if val.len() == 1 {
                return Ok(Some(val[0]));
            }
            return Ok(None);
        }
    }
    Ok(None)
}

fn decode_interest_sig_info(raw: &Bytes) -> Result<Option<SignatureInfo>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::INTEREST_SIGNATURE_INFO {
            return Ok(Some(SignatureInfo::decode(val)?));
        }
    }
    Ok(None)
}

fn decode_interest_sig_value(raw: &Bytes) -> Result<Option<Bytes>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::INTEREST_SIGNATURE_VALUE {
            return Ok(Some(val));
        }
    }
    Ok(None)
}

fn compute_interest_signed_region(raw: &Bytes) -> Result<Option<&[u8]>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let outer_header_len = raw.len() - value.len();
    let mut inner = TlvReader::new(value);
    let mut sig_info_end = 0usize;
    while !inner.is_empty() {
        let (typ, _) = inner.read_tlv()?;
        if typ == tlv_type::INTEREST_SIGNATURE_INFO {
            sig_info_end = outer_header_len + inner.position();
            break;
        }
    }
    if sig_info_end == 0 {
        return Ok(None);
    }
    Ok(Some(&raw[outer_header_len..sig_info_end]))
}

fn decode_lifetime(raw: &Bytes) -> Result<Option<Duration>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::INTEREST_LIFETIME {
            let mut ms = 0u64;
            for &b in val.iter() {
                ms = (ms << 8) | b as u64;
            }
            return Ok(Some(Duration::from_millis(ms)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;

    fn build_interest(
        components: &[&[u8]],
        nonce: Option<u32>,
        lifetime_ms: Option<u64>,
        can_be_prefix: bool,
        must_be_fresh: bool,
    ) -> Bytes {
        build_interest_full(
            components,
            nonce,
            lifetime_ms,
            can_be_prefix,
            must_be_fresh,
            None,
        )
    }

    fn build_interest_full(
        components: &[&[u8]],
        nonce: Option<u32>,
        lifetime_ms: Option<u64>,
        can_be_prefix: bool,
        must_be_fresh: bool,
        hop_limit: Option<u8>,
    ) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
            if can_be_prefix {
                w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
            }
            if must_be_fresh {
                w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
            }
            if let Some(n) = nonce {
                w.write_tlv(tlv_type::NONCE, &n.to_be_bytes());
            }
            if let Some(ms) = lifetime_ms {
                w.write_tlv(tlv_type::INTEREST_LIFETIME, &ms.to_be_bytes());
            }
            if let Some(h) = hop_limit {
                w.write_tlv(tlv_type::HOP_LIMIT, &[h]);
            }
        });
        w.finish()
    }


    #[test]
    fn new_stores_name() {
        let name =
            Name::from_components([crate::NameComponent::generic(Bytes::from_static(b"test"))]);
        let i = Interest::new(name.clone());
        assert_eq!(*i.name, name);
    }

    #[test]
    fn new_has_no_nonce_or_lifetime() {
        let i = Interest::new(Name::root());
        assert_eq!(i.nonce(), None);
        assert_eq!(i.lifetime(), None);
    }


    #[test]
    fn decode_name_only() {
        let raw = build_interest(&[b"edu", b"ucla"], None, None, false, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.name.len(), 2);
        assert_eq!(i.name.components()[0].value.as_ref(), b"edu");
        assert_eq!(i.name.components()[1].value.as_ref(), b"ucla");
    }

    #[test]
    fn decode_with_nonce() {
        let raw = build_interest(&[b"test"], Some(0xDEAD_BEEF), None, false, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.nonce(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn decode_with_lifetime() {
        let raw = build_interest(&[b"test"], None, Some(4000), false, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn decode_with_can_be_prefix() {
        let raw = build_interest(&[b"test"], None, None, true, false);
        let i = Interest::decode(raw).unwrap();
        assert!(i.selectors().can_be_prefix);
        assert!(!i.selectors().must_be_fresh);
    }

    #[test]
    fn decode_with_must_be_fresh() {
        let raw = build_interest(&[b"test"], None, None, false, true);
        let i = Interest::decode(raw).unwrap();
        assert!(!i.selectors().can_be_prefix);
        assert!(i.selectors().must_be_fresh);
    }

    #[test]
    fn decode_with_all_fields() {
        let raw = build_interest(
            &[b"edu", b"ucla", b"data"],
            Some(0x1234_5678),
            Some(8000),
            true,
            true,
        );
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.name.len(), 3);
        assert_eq!(i.nonce(), Some(0x1234_5678));
        assert_eq!(i.lifetime(), Some(Duration::from_millis(8000)));
        assert!(i.selectors().can_be_prefix);
        assert!(i.selectors().must_be_fresh);
    }

    #[test]
    fn decode_raw_field_preserved() {
        let raw = build_interest(&[b"test"], Some(42), None, false, false);
        let i = Interest::decode(raw.clone()).unwrap();
        assert_eq!(i.raw(), &raw);
    }

    #[test]
    fn decode_wrong_outer_type_errors() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
        });
        let raw = w.finish();
        assert!(matches!(
            Interest::decode(raw).unwrap_err(),
            crate::PacketError::UnknownPacketType(0x06)
        ));
    }

    #[test]
    fn decode_with_forwarding_hint() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_nested(tlv_type::FORWARDING_HINT, |w| {
                w.write_nested(tlv_type::NAME, |w| {
                    w.write_tlv(tlv_type::NAME_COMPONENT, b"ndn");
                    w.write_tlv(tlv_type::NAME_COMPONENT, b"gateway");
                });
            });
        });
        let raw = w.finish();
        let i = Interest::decode(raw).unwrap();
        let hints = i.forwarding_hint().expect("forwarding_hint present");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].len(), 2);
        assert_eq!(hints[0].components()[0].value.as_ref(), b"ndn");
    }

    #[test]
    fn decode_without_forwarding_hint() {
        let raw = build_interest(&[b"test"], None, None, false, false);
        let i = Interest::decode(raw).unwrap();
        assert!(i.forwarding_hint().is_none());
    }

    #[test]
    fn decode_app_params_wrong_digest_accepted() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]); // wrong digest
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        let i = Interest::decode(raw).expect("should accept despite wrong digest");
        assert_eq!(
            i.app_parameters().map(|b| b.as_ref()),
            Some(b"hello".as_ref())
        );
    }

    #[test]
    fn decode_app_params_without_digest_accepted() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        let i = Interest::decode(raw).expect("should accept without digest component");
        assert_eq!(
            i.app_parameters().map(|b| b.as_ref()),
            Some(b"hello".as_ref())
        );
    }

    #[test]
    fn decode_empty_name_rejected() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_tlv(tlv_type::NAME, &[]); // empty Name
        });
        let raw = w.finish();
        assert!(Interest::decode(raw).is_err());
    }

    #[test]
    fn decode_truncated_errors() {
        let raw = Bytes::from_static(&[0x05, 0x10, 0x07]); // length claims 16 bytes, only 1 follows
        assert!(Interest::decode(raw).is_err());
    }

    #[test]
    fn decode_with_hop_limit() {
        let raw = build_interest_full(&[b"test"], None, None, false, false, Some(64));
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.hop_limit(), Some(64));
    }

    #[test]
    fn decode_without_hop_limit() {
        let raw = build_interest(&[b"test"], None, None, false, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.hop_limit(), None);
    }

    #[test]
    fn decode_hop_limit_zero() {
        let raw = build_interest_full(&[b"test"], None, None, false, false, Some(0));
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.hop_limit(), Some(0));
    }


    fn build_signed_interest(components: &[&[u8]], sig_type_code: u8, sig_value: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in components {
                    w.write_tlv(tlv_type::NAME_COMPONENT, comp);
                }
            });
            w.write_nested(tlv_type::INTEREST_SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[sig_type_code]);
            });
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, sig_value);
        });
        w.finish()
    }

    #[test]
    fn decode_signed_interest_sig_info() {
        let raw = build_signed_interest(&[b"test"], 5, &[0xAB, 0xCD]);
        let i = Interest::decode(raw).unwrap();
        let si = i.sig_info().expect("sig_info present");
        assert_eq!(si.sig_type, crate::SignatureType::SignatureEd25519);
    }

    #[test]
    fn decode_signed_interest_sig_value() {
        let raw = build_signed_interest(&[b"test"], 5, &[0xDE, 0xAD]);
        let i = Interest::decode(raw).unwrap();
        let sv = i.sig_value().expect("sig_value present");
        assert_eq!(sv.as_ref(), &[0xDE, 0xAD]);
    }

    #[test]
    fn decode_signed_interest_signed_region() {
        let raw = build_signed_interest(&[b"test"], 5, &[0xAB, 0xCD]);
        let i = Interest::decode(raw.clone()).unwrap();
        let region = i.signed_region().expect("signed region present");
        // Region must not be empty.
        assert!(!region.is_empty());
        // Region must not contain the signature value bytes.
        assert!(!region.ends_with(&[0xAB, 0xCD]));
        // Region must start with the Name TLV type (0x07).
        assert_eq!(region[0], tlv_type::NAME as u8);
    }

    #[test]
    fn unsigned_interest_has_no_sig_fields() {
        let raw = build_interest(&[b"test"], None, None, false, false);
        let i = Interest::decode(raw).unwrap();
        assert!(i.sig_info().is_none());
        assert!(i.sig_value().is_none());
        assert!(i.signed_region().is_none());
    }

    #[test]
    fn signed_interest_with_key_locator() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_nested(tlv_type::INTEREST_SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5]);
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"key1");
                    });
                });
            });
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, &[0xFF]);
        });
        let raw = w.finish();
        let i = Interest::decode(raw).unwrap();
        let si = i.sig_info().unwrap();
        let kl = si.key_locator.as_ref().expect("key_locator present");
        assert_eq!(kl.components()[0].value.as_ref(), b"key1");
    }

    #[test]
    fn lazy_fields_decoded_once_and_cached() {
        let raw = build_interest(&[b"x"], Some(99), Some(1000), true, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.nonce(), i.nonce());
        assert_eq!(i.lifetime(), i.lifetime());
        assert_eq!(i.selectors(), i.selectors());
    }
}
