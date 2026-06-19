use core::time::Duration;

#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::format;
#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::vec::Vec;
#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use core::cell::OnceCell as OnceLock;
#[cfg(any(feature = "std", target_arch = "wasm32"))]
use std::sync::OnceLock;

use crate::compat::Arc;

use bytes::Bytes;

use crate::tlv_type;
use crate::{Name, PacketError, SignatureInfo};
use ndn_tlv::TlvReader;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Selector {
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
}

/// An NDN Interest packet. Fields beyond the name are lazily decoded via
/// `OnceLock` so pipeline stages that short-circuit (e.g. CS hit) pay no
/// decode cost for fields they never access.
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
    reflexive_name: OnceLock<Option<Arc<Name>>>,
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
            reflexive_name: OnceLock::new(),
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

        // Per NDN Packet Format v0.3 §2 every Interest must name at least one
        // component.
        if name.is_empty() {
            return Err(PacketError::MalformedPacket(
                "Interest Name must have at least one component".into(),
            ));
        }

        let has_app_params = validate_interest_body_structure(&inner)?;
        validate_psdc_structure(&name, has_app_params)?;

        Ok(Self {
            raw,
            name: Arc::new(name),
            selectors: OnceLock::new(),
            nonce: OnceLock::new(),
            lifetime: OnceLock::new(),
            app_params: OnceLock::new(),
            hop_limit: OnceLock::new(),
            forwarding_hint: OnceLock::new(),
            reflexive_name: OnceLock::new(),
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

    /// Reflexive-forwarding name (provisional `REFLEXIVE_NAME` element): the
    /// unpredictable reverse-routable prefix a producer Interests back along to
    /// pull parameters / run a callback. `None` when absent.
    pub fn reflexive_name(&self) -> Option<&Arc<Name>> {
        self.reflexive_name
            .get_or_init(|| {
                decode_reflexive_name(&self.raw)
                    .ok()
                    .flatten()
                    .map(Arc::new)
            })
            .as_ref()
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

    /// Signed region of a Signed Interest, matching ndn-cxx's
    /// `Interest::extractSignedRanges`: concatenation of every non-PSDC Name
    /// component TLV (outer NAME header excluded), then the
    /// `ApplicationParameters` TLV, then the `InterestSignatureInfo` TLV.
    /// Returns `None` if any of those three is missing.
    pub fn signed_region(&self) -> Option<bytes::Bytes> {
        compute_interest_signed_region(&self.raw).ok().flatten()
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}

/// Single-pass structural validation of the Interest body (positioned past
/// the `Name` TLV); does not consume `body`. Returns whether
/// `ApplicationParameters` is present (used by `validate_psdc_structure`).
/// Enforces spec element order, rejects duplicates, and aborts on unknown
/// critical TLV-TYPEs per `tlv.html` §"TLV-TYPE".
fn validate_interest_body_structure(body: &TlvReader) -> Result<bool, PacketError> {
    // Spec order per interest.html: Name=1, CanBePrefix=2, MustBeFresh=3,
    // ForwardingHint=4, Nonce=5, InterestLifetime=6, HopLimit=7,
    // ApplicationParameters=8, InterestSignatureInfo=9,
    // InterestSignatureValue=10. The Name has already been consumed.
    fn elem_index(typ: u64) -> Option<u8> {
        Some(match typ {
            t if t == tlv_type::CAN_BE_PREFIX => 2,
            t if t == tlv_type::MUST_BE_FRESH => 3,
            t if t == tlv_type::FORWARDING_HINT => 4,
            t if t == tlv_type::NONCE => 5,
            t if t == tlv_type::INTEREST_LIFETIME => 6,
            t if t == tlv_type::HOP_LIMIT => 7,
            t if t == tlv_type::APP_PARAMETERS => 8,
            t if t == tlv_type::INTEREST_SIGNATURE_INFO => 9,
            t if t == tlv_type::INTEREST_SIGNATURE_VALUE => 10,
            _ => return None,
        })
    }

    let mut scan = TlvReader::new(body.as_bytes());
    let mut last_element: u8 = 1;
    let mut has_app_params = false;
    while !scan.is_empty() {
        let (typ, val) = scan.read_tlv()?;
        match elem_index(typ) {
            Some(elem) => {
                if elem <= last_element {
                    return Err(PacketError::MalformedPacket(
                        "Interest body element out of spec order or duplicated".into(),
                    ));
                }
                last_element = elem;
                if typ == tlv_type::APP_PARAMETERS {
                    has_app_params = true;
                }
                // Nonce must be exactly 4 bytes per NDN Packet Format v0.3 §3.2.
                if typ == tlv_type::NONCE && val.len() != 4 {
                    return Err(PacketError::MalformedPacket(format!(
                        "Interest Nonce must be exactly 4 bytes; got {}",
                        val.len()
                    )));
                }
                // Eagerly decode SignatureInfo so KeyLocator-by-SigType rules
                // surface here instead of via a silent `sig_info() == None`.
                if typ == tlv_type::INTEREST_SIGNATURE_INFO {
                    crate::SignatureInfo::decode(val)?;
                }
            }
            None => {
                if crate::is_critical_tlv_type(typ) {
                    return Err(PacketError::MalformedPacket(
                        "unknown critical TLV-TYPE in Interest body".into(),
                    ));
                }
            }
        }
    }
    Ok(has_app_params)
}

/// Structural rules for `ParametersSha256DigestComponent` (PSDC) per
/// `name.html#parameters-digest-component` and `signed-interest.html`:
/// at most one PSDC; when `ApplicationParameters` is present, a PSDC MUST
/// exist and MUST be the last component. Digest *value* validation is the
/// trust layer's job and stays out of scope here.
fn validate_psdc_structure(name: &Name, has_app_params: bool) -> Result<(), PacketError> {
    let comps = name.components();
    let mut psdc_count = 0usize;
    let mut last_psdc_idx = 0usize;
    for (i, c) in comps.iter().enumerate() {
        if c.typ == tlv_type::PARAMETERS_SHA256 {
            psdc_count += 1;
            last_psdc_idx = i;
        }
    }

    if psdc_count > 1 {
        return Err(PacketError::MalformedPacket(
            "Interest Name has more than one ParametersSha256DigestComponent".into(),
        ));
    }

    if has_app_params && psdc_count == 0 {
        return Err(PacketError::MalformedPacket(
            "Interest with ApplicationParameters must contain a ParametersSha256DigestComponent"
                .into(),
        ));
    }

    if psdc_count == 1 && last_psdc_idx != comps.len() - 1 {
        return Err(PacketError::MalformedPacket(
            "ParametersSha256DigestComponent must be the last component of the Interest Name"
                .into(),
        ));
    }

    Ok(())
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
                return Err(PacketError::MalformedPacket(format!(
                    "Interest Nonce must be exactly 4 bytes; got {} bytes",
                    val.len()
                )));
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

fn decode_reflexive_name(raw: &Bytes) -> Result<Option<Name>, PacketError> {
    if raw.is_empty() {
        return Ok(None);
    }
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::REFLEXIVE_NAME {
            // Value is the Name's component TLVs (no outer NAME header), matching
            // the builder's emission below.
            let name = Name::decode(val)?;
            if name.is_empty() {
                return Ok(None);
            }
            return Ok(Some(name));
        }
    }
    Ok(None)
}

/// Decrement the `HopLimit` field of an Interest wire by one. Returns the
/// new `Bytes` and the new HopLimit, or `None` if no HopLimit TLV is present.
/// Forwarders must check `Interest::hop_limit() != Some(0)` before calling.
pub fn decrement_hop_limit(raw: &Bytes) -> Option<(Bytes, u8)> {
    if raw.is_empty() {
        return None;
    }
    let header_len = {
        let mut r = TlvReader::new(raw.clone());
        let (_, value) = r.read_tlv().ok()?;
        raw.len() - value.len()
    };

    let body = &raw[header_len..];
    let mut pos = 0;
    while pos < body.len() {
        let rest = &body[pos..];
        let (typ, type_len) = ndn_tlv::read_varu64(rest).ok()?;
        let after_type = &rest[type_len..];
        let (len, len_len) = ndn_tlv::read_varu64(after_type).ok()?;
        let val_off = type_len + len_len;
        let val_len = len as usize;
        if pos + val_off + val_len > body.len() {
            return None;
        }
        if typ == tlv_type::HOP_LIMIT && val_len == 1 {
            let abs_value_byte = header_len + pos + val_off;
            let current = raw[abs_value_byte];
            let new = current.saturating_sub(1);
            let mut out = Vec::with_capacity(raw.len());
            out.extend_from_slice(raw);
            out[abs_value_byte] = new;
            return Some((Bytes::from(out), new));
        }
        pos += val_off + val_len;
    }
    None
}

/// Allocation-free in-place variant of [`decrement_hop_limit`], for forwarders
/// that own their receive buffer and cannot allocate (e.g. `no_std` /
/// bare-metal). Decrements the `HopLimit` field directly in `wire`, returning
/// the new HopLimit, or `None` if no HopLimit TLV is present (in which case
/// `wire` is left untouched). Forwarders must check
/// `Interest::hop_limit() != Some(0)` before calling.
pub fn decrement_hop_limit_in_place(wire: &mut [u8]) -> Option<u8> {
    if wire.is_empty() {
        return None;
    }
    // Skip the outer Interest TLV header (type varint + length varint).
    let (_typ, type_len) = ndn_tlv::read_varu64(wire).ok()?;
    let (_len, len_len) = ndn_tlv::read_varu64(wire.get(type_len..)?).ok()?;
    let header_len = type_len + len_len;

    let mut pos = header_len;
    while pos < wire.len() {
        let rest = &wire[pos..];
        let (typ, type_len) = ndn_tlv::read_varu64(rest).ok()?;
        let after_type = &rest[type_len..];
        let (len, len_len) = ndn_tlv::read_varu64(after_type).ok()?;
        let val_off = type_len + len_len;
        let val_len = len as usize;
        if pos + val_off + val_len > wire.len() {
            return None;
        }
        if typ == tlv_type::HOP_LIMIT && val_len == 1 {
            let idx = pos + val_off;
            let new = wire[idx].saturating_sub(1);
            wire[idx] = new;
            return Some(new);
        }
        pos += val_off + val_len;
    }
    None
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

fn compute_interest_signed_region(raw: &Bytes) -> Result<Option<Bytes>, PacketError> {
    use bytes::BytesMut;

    if raw.is_empty() {
        return Ok(None);
    }

    let mut reader = TlvReader::new(raw.clone());
    let (outer_typ, interest_value) = reader.read_tlv()?;
    if outer_typ != tlv_type::INTEREST {
        return Ok(None);
    }

    // The Name TLV MUST be the first inner element.
    let mut inner = TlvReader::new(interest_value.clone());
    let (name_typ, name_value) = inner.read_tlv()?;
    if name_typ != tlv_type::NAME {
        return Ok(None);
    }

    // Walk the Name components and emit the full TLV bytes of each
    // non-PSDC component.
    let mut name_components_bytes = BytesMut::new();
    let mut name_reader = TlvReader::new(name_value.clone());
    while !name_reader.is_empty() {
        let pos_before = name_reader.position();
        let (comp_typ, _) = name_reader.read_tlv()?;
        let pos_after = name_reader.position();
        if comp_typ == tlv_type::PARAMETERS_SHA256 {
            continue;
        }
        name_components_bytes.extend_from_slice(&name_value[pos_before..pos_after]);
    }

    // Find AppParameters and InterestSignatureInfo in the body after the Name.
    let mut app_params_tlv: Option<Bytes> = None;
    let mut sig_info_tlv: Option<Bytes> = None;

    while !inner.is_empty() {
        let pos_before = inner.position();
        let (typ, _) = inner.read_tlv()?;
        let pos_after = inner.position();
        if typ == tlv_type::APP_PARAMETERS {
            app_params_tlv = Some(interest_value.slice(pos_before..pos_after));
        } else if typ == tlv_type::INTEREST_SIGNATURE_INFO {
            sig_info_tlv = Some(interest_value.slice(pos_before..pos_after));
            break;
        }
    }

    let (Some(ap), Some(si)) = (app_params_tlv, sig_info_tlv) else {
        return Ok(None);
    };

    let mut out = BytesMut::with_capacity(name_components_bytes.len() + ap.len() + si.len());
    out.extend_from_slice(&name_components_bytes);
    out.extend_from_slice(&ap);
    out.extend_from_slice(&si);
    Ok(Some(out.freeze()))
}

fn decode_lifetime(raw: &Bytes) -> Result<Option<Duration>, PacketError> {
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?;
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, val) = inner.read_tlv()?;
        if typ == tlv_type::INTEREST_LIFETIME {
            // Clamp to the same 1-hour ceiling as persistent Interests (audit
            // X-3): an unbounded lifetime sets a far-future PIT `expires_at`,
            // and the PIT is time-reaped, so a huge value would pin an entry
            // effectively forever. No classical Interest legitimately waits
            // longer than this.
            let max_ms = u64::from(crate::MAX_PERSISTENT_LIFETIME_SECS) * 1000;
            let ms = crate::decode_nni(&val)?.min(max_ms);
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

    /// Packet format v0.3 §3.2 pins Nonce to exactly 4 bytes; other lengths
    /// must reject rather than silently drop the value.
    #[test]
    fn decode_rejects_short_nonce() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::NONCE, &[0x01, 0x02, 0x03]);
        });
        let raw = w.finish();
        let r = Interest::decode(raw);
        assert!(
            r.is_err(),
            "Interest::decode must reject Nonce with non-4-byte length"
        );
    }

    #[test]
    fn decode_rejects_long_nonce() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::NONCE, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        });
        let raw = w.finish();
        assert!(Interest::decode(raw).is_err());
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
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]);
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

    /// Unknown critical TLV-TYPE (>31, odd) at the Interest body level must
    /// abort decoding per `tlv.html` §"TLV-TYPE".
    #[test]
    fn a03_interest_decode_rejects_unknown_critical_tlv_in_body() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(0x99, b"x");
        });
        let raw = w.finish();
        let err = Interest::decode(raw)
            .expect_err("Interest with an unknown critical TLV in body must be rejected");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// Unknown non-critical TLV (even, >31) is preserved-and-skipped; the
    /// Interest must still decode.
    #[test]
    fn a03_interest_decode_accepts_unknown_non_critical_tlv() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(0x70, b"opaque");
        });
        let raw = w.finish();
        Interest::decode(raw).expect("Interest with an unknown non-critical TLV must still decode");
    }

    /// Interest body element order per `interest.html`: Name, CanBePrefix,
    /// MustBeFresh, ForwardingHint, Nonce, InterestLifetime, HopLimit,
    /// AppParameters, ... MustBeFresh before CanBePrefix is out of order.
    #[test]
    fn a04_interest_decode_rejects_must_be_fresh_before_can_be_prefix() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
            w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        });
        let raw = w.finish();
        let err =
            Interest::decode(raw).expect_err("MustBeFresh before CanBePrefix is out of spec order");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// A duplicate of any spec-recognized Interest body element is malformed.
    #[test]
    fn a04_interest_decode_rejects_duplicate_nonce() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(tlv_type::NONCE, &[0u8, 0u8, 0u8, 1u8]);
            w.write_tlv(tlv_type::NONCE, &[0u8, 0u8, 0u8, 2u8]);
        });
        let raw = w.finish();
        let err = Interest::decode(raw)
            .expect_err("Duplicate Nonce TLV in Interest body must be rejected");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    #[test]
    fn decode_app_params_without_digest_rejected() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        assert!(
            Interest::decode(raw).is_err(),
            "Interest with ApplicationParameters but no PSDC must be rejected"
        );
    }

    /// Interest carrying `ApplicationParameters` MUST also carry a
    /// `ParametersSha256DigestComponent`.
    #[test]
    fn a02_decode_rejects_app_params_without_psdc() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"audit");
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        let err = Interest::decode(raw).expect_err(
            "Interest with ApplicationParameters but no ParametersSha256DigestComponent must be rejected",
        );
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// A `ParametersSha256DigestComponent` in the Name MUST be the last
    /// component.
    #[test]
    fn a02_a21_decode_rejects_psdc_not_last() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]);
                w.write_tlv(tlv_type::NAME_COMPONENT, b"trailing");
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        let err = Interest::decode(raw)
            .expect_err("Interest with PSDC anywhere but the last position must be rejected");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    /// More than one `ParametersSha256DigestComponent` in a Name is malformed.
    #[test]
    fn a02_decode_rejects_multiple_psdc() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"a");
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]);
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[1u8; 32]);
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"hello");
        });
        let raw = w.finish();
        let err = Interest::decode(raw).expect_err(
            "Interest with more than one ParametersSha256DigestComponent must be rejected",
        );
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    #[test]
    fn decode_empty_name_rejected() {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_tlv(tlv_type::NAME, &[]);
        });
        let raw = w.finish();
        assert!(Interest::decode(raw).is_err());
    }

    #[test]
    fn decode_truncated_errors() {
        let raw = Bytes::from_static(&[0x05, 0x10, 0x07]);
        assert!(Interest::decode(raw).is_err());
    }

    /// `decrement_hop_limit` reduces the wire's HopLimit byte by one and
    /// returns the new value.
    #[test]
    fn d01_decrement_hop_limit_reduces_value_by_one() {
        use crate::Name;

        let name: Name = "/audit/d01".parse().unwrap();
        let wire = crate::encode::InterestBuilder::new(name)
            .hop_limit(7)
            .sign_digest_sha256();
        let (new_wire, new_hl) = decrement_hop_limit(&wire).expect("must find HopLimit TLV");
        assert_eq!(new_hl, 6);

        let i = Interest::decode(new_wire).unwrap();
        assert_eq!(i.hop_limit(), Some(6));
    }

    /// In-place decrement mutates the buffer and matches the allocating form.
    #[test]
    fn d01_decrement_hop_limit_in_place_matches() {
        use crate::Name;

        let name: Name = "/audit/d01".parse().unwrap();
        let wire = crate::encode::InterestBuilder::new(name)
            .hop_limit(7)
            .sign_digest_sha256();
        let mut buf = wire.to_vec();
        let new_hl = decrement_hop_limit_in_place(&mut buf).expect("must find HopLimit TLV");
        assert_eq!(new_hl, 6);

        let i = Interest::decode(Bytes::from(buf)).unwrap();
        assert_eq!(i.hop_limit(), Some(6));
    }

    /// In-place decrement is a no-op (and `None`) when there is no HopLimit TLV.
    #[test]
    fn d01_decrement_hop_limit_in_place_none_on_absent_field() {
        use crate::Name;
        let name: Name = "/audit/d01-none".parse().unwrap();
        let wire = crate::encode::encode_interest(&name, None);
        let mut buf = wire.to_vec();
        let before = buf.clone();
        assert!(decrement_hop_limit_in_place(&mut buf).is_none());
        assert_eq!(
            buf, before,
            "wire must be untouched when no HopLimit present"
        );
    }

    /// Wire without HopLimit returns `None`; callers leave it unchanged.
    #[test]
    fn d01_decrement_hop_limit_none_on_absent_field() {
        use crate::Name;
        let name: Name = "/audit/d01-none".parse().unwrap();
        let wire = crate::encode::encode_interest(&name, None);
        assert!(decrement_hop_limit(&wire).is_none());
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
                // Sig types other than DigestSha256 / DigestBlake3 MUST carry
                // a KeyLocator; emit a stub `/test-key`.
                if !matches!(sig_type_code, 0 | 6) {
                    w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                        w.write_nested(tlv_type::NAME, |w| {
                            w.write_tlv(tlv_type::NAME_COMPONENT, b"test-key");
                        });
                    });
                }
            });
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, sig_value);
        });
        w.finish()
    }

    #[test]
    fn decode_signed_interest_sig_info() {
        let raw = build_signed_interest(&[b"test"], 0, &[0xAB, 0xCD]);
        let i = Interest::decode(raw).unwrap();
        let si = i.sig_info().expect("sig_info present");
        assert_eq!(si.sig_type, crate::SignatureType::DigestSha256);
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
        // No AppParameters → missing required range → signed_region == None.
        let raw = build_signed_interest(&[b"test"], 5, &[0xAB, 0xCD]);
        let i = Interest::decode(raw.clone()).unwrap();
        assert!(
            i.signed_region().is_none(),
            "missing AppParameters should produce no signed region"
        );
    }

    #[test]
    fn decode_signed_interest_signed_region_two_range_shape() {
        // Per ndn-cxx extractSignedRanges, range 1 starts at the first
        // non-PSDC name component's type (0x08), not the outer NAME TLV.
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
                w.write_tlv(tlv_type::PARAMETERS_SHA256, &[0u8; 32]);
            });
            w.write_tlv(tlv_type::APP_PARAMETERS, b"ap");
            w.write_nested(tlv_type::INTEREST_SIGNATURE_INFO, |w| {
                w.write_tlv(tlv_type::SIGNATURE_TYPE, &[5]);
                w.write_nested(tlv_type::KEY_LOCATOR, |w| {
                    w.write_nested(tlv_type::NAME, |w| {
                        w.write_tlv(tlv_type::NAME_COMPONENT, b"test-key");
                    });
                });
            });
            w.write_tlv(tlv_type::INTEREST_SIGNATURE_VALUE, &[0xAB, 0xCD]);
        });
        let raw = w.finish();
        let i = Interest::decode(raw).unwrap();
        let region = i.signed_region().expect("signed region present");
        assert!(!region.is_empty());
        assert_eq!(region[0], tlv_type::NAME_COMPONENT as u8);
        assert!(
            !region.windows(32).any(|w| w == [0u8; 32]),
            "signed region must not contain the 32-zero PSDC placeholder"
        );
        assert!(!region.ends_with(&[0xAB, 0xCD]));
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
        let kl_name = kl.as_name().expect("key_locator is a Name");
        assert_eq!(kl_name.components()[0].value.as_ref(), b"key1");
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
