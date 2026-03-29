use std::sync::Arc;
use std::sync::OnceLock;
use core::time::Duration;

use bytes::Bytes;

use crate::{Name, PacketError};
use crate::tlv_type;
use ndn_tlv::TlvReader;

/// Selectors that control Interest-Data matching.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Selector {
    pub can_be_prefix:  bool,
    pub must_be_fresh:  bool,
}

/// An NDN Interest packet.
///
/// Fields beyond the name and selectors are lazily decoded via `OnceLock`
/// so that pipeline stages that short-circuit (e.g., CS hit) pay no decode cost
/// for fields they never access.
#[derive(Debug)]
pub struct Interest {
    /// Wire-format bytes of the full Interest TLV.
    pub(crate) raw: Bytes,

    /// Name — always decoded eagerly (every stage needs it).
    pub name: Arc<Name>,

    /// Selectors — decoded on first access.
    selectors: OnceLock<Selector>,

    /// Nonce — decoded on first access.
    nonce: OnceLock<Option<u32>>,

    /// Interest lifetime — decoded on first access.
    lifetime: OnceLock<Option<Duration>>,

    /// ApplicationParameters (TLV 0x24) — decoded on first access.
    app_params: OnceLock<Option<Bytes>>,

    /// HopLimit (TLV 0x22) — decoded on first access.
    hop_limit: OnceLock<Option<u8>>,
}

impl Interest {
    /// Construct a minimal Interest with only a name (for testing / app use).
    pub fn new(name: Name) -> Self {
        Self {
            raw:        Bytes::new(),
            name:       Arc::new(name),
            selectors:  OnceLock::new(),
            nonce:      OnceLock::new(),
            lifetime:   OnceLock::new(),
            app_params: OnceLock::new(),
            hop_limit:  OnceLock::new(),
        }
    }

    /// Decode an Interest from raw wire bytes.
    pub fn decode(raw: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(raw.clone());
        let (typ, value) = reader.read_tlv()?;
        if typ != tlv_type::INTEREST {
            return Err(PacketError::UnknownPacketType(typ));
        }
        let mut inner = TlvReader::new(value);

        // Name is mandatory and must come first.
        let (name_typ, name_val) = inner.read_tlv()?;
        if name_typ != tlv_type::NAME {
            return Err(PacketError::UnknownPacketType(name_typ));
        }
        let name = Name::decode(name_val)?;

        // NDN Packet Format v0.3 §2: Interest/Data must have at least one
        // name component.
        if name.is_empty() {
            return Err(PacketError::MalformedPacket("Interest Name must have at least one component".into()));
        }

        Ok(Self {
            raw,
            name:       Arc::new(name),
            selectors:  OnceLock::new(),
            nonce:      OnceLock::new(),
            lifetime:   OnceLock::new(),
            app_params: OnceLock::new(),
            hop_limit:  OnceLock::new(),
        })
    }

    pub fn selectors(&self) -> &Selector {
        self.selectors.get_or_init(|| {
            decode_selectors(&self.raw).unwrap_or_default()
        })
    }

    pub fn nonce(&self) -> Option<u32> {
        *self.nonce.get_or_init(|| decode_nonce(&self.raw).ok().flatten())
    }

    pub fn lifetime(&self) -> Option<Duration> {
        *self.lifetime.get_or_init(|| decode_lifetime(&self.raw).ok().flatten())
    }

    /// The `ApplicationParameters` TLV value (type 0x24), if present.
    ///
    /// Returns `None` when the Interest was constructed without parameters (e.g.
    /// via `Interest::new`) or when the wire format contains no 0x24 TLV.
    pub fn app_parameters(&self) -> Option<&Bytes> {
        self.app_params
            .get_or_init(|| decode_app_params(&self.raw).ok().flatten())
            .as_ref()
    }

    /// HopLimit value (0–255), if present in the wire format.
    ///
    /// Per NDN Packet Format v0.3 §5.2, this is a 1-byte field.
    /// The forwarder must decrement before forwarding and drop if zero.
    pub fn hop_limit(&self) -> Option<u8> {
        *self.hop_limit.get_or_init(|| decode_hop_limit(&self.raw).ok().flatten())
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }
}

fn decode_selectors(raw: &Bytes) -> Result<Selector, PacketError> {
    let mut sel = Selector::default();
    let mut reader = TlvReader::new(raw.clone());
    let (_, value) = reader.read_tlv()?; // outer Interest TLV
    let mut inner = TlvReader::new(value);
    while !inner.is_empty() {
        let (typ, _) = inner.read_tlv()?;
        match typ {
            t if t == tlv_type::CAN_BE_PREFIX  => sel.can_be_prefix  = true,
            t if t == tlv_type::MUST_BE_FRESH  => sel.must_be_fresh  = true,
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
    if raw.is_empty() { return Ok(None); }
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

fn decode_hop_limit(raw: &Bytes) -> Result<Option<u8>, PacketError> {
    if raw.is_empty() { return Ok(None); }
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

    /// Build a complete Interest wire packet for testing.
    fn build_interest(
        components: &[&[u8]],
        nonce: Option<u32>,
        lifetime_ms: Option<u64>,
        can_be_prefix: bool,
        must_be_fresh: bool,
    ) -> Bytes {
        build_interest_full(components, nonce, lifetime_ms, can_be_prefix, must_be_fresh, None)
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
            if can_be_prefix { w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]); }
            if must_be_fresh { w.write_tlv(tlv_type::MUST_BE_FRESH, &[]); }
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

    // ── Interest::new ─────────────────────────────────────────────────────────

    #[test]
    fn new_stores_name() {
        let name = Name::from_components([
            crate::NameComponent::generic(Bytes::from_static(b"test")),
        ]);
        let i = Interest::new(name.clone());
        assert_eq!(*i.name, name);
    }

    #[test]
    fn new_has_no_nonce_or_lifetime() {
        let i = Interest::new(Name::root());
        assert_eq!(i.nonce(), None);
        assert_eq!(i.lifetime(), None);
    }

    // ── Interest::decode ──────────────────────────────────────────────────────

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
        let raw = build_interest(&[b"edu", b"ucla", b"data"], Some(0x1234_5678), Some(8000), true, true);
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
        // Start with DATA type (0x06) instead of INTEREST (0x05).
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
    fn decode_empty_name_rejected() {
        // Interest with zero name components should fail.
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

    #[test]
    fn lazy_fields_decoded_once_and_cached() {
        // Access each lazy field twice; result should be identical.
        let raw = build_interest(&[b"x"], Some(99), Some(1000), true, false);
        let i = Interest::decode(raw).unwrap();
        assert_eq!(i.nonce(), i.nonce());
        assert_eq!(i.lifetime(), i.lifetime());
        assert_eq!(i.selectors(), i.selectors());
    }
}
