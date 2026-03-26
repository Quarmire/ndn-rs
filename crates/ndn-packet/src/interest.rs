use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

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
}

impl Interest {
    /// Construct a minimal Interest with only a name (for testing / app use).
    pub fn new(name: Name) -> Self {
        Self {
            raw:      Bytes::new(),
            name:     Arc::new(name),
            selectors: OnceLock::new(),
            nonce:    OnceLock::new(),
            lifetime: OnceLock::new(),
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

        Ok(Self {
            raw,
            name: Arc::new(name),
            selectors: OnceLock::new(),
            nonce:    OnceLock::new(),
            lifetime: OnceLock::new(),
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
