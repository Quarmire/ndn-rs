//! `KeyLocator` — Name (certificate locator) or raw key digest. Per NDN
//! Packet Format v0.3 §5.2: KEY_LOCATOR (0x1c) wrapping either a NAME
//! (0x07) or a KEY_DIGEST (0x1d).

use alloc::boxed::Box;
use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::codec::TlvCodecError;
use crate::name::{Name, NameError};
use crate::tlv_type;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyLocator {
    Name(Box<Name>),
    KeyDigest(Bytes),
}

impl KeyLocator {
    pub fn encode_to_bytes(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::KEY_LOCATOR, |inner| match self {
            KeyLocator::Name(name) => {
                inner.write_nested(tlv_type::NAME, |name_inner| {
                    for c in name.components() {
                        name_inner.write_tlv(c.typ, &c.value);
                    }
                });
            }
            KeyLocator::KeyDigest(digest) => {
                inner.write_tlv(tlv_type::KEY_DIGEST, digest);
            }
        });
        w.finish()
    }

    pub fn decode_from(r: &mut TlvReader) -> Result<Self, TlvCodecError> {
        let (typ, val) = r.read_tlv()?;
        if typ != tlv_type::KEY_LOCATOR {
            return Err(TlvCodecError::UnexpectedType {
                expected: tlv_type::KEY_LOCATOR,
                found: typ,
            });
        }
        let mut inner = TlvReader::new(val);
        if inner.is_empty() {
            return Err(TlvCodecError::MissingField(tlv_type::KEY_LOCATOR));
        }
        let (kt, kv) = inner.read_tlv()?;
        match kt {
            t if t == tlv_type::NAME => {
                let name = Name::decode(kv)
                    .map_err(|NameError(_)| TlvCodecError::MalformedField(tlv_type::NAME))?;
                Ok(KeyLocator::Name(Box::new(name)))
            }
            t if t == tlv_type::KEY_DIGEST => Ok(KeyLocator::KeyDigest(kv)),
            other => Err(TlvCodecError::UnexpectedType {
                expected: tlv_type::NAME,
                found: other,
            }),
        }
    }

    pub fn as_name(&self) -> Option<&Name> {
        match self {
            KeyLocator::Name(n) => Some(n.as_ref()),
            KeyLocator::KeyDigest(_) => None,
        }
    }

    pub fn as_key_digest(&self) -> Option<&Bytes> {
        match self {
            KeyLocator::KeyDigest(b) => Some(b),
            KeyLocator::Name(_) => None,
        }
    }
}

impl core::fmt::Display for KeyLocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyLocator::Name(n) => write!(f, "{n}"),
            KeyLocator::KeyDigest(b) => {
                write!(f, "digest:")?;
                for byte in b.iter() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl From<Name> for KeyLocator {
    fn from(name: Name) -> Self {
        KeyLocator::Name(Box::new(name))
    }
}

impl From<Bytes> for KeyLocator {
    fn from(digest: Bytes) -> Self {
        KeyLocator::KeyDigest(digest)
    }
}
