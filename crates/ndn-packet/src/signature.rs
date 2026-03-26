use bytes::Bytes;

use crate::{Name, PacketError, tlv_type};
use ndn_tlv::TlvReader;
use std::sync::Arc;

/// NDN signature algorithm identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureType {
    DigestSha256,
    SignatureSha256WithRsa,
    SignatureSha256WithEcdsa,
    SignatureHmacWithSha256,
    SignatureEd25519,
    Other(u64),
}

impl SignatureType {
    pub fn code(&self) -> u64 {
        match self {
            SignatureType::DigestSha256            => 0,
            SignatureType::SignatureSha256WithRsa  => 1,
            SignatureType::SignatureSha256WithEcdsa => 3,
            SignatureType::SignatureHmacWithSha256 => 4,
            SignatureType::SignatureEd25519        => 7,
            SignatureType::Other(c)                => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            0 => SignatureType::DigestSha256,
            1 => SignatureType::SignatureSha256WithRsa,
            3 => SignatureType::SignatureSha256WithEcdsa,
            4 => SignatureType::SignatureHmacWithSha256,
            7 => SignatureType::SignatureEd25519,
            c => SignatureType::Other(c),
        }
    }
}

/// SignatureInfo TLV — algorithm and optional key locator.
#[derive(Clone, Debug)]
pub struct SignatureInfo {
    pub sig_type:    SignatureType,
    pub key_locator: Option<Arc<Name>>,
}

impl SignatureInfo {
    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(value);
        let mut sig_type = SignatureType::Other(0);
        let mut key_locator = None;

        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            match typ {
                t if t == tlv_type::SIGNATURE_TYPE => {
                    let mut code = 0u64;
                    for &b in val.iter() { code = (code << 8) | b as u64; }
                    sig_type = SignatureType::from_code(code);
                }
                t if t == tlv_type::KEY_LOCATOR => {
                    // KeyLocator contains a Name TLV.
                    let mut inner = TlvReader::new(val);
                    if !inner.is_empty() {
                        let (kt, kv) = inner.read_tlv()?;
                        if kt == tlv_type::NAME {
                            let name = Name::decode(kv)?;
                            key_locator = Some(Arc::new(name));
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Self { sig_type, key_locator })
    }
}
