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
            SignatureType::SignatureEd25519        => 5,
            SignatureType::Other(c)                => *c,
        }
    }

    pub fn from_code(code: u64) -> Self {
        match code {
            0 => SignatureType::DigestSha256,
            1 => SignatureType::SignatureSha256WithRsa,
            3 => SignatureType::SignatureSha256WithEcdsa,
            4 => SignatureType::SignatureHmacWithSha256,
            5 => SignatureType::SignatureEd25519,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_tlv::TlvWriter;
    use crate::name::build_name_value;

    fn build_sig_info(sig_type_code: u8, key_name_components: Option<&[&[u8]]>) -> bytes::Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[sig_type_code]);
        if let Some(comps) = key_name_components {
            w.write_nested(crate::tlv_type::KEY_LOCATOR, |w| {
                let name_val = build_name_value(comps);
                w.write_tlv(crate::tlv_type::NAME, &name_val);
            });
        }
        w.finish()
    }

    // ── SignatureType code round-trips ─────────────────────────────────────────

    #[test]
    fn sig_type_known_codes() {
        let cases = [
            (SignatureType::DigestSha256,             0u64),
            (SignatureType::SignatureSha256WithRsa,   1),
            (SignatureType::SignatureSha256WithEcdsa, 3),
            (SignatureType::SignatureHmacWithSha256,  4),
            (SignatureType::SignatureEd25519,         5),
        ];
        for (sig_type, code) in cases {
            assert_eq!(sig_type.code(), code, "{sig_type:?}");
            assert_eq!(SignatureType::from_code(code), sig_type);
        }
    }

    #[test]
    fn sig_type_other_code_roundtrip() {
        let t = SignatureType::Other(99);
        assert_eq!(t.code(), 99);
        assert_eq!(SignatureType::from_code(99), SignatureType::Other(99));
    }

    // ── SignatureInfo::decode ─────────────────────────────────────────────────

    #[test]
    fn decode_sig_type_only() {
        let raw = build_sig_info(5, None);
        let si = SignatureInfo::decode(raw).unwrap();
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
        assert!(si.key_locator.is_none());
    }

    #[test]
    fn decode_all_known_sig_types() {
        for code in [0u8, 1, 3, 4, 5] {
            let raw = build_sig_info(code, None);
            let si = SignatureInfo::decode(raw).unwrap();
            assert_eq!(si.sig_type.code(), code as u64);
        }
    }

    #[test]
    fn decode_with_key_locator() {
        let raw = build_sig_info(5, Some(&[b"sensor", b"node1", b"KEY", b"abc"]));
        let si = SignatureInfo::decode(raw).unwrap();
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
        let kl = si.key_locator.expect("key_locator present");
        assert_eq!(kl.len(), 4);
        assert_eq!(kl.components()[0].value.as_ref(), b"sensor");
        assert_eq!(kl.components()[3].value.as_ref(), b"abc");
    }

    #[test]
    fn decode_empty_is_other_zero() {
        // No fields — sig_type defaults to Other(0).
        let si = SignatureInfo::decode(bytes::Bytes::new()).unwrap();
        assert_eq!(si.sig_type, SignatureType::Other(0));
        assert!(si.key_locator.is_none());
    }
}
