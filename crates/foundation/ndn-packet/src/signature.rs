#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use bytes::Bytes;

use crate::{Name, PacketError, tlv_type};
use ndn_tlv::TlvReader;

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
            SignatureType::DigestSha256 => 0,
            SignatureType::SignatureSha256WithRsa => 1,
            SignatureType::SignatureSha256WithEcdsa => 3,
            SignatureType::SignatureHmacWithSha256 => 4,
            SignatureType::SignatureEd25519 => 5,
            SignatureType::Other(c) => *c,
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
///
/// Also decodes the anti-replay fields from InterestSignatureInfo:
/// SignatureNonce (0x26), SignatureTime (0x28), SignatureSeqNum (0x2A).
#[derive(Clone, Debug)]
pub struct SignatureInfo {
    pub sig_type: SignatureType,
    pub key_locator: Option<Arc<Name>>,
    /// Random nonce for anti-replay (NDN Packet Format v0.3 §5.4).
    pub sig_nonce: Option<Bytes>,
    /// Timestamp in milliseconds since Unix epoch (NDN Packet Format v0.3 §5.4).
    pub sig_time: Option<u64>,
    /// Monotonically increasing sequence number (NDN Packet Format v0.3 §5.4).
    pub sig_seq_num: Option<u64>,
}

impl SignatureInfo {
    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(value);
        let mut sig_type = SignatureType::Other(0);
        let mut key_locator = None;
        let mut sig_nonce = None;
        let mut sig_time = None;
        let mut sig_seq_num = None;

        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            match typ {
                t if t == tlv_type::SIGNATURE_TYPE => {
                    let mut code = 0u64;
                    for &b in val.iter() {
                        code = (code << 8) | b as u64;
                    }
                    sig_type = SignatureType::from_code(code);
                }
                t if t == tlv_type::KEY_LOCATOR => {
                    let mut inner = TlvReader::new(val);
                    if !inner.is_empty() {
                        let (kt, kv) = inner.read_tlv()?;
                        if kt == tlv_type::NAME {
                            let name = Name::decode(kv)?;
                            key_locator = Some(Arc::new(name));
                        }
                    }
                }
                t if t == tlv_type::SIGNATURE_NONCE => {
                    sig_nonce = Some(val);
                }
                t if t == tlv_type::SIGNATURE_TIME => {
                    let mut ms = 0u64;
                    for &b in val.iter() {
                        ms = (ms << 8) | b as u64;
                    }
                    sig_time = Some(ms);
                }
                t if t == tlv_type::SIGNATURE_SEQ_NUM => {
                    let mut n = 0u64;
                    for &b in val.iter() {
                        n = (n << 8) | b as u64;
                    }
                    sig_seq_num = Some(n);
                }
                _ => {}
            }
        }
        Ok(Self {
            sig_type,
            key_locator,
            sig_nonce,
            sig_time,
            sig_seq_num,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::build_name_value;
    use ndn_tlv::TlvWriter;

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
            (SignatureType::DigestSha256, 0u64),
            (SignatureType::SignatureSha256WithRsa, 1),
            (SignatureType::SignatureSha256WithEcdsa, 3),
            (SignatureType::SignatureHmacWithSha256, 4),
            (SignatureType::SignatureEd25519, 5),
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

    // ── Anti-replay fields ──────────────────────────────────────────────────

    #[test]
    fn decode_sig_nonce() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        w.write_tlv(crate::tlv_type::SIGNATURE_NONCE, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_nonce.as_deref(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn decode_sig_time() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        let ts: u64 = 1_700_000_000_000; // millis
        w.write_tlv(crate::tlv_type::SIGNATURE_TIME, &ts.to_be_bytes());
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_time, Some(ts));
    }

    #[test]
    fn decode_sig_seq_num() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        w.write_tlv(crate::tlv_type::SIGNATURE_SEQ_NUM, &42u64.to_be_bytes());
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_seq_num, Some(42));
    }

    #[test]
    fn decode_all_anti_replay_fields() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        w.write_tlv(crate::tlv_type::SIGNATURE_NONCE, &[0x01, 0x02]);
        w.write_tlv(crate::tlv_type::SIGNATURE_TIME, &500u64.to_be_bytes());
        w.write_tlv(crate::tlv_type::SIGNATURE_SEQ_NUM, &7u64.to_be_bytes());
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_nonce.as_deref(), Some(&[0x01, 0x02][..]));
        assert_eq!(si.sig_time, Some(500));
        assert_eq!(si.sig_seq_num, Some(7));
    }

    #[test]
    fn decode_no_anti_replay_fields() {
        let raw = build_sig_info(5, None);
        let si = SignatureInfo::decode(raw).unwrap();
        assert!(si.sig_nonce.is_none());
        assert!(si.sig_time.is_none());
        assert!(si.sig_seq_num.is_none());
    }
}
