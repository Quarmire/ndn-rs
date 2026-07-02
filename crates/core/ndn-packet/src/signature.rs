#[cfg(all(not(feature = "std"), not(target_arch = "wasm32")))]
use alloc::boxed::Box;

use crate::compat::Arc;

use bytes::Bytes;

use crate::{Name, PacketError, tlv_type};
use ndn_foundation_types::KeyLocator;
use ndn_tlv::TlvReader;

/// The algorithm that produced a packet's signature (NDN Packet Format v0.3
/// SignatureType).
///
/// Selects both how the SignatureValue is computed and how a verifier must
/// check it — e.g. [`DigestSha256`](Self::DigestSha256) is an unkeyed integrity
/// digest (no authentication), while the `SignatureSha256With*` and
/// [`SignatureEd25519`](Self::SignatureEd25519) variants are public-key signed.
/// Converts to/from the on-wire numeric code via [`code`](Self::code) /
/// [`from_code`](Self::from_code); an unrecognized code round-trips through
/// [`Other`](Self::Other) so a packet signed with a newer algorithm still
/// decodes instead of failing.
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

    /// Required SignatureValue length per `signature.html`:
    /// DigestSha256/HmacWithSha256/DigestBlake3/SignatureBlake3Keyed = 32,
    /// Ed25519 = 64. `None` for RSA/ECDSA (variable) and unknown algorithms.
    pub fn required_signature_value_len(&self) -> Option<usize> {
        match self {
            SignatureType::DigestSha256 => Some(32),
            SignatureType::SignatureHmacWithSha256 => Some(32),
            SignatureType::SignatureEd25519 => Some(64),
            SignatureType::Other(6) => Some(32),
            SignatureType::Other(7) => Some(32),
            SignatureType::SignatureSha256WithRsa
            | SignatureType::SignatureSha256WithEcdsa
            | SignatureType::Other(_) => None,
        }
    }
}

/// SignatureInfo TLV — algorithm, optional key locator, and anti-replay
/// fields (NDN Packet Format v0.3 §5.4).
#[derive(Clone, Debug)]
pub struct SignatureInfo {
    pub sig_type: SignatureType,
    pub key_locator: Option<KeyLocator>,
    pub sig_nonce: Option<Bytes>,
    pub sig_time: Option<u64>,
    pub sig_seq_num: Option<u64>,
}

impl SignatureInfo {
    pub fn key_locator_name(&self) -> Option<Arc<Name>> {
        match &self.key_locator {
            Some(KeyLocator::Name(n)) => Some(Arc::new((**n).clone())),
            _ => None,
        }
    }

    pub fn key_digest_bytes(&self) -> Option<&Bytes> {
        match &self.key_locator {
            Some(KeyLocator::KeyDigest(b)) => Some(b),
            _ => None,
        }
    }

    pub fn decode(value: Bytes) -> Result<Self, PacketError> {
        let mut reader = TlvReader::new(value);
        let mut sig_type_opt: Option<SignatureType> = None;
        let mut key_locator: Option<KeyLocator> = None;
        let mut sig_nonce = None;
        let mut sig_time = None;
        let mut sig_seq_num = None;

        while !reader.is_empty() {
            let (typ, val) = reader.read_tlv()?;
            match typ {
                t if t == tlv_type::SIGNATURE_TYPE => {
                    let code = crate::decode_nni(&val)?;
                    sig_type_opt = Some(SignatureType::from_code(code));
                }
                t if t == tlv_type::KEY_LOCATOR => {
                    let mut inner = TlvReader::new(val);
                    if !inner.is_empty() {
                        let (kt, kv) = inner.read_tlv()?;
                        if kt == tlv_type::NAME {
                            let name = Name::decode(kv)?;
                            key_locator = Some(KeyLocator::Name(Box::new(name)));
                        } else if kt == tlv_type::KEY_DIGEST {
                            key_locator = Some(KeyLocator::KeyDigest(kv));
                        }
                    }
                }
                t if t == tlv_type::SIGNATURE_NONCE => {
                    sig_nonce = Some(val);
                }
                t if t == tlv_type::SIGNATURE_TIME => {
                    let ms = crate::decode_nni(&val)?;
                    sig_time = Some(ms);
                }
                t if t == tlv_type::SIGNATURE_SEQ_NUM => {
                    let n = crate::decode_nni(&val)?;
                    sig_seq_num = Some(n);
                }
                t if t == tlv_type::VALIDITY_PERIOD => {
                    // Critical TLV 0xFD (Certificate Format v2). Acknowledged
                    // here so the critical-bit check below does not reject
                    // legitimate certs; the cert layer parses it separately.
                    let _ = val;
                }
                _ => {
                    if crate::is_critical_tlv_type(typ) {
                        return Err(PacketError::MalformedPacket(
                            "unknown critical TLV-TYPE in SignatureInfo body".into(),
                        ));
                    }
                }
            }
        }

        // KeyLocator presence rules per signature.html KeyLocator table:
        // codes {0, 6} MUST NOT have one; {1, 3, 4, 5, 7} MUST. Unknown
        // types are unconstrained.
        if let Some(ref st) = sig_type_opt {
            match st.code() {
                0 | 6 if key_locator.is_some() => {
                    return Err(PacketError::KeyLocatorRule {
                        sig_type_code: st.code(),
                    });
                }
                1 | 3 | 4 | 5 | 7 if key_locator.is_none() => {
                    return Err(PacketError::KeyLocatorRule {
                        sig_type_code: st.code(),
                    });
                }
                _ => {}
            }
        }

        let sig_type = sig_type_opt.unwrap_or(SignatureType::Other(0));
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

    #[test]
    fn n04_sig_info_decode_rejects_unknown_critical_tlv() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
        w.write_tlv(0x99, b"x");
        let err = SignatureInfo::decode(w.finish())
            .expect_err("unknown critical TLV inside SignatureInfo must be rejected");
        match err {
            PacketError::MalformedPacket(_) => {}
            other => panic!("expected MalformedPacket, got {other:?}"),
        }
    }

    #[test]
    fn n04_sig_info_decode_accepts_unknown_non_critical_tlv() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
        w.write_tlv(0x70, b"opaque");
        SignatureInfo::decode(w.finish())
            .expect("unknown non-critical TLV inside SignatureInfo must still decode");
    }

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

    #[test]
    fn decode_sig_type_only() {
        let raw = build_sig_info(0, None);
        let si = SignatureInfo::decode(raw).unwrap();
        assert_eq!(si.sig_type, SignatureType::DigestSha256);
        assert!(si.key_locator.is_none());
    }

    #[test]
    fn decode_all_known_sig_types() {
        let raw = build_sig_info(0u8, None);
        let si = SignatureInfo::decode(raw).unwrap();
        assert_eq!(si.sig_type.code(), 0u64);
        for code in [1u8, 3, 4, 5] {
            let raw = build_sig_info(code, Some(&[b"key"]));
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
        let kl_name = match &kl {
            KeyLocator::Name(n) => n.as_ref(),
            _ => panic!("expected KeyLocator::Name"),
        };
        assert_eq!(kl_name.len(), 4);
        assert_eq!(kl_name.components()[0].value.as_ref(), b"sensor");
        assert_eq!(kl_name.components()[3].value.as_ref(), b"abc");
    }

    #[test]
    fn decode_with_key_digest_locator() {
        let digest = [0xABu8; 32];
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        w.write_nested(crate::tlv_type::KEY_LOCATOR, |w| {
            w.write_tlv(crate::tlv_type::KEY_DIGEST, &digest);
        });
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_type, SignatureType::SignatureEd25519);
        let kd = si.key_digest_bytes().expect("key_digest present");
        assert_eq!(kd.len(), 32);
        assert!(kd.iter().all(|&b| b == 0xAB));
        assert!(si.key_locator_name().is_none());
    }

    #[test]
    fn decode_empty_is_other_zero() {
        let si = SignatureInfo::decode(bytes::Bytes::new()).unwrap();
        assert_eq!(si.sig_type, SignatureType::Other(0));
        assert!(si.key_locator.is_none());
    }

    #[test]
    fn decode_sig_nonce() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
        w.write_tlv(crate::tlv_type::SIGNATURE_NONCE, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_nonce.as_deref(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    }

    #[test]
    fn decode_sig_time() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
        let ts: u64 = 1_700_000_000_000;
        w.write_tlv(crate::tlv_type::SIGNATURE_TIME, &ts.to_be_bytes());
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_time, Some(ts));
    }

    #[test]
    fn decode_sig_seq_num() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
        w.write_tlv(crate::tlv_type::SIGNATURE_SEQ_NUM, &42u64.to_be_bytes());
        let si = SignatureInfo::decode(w.finish()).unwrap();
        assert_eq!(si.sig_seq_num, Some(42));
    }

    #[test]
    fn decode_all_anti_replay_fields() {
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[0]);
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
        let raw = build_sig_info(0, None);
        let si = SignatureInfo::decode(raw).unwrap();
        assert!(si.sig_nonce.is_none());
        assert!(si.sig_time.is_none());
        assert!(si.sig_seq_num.is_none());
    }

    #[test]
    fn key_locator_name_accessor() {
        let raw = build_sig_info(5, Some(&[b"sensor", b"node1"]));
        let si = SignatureInfo::decode(raw).unwrap();
        let name = si.key_locator_name().expect("accessor returns name");
        assert_eq!(name.len(), 2);
        assert_eq!(name.components()[0].value.as_ref(), b"sensor");
    }

    #[test]
    fn key_digest_bytes_accessor() {
        let digest = [0xBBu8; 32];
        let mut w = TlvWriter::new();
        w.write_tlv(crate::tlv_type::SIGNATURE_TYPE, &[5]);
        w.write_nested(crate::tlv_type::KEY_LOCATOR, |w| {
            w.write_tlv(crate::tlv_type::KEY_DIGEST, &digest);
        });
        let si = SignatureInfo::decode(w.finish()).unwrap();
        let kd = si.key_digest_bytes().expect("accessor returns digest");
        assert!(kd.iter().all(|&b| b == 0xBB));
        assert!(si.key_locator_name().is_none());
    }

    // KeyLocator presence rules per signature.html and blake3-signature-spec.md.

    /// DigestSha256 (0): KeyLocator MUST NOT be present.
    #[test]
    fn a15_keylocator_digest_sha256_rejects_locator() {
        let raw = build_sig_info(0, Some(&[b"key"]));
        let err =
            SignatureInfo::decode(raw).expect_err("DigestSha256 with KeyLocator must be rejected");
        assert!(
            matches!(err, PacketError::KeyLocatorRule { sig_type_code: 0 }),
            "expected KeyLocatorRule(0), got {err:?}"
        );
        let raw_ok = build_sig_info(0, None);
        SignatureInfo::decode(raw_ok).expect("DigestSha256 without KeyLocator must decode");
    }

    /// Signing types (1, 3, 4, 5): KeyLocator MUST be present.
    #[test]
    fn a15_keylocator_signing_types_require_locator() {
        for code in [1u8, 3, 4, 5] {
            let raw_bad = build_sig_info(code, None);
            let err = SignatureInfo::decode(raw_bad).expect_err(&format!(
                "sig_type={code} without KeyLocator must be rejected"
            ));
            assert!(
                matches!(err, PacketError::KeyLocatorRule { .. }),
                "sig_type={code}: expected KeyLocatorRule, got {err:?}"
            );
            let raw_ok = build_sig_info(code, Some(&[b"key"]));
            SignatureInfo::decode(raw_ok)
                .unwrap_or_else(|e| panic!("sig_type={code} with KeyLocator must decode: {e}"));
        }
    }

    /// DigestBlake3 (6): KeyLocator MUST NOT be present.
    #[test]
    fn a15_keylocator_digest_blake3_rejects_locator() {
        let raw = build_sig_info(6, Some(&[b"key"]));
        let err = SignatureInfo::decode(raw)
            .expect_err("DigestBlake3 (6) with KeyLocator must be rejected");
        assert!(
            matches!(err, PacketError::KeyLocatorRule { sig_type_code: 6 }),
            "expected KeyLocatorRule(6), got {err:?}"
        );
        let raw_ok = build_sig_info(6, None);
        SignatureInfo::decode(raw_ok).expect("DigestBlake3 without KeyLocator must decode");
    }

    /// SignatureBlake3Keyed (7): KeyLocator MUST be present.
    #[test]
    fn a15_keylocator_blake3_keyed_requires_locator() {
        let raw_bad = build_sig_info(7, None);
        let err = SignatureInfo::decode(raw_bad)
            .expect_err("SignatureBlake3Keyed (7) without KeyLocator must be rejected");
        assert!(
            matches!(err, PacketError::KeyLocatorRule { sig_type_code: 7 }),
            "expected KeyLocatorRule(7), got {err:?}"
        );
        let raw_ok = build_sig_info(7, Some(&[b"key"]));
        SignatureInfo::decode(raw_ok).expect("SignatureBlake3Keyed with KeyLocator must decode");
    }

    /// Unknown / Other types: no KeyLocator rule applied.
    #[test]
    fn a15_keylocator_unknown_type_no_validation() {
        let raw_no_kl = build_sig_info(99, None);
        SignatureInfo::decode(raw_no_kl).expect("Other(99) without KeyLocator must decode");
        let raw_with_kl = build_sig_info(99, Some(&[b"key"]));
        SignatureInfo::decode(raw_with_kl).expect("Other(99) with KeyLocator must decode");
    }
}
