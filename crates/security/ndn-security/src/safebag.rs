//! NDN SafeBag — wasm-compatible spec-canonical encoder/decoder for the
//! ndn-cxx `safe-bag` wire format
//! (<https://github.com/named-data/ndn-cxx/blob/master/docs/specs/safe-bag.rst>),
//! for transferring an identity (a certificate plus its password-encrypted
//! private key):
//!
//! ```text
//! SafeBag (0x80) {
//!     Data (0x06) { ... certificate ... }
//!     EncryptedKey (0x81) { EncryptedPrivateKeyInfo per RFC 5958 }
//! }
//! ```
//!
//! The certificate is the complete Data packet wire encoding including its
//! `0x06` header. EncryptedKey is the raw DER produced by the rustcrypto
//! `pkcs8` `encryption` feature: PBES2 with PBKDF2-HMAC-SHA256 and
//! AES-256-CBC — matching `ndnsec export` and OpenSSL's
//! `i2d_PKCS8PrivateKey_bio` defaults.
//!
//! Algorithm support (the ndn-cxx interop conversions, used by
//! [`crate::file_tpm::FileTpm`]): RSA converts PKCS#1 to PKCS#8 then
//! encrypts; ECDSA-P256 converts SEC1 to PKCS#8; Ed25519 is already PKCS#8
//! on disk. RSA and ECDSA roundtrip with `ndnsec export`/`import`; Ed25519
//! is ndn-rs-only (ndn-cxx `tpm-file` has no Ed25519 path).

#![deny(rust_2018_idioms)]

use bytes::Bytes;
use ndn_packet::tlv_type;
use ndn_tlv::{TlvReader, TlvWriter};
use thiserror::Error;

use crate::file_tpm::{FileTpmError, TpmKeyKind};

const TLV_SAFE_BAG: u64 = 0x80; // 128
const TLV_ENCRYPTED_KEY: u64 = 0x81; // 129

/// Errors specific to SafeBag encode/decode, PKCS#8 encryption, and the
/// ndn-cxx key-format conversions.
#[derive(Debug, Error)]
pub enum SafeBagError {
    #[error("malformed SafeBag TLV: {0}")]
    Malformed(String),
    #[error("PKCS#8 encryption error: {0}")]
    Pkcs8(String),
    #[error("Ed25519 PKCS#8 conversion: {0}")]
    Ed25519(String),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
    #[error("file tpm error: {0}")]
    Tpm(#[from] FileTpmError),
    #[error("unsupported algorithm in SafeBag: {0}")]
    UnsupportedAlgorithm(String),
}

/// A decoded SafeBag: the certificate Data wire bytes plus the
/// password-encrypted PKCS#8 private key DER.
#[derive(Clone, Debug)]
pub struct SafeBag {
    /// Full wire-encoded certificate Data packet (TLV starting at 0x06);
    /// opaque to SafeBag.
    pub certificate: Bytes,
    /// `EncryptedPrivateKeyInfo` DER (RFC 5958). Recover the
    /// `PrivateKeyInfo` via [`SafeBag::decrypt_pkcs8`].
    pub encrypted_key: Bytes,
}

impl SafeBag {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_SAFE_BAG, |w| {
            w.write_raw(&self.certificate);
            w.write_tlv(TLV_ENCRYPTED_KEY, &self.encrypted_key);
        });
        w.finish()
    }

    /// Strict: validates the outer SafeBag, inner Data, and inner EncryptedKey types.
    pub fn decode(wire: &[u8]) -> Result<Self, SafeBagError> {
        let mut outer = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = outer
            .read_tlv()
            .map_err(|e| SafeBagError::Malformed(format!("outer TLV: {e:?}")))?;
        if typ != TLV_SAFE_BAG {
            return Err(SafeBagError::Malformed(format!(
                "expected SafeBag (0x80), got 0x{typ:x}"
            )));
        }

        let mut inner = TlvReader::new(body);

        let (cert_type, cert_body) = inner
            .read_tlv()
            .map_err(|e| SafeBagError::Malformed(format!("certificate TLV: {e:?}")))?;
        if cert_type != tlv_type::DATA {
            return Err(SafeBagError::Malformed(format!(
                "expected Data (0x06) inside SafeBag, got 0x{cert_type:x}"
            )));
        }
        // TlvReader consumed the header; re-emit the full Data TLV.
        let mut cert_w = TlvWriter::new();
        cert_w.write_tlv(tlv_type::DATA, &cert_body);
        let certificate = cert_w.finish();

        let (ek_type, ek_body) = inner
            .read_tlv()
            .map_err(|e| SafeBagError::Malformed(format!("EncryptedKey TLV: {e:?}")))?;
        if ek_type != TLV_ENCRYPTED_KEY {
            return Err(SafeBagError::Malformed(format!(
                "expected EncryptedKey (0x81), got 0x{ek_type:x}"
            )));
        }

        Ok(Self {
            certificate,
            encrypted_key: ek_body,
        })
    }

    /// Wraps an unencrypted PKCS#8 `PrivateKeyInfo` DER under PBES2 /
    /// PBKDF2-HMAC-SHA256 / AES-256-CBC (`ndnsec export`-compatible;
    /// matches OpenSSL `PKCS8_encrypt` defaults).
    pub fn encrypt(
        certificate: Bytes,
        pkcs8_pki_der: &[u8],
        password: &[u8],
    ) -> Result<Self, SafeBagError> {
        use pkcs8::PrivateKeyInfo;
        use rand_core::RngCore;
        let pki = PrivateKeyInfo::try_from(pkcs8_pki_der)
            .map_err(|e| SafeBagError::Pkcs8(format!("parse PrivateKeyInfo: {e}")))?;
        let mut salt = [0u8; 16];
        let mut iv = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut salt);
        rand_core::OsRng.fill_bytes(&mut iv);
        // PBKDF2 iterations raised above the legacy 2048 default per modern
        // guidance (audit SB-2); the count is embedded and read on import, so
        // ndnsec/ndn-cxx interop is preserved.
        let params = pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(600_000, &salt, &iv)
            .map_err(|e| SafeBagError::Pkcs8(format!("pbes2 params: {e}")))?;
        let encrypted = pki
            .encrypt_with_params(params, password)
            .map_err(|e| SafeBagError::Pkcs8(format!("encrypt: {e}")))?;
        Ok(Self {
            certificate,
            encrypted_key: Bytes::copy_from_slice(encrypted.as_bytes()),
        })
    }

    /// Returns the unencrypted PKCS#8 `PrivateKeyInfo` DER; the caller
    /// dispatches on the algorithm OID or uses [`Self::decrypt_ed25519_seed`].
    pub fn decrypt_pkcs8(&self, password: &[u8]) -> Result<Vec<u8>, SafeBagError> {
        use pkcs8::EncryptedPrivateKeyInfo;
        let epki = EncryptedPrivateKeyInfo::try_from(&self.encrypted_key[..])
            .map_err(|e| SafeBagError::Pkcs8(format!("parse EncryptedPrivateKeyInfo: {e}")))?;
        let decrypted = epki
            .decrypt(password)
            .map_err(|e| SafeBagError::Pkcs8(format!("decrypt: {e}")))?;
        Ok(decrypted.as_bytes().to_vec())
    }

    /// Alias of [`Self::decrypt_pkcs8`] under the retired interop wrapper's
    /// method name (kept for `safe_bag` path compatibility).
    pub fn decrypt_key(&self, password: &[u8]) -> Result<Vec<u8>, SafeBagError> {
        self.decrypt_pkcs8(password)
    }

    pub fn decrypt_ed25519_seed(&self, password: &[u8]) -> Result<[u8; 32], SafeBagError> {
        let pkcs8 = self.decrypt_pkcs8(password)?;
        pkcs8_to_ed25519_seed(&pkcs8)
    }
}

/// Identified by the PKCS#8 `PrivateKeyAlgorithm` OID. `Ed25519`
/// (1.3.101.112) is not understood by ndn-cxx / NFD; `EcdsaP256`
/// (1.2.840.10045.2.1 + secp256r1) interops with them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SafeBagAlgorithm {
    Ed25519,
    EcdsaP256,
    /// Raw OID dotted string for routing to bespoke signers.
    Other(String),
}

impl SafeBag {
    /// Determines the signing algorithm without exposing the secret seed.
    pub fn algorithm(&self, password: &[u8]) -> Result<SafeBagAlgorithm, SafeBagError> {
        use pkcs8::PrivateKeyInfo;
        let pkcs8 = self.decrypt_pkcs8(password)?;
        let pki = PrivateKeyInfo::try_from(&pkcs8[..])
            .map_err(|e| SafeBagError::Pkcs8(format!("parse PrivateKeyInfo: {e}")))?;
        let oid = pki.algorithm.oid.to_string();
        Ok(match oid.as_str() {
            "1.3.101.112" => SafeBagAlgorithm::Ed25519,
            "1.2.840.10045.2.1" => SafeBagAlgorithm::EcdsaP256,
            other => SafeBagAlgorithm::Other(other.to_string()),
        })
    }
}

pub fn ed25519_seed_to_pkcs8(seed: &[u8; 32]) -> Result<Vec<u8>, SafeBagError> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    let sk = SigningKey::from_bytes(seed);
    let doc = sk
        .to_pkcs8_der()
        .map_err(|e| SafeBagError::Ed25519(format!("to_pkcs8_der: {e}")))?;
    Ok(doc.as_bytes().to_vec())
}

pub fn pkcs8_to_ed25519_seed(pkcs8_der: &[u8]) -> Result<[u8; 32], SafeBagError> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    let sk = SigningKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| SafeBagError::Ed25519(format!("from_pkcs8_der: {e}")))?;
    Ok(sk.to_bytes())
}

// ---------------------------------------------------------------------------
// ndn-cxx `tpm-file` on-disk key-format conversions (from the retired
// `safe_bag` interop wrapper); consumed by `crate::file_tpm`.
// ---------------------------------------------------------------------------

/// PKCS#1 `RSAPrivateKey` -> PKCS#8 `PrivateKeyInfo` (DER).
pub(crate) fn rsa_pkcs1_to_pkcs8(pkcs1_der: &[u8]) -> Result<Vec<u8>, SafeBagError> {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    let sk = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| SafeBagError::KeyConversion(format!("rsa pkcs1 parse: {e}")))?;
    let pkcs8_doc = sk
        .to_pkcs8_der()
        .map_err(|e| SafeBagError::KeyConversion(format!("rsa to pkcs8: {e}")))?;
    Ok(pkcs8_doc.as_bytes().to_vec())
}

/// PKCS#8 `PrivateKeyInfo` (RSA) -> PKCS#1 `RSAPrivateKey` (DER).
pub(crate) fn rsa_pkcs8_to_pkcs1(pkcs8_der: &[u8]) -> Result<Vec<u8>, SafeBagError> {
    use pkcs1::EncodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    let sk = RsaPrivateKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| SafeBagError::KeyConversion(format!("rsa pkcs8 parse: {e}")))?;
    let pkcs1_doc = sk
        .to_pkcs1_der()
        .map_err(|e| SafeBagError::KeyConversion(format!("rsa to pkcs1: {e}")))?;
    Ok(pkcs1_doc.as_bytes().to_vec())
}

/// SEC1 `ECPrivateKey` (P-256) -> PKCS#8 `PrivateKeyInfo` (DER).
/// Hand-extracts the 32-byte scalar to dodge `from_sec1_der`'s
/// AlgorithmIdentifier-parameters check.
pub(crate) fn ec_sec1_to_pkcs8(sec1_der: &[u8]) -> Result<Vec<u8>, SafeBagError> {
    use p256_ecdsa::SecretKey;
    use p256_ecdsa::pkcs8::EncodePrivateKey;

    let scalar = crate::file_tpm::parse_sec1_p256_priv_scalar(sec1_der)?;
    let secret = SecretKey::from_slice(&scalar)
        .map_err(|e| SafeBagError::KeyConversion(format!("p256 from scalar: {e}")))?;
    let pkcs8_doc = secret
        .to_pkcs8_der()
        .map_err(|e| SafeBagError::KeyConversion(format!("p256 to pkcs8: {e}")))?;
    Ok(pkcs8_doc.as_bytes().to_vec())
}

/// PKCS#8 `PrivateKeyInfo` (P-256 ECDSA) -> SEC1 `ECPrivateKey` (DER).
pub(crate) fn ec_pkcs8_to_sec1(pkcs8_der: &[u8]) -> Result<Vec<u8>, SafeBagError> {
    use p256_ecdsa::SecretKey;
    use p256_ecdsa::pkcs8::DecodePrivateKey;

    let secret = SecretKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| SafeBagError::KeyConversion(format!("p256 pkcs8 parse: {e}")))?;
    let sec1_doc = secret
        .to_sec1_der()
        .map_err(|e| SafeBagError::KeyConversion(format!("p256 to sec1: {e}")))?;
    Ok(sec1_doc.as_slice().to_vec())
}

pub(crate) fn detect_pkcs8_algorithm(pkcs8_der: &[u8]) -> Result<TpmKeyKind, SafeBagError> {
    use pkcs8::PrivateKeyInfo;
    let pki = PrivateKeyInfo::try_from(pkcs8_der)
        .map_err(|e| SafeBagError::Pkcs8(format!("PrivateKeyInfo parse: {e}")))?;
    let oid = pki.algorithm.oid;
    if oid.to_string() == "1.2.840.113549.1.1.1" {
        Ok(TpmKeyKind::Rsa)
    } else if oid.to_string() == "1.2.840.10045.2.1" {
        Ok(TpmKeyKind::EcdsaP256)
    } else if oid.to_string() == "1.3.101.112" {
        Ok(TpmKeyKind::Ed25519)
    } else {
        Err(SafeBagError::UnsupportedAlgorithm(format!(
            "unknown PKCS#8 algorithm OID {oid}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cert(payload: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::DATA, |w| {
            w.write_nested(tlv_type::NAME, |w| {
                w.write_tlv(tlv_type::NAME_COMPONENT, b"test");
            });
            w.write_tlv(tlv_type::CONTENT, payload);
        });
        w.finish()
    }

    #[test]
    fn ed25519_seed_pkcs8_roundtrip() {
        let seed = [0x42u8; 32];
        let pkcs8 = ed25519_seed_to_pkcs8(&seed).expect("encode");
        let recovered = pkcs8_to_ed25519_seed(&pkcs8).expect("decode");
        assert_eq!(seed, recovered);
    }

    #[test]
    fn safebag_encrypt_decrypt_ed25519() {
        let seed = [0xAAu8; 32];
        let pkcs8 = ed25519_seed_to_pkcs8(&seed).expect("encode pkcs8");
        let cert = fake_cert(b"identity-cert");
        let bag = SafeBag::encrypt(cert.clone(), &pkcs8, b"hunter2").expect("encrypt");

        let recovered = bag.decrypt_ed25519_seed(b"hunter2").expect("decrypt");
        assert_eq!(seed, recovered);

        assert!(bag.decrypt_ed25519_seed(b"wrong").is_err());

        assert_eq!(bag.certificate, cert);
    }

    #[test]
    fn algorithm_detection_ed25519() {
        let seed = [0x55u8; 32];
        let pkcs8 = ed25519_seed_to_pkcs8(&seed).expect("encode pkcs8");
        let bag = SafeBag::encrypt(fake_cert(b"c"), &pkcs8, b"pw").expect("encrypt");
        assert_eq!(bag.algorithm(b"pw").unwrap(), SafeBagAlgorithm::Ed25519);
    }

    #[test]
    fn algorithm_detection_ecdsa_p256() {
        use p256_ecdsa::SecretKey;
        use p256_ecdsa::pkcs8::EncodePrivateKey;
        let sk = SecretKey::random(&mut rand_core::OsRng);
        let pkcs8 = sk.to_pkcs8_der().expect("encode ecdsa pkcs8");
        let bag = SafeBag::encrypt(fake_cert(b"c"), pkcs8.as_bytes(), b"pw").expect("encrypt");
        assert_eq!(bag.algorithm(b"pw").unwrap(), SafeBagAlgorithm::EcdsaP256);
    }

    #[test]
    fn safebag_encode_decode_roundtrip() {
        let seed = [0x77u8; 32];
        let pkcs8 = ed25519_seed_to_pkcs8(&seed).expect("encode pkcs8");
        let cert = fake_cert(b"hello");
        let bag = SafeBag::encrypt(cert.clone(), &pkcs8, b"pw").expect("encrypt");

        let wire = bag.encode();
        let parsed = SafeBag::decode(&wire).expect("decode");
        assert_eq!(parsed.certificate, cert);

        let recovered = parsed.decrypt_ed25519_seed(b"pw").expect("decrypt parsed");
        assert_eq!(seed, recovered);
    }

    #[test]
    fn safebag_decode_rejects_wrong_outer_type() {
        let wire = [0x06, 0x01, 0xff];
        assert!(SafeBag::decode(&wire).is_err());
    }
}

/// Tests carried over verbatim from the retired `safe_bag` interop wrapper,
/// now exercising the unified codec (proof the merge changed no wire or
/// conversion behavior).
#[cfg(test)]
mod interop_tests {
    use super::*;

    /// Minimal `0x06 LL <body>` Data TLV; SafeBag treats it opaquely.
    fn fake_cert(body: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(tlv_type::DATA, body);
        w.finish()
    }

    #[test]
    fn safebag_tlv_roundtrip() {
        let cert = fake_cert(b"fake certificate body");
        let sb = SafeBag {
            certificate: cert.clone(),
            encrypted_key: Bytes::from_static(b"opaque encrypted key bytes"),
        };
        let wire = sb.encode();
        assert_eq!(wire[0], 0x80, "outer TLV must be SafeBag (0x80)");
        let decoded = SafeBag::decode(&wire).unwrap();
        assert_eq!(decoded.certificate, cert);
        assert_eq!(decoded.encrypted_key, sb.encrypted_key);
    }

    #[test]
    fn safebag_decode_rejects_wrong_outer_type() {
        let mut w = TlvWriter::new();
        w.write_tlv(tlv_type::DATA, b"oops");
        let wire = w.finish();
        match SafeBag::decode(&wire) {
            Err(SafeBagError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn pkcs8_encrypt_decrypt_roundtrip_ed25519() {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pkcs8 = sk.to_pkcs8_der().unwrap();

        let cert = fake_cert(b"ed25519 cert");
        let pw = b"correct horse battery staple";

        let sb = SafeBag::encrypt(cert.clone(), pkcs8.as_bytes(), pw).unwrap();
        assert!(
            sb.encrypted_key.windows(32).all(|w| w != seed),
            "encrypted key leaked the seed"
        );
        let decrypted = sb.decrypt_key(pw).unwrap();
        assert_eq!(&decrypted[..], pkcs8.as_bytes());

        assert!(sb.decrypt_key(b"wrong password").is_err());

        let wire = sb.encode();
        let sb2 = SafeBag::decode(&wire).unwrap();
        assert_eq!(sb2.decrypt_key(pw).unwrap(), decrypted);
    }

    #[test]
    fn rsa_pkcs1_pkcs8_roundtrip() {
        use pkcs1::EncodeRsaPrivateKey;
        use rsa::RsaPrivateKey;
        // 1024-bit key for test speed.
        let mut rng = rsa::rand_core::OsRng;
        let sk = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pkcs1 = sk.to_pkcs1_der().unwrap();
        let pkcs8 = rsa_pkcs1_to_pkcs8(pkcs1.as_bytes()).unwrap();
        let pkcs1_again = rsa_pkcs8_to_pkcs1(&pkcs8).unwrap();
        assert_eq!(pkcs1.as_bytes(), pkcs1_again.as_slice());
    }

    #[test]
    fn ec_sec1_pkcs8_roundtrip() {
        use p256_ecdsa::SecretKey;
        use p256_ecdsa::pkcs8::EncodePrivateKey;
        // Fixed scalar so the roundtrip is deterministic.
        let scalar = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD,
            0xDE, 0xEF, 0xFE, 0xED,
        ];
        let secret = SecretKey::from_slice(&scalar).unwrap();
        let pkcs8 = secret.to_pkcs8_der().unwrap();

        let sec1 = ec_pkcs8_to_sec1(pkcs8.as_bytes()).unwrap();
        let pkcs8_again = ec_sec1_to_pkcs8(&sec1).unwrap();
        assert_eq!(pkcs8.as_bytes(), pkcs8_again.as_slice());
    }

    #[test]
    fn detect_pkcs8_algorithm_recognises_each_kind() {
        {
            use ed25519_dalek::SigningKey;
            use ed25519_dalek::pkcs8::EncodePrivateKey;
            let sk = SigningKey::from_bytes(&[5u8; 32]);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            assert_eq!(
                detect_pkcs8_algorithm(pkcs8.as_bytes()).unwrap(),
                TpmKeyKind::Ed25519
            );
        }
        {
            use rsa::RsaPrivateKey;
            use rsa::pkcs8::EncodePrivateKey;
            let mut rng = rsa::rand_core::OsRng;
            let sk = RsaPrivateKey::new(&mut rng, 1024).unwrap();
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            assert_eq!(
                detect_pkcs8_algorithm(pkcs8.as_bytes()).unwrap(),
                TpmKeyKind::Rsa
            );
        }
        {
            use p256_ecdsa::SecretKey;
            use p256_ecdsa::pkcs8::EncodePrivateKey;
            let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
            let pkcs8 = secret.to_pkcs8_der().unwrap();
            assert_eq!(
                detect_pkcs8_algorithm(pkcs8.as_bytes()).unwrap(),
                TpmKeyKind::EcdsaP256
            );
        }
    }
}
