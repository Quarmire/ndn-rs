//! `SafeBag` — ndn-cxx interop wrapper for transferring an identity
//! (a certificate plus its password-encrypted private key) between
//! machines.
//!
//! # Wire format
//!
//! Pinned to ndn-cxx tag `ndn-cxx-0.9.0`, files
//! `ndn-cxx/encoding/tlv-security.hpp:34-35` and
//! `ndn-cxx/security/safe-bag.{hpp,cpp}`. Spec link inside ndn-cxx:
//! `<a href="../specs/safe-bag.html">`. The wire layout is two nested
//! TLVs inside a SafeBag outer TLV:
//!
//! ```text
//! SafeBag (TLV 128 = 0x80) {
//!   Data         (TLV 6 = 0x06) -- the full certificate Data packet
//!   EncryptedKey (TLV 129 = 0x81) -- PKCS#8 EncryptedPrivateKeyInfo DER
//! }
//! ```
//!
//! The certificate is stored as the **complete** Data packet wire
//! encoding including its own outer `0x06` header. The EncryptedKey
//! body is the raw DER of an `EncryptedPrivateKeyInfo` produced by
//! the rustcrypto `pkcs8` crate's `encryption` feature, which in turn
//! uses PBES2 with PBKDF2-HMAC-SHA256 for key derivation and AES-256-
//! CBC for content encryption — exactly the defaults that OpenSSL's
//! `i2d_PKCS8PrivateKey_bio` produces on modern releases, which is
//! what ndn-cxx's `BackEndFile::doExportKey` calls.
//!
//! # Algorithm support (path C of the FileTpm design discussion)
//!
//! - **RSA** — convert PKCS#1 `RSAPrivateKey` (FileTpm on-disk form)
//!   to PKCS#8 `PrivateKeyInfo`, then encrypt. Roundtrips with
//!   `ndnsec export` / `ndnsec import`.
//! - **ECDSA-P256** — convert SEC1 `ECPrivateKey` to PKCS#8, then
//!   encrypt. Roundtrips with ndnsec.
//! - **Ed25519** — already PKCS#8 on disk (sentinel suffix); encrypt
//!   directly. ndn-rs ↔ ndn-rs interop only — ndn-cxx tpm-file does
//!   not handle Ed25519 keys regardless of how they're transferred.

use bytes::Bytes;
use ndn_packet::tlv_type;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::file_tpm::{FileTpmError, TpmKeyKind};

// TLV type codes from ndn-cxx encoding/tlv-security.hpp.
const TLV_SAFE_BAG: u64 = 0x80; // 128
const TLV_ENCRYPTED_KEY: u64 = 0x81; // 129

/// Errors specific to SafeBag encode/decode and PKCS#8 encryption.
#[derive(Debug, thiserror::Error)]
pub enum SafeBagError {
    #[error("malformed SafeBag TLV: {0}")]
    Malformed(String),
    #[error("PKCS#8 encryption error: {0}")]
    Pkcs8(String),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
    #[error("file tpm error: {0}")]
    Tpm(#[from] FileTpmError),
    #[error("unsupported algorithm in SafeBag: {0}")]
    UnsupportedAlgorithm(String),
}

/// A decoded SafeBag — the certificate Data wire bytes and the
/// password-encrypted PKCS#8 private key DER.
#[derive(Clone, Debug)]
pub struct SafeBag {
    /// Full wire-encoded certificate Data packet (TLV starting at
    /// type 0x06). Opaque to SafeBag itself; the caller hands this to
    /// the PIB or a Data decoder.
    pub certificate: Bytes,
    /// `EncryptedPrivateKeyInfo` DER per RFC 5958 / PKCS#8. Use
    /// [`SafeBag::decrypt_key`] with the export password to recover
    /// the unencrypted PKCS#8 PrivateKeyInfo.
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
        // Re-emit the full Data TLV (TlvReader consumed the header).
        let mut cert_w = TlvWriter::new();
        cert_w.write_tlv(tlv_type::DATA, &cert_body);
        let certificate = cert_w.finish();

        let (ek_type, ek_body) = inner
            .read_tlv()
            .map_err(|e| SafeBagError::Malformed(format!("EncryptedKey TLV: {e:?}")))?;
        if ek_type != TLV_ENCRYPTED_KEY {
            return Err(SafeBagError::Malformed(format!(
                "expected EncryptedKey (0x81) inside SafeBag, got 0x{ek_type:x}"
            )));
        }

        Ok(Self {
            certificate,
            encrypted_key: ek_body,
        })
    }

    /// Build a SafeBag by encrypting an unencrypted PKCS#8
    /// `PrivateKeyInfo` DER with `password`. Uses the rustcrypto
    /// `pkcs8` crate's default PBES2 parameters: PBKDF2-HMAC-SHA256
    /// with a random 16-byte salt and AES-256-CBC with a random IV.
    /// These match the OpenSSL `PKCS8_encrypt` defaults that ndn-cxx
    /// produces.
    pub fn encrypt(
        certificate: Bytes,
        pkcs8_pki_der: &[u8],
        password: &[u8],
    ) -> Result<Self, SafeBagError> {
        use pkcs8::PrivateKeyInfo;
        let pki = PrivateKeyInfo::try_from(pkcs8_pki_der)
            .map_err(|e| SafeBagError::Pkcs8(format!("parse PrivateKeyInfo: {e}")))?;
        let encrypted = pki
            .encrypt(rsa::rand_core::OsRng, password)
            .map_err(|e| SafeBagError::Pkcs8(format!("encrypt: {e}")))?;
        Ok(Self {
            certificate,
            encrypted_key: Bytes::copy_from_slice(encrypted.as_bytes()),
        })
    }

    /// Decrypt the SafeBag's encrypted private key with `password`,
    /// returning the unencrypted PKCS#8 `PrivateKeyInfo` DER. The
    /// caller dispatches on the embedded algorithm OID.
    pub fn decrypt_key(&self, password: &[u8]) -> Result<Vec<u8>, SafeBagError> {
        use pkcs8::EncryptedPrivateKeyInfo;
        let epki = EncryptedPrivateKeyInfo::try_from(&self.encrypted_key[..])
            .map_err(|e| SafeBagError::Pkcs8(format!("parse EncryptedPrivateKeyInfo: {e}")))?;
        let decrypted = epki
            .decrypt(password)
            .map_err(|e| SafeBagError::Pkcs8(format!("decrypt: {e}")))?;
        Ok(decrypted.as_bytes().to_vec())
    }
}

/// Convert an RSA PKCS#1 `RSAPrivateKey` DER (the FileTpm on-disk
/// form for RSA) into a PKCS#8 `PrivateKeyInfo` DER.
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

/// Convert a PKCS#8 `PrivateKeyInfo` DER carrying an RSA key back
/// into the PKCS#1 `RSAPrivateKey` form FileTpm stores on disk.
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

/// Convert a SEC1 `ECPrivateKey` DER (the FileTpm on-disk form for
/// ECDSA-P256) into a PKCS#8 `PrivateKeyInfo` DER. Bypasses
/// `SecretKey::from_sec1_der` (which is brittle on missing
/// AlgorithmIdentifier parameters) by hand-extracting the 32-byte
/// scalar via [`crate::file_tpm::parse_sec1_p256_priv_scalar`] and
/// re-constructing the SecretKey from the raw scalar.
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

/// Convert a PKCS#8 `PrivateKeyInfo` DER carrying a P-256 ECDSA key
/// back into the SEC1 `ECPrivateKey` form FileTpm stores on disk.
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

    /// A minimal "Data packet" — just `0x06 LL <body>` — that we can
    /// stuff into a SafeBag for roundtrip tests. SafeBag treats the
    /// certificate as opaque bytes; nothing in this module parses the
    /// Data, so a syntactically-valid TLV with arbitrary body is fine.
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
        // Outer TLV must start with 0x80.
        assert_eq!(wire[0], 0x80);
        let decoded = SafeBag::decode(&wire).unwrap();
        assert_eq!(decoded.certificate, cert);
        assert_eq!(decoded.encrypted_key, sb.encrypted_key);
    }

    #[test]
    fn safebag_decode_rejects_wrong_outer_type() {
        // Outer TLV with a non-SafeBag type code (use 0x06 = Data).
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
        // Generate an Ed25519 key as raw PKCS#8 (the form FileTpm
        // already produces for the .privkey-ed25519 sentinel suffix).
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        let mut seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let pkcs8 = sk.to_pkcs8_der().unwrap();

        let cert = fake_cert(b"ed25519 cert");
        let pw = b"correct horse battery staple";

        let sb = SafeBag::encrypt(cert.clone(), pkcs8.as_bytes(), pw).unwrap();
        // Encrypted blob must NOT contain the plain key bytes.
        assert!(
            sb.encrypted_key.windows(32).all(|w| w != seed),
            "encrypted key leaked the seed"
        );
        let decrypted = sb.decrypt_key(pw).unwrap();
        // After decryption we should get back exactly the original
        // PKCS#8 PrivateKeyInfo DER.
        assert_eq!(&decrypted[..], pkcs8.as_bytes());

        // Wrong password must fail.
        assert!(sb.decrypt_key(b"wrong password").is_err());

        // SafeBag wire-roundtrip preserves both fields.
        let wire = sb.encode();
        let sb2 = SafeBag::decode(&wire).unwrap();
        assert_eq!(sb2.decrypt_key(pw).unwrap(), decrypted);
    }

    #[test]
    fn rsa_pkcs1_pkcs8_roundtrip() {
        use pkcs1::EncodeRsaPrivateKey;
        use rsa::RsaPrivateKey;
        // Use a tiny key (1024 bits) for test speed; production keys
        // would be 2048+.
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
        // Generate a fresh key as PKCS#8 (which then we need to convert
        // to SEC1 by hand because to_sec1_der is on a different trait
        // path that's not always in scope). Use a known scalar for a
        // deterministic test.
        let scalar = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD,
            0xDE, 0xEF, 0xFE, 0xED,
        ];
        let secret = SecretKey::from_slice(&scalar).unwrap();
        let pkcs8 = secret.to_pkcs8_der().unwrap();

        // PKCS#8 → SEC1 → PKCS#8 should roundtrip cleanly.
        let sec1 = ec_pkcs8_to_sec1(pkcs8.as_bytes()).unwrap();
        let pkcs8_again = ec_sec1_to_pkcs8(&sec1).unwrap();
        assert_eq!(pkcs8.as_bytes(), pkcs8_again.as_slice());
    }

    #[test]
    fn detect_pkcs8_algorithm_recognises_each_kind() {
        // Ed25519
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
        // RSA
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
        // ECDSA-P256
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
