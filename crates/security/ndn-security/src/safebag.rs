//! NDN SafeBag — wasm-compatible spec-canonical encoder/decoder for the
//! ndn-cxx `safe-bag` wire format
//! (<https://github.com/named-data/ndn-cxx/blob/master/docs/specs/safe-bag.rst>):
//!
//! ```text
//! SafeBag (0x80) {
//!     Data (0x06) { ... certificate ... }
//!     EncryptedKey (0x81) { EncryptedPrivateKeyInfo per RFC 5958 }
//! }
//! ```
//!
//! Encryption uses PBES2 with PBKDF2-HMAC-SHA256 + AES-256-CBC, matching
//! `ndnsec export`.

#![deny(rust_2018_idioms)]

use bytes::Bytes;
use ndn_packet::tlv_type;
use ndn_tlv::{TlvReader, TlvWriter};
use thiserror::Error;

const TLV_SAFE_BAG: u64 = 0x80;
const TLV_ENCRYPTED_KEY: u64 = 0x81;

#[derive(Debug, Error)]
pub enum SafeBagError {
    #[error("malformed SafeBag TLV: {0}")]
    Malformed(String),
    #[error("PKCS#8 encryption error: {0}")]
    Pkcs8(String),
    #[error("Ed25519 PKCS#8 conversion: {0}")]
    Ed25519(String),
}

#[derive(Clone, Debug)]
pub struct SafeBag {
    /// Full wire-encoded Data TLV (type 0x06).
    pub certificate: Bytes,
    /// `EncryptedPrivateKeyInfo` DER (RFC 5958).
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

    /// Wraps an unencrypted PKCS#8 `PrivateKeyInfo` DER under PBES2
    /// defaults (`ndnsec export`-compatible).
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
