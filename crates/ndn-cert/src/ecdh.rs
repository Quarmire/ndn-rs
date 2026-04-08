//! ECDH key agreement + HKDF-SHA256 + AES-GCM-128 for NDNCERT 0.3.
//!
//! The protocol mandates P-256 (prime256v1 / secp256r1) ECDH with:
//! - HKDF-SHA256 (RFC 5869): IKM = shared_secret, salt = 32-byte CA-provided salt,
//!   info = 8-byte request_id → 16-byte AES-128 key
//! - AES-GCM-128: 12-byte IV (from OS RNG), 16-byte auth tag,
//!   request_id as additional associated data (AAD)

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use bytes::Bytes;
use hkdf::Hkdf;
use p256::{
    EncodedPoint, NistP256, PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::FromEncodedPoint,
};
use sha2::Sha256;

use crate::error::CertError;

/// An ephemeral P-256 ECDH key pair.
///
/// Both CA and client generate a fresh keypair per enrollment session.
/// The keypair is consumed by `derive_session_key` since the ephemeral
/// secret must not be reused.
pub struct EcdhKeypair {
    secret: EphemeralSecret,
}

impl EcdhKeypair {
    /// Generate a fresh ephemeral P-256 key pair using the OS RNG.
    pub fn generate() -> Self {
        Self {
            secret: EphemeralSecret::random(&mut OsRng),
        }
    }

    /// The uncompressed public key (65 bytes: 0x04 || X || Y).
    /// Send this in `TLV_ECDH_PUB`.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let pub_key: PublicKey = (&self.secret).into();
        EncodedPoint::from(&pub_key).as_bytes().to_vec()
    }

    /// Generate a random 32-byte HKDF salt.
    pub fn random_salt() -> [u8; 32] {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut salt = [0u8; 32];
        rng.fill(&mut salt).unwrap_or(());
        salt
    }

    /// Perform ECDH with `peer_pub_bytes` and derive a 128-bit AES session key
    /// via HKDF-SHA256.
    ///
    /// - `peer_pub_bytes`: uncompressed P-256 public key from the other party (65 bytes)
    /// - `salt`: 32-byte random salt from the CA's NEW response
    /// - `request_id`: 8-byte request identifier (HKDF info field)
    pub fn derive_session_key(
        self,
        peer_pub_bytes: &[u8],
        salt: &[u8; 32],
        request_id: &[u8; 8],
    ) -> Result<SessionKey, CertError> {
        let peer_point = EncodedPoint::from_bytes(peer_pub_bytes)
            .map_err(|_| CertError::InvalidRequest("invalid peer ECDH public key".into()))?;
        let peer_pub = Option::<PublicKey>::from(
            <PublicKey as FromEncodedPoint<NistP256>>::from_encoded_point(&peer_point),
        )
        .ok_or_else(|| CertError::InvalidRequest("invalid P-256 point".into()))?;

        // ECDH shared secret.
        let shared = self.secret.diffie_hellman(&peer_pub);

        // HKDF-SHA256: IKM = shared_secret, salt = random_salt, info = request_id.
        let hk = Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes());
        let mut aes_key = [0u8; 16];
        hk.expand(request_id, &mut aes_key)
            .map_err(|_| CertError::InvalidRequest("HKDF expand failed".into()))?;

        Ok(SessionKey { key: aes_key })
    }
}

/// A 128-bit AES-GCM session key derived via ECDH + HKDF.
///
/// Used to encrypt/decrypt CHALLENGE parameters.
#[derive(Clone)]
pub struct SessionKey {
    pub(crate) key: [u8; 16],
}

impl SessionKey {
    /// Encrypt `plaintext` with AES-GCM-128.
    ///
    /// `aad` is the Additional Associated Data (request_id per spec).
    /// Returns `(iv, ciphertext, auth_tag)`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<([u8; 12], Bytes, [u8; 16]), CertError> {
        let cipher = Aes128Gcm::new_from_slice(&self.key)
            .map_err(|_| CertError::InvalidRequest("AES key init failed".into()))?;

        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
        let nonce_arr: [u8; 12] = nonce.into();

        let ciphertext_with_tag = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CertError::InvalidRequest("AES-GCM encryption failed".into()))?;

        // AES-GCM appends the 16-byte tag at the end of the ciphertext.
        let split_at = ciphertext_with_tag.len() - 16;
        let (ct, tag) = ciphertext_with_tag.split_at(split_at);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        Ok((nonce_arr, Bytes::copy_from_slice(ct), tag_arr))
    }

    /// Decrypt `ciphertext` with AES-GCM-128.
    ///
    /// `aad` must match the value used during encryption.
    pub fn decrypt(
        &self,
        iv: &[u8; 12],
        ciphertext: &[u8],
        auth_tag: &[u8; 16],
        aad: &[u8],
    ) -> Result<Vec<u8>, CertError> {
        use aes_gcm::aead::generic_array::GenericArray;

        let cipher = Aes128Gcm::new_from_slice(&self.key)
            .map_err(|_| CertError::InvalidRequest("AES key init failed".into()))?;

        // Reassemble ciphertext || tag as aes-gcm expects.
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + 16);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(auth_tag);

        let nonce = GenericArray::from_slice(iv);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ct_with_tag,
                    aad,
                },
            )
            .map_err(|_| {
                CertError::InvalidRequest("AES-GCM decryption failed (bad tag)".into())
            })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdh_key_agreement_produces_same_session_key() {
        let client_kp = EcdhKeypair::generate();
        let ca_kp = EcdhKeypair::generate();

        let client_pub = client_kp.public_key_bytes();
        let ca_pub = ca_kp.public_key_bytes();

        let salt = [0x42u8; 32];
        let request_id = [0x01u8; 8];

        let client_session = client_kp
            .derive_session_key(&ca_pub, &salt, &request_id)
            .unwrap();
        let ca_session = ca_kp
            .derive_session_key(&client_pub, &salt, &request_id)
            .unwrap();

        assert_eq!(client_session.key, ca_session.key);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp_a = EcdhKeypair::generate();
        let kp_b = EcdhKeypair::generate();
        let pub_a = kp_a.public_key_bytes();
        let pub_b = kp_b.public_key_bytes();

        let salt = [0x11u8; 32];
        let request_id = [0x22u8; 8];

        let key_a = kp_a.derive_session_key(&pub_b, &salt, &request_id).unwrap();
        let key_b = kp_b.derive_session_key(&pub_a, &salt, &request_id).unwrap();

        let plaintext = b"{\"code\":\"123456\"}";
        let aad = &request_id[..];

        let (iv, ct, tag) = key_a.encrypt(plaintext, aad).unwrap();
        let decrypted = key_b.decrypt(&iv, &ct, &tag, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_tag() {
        let kp_a = EcdhKeypair::generate();
        let kp_b = EcdhKeypair::generate();
        let pub_a = kp_a.public_key_bytes();
        let pub_b = kp_b.public_key_bytes();

        let salt = [0x33u8; 32];
        let request_id = [0x44u8; 8];

        let key_a = kp_a.derive_session_key(&pub_b, &salt, &request_id).unwrap();
        let key_b = kp_b.derive_session_key(&pub_a, &salt, &request_id).unwrap();

        let (iv, ct, mut tag) = key_a.encrypt(b"secret", &request_id).unwrap();
        tag[0] ^= 0xFF; // corrupt the tag

        assert!(key_b.decrypt(&iv, &ct, &tag, &request_id).is_err());
    }

    #[test]
    fn public_key_is_65_bytes() {
        let kp = EcdhKeypair::generate();
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04); // uncompressed point marker
    }
}
