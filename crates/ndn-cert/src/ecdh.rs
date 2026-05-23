//! NDNCERT v0.3 §2.3 — P-256 ECDH + HKDF-SHA256 (RFC 5869) + AES-GCM-128.
//!
//! IV is `[8B random prefix][4B counter, big-endian]`; counter increments by
//! `ceil(payload_len / 16)` per encryption. Each side keeps its own IV state
//! and the CA rejects matching prefixes to prevent reuse.

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use bytes::Bytes;
use hkdf::Hkdf;
use ndn_tlv::{TlvReader, TlvWriter};
use p256::{
    EncodedPoint, NistP256, PublicKey, ecdh::EphemeralSecret,
    elliptic_curve::sec1::FromEncodedPoint,
};
use sha2::Sha256;

use crate::{
    error::CertError,
    tlv::{TLV_AUTH_TAG, TLV_ENCRYPTED_PAYLOAD, TLV_IV},
};

/// Ephemeral P-256 keypair. Consumed by `derive_session_key`.
pub struct EcdhKeypair {
    secret: EphemeralSecret,
}

impl EcdhKeypair {
    pub fn generate() -> Self {
        Self {
            secret: EphemeralSecret::random(&mut OsRng),
        }
    }

    /// Uncompressed point (65 bytes: 0x04 || X || Y) — write into `TLV_ECDH_PUB`.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let pub_key: PublicKey = (&self.secret).into();
        EncodedPoint::from(&pub_key).as_bytes().to_vec()
    }

    pub fn random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        let _ = getrandom::getrandom(&mut salt);
        salt
    }
}

/// `[8 random bytes][4 zero counter bytes]`.
pub fn new_encryption_iv() -> [u8; 12] {
    let mut iv = [0u8; 12];
    let _ = getrandom::getrandom(&mut iv[..8]);
    iv
}

/// Advance counter by `ceil(payload_len / 16)`.
pub fn advance_iv_counter(iv: &mut [u8; 12], payload_len: usize) {
    let increment = payload_len.saturating_add(15) / 16;
    let counter = u32::from_be_bytes(iv[8..12].try_into().unwrap());
    let new_counter = counter.saturating_add(increment as u32);
    iv[8..12].copy_from_slice(&new_counter.to_be_bytes());
}

impl EcdhKeypair {
    /// `peer_pub_bytes` is the uncompressed P-256 point (65 bytes); `salt` is
    /// the 32-byte HKDF salt from the NEW response; `request_id` is the HKDF
    /// info field.
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

        let shared = self.secret.diffie_hellman(&peer_pub);

        let hk = Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes());
        let mut aes_key = [0u8; 16];
        hk.expand(request_id, &mut aes_key)
            .map_err(|_| CertError::InvalidRequest("HKDF expand failed".into()))?;

        Ok(SessionKey { key: aes_key })
    }
}

#[derive(Clone)]
pub struct SessionKey {
    pub(crate) key: [u8; 16],
}

impl SessionKey {
    /// `aad` is the NDNCERT-spec request_id. Returns `(iv, ciphertext, auth_tag)`.
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

        let split_at = ciphertext_with_tag.len() - 16;
        let (ct, tag) = ciphertext_with_tag.split_at(split_at);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        Ok((nonce_arr, Bytes::copy_from_slice(ct), tag_arr))
    }

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
            .map_err(|_| CertError::InvalidRequest("AES-GCM decryption failed (bad tag)".into()))?;

        Ok(plaintext)
    }

    /// Caller must advance the counter via [`advance_iv_counter`] after each call.
    fn encrypt_with_iv(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        iv: &[u8; 12],
    ) -> Result<(Bytes, [u8; 16]), CertError> {
        use aes_gcm::aead::generic_array::GenericArray;

        let cipher = Aes128Gcm::new_from_slice(&self.key)
            .map_err(|_| CertError::InvalidRequest("AES key init failed".into()))?;

        let nonce = GenericArray::from_slice(iv);
        let ciphertext_with_tag = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CertError::InvalidRequest("AES-GCM encryption failed".into()))?;

        let split_at = ciphertext_with_tag.len() - 16;
        let (ct, tag) = ciphertext_with_tag.split_at(split_at);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        Ok((Bytes::copy_from_slice(ct), tag_arr))
    }

    /// Encode `{IV, AuthTag, EncryptedPayload}` and advance `iv_state`.
    pub fn seal_envelope(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        iv_state: &mut [u8; 12],
    ) -> Result<Vec<u8>, CertError> {
        let (ct, tag) = self.encrypt_with_iv(plaintext, aad, iv_state)?;
        let iv_snapshot = *iv_state;
        advance_iv_counter(iv_state, plaintext.len());

        let mut w = TlvWriter::new();
        w.write_tlv(TLV_IV, &iv_snapshot);
        w.write_tlv(TLV_AUTH_TAG, &tag);
        w.write_tlv(TLV_ENCRYPTED_PAYLOAD, &ct);
        Ok(w.finish().to_vec())
    }

    /// Decode `{IV, AuthTag, EncryptedPayload}`; on success sets `decryption_iv`.
    pub fn open_envelope(
        &self,
        envelope_bytes: &[u8],
        aad: &[u8],
        decryption_iv: &mut Option<[u8; 12]>,
    ) -> Result<Vec<u8>, CertError> {
        let mut r = TlvReader::new(bytes::Bytes::copy_from_slice(envelope_bytes));
        let mut iv = None;
        let mut auth_tag = None;
        let mut ciphertext = None;

        while !r.is_empty() {
            let (typ, val) = r
                .read_tlv()
                .map_err(|e| CertError::InvalidRequest(format!("envelope TLV parse error: {e}")))?;
            match typ {
                TLV_IV if val.len() == 12 => {
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(&val);
                    iv = Some(arr);
                }
                TLV_AUTH_TAG if val.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&val);
                    auth_tag = Some(arr);
                }
                TLV_ENCRYPTED_PAYLOAD => ciphertext = Some(val),
                _ => {}
            }
        }

        let iv = iv.ok_or_else(|| CertError::InvalidRequest("envelope missing IV".into()))?;
        let auth_tag =
            auth_tag.ok_or_else(|| CertError::InvalidRequest("envelope missing AuthTag".into()))?;
        let ciphertext = ciphertext
            .ok_or_else(|| CertError::InvalidRequest("envelope missing EncryptedPayload".into()))?;

        let plaintext = self.decrypt(&iv, &ciphertext, &auth_tag, aad)?;
        *decryption_iv = Some(iv);
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
        tag[0] ^= 0xFF;

        assert!(key_b.decrypt(&iv, &ct, &tag, &request_id).is_err());
    }

    #[test]
    fn public_key_is_65_bytes() {
        let kp = EcdhKeypair::generate();
        let pub_bytes = kp.public_key_bytes();
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
    }

    #[test]
    fn new_encryption_iv_is_structured() {
        let iv = new_encryption_iv();
        assert_eq!(iv.len(), 12);
        assert_eq!(&iv[8..12], &[0u8; 4]);
    }

    #[test]
    fn advance_iv_counter_increments_by_ceil_blocks() {
        let mut iv = new_encryption_iv();
        let prefix = iv[..8].to_vec();
        advance_iv_counter(&mut iv, 16);
        assert_eq!(u32::from_be_bytes(iv[8..12].try_into().unwrap()), 1);
        assert_eq!(&iv[..8], prefix.as_slice());
        advance_iv_counter(&mut iv, 17);
        assert_eq!(u32::from_be_bytes(iv[8..12].try_into().unwrap()), 3);
    }

    #[test]
    fn seal_open_envelope_roundtrip() {
        let key = SessionKey { key: [0x42u8; 16] };
        let plaintext = b"hello NDNCERT challenge";
        let aad = &[0xABu8; 8];

        let mut iv_state = new_encryption_iv();
        let envelope = key.seal_envelope(plaintext, aad, &mut iv_state).unwrap();

        let counter_after = u32::from_be_bytes(iv_state[8..12].try_into().unwrap());
        assert!(counter_after > 0);

        let mut dec_iv: Option<[u8; 12]> = None;
        let recovered = key.open_envelope(&envelope, aad, &mut dec_iv).unwrap();
        assert_eq!(recovered, plaintext);
        assert!(dec_iv.is_some());
    }

    #[test]
    fn seal_multiple_rounds_monotonic_counter() {
        let key = SessionKey { key: [0x11u8; 16] };
        let aad = &[0x22u8; 8];
        let mut iv_state = new_encryption_iv();
        let prefix = iv_state[..8].to_vec();

        key.seal_envelope(b"first round payload", aad, &mut iv_state)
            .unwrap();
        let counter1 = u32::from_be_bytes(iv_state[8..12].try_into().unwrap());

        key.seal_envelope(b"second round payload", aad, &mut iv_state)
            .unwrap();
        let counter2 = u32::from_be_bytes(iv_state[8..12].try_into().unwrap());

        assert!(counter2 > counter1, "counter must increase monotonically");
        assert_eq!(&iv_state[..8], prefix.as_slice());
    }
}
