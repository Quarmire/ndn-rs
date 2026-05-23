use std::future::Future;
use std::pin::Pin;

use ndn_packet::SignatureType;

use crate::TrustError;
use crate::signer::{SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED, SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid,
    Invalid,
}

pub trait Verifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>>;
}

/// Dispatch signature verification against the algorithm declared in the
/// packet's `SignatureInfo`. Returns `Ok(Valid)` / `Ok(Invalid)` for
/// handled algorithms, `Err(InvalidKey)` / `Err(InvalidSignature)` for
/// malformed inputs, and `Err(UnsupportedSignatureType)` for unknown
/// codes. All NDN Packet Format v0.3 codes plus BLAKE3 (6, 7) are wired.
pub async fn verify_by_sig_type(
    sig_type: SignatureType,
    region: &[u8],
    sig_value: &[u8],
    public_key: &[u8],
) -> Result<VerifyOutcome, TrustError> {
    match sig_type {
        SignatureType::DigestSha256 => {
            DigestSha256Verifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::SignatureEd25519 => {
            // Certificate Format v2 stores the public key as a 44-byte
            // DER SubjectPublicKeyInfo envelope; `Ed25519Verifier` wants
            // the raw 32-byte key. Strip here so callers can pass
            // `cert.public_key` directly.
            let raw = if crate::spki::is_ed25519_spki(public_key) {
                crate::spki::unwrap_ed25519(public_key)
                    .map(|k| k.to_vec())
                    .ok_or(TrustError::InvalidKey)?
            } else {
                public_key.to_vec()
            };
            Ed25519Verifier.verify(region, sig_value, &raw).await
        }
        SignatureType::SignatureHmacWithSha256 => {
            HmacSha256Verifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::SignatureSha256WithRsa => {
            RsaSha256Verifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::SignatureSha256WithEcdsa => {
            EcdsaSha256Verifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::Other(c) if c == SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN => {
            Blake3DigestVerifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::Other(c) if c == SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED => {
            Blake3KeyedVerifier
                .verify(region, sig_value, public_key)
                .await
        }
        SignatureType::Other(c) => Err(TrustError::UnsupportedSignatureType {
            code: c,
            name: format!("Other({c})"),
        }),
    }
}

/// SHA-256 digest verifier — `sig_value` must equal `SHA-256(region)`.
/// `public_key` is unused; trust is established at a higher layer.
pub struct DigestSha256Verifier;

impl Verifier for DigestSha256Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        _public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(region);
            if hash.as_slice() == sig_value {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

/// HMAC-SHA-256 verifier; `public_key` is the shared HMAC key.
/// Constant-time tag comparison is delegated to ring.
pub struct HmacSha256Verifier;

impl Verifier for HmacSha256Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            if crate::hmac_sha256::verify(public_key, region, sig_value) {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

pub struct Ed25519Verifier;

impl Ed25519Verifier {
    pub fn verify_sync(&self, region: &[u8], sig_value: &[u8], public_key: &[u8]) -> VerifyOutcome {
        use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

        let Ok(vk) = VerifyingKey::from_bytes(public_key.try_into().unwrap_or(&[0u8; 32])) else {
            return VerifyOutcome::Invalid;
        };

        let Ok(sig_bytes): Result<&[u8; 64], _> = sig_value.try_into() else {
            return VerifyOutcome::Invalid;
        };
        let sig = Signature::from_bytes(sig_bytes);

        match vk.verify(region, &sig) {
            Ok(()) => VerifyOutcome::Valid,
            Err(_) => VerifyOutcome::Invalid,
        }
    }
}

impl Verifier for Ed25519Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

            let vk = VerifyingKey::from_bytes(
                public_key.try_into().map_err(|_| TrustError::InvalidKey)?,
            )
            .map_err(|_| TrustError::InvalidKey)?;

            let sig_bytes: &[u8; 64] = sig_value
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?;
            let sig = Signature::from_bytes(sig_bytes);

            match vk.verify(region, &sig) {
                Ok(()) => Ok(VerifyOutcome::Valid),
                Err(_) => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}

/// Batch-verify Ed25519 signatures (~2-3x faster than individual verify).
/// Any single invalid signature fails the whole batch.
pub fn ed25519_verify_batch(
    messages: &[&[u8]],
    signatures: &[&[u8; 64]],
    public_keys: &[&[u8; 32]],
) -> Result<VerifyOutcome, TrustError> {
    use ed25519_dalek::{Signature, VerifyingKey, verify_batch};

    let n = messages.len();
    if signatures.len() != n || public_keys.len() != n {
        return Err(TrustError::InvalidSignature);
    }
    if n == 0 {
        return Ok(VerifyOutcome::Valid);
    }

    let sigs: Vec<Signature> = signatures
        .iter()
        .map(|s| Signature::from_bytes(s))
        .collect();

    // A malformed public key surfaces as InvalidKey (structural error);
    // a mismatched signature surfaces as Ok(Invalid) for symmetry with
    // the single-`verify()` semantic.
    let mut keys: Vec<VerifyingKey> = Vec::with_capacity(n);
    for pk in public_keys {
        match VerifyingKey::from_bytes(pk) {
            Ok(vk) => keys.push(vk),
            Err(_) => return Err(TrustError::InvalidKey),
        }
    }

    match verify_batch(messages, &sigs, &keys) {
        Ok(()) => Ok(VerifyOutcome::Valid),
        Err(_) => Ok(VerifyOutcome::Invalid),
    }
}

/// BLAKE3 digest verifier — `sig_value` must equal `BLAKE3(region)`.
/// `public_key` is unused; pass an empty slice. Large inputs (≥
/// [`BLAKE3_RAYON_THRESHOLD`]) hash via `update_rayon`.
///
/// [`BLAKE3_RAYON_THRESHOLD`]: crate::signer::BLAKE3_RAYON_THRESHOLD
pub struct Blake3DigestVerifier;

impl Verifier for Blake3DigestVerifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        _public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            let Ok(expected): Result<&[u8; 32], _> = sig_value.try_into() else {
                return Ok(VerifyOutcome::Invalid);
            };
            let hash = crate::signer::blake3_hash_auto(region);
            if hash.as_bytes() == expected {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

/// BLAKE3 keyed verifier — `sig_value` must equal `BLAKE3_keyed(region)`.
/// `public_key` is the 32-byte BLAKE3 key. Same large-input dispatch as
/// [`Blake3DigestVerifier`].
pub struct Blake3KeyedVerifier;

impl Verifier for Blake3KeyedVerifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            let key: &[u8; 32] = public_key.try_into().map_err(|_| TrustError::InvalidKey)?;
            let Ok(expected): Result<&[u8; 32], _> = sig_value.try_into() else {
                return Ok(VerifyOutcome::Invalid);
            };
            let hash = crate::signer::blake3_keyed_hash_auto(key, region);
            if hash.as_bytes() == expected {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

/// RSA PKCS#1 v1.5 / SHA-256 verifier. `public_key` is DER-encoded SPKI.
pub struct RsaSha256Verifier;

impl Verifier for RsaSha256Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use rsa::{
                RsaPublicKey,
                pkcs1v15::{Signature as RsaSig, VerifyingKey as RsaVk},
                pkcs8::DecodePublicKey,
                sha2::Sha256,
                signature::Verifier as _,
            };

            let pk = RsaPublicKey::from_public_key_der(public_key)
                .map_err(|_| TrustError::InvalidKey)?;
            let vk = RsaVk::<Sha256>::new(pk);
            let sig = RsaSig::try_from(sig_value).map_err(|_| TrustError::InvalidSignature)?;
            match vk.verify(region, &sig) {
                Ok(()) => Ok(VerifyOutcome::Valid),
                Err(_) => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}

/// ECDSA / P-256 / SHA-256 verifier. `public_key` is DER-encoded SPKI.
pub struct EcdsaSha256Verifier;

impl Verifier for EcdsaSha256Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use p256_ecdsa::{
                ecdsa::{DerSignature, VerifyingKey, signature::Verifier as _},
                pkcs8::DecodePublicKey,
            };

            let vk = VerifyingKey::from_public_key_der(public_key)
                .map_err(|_| TrustError::InvalidKey)?;
            let sig =
                DerSignature::try_from(sig_value).map_err(|_| TrustError::InvalidSignature)?;
            match vk.verify(region, &sig) {
                Ok(()) => Ok(VerifyOutcome::Valid),
                Err(_) => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// Test fixture: signing key, 32-byte public key, message bytes, 64-byte signature.
    type Ed25519BatchEntry = (SigningKey, [u8; 32], Vec<u8>, [u8; 64]);

    fn keypair(seed: &[u8; 32]) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[tokio::test]
    async fn valid_signature_returns_valid() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let region = b"signed region";
        let sig = sk.sign(region).to_bytes();
        let outcome = Ed25519Verifier.verify(region, &sig, &pk).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn wrong_signature_returns_invalid() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let region = b"signed region";
        let bad_sig = [0u8; 64];
        let outcome = Ed25519Verifier.verify(region, &bad_sig, &pk).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn wrong_key_returns_invalid() {
        let (sk, _) = keypair(&[1u8; 32]);
        let (_, pk2) = keypair(&[2u8; 32]); // different key
        let region = b"signed region";
        let sig = sk.sign(region).to_bytes();
        let outcome = Ed25519Verifier.verify(region, &sig, &pk2).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn short_public_key_returns_err() {
        let sig = [0u8; 64];
        let result = Ed25519Verifier.verify(b"region", &sig, &[0u8; 16]).await;
        assert!(matches!(result, Err(TrustError::InvalidKey)));
    }

    #[tokio::test]
    async fn short_signature_returns_err() {
        let (_, pk) = keypair(&[1u8; 32]);
        let result = Ed25519Verifier.verify(b"region", &[0u8; 32], &pk).await;
        assert!(matches!(result, Err(TrustError::InvalidSignature)));
    }

    #[test]
    fn batch_all_valid_returns_valid() {
        let ns: Vec<Ed25519BatchEntry> = (0u8..10)
            .map(|i| {
                let (sk, pk) = keypair(&[i; 32]);
                let msg = format!("message {i}").into_bytes();
                let sig = sk.sign(&msg).to_bytes();
                (sk, pk, msg, sig)
            })
            .collect();
        let messages: Vec<&[u8]> = ns.iter().map(|(_, _, m, _)| m.as_slice()).collect();
        let signatures: Vec<&[u8; 64]> = ns.iter().map(|(_, _, _, s)| s).collect();
        let public_keys: Vec<&[u8; 32]> = ns.iter().map(|(_, pk, _, _)| pk).collect();
        let out = ed25519_verify_batch(&messages, &signatures, &public_keys).unwrap();
        assert_eq!(out, VerifyOutcome::Valid);
    }

    /// One bad signature fails the whole batch; callers then fall back
    /// to per-signature verify to locate the culprit.
    #[test]
    fn batch_one_bad_sig_returns_invalid() {
        let ns: Vec<Ed25519BatchEntry> = (0u8..10)
            .map(|i| {
                let (sk, pk) = keypair(&[i; 32]);
                let msg = format!("message {i}").into_bytes();
                let sig = sk.sign(&msg).to_bytes();
                (sk, pk, msg, sig)
            })
            .collect();
        let messages: Vec<&[u8]> = ns.iter().map(|(_, _, m, _)| m.as_slice()).collect();
        let mut signatures: Vec<[u8; 64]> = ns.iter().map(|(_, _, _, s)| *s).collect();
        // Corrupt one byte of one signature.
        signatures[4][0] ^= 0x80;
        let sig_refs: Vec<&[u8; 64]> = signatures.iter().collect();
        let public_keys: Vec<&[u8; 32]> = ns.iter().map(|(_, pk, _, _)| pk).collect();
        let out = ed25519_verify_batch(&messages, &sig_refs, &public_keys).unwrap();
        assert_eq!(out, VerifyOutcome::Invalid);
    }

    #[test]
    fn batch_length_mismatch_returns_err() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"a message";
        let sig = sk.sign(msg).to_bytes();
        let messages: &[&[u8]] = &[msg, msg];
        let sigs = [&sig];
        let keys = [&pk, &pk];
        let out = ed25519_verify_batch(messages, &sigs, &keys);
        assert!(matches!(out, Err(TrustError::InvalidSignature)));
    }

    #[test]
    fn batch_empty_is_vacuously_valid() {
        let out = ed25519_verify_batch(&[], &[], &[]).unwrap();
        assert_eq!(out, VerifyOutcome::Valid);
    }

    // No "malformed public key returns InvalidKey" test: ed25519-dalek's
    // `VerifyingKey::from_bytes` accepts all-zero / all-FF as unusable
    // curve points, so the InvalidKey branch only fires for inputs the
    // curve encoding considers non-points. A bogus key surfaces as
    // `VerifyOutcome::Invalid`, which is what the forwarder needs.

    fn rsa_keypair_2048() -> (
        rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>,
        rsa::pkcs1v15::VerifyingKey<rsa::sha2::Sha256>,
    ) {
        use rand::rngs::OsRng;
        use rsa::{RsaPrivateKey, pkcs1v15::SigningKey, sha2::Sha256, signature::Keypair};
        let sk = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let signing = SigningKey::<Sha256>::new(sk);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    #[tokio::test]
    async fn rsa_valid_signature_returns_valid() {
        use rsa::{
            pkcs8::EncodePublicKey,
            signature::{SignatureEncoding, Signer as _},
        };

        let (sk, vk) = rsa_keypair_2048();
        let region = b"rsa test region";
        let sig: rsa::pkcs1v15::Signature = sk.sign(region);
        let pk_der = vk.to_public_key_der().unwrap();
        let outcome = RsaSha256Verifier
            .verify(region, &sig.to_vec(), pk_der.as_bytes())
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn rsa_wrong_signature_returns_invalid() {
        use rsa::pkcs8::EncodePublicKey;

        let (_sk, vk) = rsa_keypair_2048();
        let pk_der = vk.to_public_key_der().unwrap();
        let bad_sig = vec![0u8; 256];
        let outcome = RsaSha256Verifier
            .verify(b"rsa test region", &bad_sig, pk_der.as_bytes())
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn rsa_bad_key_returns_err() {
        let result = RsaSha256Verifier
            .verify(b"data", &[0u8; 256], b"not-a-der-key")
            .await;
        assert!(matches!(result, Err(TrustError::InvalidKey)));
    }

    fn ecdsa_keypair() -> (p256_ecdsa::ecdsa::SigningKey, p256_ecdsa::PublicKey) {
        use p256_ecdsa::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let pk = p256_ecdsa::PublicKey::from(sk.verifying_key());
        (sk, pk)
    }

    #[tokio::test]
    async fn ecdsa_valid_signature_returns_valid() {
        use p256_ecdsa::{
            ecdsa::{DerSignature, signature::Signer as _},
            pkcs8::EncodePublicKey,
        };

        let (sk, pk) = ecdsa_keypair();
        let region = b"ecdsa test region";
        let sig: DerSignature = sk.sign(region);
        let pk_der = pk.to_public_key_der().unwrap();
        let outcome = EcdsaSha256Verifier
            .verify(region, sig.as_bytes(), pk_der.as_bytes())
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn ecdsa_wrong_signature_returns_invalid() {
        use p256_ecdsa::pkcs8::EncodePublicKey;

        let (_sk, pk) = ecdsa_keypair();
        let pk_der = pk.to_public_key_der().unwrap();
        // Structurally valid DER SEQUENCE { INTEGER 1, INTEGER 1 } as a
        // signature that will not verify.
        let bad_der = [0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let outcome = EcdsaSha256Verifier
            .verify(b"ecdsa test region", &bad_der, pk_der.as_bytes())
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn ecdsa_bad_key_returns_err() {
        let result = EcdsaSha256Verifier
            .verify(b"data", &[0u8; 64], b"not-a-der-key")
            .await;
        assert!(matches!(result, Err(TrustError::InvalidKey)));
    }
}
