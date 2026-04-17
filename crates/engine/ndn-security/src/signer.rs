use std::future::Future;
use std::pin::Pin;

use crate::TrustError;
use bytes::Bytes;
use ndn_packet::{Name, SignatureType};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_name(&self) -> &Name;
    fn cert_name(&self) -> Option<&Name> {
        None
    }
    fn public_key(&self) -> Option<Bytes> {
        None
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let _ = region;
        unimplemented!(
            "sign_sync not implemented for this signer — override if signing is CPU-only"
        )
    }
}

pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    key_name: Name,
    cert_name: Option<Name>,
}

impl Ed25519Signer {
    pub fn new(
        signing_key: ed25519_dalek::SigningKey,
        key_name: Name,
        cert_name: Option<Name>,
    ) -> Self {
        Self {
            signing_key,
            key_name,
            cert_name,
        }
    }

    pub fn from_seed(seed: &[u8; 32], key_name: Name) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        Self::new(signing_key, key_name, None)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureEd25519
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn cert_name(&self) -> Option<&Name> {
        self.cert_name.as_ref()
    }

    fn public_key(&self) -> Option<Bytes> {
        Some(Bytes::copy_from_slice(&self.public_key_bytes()))
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(region);
        Ok(Bytes::copy_from_slice(&sig.to_bytes()))
    }
}

pub struct HmacSha256Signer {
    key: ring::hmac::Key,
    key_name: Name,
}

impl HmacSha256Signer {
    pub fn new(key_bytes: &[u8], key_name: Name) -> Self {
        Self {
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes),
            key_name,
        }
    }
}

impl Signer for HmacSha256Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureHmacWithSha256
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let tag = ring::hmac::sign(&self.key, region);
        Ok(Bytes::copy_from_slice(tag.as_ref()))
    }
}

// Plain and keyed BLAKE3 use distinct type codes to prevent downgrade attacks.
// Both are reserved on the NDN TLV SignatureType registry.
// See `docs/wiki/src/reference/blake3-signature-spec.md`.

pub const SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN: u64 = 6;
pub const SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED: u64 = 7;

/// Plain BLAKE3 digest signer (type 6). No secret key -- integrity only.
pub struct Blake3Signer {
    key_name: Name,
}

impl Blake3Signer {
    pub fn new(key_name: Name) -> Self {
        Self { key_name }
    }
}

impl Signer for Blake3Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN)
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let hash = blake3_hash_auto(region);
        Ok(Bytes::copy_from_slice(hash.as_bytes()))
    }
}

/// 128 KiB: crossover where rayon thread-spawn overhead pays for itself.
pub const BLAKE3_RAYON_THRESHOLD: usize = 128 * 1024;

pub fn blake3_hash_auto(region: &[u8]) -> blake3::Hash {
    if region.len() >= BLAKE3_RAYON_THRESHOLD {
        let mut h = blake3::Hasher::new();
        h.update_rayon(region);
        h.finalize()
    } else {
        blake3::hash(region)
    }
}

pub fn blake3_keyed_hash_auto(key: &[u8; 32], region: &[u8]) -> blake3::Hash {
    if region.len() >= BLAKE3_RAYON_THRESHOLD {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update_rayon(region);
        h.finalize()
    } else {
        blake3::keyed_hash(key, region)
    }
}

/// Keyed BLAKE3 signer (type 7). Requires a 32-byte secret.
pub struct Blake3KeyedSigner {
    key: [u8; 32],
    key_name: Name,
}

impl Blake3KeyedSigner {
    pub fn new(key: [u8; 32], key_name: Name) -> Self {
        Self { key, key_name }
    }
}

impl Signer for Blake3KeyedSigner {
    fn sig_type(&self) -> SignatureType {
        SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED)
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let hash = blake3_keyed_hash_auto(&self.key, region);
        Ok(Bytes::copy_from_slice(hash.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;

    fn test_key_name() -> Name {
        Name::from_components([NameComponent::generic(bytes::Bytes::from_static(
            b"testkey",
        ))])
    }

    #[tokio::test]
    async fn sig_type_is_ed25519() {
        let s = Ed25519Signer::from_seed(&[1u8; 32], test_key_name());
        assert_eq!(s.sig_type(), SignatureType::SignatureEd25519);
    }

    #[tokio::test]
    async fn sign_produces_64_bytes() {
        let s = Ed25519Signer::from_seed(&[2u8; 32], test_key_name());
        let sig = s.sign(b"hello ndn").await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn deterministic_signature() {
        let seed = [3u8; 32];
        let s1 = Ed25519Signer::from_seed(&seed, test_key_name());
        let s2 = Ed25519Signer::from_seed(&seed, test_key_name());
        let sig1 = s1.sign(b"region").await.unwrap();
        let sig2 = s2.sign(b"region").await.unwrap();
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn different_region_different_signature() {
        let s = Ed25519Signer::from_seed(&[4u8; 32], test_key_name());
        let sig1 = s.sign(b"region-a").await.unwrap();
        let sig2 = s.sign(b"region-b").await.unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn key_name_accessor() {
        let name = test_key_name();
        let s = Ed25519Signer::from_seed(&[0u8; 32], name.clone());
        assert_eq!(s.key_name(), &name);
    }

    #[test]
    fn cert_name_defaults_to_none() {
        let s = Ed25519Signer::from_seed(&[0u8; 32], test_key_name());
        assert!(s.cert_name().is_none());
    }


    #[test]
    fn hmac_sig_type() {
        let s = HmacSha256Signer::new(b"secret", test_key_name());
        assert_eq!(s.sig_type(), SignatureType::SignatureHmacWithSha256);
    }

    #[test]
    fn hmac_sign_sync_produces_32_bytes() {
        let s = HmacSha256Signer::new(b"secret", test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn hmac_deterministic() {
        let s1 = HmacSha256Signer::new(b"key", test_key_name());
        let s2 = HmacSha256Signer::new(b"key", test_key_name());
        assert_eq!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[test]
    fn hmac_different_key_different_sig() {
        let s1 = HmacSha256Signer::new(b"key-a", test_key_name());
        let s2 = HmacSha256Signer::new(b"key-b", test_key_name());
        assert_ne!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[tokio::test]
    async fn hmac_async_matches_sync() {
        let s = HmacSha256Signer::new(b"key", test_key_name());
        let async_sig = s.sign(b"data").await.unwrap();
        let sync_sig = s.sign_sync(b"data").unwrap();
        assert_eq!(async_sig, sync_sig);
    }


    #[test]
    fn ed25519_sign_sync_produces_64_bytes() {
        let s = Ed25519Signer::from_seed(&[2u8; 32], test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn ed25519_async_matches_sync() {
        let s = Ed25519Signer::from_seed(&[5u8; 32], test_key_name());
        let async_sig = s.sign(b"data").await.unwrap();
        let sync_sig = s.sign_sync(b"data").unwrap();
        assert_eq!(async_sig, sync_sig);
    }

    #[test]
    fn blake3_plain_and_keyed_use_distinct_sig_types() {
        let plain = Blake3Signer::new(test_key_name());
        let keyed = Blake3KeyedSigner::new([9u8; 32], test_key_name());
        assert_eq!(
            plain.sig_type(),
            SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN)
        );
        assert_eq!(
            keyed.sig_type(),
            SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED)
        );
        assert_ne!(
            plain.sig_type(),
            keyed.sig_type(),
            "plain and keyed BLAKE3 must not share a type code"
        );
    }

    #[test]
    fn blake3_sig_type_code_values_are_pinned() {
        assert_eq!(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN, 6);
        assert_eq!(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED, 7);
    }

    #[test]
    fn blake3_plain_produces_32_bytes() {
        let s = Blake3Signer::new(test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn blake3_keyed_produces_32_bytes() {
        let s = Blake3KeyedSigner::new([1u8; 32], test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn blake3_keyed_different_key_different_sig() {
        let s1 = Blake3KeyedSigner::new([1u8; 32], test_key_name());
        let s2 = Blake3KeyedSigner::new([2u8; 32], test_key_name());
        assert_ne!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[test]
    fn blake3_plain_and_keyed_with_zero_key_differ() {
        let plain = Blake3Signer::new(test_key_name());
        let keyed = Blake3KeyedSigner::new([0u8; 32], test_key_name());
        assert_ne!(
            plain.sign_sync(b"region").unwrap(),
            keyed.sign_sync(b"region").unwrap()
        );
    }
}
