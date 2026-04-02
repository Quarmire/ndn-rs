use std::pin::Pin;
use std::future::Future;

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};
use crate::TrustError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Signs a region of bytes and produces a signature value.
///
/// Implemented as a dyn-compatible trait using `BoxFuture` so it can be stored
/// as `Arc<dyn Signer>` in the key store.
pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_name(&self) -> &Name;
    /// The certificate name to embed as a key locator in SignatureInfo, if any.
    fn cert_name(&self) -> Option<&Name> { None }
    /// Return the raw public key bytes, if available.
    fn public_key(&self) -> Option<Bytes> { None }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;

    /// Synchronous signing — avoids `Box::pin` and async state machine overhead.
    ///
    /// Signers whose work is pure CPU (Ed25519, HMAC) should override this.
    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let _ = region;
        unimplemented!("sign_sync not implemented for this signer — override if signing is CPU-only")
    }
}

/// Ed25519 signer using `ed25519-dalek`.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    key_name:    Name,
    cert_name:   Option<Name>,
}

impl Ed25519Signer {
    pub fn new(
        signing_key: ed25519_dalek::SigningKey,
        key_name: Name,
        cert_name: Option<Name>,
    ) -> Self {
        Self { signing_key, key_name, cert_name }
    }

    /// Construct from raw 32-byte seed bytes.
    pub fn from_seed(seed: &[u8; 32], key_name: Name) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        Self::new(signing_key, key_name, None)
    }

    /// Return the 32-byte compressed Ed25519 public key (verifying key).
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

/// HMAC-SHA256 signer for symmetric (pre-shared key) authentication.
///
/// Significantly faster than Ed25519 (~10x) since it only computes a keyed
/// hash rather than elliptic curve math.
pub struct HmacSha256Signer {
    key:      ring::hmac::Key,
    key_name: Name,
}

impl HmacSha256Signer {
    /// Create from raw key bytes (any length; 32+ bytes recommended).
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

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;

    fn test_key_name() -> Name {
        Name::from_components([NameComponent::generic(bytes::Bytes::from_static(b"testkey"))])
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

    // ── HMAC-SHA256 tests ──────────────────────────────────────────────────

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
        assert_eq!(s1.sign_sync(b"data").unwrap(), s2.sign_sync(b"data").unwrap());
    }

    #[test]
    fn hmac_different_key_different_sig() {
        let s1 = HmacSha256Signer::new(b"key-a", test_key_name());
        let s2 = HmacSha256Signer::new(b"key-b", test_key_name());
        assert_ne!(s1.sign_sync(b"data").unwrap(), s2.sign_sync(b"data").unwrap());
    }

    #[tokio::test]
    async fn hmac_async_matches_sync() {
        let s = HmacSha256Signer::new(b"key", test_key_name());
        let async_sig = s.sign(b"data").await.unwrap();
        let sync_sig = s.sign_sync(b"data").unwrap();
        assert_eq!(async_sig, sync_sig);
    }

    // ── Ed25519 sign_sync tests ────────────────────────────────────────────

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
}
