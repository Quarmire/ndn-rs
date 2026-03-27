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

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;
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

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move {
            use ed25519_dalek::Signer as _;
            let sig = self.signing_key.sign(region);
            Ok(Bytes::copy_from_slice(&sig.to_bytes()))
        })
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
}
