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
