use std::pin::Pin;
use std::future::Future;

use crate::TrustError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of a signature verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid,
    /// Signature is cryptographically invalid.
    Invalid,
}

/// Verifies a signature against a public key.
pub trait Verifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        region:     &'a [u8],
        sig_value:  &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>>;
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify<'a>(
        &'a self,
        region:     &'a [u8],
        sig_value:  &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use ed25519_dalek::{Signature, VerifyingKey, Verifier as _};

            let vk = VerifyingKey::from_bytes(
                public_key.try_into().map_err(|_| TrustError::InvalidKey)?,
            ).map_err(|_| TrustError::InvalidKey)?;

            let sig_bytes: &[u8; 64] = sig_value
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?;
            let sig = Signature::from_bytes(sig_bytes);

            match vk.verify(region, &sig) {
                Ok(())  => Ok(VerifyOutcome::Valid),
                Err(_)  => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}
