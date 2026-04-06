use std::future::Future;
use std::pin::Pin;

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
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>>;
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Synchronous Ed25519 verification — avoids boxing a Future for CPU-only work.
    pub fn verify_sync(
        &self,
        region: &[u8],
        sig_value: &[u8],
        public_key: &[u8],
    ) -> VerifyOutcome {
        use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

        let Ok(vk) = VerifyingKey::from_bytes(
            public_key.try_into().unwrap_or(&[0u8; 32]),
        ) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

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
}
