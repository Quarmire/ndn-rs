//! Enclave-backed custodian — a P-256 signing key held in platform secure
//! hardware (Android Keystore / StrongBox, iOS Secure Enclave), gated by
//! per-use biometric. The private key is generated inside the enclave and never
//! leaves it; signing happens inside the enclave after the platform's biometric
//! prompt.
//!
//! The actual Keystore / Secure-Enclave calls are platform code (Kotlin /
//! Swift) reached over FFI. This module defines the [`EnclaveBackend`] seam the
//! platform implements and the [`EnclaveCustodian`] that exposes it through the
//! [`Custodian`] trait, so an enclave key slots into the `CustodianRegistry`
//! and the security-tier UI like any other custodian — and, adapted through
//! [`CustodianSigner`](crate::CustodianSigner), backs the
//! [`RemoteSignerResponder`](crate::RemoteSignerResponder) so a phone can sign
//! for another device under biometric.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::KeyId;
use crate::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};

/// The platform's secure-hardware signing op for one enclave key. Implemented
/// by the host (Android Keystore / iOS Secure Enclave via FFI). `sign`
/// triggers the biometric prompt and signs inside the enclave.
#[async_trait]
pub trait EnclaveBackend: Send + Sync {
    /// The enclave key's public key (SEC1 / uncompressed P-256 point), for the
    /// `KeyLocator` and verification. The private half never leaves the enclave.
    fn public_key(&self) -> Bytes;

    /// Sign `region` with the enclave key: the platform shows a biometric
    /// prompt rendering what is being authorized, signs inside the enclave, and
    /// returns the ECDSA (`SignatureSha256WithEcdsa`) signature. A user denial
    /// or timeout is an `Err`.
    async fn sign(&self, region: &[u8]) -> Result<Bytes, CustodianError>;

    /// Whether the enclave key is usable right now (key present, biometry
    /// enrolled, device unlocked).
    fn is_available(&self) -> bool;
}

/// A [`Custodian`] over an [`EnclaveBackend`]. Reports
/// [`CustodianRef::Tpm`] — the key lives in this machine's secure element, and
/// every `sign` prompts for biometric — so the security-tier UI shows it as
/// on-device hardware with per-use approval.
pub struct EnclaveCustodian {
    backend: Arc<dyn EnclaveBackend>,
    device_id: String,
}

impl EnclaveCustodian {
    pub fn new(backend: Arc<dyn EnclaveBackend>, device_id: impl Into<String>) -> Self {
        Self {
            backend,
            device_id: device_id.into(),
        }
    }

    /// The enclave key's public key — e.g. to build the `CustodianSigner`'s
    /// `KeyLocator` or to publish a self-signed certificate for it.
    pub fn public_key(&self) -> Bytes {
        self.backend.public_key()
    }
}

#[async_trait]
impl Custodian for EnclaveCustodian {
    fn kind(&self) -> CustodianRef {
        CustodianRef::Tpm {
            device_id: self.device_id.clone(),
        }
    }

    async fn is_available(&self) -> bool {
        self.backend.is_available()
    }

    fn prompts_per_action(&self) -> bool {
        // Per-use biometric: every signature triggers an enclave prompt.
        true
    }

    async fn unlock(&self, _ctx: UnlockContext) -> Result<(), CustodianError> {
        // No separate unlock step — the biometric prompt is per `sign`. Report
        // availability so callers can gate the UI.
        if self.backend.is_available() {
            Ok(())
        } else {
            Err(CustodianError::Unavailable)
        }
    }

    async fn sign(
        &self,
        _key_id: &KeyId,
        _name: &Name,
        content: &[u8],
    ) -> Result<Bytes, CustodianError> {
        self.backend.sign(content).await
    }

    async fn unwrap_for(
        &self,
        _key_id: &KeyId,
        _wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError> {
        // Content-key unwrap inside the enclave is a later phase; signing is the
        // v1 capability.
        Err(CustodianError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::verifier::EcdsaSha256Verifier;
    use ndn_security::{EcdsaP256Signer, Signer, VerifyOutcome, Verifier};

    /// A software stand-in for the platform enclave: a P-256 key whose `sign`
    /// stands in for the biometric-gated Keystore / Secure-Enclave op.
    struct SoftwareEnclave {
        signer: EcdsaP256Signer,
        public_key: Bytes,
    }

    #[async_trait]
    impl EnclaveBackend for SoftwareEnclave {
        fn public_key(&self) -> Bytes {
            self.public_key.clone()
        }
        async fn sign(&self, region: &[u8]) -> Result<Bytes, CustodianError> {
            self.signer
                .sign_sync(region)
                .map_err(|e| CustodianError::SignFailed(e.to_string()))
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn enclave_custodian_signs_and_verifies() {
        let key: Name = "/op/phone/KEY/enclave".parse().unwrap();
        let signer = EcdsaP256Signer::from_seed(&[5u8; 32], key.clone()).unwrap();
        let pk = signer.public_key().unwrap();
        let backend = Arc::new(SoftwareEnclave {
            signer,
            public_key: pk.clone(),
        });

        let custodian = EnclaveCustodian::new(backend, "phone-1");

        assert!(custodian.is_available().await);
        assert!(custodian.prompts_per_action(), "per-use biometric");
        assert!(
            custodian.kind().key_on_this_machine(),
            "the enclave key is on this device (in secure hardware)"
        );

        let region = b"a privileged command region";
        let sig = custodian
            .sign(&KeyId(key.clone()), &key, region)
            .await
            .expect("enclave signs");
        assert!(matches!(
            EcdsaSha256Verifier.verify(region, &sig, &pk).await,
            Ok(VerifyOutcome::Valid)
        ));
    }
}
