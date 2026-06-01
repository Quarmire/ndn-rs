//! Fob custodian — the operator key lives on a paired phone, which gates each
//! signature with on-device biometric. The key never touches this host, so
//! it's the desktop dashboard's real per-use second factor (where a local
//! keychain can't be, on an unsigned build).
//!
//! This module is the **dashboard side + the wire contract**: the
//! [`FobTransport`] channel (concrete impls ride an NDN face — WebRTC, BLE,
//! Wi-Fi Aware — or a relay) and [`FobCustodian`], which delegates
//! [`Custodian::sign`] to the phone. The phone app implements the matching
//! responder against the same [`FobSignRequest`] shape.
//!
//! Full design + protocol + security model:
//! `.claude/notes/remote-fob-design-2026-06-01.md`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::KeyId;
use crate::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};

/// A signing request sent to the fob.
///
/// `context` is the human-readable summary of *what* is being authorized
/// (e.g. the command name) — the phone shows it so the operator approves the
/// real action, not a blind blob. This is the MITM defence: a tampered
/// `region` surfaces as a different `context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FobSignRequest {
    /// Key name the dashboard expects the fob to sign with.
    pub key_name: Name,
    /// The exact bytes to sign (the command's signed region).
    pub region: Bytes,
    /// Human-readable summary shown on the phone for approval.
    pub context: String,
}

/// The channel to the paired fob. Concrete impls ride an NDN face (WebRTC /
/// BLE / Wi-Fi Aware) or a relay; a loopback impl backs tests so the
/// delegation logic is testable without a real device or channel.
#[async_trait]
pub trait FobTransport: Send + Sync {
    /// Send `req` to the fob and await the operator-approved signature. Errors
    /// when the fob is unreachable, denies, or times out.
    async fn request_signature(&self, req: &FobSignRequest) -> Result<Bytes, CustodianError>;

    /// Whether the fob is reachable right now.
    async fn is_reachable(&self) -> bool;
}

/// A [`Custodian`] whose key lives on a remote fob. `sign` delegates to the
/// phone over [`FobTransport`]; the phone gates each signature with biometric.
/// The private key never touches this host.
pub struct FobCustodian {
    transport: Arc<dyn FobTransport>,
    fob_id: String,
}

impl FobCustodian {
    pub fn new(transport: Arc<dyn FobTransport>, fob_id: impl Into<String>) -> Self {
        Self {
            transport,
            fob_id: fob_id.into(),
        }
    }
}

#[async_trait]
impl Custodian for FobCustodian {
    fn kind(&self) -> CustodianRef {
        CustodianRef::Fob {
            fob_id: self.fob_id.clone(),
        }
    }

    async fn is_available(&self) -> bool {
        self.transport.is_reachable().await
    }

    fn prompts_per_action(&self) -> bool {
        true
    }

    async fn unlock(&self, _ctx: UnlockContext) -> Result<(), CustodianError> {
        if self.transport.is_reachable().await {
            Ok(())
        } else {
            Err(CustodianError::Unavailable)
        }
    }

    async fn sign(
        &self,
        _key_id: &KeyId,
        name: &Name,
        content: &[u8],
    ) -> Result<Bytes, CustodianError> {
        let req = FobSignRequest {
            key_name: name.clone(),
            region: Bytes::copy_from_slice(content),
            context: format!("Authorize a signed command as {name}"),
        };
        self.transport.request_signature(&req).await
    }

    async fn unwrap_for(
        &self,
        _key_id: &KeyId,
        _wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError> {
        // Content-key unwrap on a fob is a later phase (the fob would unwrap
        // after UV); signing is the v1 capability.
        Err(CustodianError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::{Ed25519Signer, Ed25519Verifier, Signer, VerifyOutcome};

    /// A loopback fob: signs locally, standing in for the phone so the
    /// delegation loop is testable without a real device or channel.
    struct LoopbackFob {
        signer: Ed25519Signer,
        reachable: bool,
    }

    #[async_trait]
    impl FobTransport for LoopbackFob {
        async fn request_signature(&self, req: &FobSignRequest) -> Result<Bytes, CustodianError> {
            self.signer
                .sign_sync(&req.region)
                .map_err(|e| CustodianError::SignFailed(e.to_string()))
        }
        async fn is_reachable(&self) -> bool {
            self.reachable
        }
    }

    #[tokio::test]
    async fn fob_custodian_delegates_signing_and_verifies() {
        let name: Name = "/op/alice/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[9u8; 32], name.clone());
        let pk = signer.public_key_bytes();

        let transport = Arc::new(LoopbackFob {
            signer,
            reachable: true,
        });
        let fob = FobCustodian::new(transport, "phone-1");

        assert!(fob.is_available().await);
        assert!(fob.prompts_per_action());
        assert!(!fob.kind().key_on_this_machine(), "fob key is off-host");

        // The dashboard delegates signing to the fob; the returned signature
        // verifies against the fob's public key.
        let region = b"to-be-signed command region";
        let sig = fob
            .sign(&KeyId(name.clone()), &name, region)
            .await
            .expect("fob signs");
        assert!(matches!(
            Ed25519Verifier.verify_sync(region, &sig, &pk),
            VerifyOutcome::Valid
        ));
    }

    #[tokio::test]
    async fn unreachable_fob_is_unavailable() {
        let name: Name = "/op/bob/KEY/k1".parse().unwrap();
        let transport = Arc::new(LoopbackFob {
            signer: Ed25519Signer::from_seed(&[1u8; 32], name),
            reachable: false,
        });
        let fob = FobCustodian::new(transport, "phone-off");
        assert!(!fob.is_available().await);
        assert!(matches!(
            fob.unlock(UnlockContext::default()).await,
            Err(CustodianError::Unavailable)
        ));
    }
}
