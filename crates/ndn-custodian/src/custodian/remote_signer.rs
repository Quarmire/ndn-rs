//! Remote-signer custodian — the operator key lives on *another* device or
//! process (a phone, a second machine, a hardware token, a server), which
//! gates each signature (typically with biometric / a tap) and signs on the
//! dashboard's behalf. The key never touches this host, so it's the desktop
//! dashboard's real per-use second factor (where a local keychain can't be,
//! on an unsigned build).
//!
//! A phone "fob" is one instance — it's just a [`RemoteCustodian`] reporting
//! [`CustodianRef::Fob`]; a networked signer reports [`CustodianRef::Remote`].
//!
//! This module is the **dashboard side + the wire contract**: the
//! [`RemoteSignerTransport`] channel (concrete impls ride an NDN face —
//! WebRTC, BLE, Wi-Fi Aware — or a relay) and [`RemoteCustodian`], which
//! delegates [`Custodian::sign`] to the remote signer. The signer app
//! implements the matching responder against the same [`RemoteSignRequest`].
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

/// A signing request sent to the remote signer.
///
/// `context` is the human-readable summary of *what* is being authorized
/// (e.g. the command name) — the remote device shows it so the operator
/// approves the real action, not a blind blob. This is the MITM defence: a
/// tampered `region` surfaces as a different `context`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignRequest {
    /// Key name the dashboard expects the signer to sign with.
    pub key_name: Name,
    /// The exact bytes to sign (the command's signed region).
    pub region: Bytes,
    /// Human-readable summary shown on the remote device for approval.
    pub context: String,
}

/// The channel to the remote signer. Concrete impls ride an NDN face (WebRTC /
/// BLE / Wi-Fi Aware) or a relay; a loopback impl backs tests so the
/// delegation logic is testable without a real device or channel.
#[async_trait]
pub trait RemoteSignerTransport: Send + Sync {
    /// Send `req` to the remote signer and await the operator-approved
    /// signature. Errors when it's unreachable, denies, or times out.
    async fn request_signature(&self, req: &RemoteSignRequest) -> Result<Bytes, CustodianError>;

    /// Whether the remote signer is reachable right now.
    async fn is_reachable(&self) -> bool;
}

/// A [`Custodian`] whose key lives on a remote signer. `sign` delegates to it
/// over a [`RemoteSignerTransport`]; the remote device gates each signature.
/// The private key never touches this host. `kind` lets the caller say what
/// the signer is (a phone [`CustodianRef::Fob`], a networked
/// [`CustodianRef::Remote`], a [`CustodianRef::Tpm`], …).
pub struct RemoteCustodian {
    transport: Arc<dyn RemoteSignerTransport>,
    kind: CustodianRef,
}

impl RemoteCustodian {
    pub fn new(transport: Arc<dyn RemoteSignerTransport>, kind: CustodianRef) -> Self {
        Self { transport, kind }
    }
}

#[async_trait]
impl Custodian for RemoteCustodian {
    fn kind(&self) -> CustodianRef {
        self.kind.clone()
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
        let req = RemoteSignRequest {
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
        // Content-key unwrap on a remote signer is a later phase (it would
        // unwrap after UV); signing is the v1 capability.
        Err(CustodianError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::{Ed25519Signer, Ed25519Verifier, Signer, VerifyOutcome};

    /// A loopback remote signer: signs locally, standing in for the remote
    /// device so the delegation loop is testable without one.
    struct LoopbackSigner {
        signer: Ed25519Signer,
        reachable: bool,
    }

    #[async_trait]
    impl RemoteSignerTransport for LoopbackSigner {
        async fn request_signature(
            &self,
            req: &RemoteSignRequest,
        ) -> Result<Bytes, CustodianError> {
            self.signer
                .sign_sync(&req.region)
                .map_err(|e| CustodianError::SignFailed(e.to_string()))
        }
        async fn is_reachable(&self) -> bool {
            self.reachable
        }
    }

    #[tokio::test]
    async fn remote_custodian_delegates_signing_and_verifies() {
        let name: Name = "/op/alice/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[9u8; 32], name.clone());
        let pk = signer.public_key_bytes();

        let transport = Arc::new(LoopbackSigner {
            signer,
            reachable: true,
        });
        // A phone fob is one kind of remote signer.
        let custodian = RemoteCustodian::new(
            transport,
            CustodianRef::Fob {
                fob_id: "phone-1".into(),
            },
        );

        assert!(custodian.is_available().await);
        assert!(custodian.prompts_per_action());
        assert!(!custodian.kind().key_on_this_machine(), "key is off-host");

        // The dashboard delegates signing to the remote signer; the returned
        // signature verifies against the signer's public key.
        let region = b"to-be-signed command region";
        let sig = custodian
            .sign(&KeyId(name.clone()), &name, region)
            .await
            .expect("remote signs");
        assert!(matches!(
            Ed25519Verifier.verify_sync(region, &sig, &pk),
            VerifyOutcome::Valid
        ));
    }

    #[tokio::test]
    async fn unreachable_remote_is_unavailable() {
        let name: Name = "/op/bob/KEY/k1".parse().unwrap();
        let transport = Arc::new(LoopbackSigner {
            signer: Ed25519Signer::from_seed(&[1u8; 32], name.clone()),
            reachable: false,
        });
        let custodian =
            RemoteCustodian::new(transport, CustodianRef::Remote { reachable_via: name });
        assert!(!custodian.is_available().await);
        assert!(matches!(
            custodian.unlock(UnlockContext::default()).await,
            Err(CustodianError::Unavailable)
        ));
    }
}
