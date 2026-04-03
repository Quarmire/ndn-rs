use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ndn_packet::Name;
use ndn_security::{SecurityManager, Signer, TrustSchema, Validator, pib::FilePib};

use crate::AppError;

/// Simplified security facade for application-level signing and verification.
///
/// Wraps `SecurityManager` with ergonomic defaults for key generation,
/// signing, and validation.
pub struct KeyChain {
    mgr: SecurityManager,
}

impl KeyChain {
    /// Create an in-memory keychain (testing/ephemeral).
    pub fn new() -> Self {
        Self {
            mgr: SecurityManager::new(),
        }
    }

    /// Open a persistent keychain from a PIB directory for the given identity.
    pub fn open(path: impl AsRef<Path>, identity: &Name) -> Result<Self, AppError> {
        let pib = FilePib::open(path.as_ref()).map_err(|e| AppError::Engine(e.into()))?;
        let mgr =
            SecurityManager::from_pib(&pib, identity).map_err(|e| AppError::Engine(e.into()))?;
        Ok(Self { mgr })
    }

    /// Default certificate validity: 365 days (in milliseconds).
    const DEFAULT_CERT_VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

    /// Generate an Ed25519 key pair and self-signed certificate for an identity.
    ///
    /// `validity` sets the certificate lifetime. Pass `None` for the default
    /// of 365 days.
    ///
    /// Returns a `Signer` handle suitable for use with `DataBuilder::sign()`.
    pub fn create_identity(
        &self,
        identity: impl Into<Name>,
        validity: Option<Duration>,
    ) -> Result<Arc<dyn Signer>, AppError> {
        let name = identity.into();
        self.mgr
            .generate_ed25519(name.clone())
            .map_err(|e| AppError::Engine(e.into()))?;

        let signer = self
            .mgr
            .get_signer_sync(&name)
            .map_err(|e| AppError::Engine(e.into()))?;

        let validity_ms = validity
            .map(|d| d.as_millis() as u64)
            .unwrap_or(Self::DEFAULT_CERT_VALIDITY_MS);

        if let Some(pk) = signer.public_key() {
            let _ = self.mgr.issue_self_signed(&name, pk, validity_ms);
        }

        Ok(signer)
    }

    /// Get the signer for an existing identity.
    pub async fn signer(&self, identity: impl Into<Name>) -> Result<Arc<dyn Signer>, AppError> {
        let name = identity.into();
        self.mgr
            .get_signer(&name)
            .await
            .map_err(|e| AppError::Engine(e.into()))
    }

    /// Build a `Validator` configured with this keychain's trust anchors.
    ///
    /// Uses a permissive trust schema by default (any signer with a known
    /// certificate is accepted). For production use, configure a proper
    /// `TrustSchema`.
    pub fn validator(&self) -> Validator {
        let schema = TrustSchema::new(); // permissive
        let v = Validator::new(schema);
        // Pre-populate the validator's cert cache with our anchors.
        for anchor_name in self.mgr.trust_anchor_names() {
            if let Some(cert) = self.mgr.trust_anchor(&anchor_name) {
                v.cert_cache().insert(cert);
            }
        }
        v
    }

    /// Access the underlying `SecurityManager`.
    pub fn manager(&self) -> &SecurityManager {
        &self.mgr
    }
}

impl Default for KeyChain {
    fn default() -> Self {
        Self::new()
    }
}
