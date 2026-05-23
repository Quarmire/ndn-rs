//! [`NdnIdentity`] — KeyChain extended with NDNCERT enrollment, DID-based
//! trust bootstrap, and background certificate renewal.

use std::{path::Path, sync::Arc};

use ndn_security::KeyChain;
use ndn_security::did::{UniversalResolver, name_to_did};

use crate::{
    device::DeviceConfig, enroll::EnrollConfig, error::IdentityError, renewal::RenewalHandle,
};

/// For day-to-day signing and validation, use [`KeyChain`] directly.
/// `NdnIdentity` is the right type when enrollment, DID bootstrap, or
/// background renewal are needed.
pub struct NdnIdentity {
    pub(crate) keychain: KeyChain,
    #[allow(dead_code)]
    pub(crate) renewal: Option<RenewalHandle>,
}

impl std::ops::Deref for NdnIdentity {
    type Target = KeyChain;

    fn deref(&self) -> &KeyChain {
        &self.keychain
    }
}

impl NdnIdentity {
    /// In-memory, self-signed; keys are not persisted.
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let keychain = KeyChain::ephemeral(name)?;
        Ok(Self {
            keychain,
            renewal: None,
        })
    }

    /// On first run, generates an Ed25519 key and self-signed cert.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let keychain = KeyChain::open_or_create(path, name)?;
        Ok(Self {
            keychain,
            renewal: None,
        })
    }

    /// Runs the NDNCERT INFO → NEW → CHALLENGE exchange and persists the
    /// issued cert if `config.storage` is set.
    pub async fn enroll(config: EnrollConfig) -> Result<Self, IdentityError> {
        crate::enroll::run_enrollment(config).await
    }

    /// Selects the challenge from `config.factory_credential`, enrolls,
    /// and (optionally) starts background renewal.
    pub async fn provision(config: DeviceConfig) -> Result<Self, IdentityError> {
        crate::device::run_provisioning(config).await
    }

    /// `did:key:…` uses the public key directly as the anchor;
    /// `did:ndn:…` / `did:web:…` are resolved via `resolver`.
    pub async fn from_did(
        did: &str,
        name: impl AsRef<str>,
        resolver: &UniversalResolver,
    ) -> Result<Self, IdentityError> {
        let doc = resolver.resolve_document(did).await?;
        let identity = Self::ephemeral(name)?;
        if let Some(anchor) = ndn_security::did::did_document_to_trust_anchor(
            &doc,
            Arc::new(identity.keychain.name().clone()),
        ) {
            identity.keychain.add_trust_anchor(anchor);
        }
        Ok(identity)
    }

    pub(crate) fn from_keychain(keychain: KeyChain, renewal: Option<RenewalHandle>) -> Self {
        Self { keychain, renewal }
    }

    /// Wrap an existing keychain (no renewal task).
    pub fn from_keychain_public(keychain: KeyChain) -> Self {
        Self {
            keychain,
            renewal: None,
        }
    }

    /// `did:ndn` URI for this identity.
    pub fn did(&self) -> String {
        name_to_did(self.keychain.name())
    }

    /// Drops the renewal task (if any) and returns the keychain.
    pub fn into_keychain(self) -> KeyChain {
        self.keychain
    }
}

impl std::fmt::Debug for NdnIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NdnIdentity")
            .field("name", &self.keychain.name().to_string())
            .field("key_name", &self.keychain.key_name().to_string())
            .finish()
    }
}
