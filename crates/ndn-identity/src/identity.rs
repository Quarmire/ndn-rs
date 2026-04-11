//! [`NdnIdentity`] — a named NDN identity with full lifecycle management.

use std::{path::Path, sync::Arc};

use ndn_security::KeyChain;
use ndn_security::did::{UniversalResolver, name_to_did};

use crate::{
    device::DeviceConfig,
    enroll::EnrollConfig,
    error::IdentityError,
    renewal::RenewalHandle,
};

/// A named NDN identity with full lifecycle management.
///
/// `NdnIdentity` extends [`KeyChain`] with identity lifecycle operations:
/// NDNCERT enrollment, fleet provisioning, DID-based trust, and background
/// certificate renewal.
///
/// For the vast majority of applications — signing data and validating
/// incoming packets — use [`KeyChain`] directly (available as
/// `ndn_app::KeyChain` or `ndn_security::KeyChain`). Reach for `NdnIdentity`
/// when you need:
/// - [`enroll`] / [`provision`] — NDNCERT certificate issuance
/// - [`from_did`] — trust bootstrapping from a DID document
/// - [`did`] — `did:ndn` URI for this identity
///
/// [`enroll`]: Self::enroll
/// [`provision`]: Self::provision
/// [`from_did`]: Self::from_did
/// [`did`]: Self::did
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
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create an ephemeral, in-memory, self-signed identity.
    ///
    /// Suitable for testing and short-lived producers. Keys are not persisted.
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let keychain = KeyChain::ephemeral(name)?;
        Ok(Self { keychain, renewal: None })
    }

    /// Open a persistent identity from a PIB directory, creating it if absent.
    ///
    /// On first run, generates an Ed25519 key and self-signed certificate.
    /// On subsequent runs, loads the existing key and certificate.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let keychain = KeyChain::open_or_create(path, name)?;
        Ok(Self { keychain, renewal: None })
    }

    /// Enroll via NDNCERT using the given configuration.
    ///
    /// Performs the full NDNCERT exchange: INFO → NEW → CHALLENGE. The issued
    /// certificate is persisted if `config.storage` is set.
    pub async fn enroll(config: EnrollConfig) -> Result<Self, IdentityError> {
        crate::enroll::run_enrollment(config).await
    }

    /// Zero-touch device provisioning.
    ///
    /// Selects a challenge type based on [`FactoryCredential`], enrolls with
    /// the CA, and starts a background renewal task if requested.
    ///
    /// [`FactoryCredential`]: crate::device::FactoryCredential
    pub async fn provision(config: DeviceConfig) -> Result<Self, IdentityError> {
        crate::device::run_provisioning(config).await
    }

    /// Bootstrap trust from a DID document and create a local ephemeral identity
    /// that trusts it.
    ///
    /// - `did:key:…` — public key used directly as a trust anchor.
    /// - `did:ndn:…` / `did:web:…` — document resolved via `resolver`.
    pub async fn from_did(
        did: &str,
        name: impl AsRef<str>,
        resolver: &UniversalResolver,
    ) -> Result<Self, IdentityError> {
        let doc = resolver.resolve(did).await?;
        let identity = Self::ephemeral(name)?;
        if let Some(anchor) = ndn_security::did::did_document_to_trust_anchor(
            &doc,
            Arc::new(identity.keychain.name().clone()),
        ) {
            identity.keychain.add_trust_anchor(anchor);
        }
        Ok(identity)
    }

    // ── Internal constructor ──────────────────────────────────────────────────

    /// Construct from a pre-built [`KeyChain`] and an optional renewal handle.
    ///
    /// Used by `enroll.rs` and `device.rs` which build the `SecurityManager`
    /// directly before wrapping it.
    pub(crate) fn from_keychain(keychain: KeyChain, renewal: Option<RenewalHandle>) -> Self {
        Self { keychain, renewal }
    }

    // ── Identity-specific accessors ───────────────────────────────────────────

    /// The `did:ndn` URI for this identity.
    pub fn did(&self) -> String {
        name_to_did(self.keychain.name())
    }

    /// Convert this `NdnIdentity` into the underlying [`KeyChain`].
    ///
    /// The renewal task (if any) is dropped and its background task cancelled.
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
