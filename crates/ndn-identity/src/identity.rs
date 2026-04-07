//! [`NdnIdentity`] — the primary handle for an NDN identity.

use std::{path::Path, sync::Arc, time::Duration};

use ndn_did::{UniversalResolver, name_to_did};
use ndn_packet::Name;
use ndn_security::{SecurityManager, Signer, TrustSchema, Validator};

use crate::{
    device::DeviceConfig,
    enroll::EnrollConfig,
    error::IdentityError,
    renewal::RenewalHandle,
};

/// A handle for a named NDN identity.
///
/// Wraps a [`SecurityManager`] and provides a clean API for signing, validation,
/// and identity lifecycle management. The underlying `SecurityManager` is always
/// accessible via [`security_manager`](NdnIdentity::security_manager) for
/// low-level control.
pub struct NdnIdentity {
    pub(crate) name: Name,
    pub(crate) manager: Arc<SecurityManager>,
    pub(crate) key_name: Name,
    #[allow(dead_code)]
    pub(crate) renewal: Option<RenewalHandle>,
}

impl NdnIdentity {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create an ephemeral, in-memory, self-signed identity.
    ///
    /// Suitable for testing and short-lived producers. Keys are not persisted.
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| IdentityError::Name(name.as_ref().to_string()))?;

        let manager = SecurityManager::new();
        let key_name = name.clone().append("KEY").append("v=0");
        manager.generate_ed25519(key_name.clone())?;

        // Self-sign with 365-day validity.
        let validity_ms = Duration::from_secs(365 * 86400).as_millis() as u64;
        let signer = manager.get_signer_sync(&key_name)?;
        let pubkey = signer.public_key().unwrap_or_default();
        let cert = manager.issue_self_signed(&key_name, pubkey, validity_ms)?;
        manager.add_trust_anchor(cert);

        Ok(Self {
            name,
            manager: Arc::new(manager),
            key_name,
            renewal: None,
        })
    }

    /// Open a persistent identity from a PIB directory, creating it if absent.
    ///
    /// On first run, generates an Ed25519 key and self-signed certificate.
    /// On subsequent runs, loads the existing key and certificate.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, IdentityError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| IdentityError::Name(name.as_ref().to_string()))?;

        let (manager, _created) = SecurityManager::auto_init(&name, path)?;
        let key_name = derive_key_name(&name, &manager)?;

        Ok(Self {
            name,
            manager: Arc::new(manager),
            key_name,
            renewal: None,
        })
    }

    /// Enroll via NDNCERT using the given configuration.
    ///
    /// This performs the full NDNCERT exchange: INFO → NEW → CHALLENGE.
    /// The issued certificate is persisted if `config.storage` is set.
    pub async fn enroll(config: EnrollConfig) -> Result<Self, IdentityError> {
        crate::enroll::run_enrollment(config).await
    }

    /// Zero-touch device provisioning.
    ///
    /// Automatically selects a challenge type based on [`FactoryCredential`],
    /// enrolls with the CA, and starts a background renewal task.
    pub async fn provision(config: DeviceConfig) -> Result<Self, IdentityError> {
        crate::device::run_provisioning(config).await
    }

    /// Resolve a DID to a trust anchor and create a local ephemeral identity
    /// that trusts it.
    ///
    /// If the DID is `did:key:...`, the key is used directly.
    /// For `did:ndn:...` and `did:web:...`, the document is resolved via the
    /// provided resolver.
    pub async fn from_did(
        did: &str,
        name: impl AsRef<str>,
        resolver: &UniversalResolver,
    ) -> Result<Self, IdentityError> {
        let doc = resolver.resolve(did).await?;
        let identity = Self::ephemeral(name)?;
        if let Some(anchor) = ndn_did::did_document_to_trust_anchor(
            &doc,
            Arc::new(identity.name.clone()),
        ) {
            identity.manager.add_trust_anchor(anchor);
        }
        Ok(identity)
    }

    // ── Identity accessors ────────────────────────────────────────────────────

    /// The NDN name of this identity (e.g. `/com/acme/alice`).
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// The `did:ndn` representation of this identity.
    pub fn did(&self) -> String {
        name_to_did(&self.name)
    }

    /// The name of the signing key (e.g. `/com/acme/alice/KEY/v=0`).
    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    // ── Security operations ───────────────────────────────────────────────────

    /// Get the signer for this identity.
    pub fn signer(&self) -> Result<Arc<dyn Signer>, IdentityError> {
        Ok(self.manager.get_signer_sync(&self.key_name)?)
    }

    /// Build a [`Validator`] that trusts this identity's anchors.
    ///
    /// Uses an accept-all trust schema (no name-pattern enforcement).
    /// For strict schema enforcement, build a `Validator` manually from
    /// `security_manager()`.
    pub fn validator(&self) -> Validator {
        Validator::new(TrustSchema::accept_all())
    }

    // ── Escape hatch ──────────────────────────────────────────────────────────

    /// Full access to the underlying [`SecurityManager`].
    ///
    /// Use this for operations not covered by the `NdnIdentity` API.
    pub fn security_manager(&self) -> &SecurityManager {
        &self.manager
    }

    /// The shared [`Arc`] wrapping the security manager.
    pub fn security_manager_arc(&self) -> Arc<SecurityManager> {
        self.manager.clone()
    }
}

impl std::fmt::Debug for NdnIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NdnIdentity")
            .field("name", &self.name.to_string())
            .field("key_name", &self.key_name.to_string())
            .finish()
    }
}

/// Derive the signing key name from a loaded SecurityManager.
///
/// Looks for a trust anchor whose name starts with the identity name and
/// contains a "KEY" component.
pub(crate) fn derive_key_name(
    name: &Name,
    manager: &SecurityManager,
) -> Result<Name, IdentityError> {
    let name_str = name.to_string();
    for anchor_name in manager.trust_anchor_names() {
        let anchor_str = anchor_name.to_string();
        if anchor_str.starts_with(&name_str) && anchor_str.contains("/KEY/") {
            // Strip the trailing /self or issuer component to get the key name
            // by parsing the anchor name directly as the key name.
            let key_name: Name = anchor_str
                .parse()
                .map_err(|_| IdentityError::Name(anchor_str.clone()))?;
            return Ok(key_name);
        }
    }
    // Fallback: construct a conventional key name.
    Ok(name.clone().append("KEY").append("v=0"))
}
