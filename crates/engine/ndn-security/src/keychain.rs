//! [`KeyChain`] — the primary security API for NDN applications.

use std::path::Path;
use std::sync::Arc;

use ndn_packet::Name;

use ndn_packet::SignatureType;
use ndn_packet::encode::{DataBuilder, InterestBuilder};

use crate::{CertCache, Certificate, SecurityManager, Signer, TrustError, TrustSchema, Validator};

/// A named NDN identity with an associated signing key and trust anchors.
///
/// `KeyChain` is the single entry point for NDN security in both applications
/// and the forwarder. It owns a signing key, a certificate cache, and a set of
/// trust anchors, and exposes methods for signing packets and building validators.
///
/// # Constructors
///
/// - [`KeyChain::ephemeral`] — in-memory, self-signed; ideal for tests and
///   short-lived producers.
/// - [`KeyChain::open_or_create`] — file-backed PIB; generates a key on first
///   run and reloads it on subsequent runs.
/// - [`KeyChain::from_parts`] — construct from a pre-built [`SecurityManager`];
///   intended for framework code (NDNCERT enrollment, device provisioning).
///
/// # Examples
///
/// ```rust,no_run
/// use ndn_security::KeyChain;
///
/// // Ephemeral identity (testing / short-lived producers)
/// let kc = KeyChain::ephemeral("/com/example/alice")?;
/// let signer = kc.signer()?;
///
/// // Persistent identity
/// let kc = KeyChain::open_or_create(
///     std::path::Path::new("/var/lib/ndn"),
///     "/com/example/alice",
/// )?;
/// # Ok::<(), ndn_security::TrustError>(())
/// ```
pub struct KeyChain {
    pub(crate) mgr: Arc<SecurityManager>,
    name: Name,
    key_name: Name,
}

/// Default certificate validity (365 days in milliseconds).
const DEFAULT_CERT_VALIDITY_MS: u64 = 365 * 24 * 3600 * 1_000;

impl KeyChain {
    /// Create an ephemeral, in-memory identity with a freshly generated Ed25519 key.
    ///
    /// The key is self-signed with a 365-day certificate and registered as a
    /// trust anchor. Keys are not persisted — use [`open_or_create`] for
    /// long-lived identities.
    ///
    /// [`open_or_create`]: Self::open_or_create
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, TrustError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| TrustError::KeyStore(format!("invalid NDN name: {}", name.as_ref())))?;

        let mgr = SecurityManager::new();
        let key_name = name.clone().append("KEY").append("v=0");
        mgr.generate_ed25519(key_name.clone())?;

        let signer = mgr.get_signer_sync(&key_name)?;
        let pubkey = signer.public_key().unwrap_or_default();
        let cert = mgr.issue_self_signed(&key_name, pubkey, DEFAULT_CERT_VALIDITY_MS)?;
        mgr.add_trust_anchor(cert);

        Ok(Self {
            mgr: Arc::new(mgr),
            name,
            key_name,
        })
    }

    /// Open a persistent identity from a PIB directory, creating it if absent.
    ///
    /// On first run, generates an Ed25519 key and self-signed certificate.
    /// On subsequent runs, loads the existing key and certificate from disk.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, TrustError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| TrustError::KeyStore(format!("invalid NDN name: {}", name.as_ref())))?;

        let (mgr, _created) = SecurityManager::auto_init(&name, path)?;

        let key_name = derive_key_name(&name, &mgr)
            .unwrap_or_else(|| name.clone().append("KEY").append("v=0"));

        Ok(Self {
            mgr: Arc::new(mgr),
            name,
            key_name,
        })
    }

    /// Construct a `KeyChain` from a pre-built `SecurityManager`.
    ///
    /// This is an escape hatch for framework code (NDNCERT enrollment, device
    /// provisioning) that needs to build a `SecurityManager` before wrapping it.
    /// Prefer [`ephemeral`] or [`open_or_create`] for application code.
    ///
    /// [`ephemeral`]: Self::ephemeral
    /// [`open_or_create`]: Self::open_or_create
    pub fn from_parts(mgr: Arc<SecurityManager>, name: Name, key_name: Name) -> Self {
        Self {
            mgr,
            name,
            key_name,
        }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    pub fn signer(&self) -> Result<Arc<dyn Signer>, TrustError> {
        self.mgr.get_signer_sync(&self.key_name)
    }

    /// Build a [`Validator`] pre-configured with this identity's trust anchors.
    ///
    /// Uses [`TrustSchema::accept_all`] by default (any correctly-signed packet
    /// whose certificate chain terminates in a known anchor is accepted). For
    /// stricter namespace-based policy, call
    /// [`Validator::set_schema`](crate::Validator::set_schema) on the result or
    /// use [`TrustSchema::hierarchical`].
    pub fn validator(&self) -> Validator {
        let v = Validator::new(TrustSchema::accept_all());
        for anchor_name in self.mgr.trust_anchor_names() {
            if let Some(cert) = self.mgr.trust_anchor(&anchor_name) {
                v.cert_cache().insert(cert);
            }
        }
        v
    }

    /// Add an external trust anchor certificate.
    ///
    /// Use this to accept data signed by a CA that was not issued by this
    /// identity (e.g., a network-wide trust anchor discovered via NDNCERT).
    pub fn add_trust_anchor(&self, cert: Certificate) {
        self.mgr.add_trust_anchor(cert);
    }

    /// Access the certificate cache.
    ///
    /// Useful for pre-populating the cache with known intermediate certificates
    /// before validation.
    pub fn cert_cache(&self) -> &CertCache {
        self.mgr.cert_cache()
    }

    /// Build a [`Validator`] that trusts only certificates issued under `anchor_prefix`.
    ///
    /// Shorthand for creating a consumer-side validator when you know the
    /// trust-anchor prefix and don't need a full KeyChain. For example, to
    /// accept Data signed by any certificate under `/ndn/testbed`:
    ///
    /// ```rust
    /// use ndn_security::KeyChain;
    ///
    /// let validator = KeyChain::trust_only("/ndn/testbed").unwrap();
    /// ```
    ///
    /// Uses [`TrustSchema::hierarchical`] so the Data name must be a sub-name
    /// of the signing certificate prefix.
    pub fn trust_only(anchor_prefix: impl AsRef<str>) -> Result<Validator, TrustError> {
        let prefix: Name = anchor_prefix.as_ref().parse().map_err(|_| {
            TrustError::KeyStore(format!("invalid prefix: {}", anchor_prefix.as_ref()))
        })?;
        let kc = Self::ephemeral(anchor_prefix.as_ref())?;
        let v = Validator::new(TrustSchema::hierarchical());
        for anchor_name in kc.mgr.trust_anchor_names() {
            if anchor_name.to_string().starts_with(&prefix.to_string())
                && let Some(cert) = kc.mgr.trust_anchor(&anchor_name)
            {
                v.cert_cache().insert(cert);
            }
        }
        Ok(v)
    }

    /// Sign a Data packet using this KeyChain's signing key.
    ///
    /// Returns the encoded, signed Data wire bytes. Uses Ed25519 with the
    /// key locator set to this identity's key name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the signing key is not available.
    pub fn sign_data(&self, builder: DataBuilder) -> Result<bytes::Bytes, TrustError> {
        let signer = self.signer()?;
        let key_name = self.key_name.clone();
        Ok(
            builder.sign_sync(SignatureType::SignatureEd25519, Some(&key_name), |region| {
                signer.sign_sync(region).unwrap_or_default()
            }),
        )
    }

    /// Sign an Interest using this KeyChain's signing key.
    ///
    /// Returns the encoded, signed Interest wire bytes. Uses Ed25519 with the
    /// key locator set to this identity's key name.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the signing key is not available.
    pub fn sign_interest(&self, builder: InterestBuilder) -> Result<bytes::Bytes, TrustError> {
        let signer = self.signer()?;
        let key_name = self.key_name.clone();
        Ok(
            builder.sign_sync(SignatureType::SignatureEd25519, Some(&key_name), |region| {
                signer.sign_sync(region).unwrap_or_default()
            }),
        )
    }

    /// Build a [`Validator`] pre-configured with this identity's trust anchors.
    ///
    /// Alias for [`validator`](Self::validator). Provided for API symmetry with
    /// the `trust_only` constructor.
    pub fn build_validator(&self) -> Validator {
        self.validator()
    }

    /// The `Arc`-wrapped `SecurityManager` backing this keychain.
    ///
    /// Intended for framework code (e.g., background renewal tasks) that needs
    /// to share the manager across async tasks. Prefer the higher-level methods
    /// for application code.
    pub fn manager_arc(&self) -> Arc<SecurityManager> {
        Arc::clone(&self.mgr)
    }
}

impl std::fmt::Debug for KeyChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyChain")
            .field("name", &self.name.to_string())
            .field("key_name", &self.key_name.to_string())
            .finish()
    }
}

/// Derive the signing key name from the trust anchors already loaded into a
/// `SecurityManager`.
///
/// Looks for an anchor whose name begins with `identity_name` and contains a
/// `/KEY/` component.
pub(crate) fn derive_key_name(identity_name: &Name, mgr: &SecurityManager) -> Option<Name> {
    let name_str = identity_name.to_string();
    for anchor_name in mgr.trust_anchor_names() {
        let anchor_str = anchor_name.to_string();
        if anchor_str.starts_with(&name_str)
            && anchor_str.contains("/KEY/")
            && let Ok(key_name) = anchor_str.parse::<Name>()
        {
            return Some(key_name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_generates_key_and_anchor() {
        let kc = KeyChain::ephemeral("/test/alice").unwrap();
        assert_eq!(kc.name().to_string(), "/test/alice");
        assert!(kc.key_name().to_string().contains("/KEY/"));
        assert!(kc.signer().is_ok());
        let _v = kc.validator();
    }

    #[test]
    fn open_or_create_generates_on_empty_pib() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let kc = KeyChain::open_or_create(&pib_path, "/test/router1").unwrap();
        assert!(kc.signer().is_ok());

        let kc2 = KeyChain::open_or_create(&pib_path, "/test/router1").unwrap();
        assert_eq!(kc.key_name().to_string(), kc2.key_name().to_string(),);
    }

    #[test]
    fn from_parts_roundtrip() {
        let mgr = SecurityManager::new();
        let name: Name = "/test/node".parse().unwrap();
        let key_name: Name = "/test/node/KEY/v=0".parse().unwrap();
        let kc = KeyChain::from_parts(Arc::new(mgr), name.clone(), key_name.clone());
        assert_eq!(kc.name(), &name);
        assert_eq!(kc.key_name(), &key_name);
    }
}
