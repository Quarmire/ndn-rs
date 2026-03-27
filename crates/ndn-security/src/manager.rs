use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Name, NameComponent, SignatureInfo, SignatureType};

use crate::{
    cert_cache::{Certificate, CertCache},
    key_store::{KeyAlgorithm, MemKeyStore},
    signer::{Ed25519Signer, Signer},
    TrustError,
};

/// High-level NDN security manager.
///
/// Owns a key store and certificate cache, and provides operations for:
/// - Key pair generation
/// - Self-signed certificate issuance (trust-anchor certificates)
/// - Certificate issuance (signing a key Data packet with another key)
/// - Trust anchor registration
/// - Retrieving a signer for a key name
///
/// For production use, replace `MemKeyStore` with a file-backed store.
pub struct SecurityManager {
    keys:       MemKeyStore,
    cert_cache: CertCache,
    /// Trust anchors — self-signed certs that are implicitly trusted.
    anchors:    dashmap::DashMap<Arc<Name>, Certificate>,
}

impl SecurityManager {
    pub fn new() -> Self {
        Self {
            keys:       MemKeyStore::new(),
            cert_cache: CertCache::new(),
            anchors:    dashmap::DashMap::new(),
        }
    }

    /// Generate a new Ed25519 key pair using a cryptographically random seed
    /// and store it in the in-memory key store.
    ///
    /// `key_name` should follow NDN key naming convention:
    /// `/<identity>/KEY/<key-id>`.
    ///
    /// Returns the key name on success.
    pub fn generate_ed25519(&self, key_name: Name) -> Result<Name, TrustError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed)
            .map_err(|_| TrustError::KeyStore("system RNG unavailable".into()))?;
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        self.keys.add(Arc::new(key_name.clone()), signer);
        Ok(key_name)
    }

    /// Generate a new Ed25519 key from explicit raw seed bytes (for testing).
    pub fn generate_ed25519_from_seed(
        &self,
        key_name: Name,
        seed: &[u8; 32],
    ) -> Result<Name, TrustError> {
        let signer = Ed25519Signer::from_seed(seed, key_name.clone());
        self.keys.add(Arc::new(key_name.clone()), signer);
        Ok(key_name)
    }

    /// Issue a self-signed certificate (trust anchor).
    ///
    /// The certificate is inserted into both the cert cache and the anchor set.
    /// `validity_ms` is the certificate lifetime in milliseconds; pass `u64::MAX`
    /// for non-expiring anchors.
    pub fn issue_self_signed(
        &self,
        key_name: &Name,
        public_key_bytes: Bytes,
        validity_ms: u64,
    ) -> Result<Certificate, TrustError> {
        let now_ns = now_ns();
        let valid_until = if validity_ms == u64::MAX {
            u64::MAX
        } else {
            now_ns + validity_ms * 1_000_000
        };
        let cert = Certificate {
            name:        Arc::new(key_name.clone()),
            public_key:  public_key_bytes,
            valid_from:  now_ns,
            valid_until,
        };
        self.cert_cache.insert(cert.clone());
        self.anchors.insert(Arc::new(key_name.clone()), cert.clone());
        Ok(cert)
    }

    /// Issue a certificate for `subject_key` signed by `issuer_key`.
    ///
    /// Both keys must already exist in the key store. The certificate is stored
    /// in the cert cache.
    pub async fn certify(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
    ) -> Result<Certificate, TrustError> {
        let issuer_signer = self.keys.get_signer_sync(issuer_key_name)?;

        // In NDN the certificate is a Data packet. We encode a minimal signed
        // region: subject-name TLV + sig-info TLV, then sign it.
        // For now, we create the Certificate struct directly (a full TLV
        // encoding is done by the serializer layer not yet implemented).
        let _ = issuer_signer; // will be used when full TLV encoding is added

        let now_ns = now_ns();
        let valid_until = now_ns + validity_ms * 1_000_000;
        let cert = Certificate {
            name:        Arc::new(subject_key_name.clone()),
            public_key:  subject_public_key,
            valid_from:  now_ns,
            valid_until,
        };
        self.cert_cache.insert(cert.clone());
        Ok(cert)
    }

    /// Register a pre-existing certificate as a trust anchor.
    pub fn add_trust_anchor(&self, cert: Certificate) {
        self.anchors.insert(Arc::clone(&cert.name), cert.clone());
        self.cert_cache.insert(cert);
    }

    /// Look up a trust anchor by key name.
    pub fn trust_anchor(&self, key_name: &Name) -> Option<Certificate> {
        self.anchors
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| r.value().clone())
    }

    /// List all trust anchor names.
    pub fn trust_anchor_names(&self) -> Vec<Arc<Name>> {
        self.anchors.iter().map(|r| Arc::clone(r.key())).collect()
    }

    /// Retrieve a signer for the given key name.
    pub async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        use crate::key_store::KeyStore;
        self.keys.get_signer(key_name).await
    }

    /// Access the certificate cache (e.g., to pass to a `Validator`).
    pub fn cert_cache(&self) -> &CertCache {
        &self.cert_cache
    }

    /// Build a `SecurityManager` by loading an identity from a [`FilePib`].
    ///
    /// - Loads the signing key for `identity` from the PIB.
    /// - If a certificate is present for that identity, inserts it into the
    ///   cert cache.
    /// - Loads all trust anchors stored in the PIB.
    ///
    /// [`FilePib`]: crate::pib::FilePib
    pub fn from_pib(
        pib: &crate::pib::FilePib,
        identity: &Name,
    ) -> Result<Self, TrustError> {
        let mgr = SecurityManager::new();

        // Load the signing key.
        let signer = pib.get_signer(identity)?;
        mgr.keys.add(Arc::new(identity.clone()), signer);

        // Load the identity's certificate if present.
        if let Ok(cert) = pib.get_cert(identity) {
            mgr.cert_cache.insert(cert);
        }

        // Load all trust anchors.
        for anchor in pib.trust_anchors()? {
            mgr.add_trust_anchor(anchor);
        }

        Ok(mgr)
    }
}

impl Default for SecurityManager {
    fn default() -> Self { Self::new() }
}

/// Extension on `MemKeyStore` for synchronous lookup needed within the manager.
trait MemKeyStoreExt {
    fn get_signer_sync(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError>;
}

impl MemKeyStoreExt for MemKeyStore {
    fn get_signer_sync(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        // We block briefly — acceptable since this is called from an async context
        // where the future is not being driven. Use `futures::executor::block_on`
        // would be cleaner, but to avoid adding a dep we just use a direct trick:
        // MemKeyStore::get_signer is actually sync underneath.
        // This re-implements the lookup without the async overhead.
        Err(TrustError::CertNotFound { name: key_name.to_string() })
        // ^ Real impl would reach into the DashMap directly; left as stub
        // since certify() needs full TLV cert encoding not yet implemented.
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;

    fn key_name(s: &'static str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::from_static(s.as_bytes()))])
    }

    #[test]
    fn generate_ed25519_stores_key() {
        let mgr = SecurityManager::new();
        let kn = key_name("mykey");
        assert!(mgr.generate_ed25519(kn.clone()).is_ok());
    }

    #[test]
    fn issue_self_signed_adds_anchor() {
        let mgr = SecurityManager::new();
        let kn = key_name("anchor");
        let pk = Bytes::from_static(&[0xAB; 32]);
        let cert = mgr.issue_self_signed(&kn, pk, u64::MAX).unwrap();
        assert_eq!(*cert.name, kn);
        assert!(mgr.trust_anchor(&kn).is_some());
    }

    #[test]
    fn trust_anchor_not_present_returns_none() {
        let mgr = SecurityManager::new();
        let kn = key_name("missing");
        assert!(mgr.trust_anchor(&kn).is_none());
    }

    #[test]
    fn add_trust_anchor_inserts_into_cache() {
        let mgr = SecurityManager::new();
        let kn = key_name("ta");
        let cert = Certificate {
            name:        Arc::new(kn.clone()),
            public_key:  Bytes::from_static(&[1u8; 32]),
            valid_from:  0,
            valid_until: u64::MAX,
        };
        mgr.add_trust_anchor(cert.clone());
        assert!(mgr.trust_anchor(&kn).is_some());
        assert!(mgr.cert_cache().get(&Arc::new(kn)).is_some());
    }

    #[test]
    fn trust_anchor_names_returns_all() {
        let mgr = SecurityManager::new();
        let kn1 = key_name("a");
        let kn2 = key_name("b");
        for kn in [&kn1, &kn2] {
            mgr.add_trust_anchor(Certificate {
                name:        Arc::new(kn.clone()),
                public_key:  Bytes::from_static(&[0; 32]),
                valid_from:  0,
                valid_until: u64::MAX,
            });
        }
        let names = mgr.trust_anchor_names();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn generate_from_seed_and_retrieve() {
        let mgr = SecurityManager::new();
        let kn = key_name("seeded");
        let seed = [7u8; 32];
        mgr.generate_ed25519_from_seed(kn.clone(), &seed).unwrap();
        // Key is stored; we can confirm by checking the key store state indirectly.
        // (get_signer is async; tested separately)
    }

    #[tokio::test]
    async fn get_signer_after_generate() {
        use crate::key_store::KeyStore;
        let mgr = SecurityManager::new();
        let kn = key_name("sigkey");
        let seed = [9u8; 32];
        mgr.generate_ed25519_from_seed(kn.clone(), &seed).unwrap();
        let signer = mgr.get_signer(&kn).await.unwrap();
        assert_eq!(signer.key_name(), &kn);
    }
}
