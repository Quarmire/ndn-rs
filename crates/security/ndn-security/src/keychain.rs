//! [`KeyChain`] — the primary security API for NDN applications.

use std::path::Path;
use std::sync::Arc;

use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};

use crate::{
    CertCache, Certificate, SecurityManager, SignWith, Signer, SignerSelection, SigningInfo,
    TrustError, TrustSchema, Validator,
};
use bytes::Bytes;

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

/// Signature algorithm for a freshly generated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

const DEFAULT_CERT_VALIDITY_MS: u64 = 365 * 24 * 3600 * 1_000;

impl KeyChain {
    /// Ephemeral in-memory identity with a fresh Ed25519 key
    /// `<name>/KEY/<key-id>`, self-signed with a 365-day certificate
    /// `<key>/self/<version>` ([`cert_name`](Self::cert_name)) registered as
    /// a trust anchor. Not persisted — use
    /// [`open_or_create`](Self::open_or_create) for long-lived identities.
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, TrustError> {
        Self::ephemeral_with_algo(name, crate::KeyAlgorithm::Ed25519)
    }

    /// Like [`ephemeral`](Self::ephemeral) but ECDSA-P256. Use this when
    /// the identity must be verifiable by ndn-cxx tooling, which doesn't
    /// support Ed25519.
    pub fn ephemeral_ecdsa(name: impl AsRef<str>) -> Result<Self, TrustError> {
        Self::ephemeral_with_algo(name, crate::KeyAlgorithm::EcdsaP256)
    }

    fn ephemeral_with_algo(
        name: impl AsRef<str>,
        algo: crate::KeyAlgorithm,
    ) -> Result<Self, TrustError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| TrustError::KeyStore(format!("invalid NDN name: {}", name.as_ref())))?;

        // NDN Certificate Format v2: the key is `<name>/KEY/<key-id>` (a
        // random key id; a failing RNG is an error); `issue_self_signed`
        // names its certificate `<key>/self/<version>`.
        let mgr = SecurityManager::new();
        let key_name = crate::cert_name::new_key_name(&name)?;
        match algo {
            crate::KeyAlgorithm::Ed25519 => {
                mgr.generate_ed25519(key_name.clone())?;
            }
            crate::KeyAlgorithm::EcdsaP256 => {
                mgr.generate_ecdsa_p256(key_name.clone())?;
            }
            crate::KeyAlgorithm::Rsa2048 => {
                return Err(TrustError::KeyStore(
                    "RSA-2048 ephemeral keychain not implemented yet".into(),
                ));
            }
        }

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

    /// Open a persistent identity from a PIB directory, generating one on
    /// first run and reloading it thereafter. The key is the identity's
    /// default key under `<name>/KEY/`
    /// ([`FilePib::default_key`](crate::FilePib::default_key)); other
    /// identities in the same PIB are not touched.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, TrustError> {
        let name: Name = name
            .as_ref()
            .parse()
            .map_err(|_| TrustError::KeyStore(format!("invalid NDN name: {}", name.as_ref())))?;

        let (mgr, _created) = SecurityManager::auto_init(&name, path)?;

        let key_name = mgr.identity_key_name(&name).ok_or_else(|| {
            TrustError::KeyStore(format!("PIB at {} holds no key for {name}", path.display()))
        })?;

        Ok(Self {
            mgr: Arc::new(mgr),
            name,
            key_name,
        })
    }

    /// Escape hatch for framework code (NDNCERT enrollment, device
    /// provisioning) that builds a `SecurityManager` first. Application
    /// code should prefer [`ephemeral`](Self::ephemeral) or
    /// [`open_or_create`](Self::open_or_create).
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

    /// The name of this key's current certificate,
    /// `<key>/<issuer-id>/<version>`: the newest currently valid certificate
    /// of [`key_name`](Self::key_name) held in the cache (the self-signed one
    /// of an [`ephemeral`](Self::ephemeral) identity, the CA-issued one of an
    /// enrolled key), else the newest one held. `None` when no certificate
    /// of the key is held, e.g. a [`from_parts`](Self::from_parts) keychain
    /// over a bare signer.
    pub fn cert_name(&self) -> Option<Name> {
        self.mgr
            .cert_cache()
            .get(&Arc::new(self.key_name.clone()))
            .map(|cert| (*cert.name).clone())
    }

    pub fn signer(&self) -> Result<Arc<dyn Signer>, TrustError> {
        self.mgr.get_signer_sync(&self.key_name)
    }

    /// Resolve a [`SignerSelection`] to a concrete signer; `Ok(None)`
    /// for `SignerSelection::Digest` (routes through the `DigestSha256`
    /// fast path in [`sign_packet`](Self::sign_packet)).
    pub fn resolve_selection(
        &self,
        selection: &SignerSelection,
    ) -> Result<Option<Arc<dyn Signer>>, TrustError> {
        match selection {
            SignerSelection::Digest => Ok(None),
            SignerSelection::Identity(name) => {
                if name == &self.name {
                    Ok(Some(self.signer()?))
                } else {
                    Ok(Some(self.mgr.identity_signer(name)?))
                }
            }
            SignerSelection::Key(key_name) => Ok(Some(self.mgr.get_signer_sync(key_name)?)),
            SignerSelection::Cert(cert_name) => {
                let cert_arc = Arc::new(cert_name.clone());
                let _cert = self.mgr.cert_cache().get(&cert_arc).ok_or_else(|| {
                    TrustError::CertNotFound {
                        name: cert_name.to_string(),
                    }
                })?;
                // Cert name is `<identity>/KEY/<keyid>/<issuer>/<version>`;
                // the key name drops the trailing `<issuer>/<version>` pair.
                // Try the cert name first (a legacy PIB key stored under its
                // certificate's name), then the key.
                if let Ok(signer) = self.mgr.get_signer_sync(cert_name) {
                    return Ok(Some(signer));
                }
                if crate::cert_name::is_cert_name(cert_name) {
                    let key_name = crate::cert_name::key_name_of(cert_name);
                    return Ok(Some(self.mgr.get_signer_sync(&key_name)?));
                }
                Err(TrustError::CertNotFound {
                    name: cert_name.to_string(),
                })
            }
            SignerSelection::HmacKey(key_name) => Ok(Some(self.mgr.get_signer_sync(key_name)?)),
            SignerSelection::Suggested { for_name } => {
                // Until LVS rule evaluation is wired: the registered identity
                // with the longest name covering `for_name` signs. A name no
                // identity covers is an error, never another identity's key.
                match self.mgr.identity_key_for(for_name) {
                    Some((identity, _)) if identity == self.name => Ok(Some(self.signer()?)),
                    Some((_, key_name)) => Ok(Some(self.mgr.get_signer_sync(&key_name)?)),
                    None => Err(TrustError::KeyStore(format!(
                        "SignerSelection::Suggested: no identity held by this keychain \
                         covers {for_name}"
                    ))),
                }
            }
        }
    }

    /// Sign a packet builder ([`DataBuilder`] / [`InterestBuilder`])
    /// using `info`. `Digest` routes to the `sign_digest_sha256` fast
    /// path; other selections resolve through
    /// [`resolve_selection`](Self::resolve_selection).
    ///
    /// [`DataBuilder`]: ndn_packet::encode::DataBuilder
    /// [`InterestBuilder`]: ndn_packet::encode::InterestBuilder
    pub fn sign_packet<P: SignWith>(
        &self,
        packet: P,
        info: &SigningInfo,
    ) -> Result<Bytes, TrustError> {
        match self.resolve_selection(&info.selection)? {
            None => Ok(packet.sign_digest_sha256()),
            Some(signer) => packet.sign_with_sync(&*signer),
        }
    }

    /// Build a [`Validator`] pre-configured with this identity's trust
    /// anchors and [`TrustSchema::hierarchical`]. For looser policy, call
    /// [`Validator::set_schema`](crate::Validator::set_schema) with
    /// [`TrustSchema::accept_all`] on the result.
    pub fn validator(&self) -> Validator {
        let v = Validator::new(TrustSchema::hierarchical());
        for anchor_name in self.mgr.trust_anchor_names() {
            if let Some(cert) = self.mgr.trust_anchor(&anchor_name) {
                v.cert_cache().insert(cert);
            }
        }
        v
    }

    /// Add an external trust anchor (e.g. a network-wide root discovered
    /// via NDNCERT).
    pub fn add_trust_anchor(&self, cert: Certificate) -> bool {
        self.mgr.add_trust_anchor(cert)
    }

    pub fn cert_cache(&self) -> &CertCache {
        self.mgr.cert_cache()
    }

    /// Consumer-side validator that trusts only certificates under
    /// `anchor_prefix`, using [`TrustSchema::hierarchical`].
    ///
    /// ```rust
    /// use ndn_security::KeyChain;
    /// let validator = KeyChain::trust_only("/ndn/testbed").unwrap();
    /// ```
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

    /// Sign a Data packet using this KeyChain's signing key. The
    /// `SignatureType` written into `SignatureInfo` is the active
    /// signer's `sig_type()`.
    pub fn sign_data(&self, builder: DataBuilder) -> Result<bytes::Bytes, TrustError> {
        let signer = self.signer()?;
        let sig_type = signer.sig_type();
        let key_name = self.key_name.clone();
        Ok(builder.sign_sync(sig_type, Some(&key_name), |region| {
            signer.sign_sync(region).unwrap_or_default()
        }))
    }

    /// Sign an Interest using this KeyChain's signing key. The
    /// `SignatureType` written into `InterestSignatureInfo` is the active
    /// signer's `sig_type()`.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] if the signing key is not available.
    pub fn sign_interest(&self, builder: InterestBuilder) -> Result<bytes::Bytes, TrustError> {
        let signer = self.signer()?;
        let sig_type = signer.sig_type();
        let key_name = self.key_name.clone();
        Ok(builder.sign_sync(sig_type, Some(&key_name), |region| {
            signer.sign_sync(region).unwrap_or_default()
        }))
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

    /// Consume the keychain and yield its `Arc<SecurityManager>` without
    /// the extra clone [`manager_arc`](Self::manager_arc) makes — e.g. to
    /// hand the manager to `EngineBuilder::security`.
    pub fn into_manager_arc(self) -> Arc<SecurityManager> {
        self.mgr
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An ephemeral key is named `<id>/KEY/<key-id>`; its self-signed
    /// certificate `<key>/self/<version>` is a separate, cert-v2 name.
    #[test]
    fn ephemeral_generates_key_and_anchor() {
        let kc = KeyChain::ephemeral("/test/alice").unwrap();
        assert_eq!(kc.name().to_string(), "/test/alice");
        let key = kc.key_name();
        assert_eq!(key.len(), 4, "{key}");
        assert!(key.has_prefix(&"/test/alice/KEY".parse().unwrap()), "{key}");
        assert!(!crate::cert_name::is_cert_name(key), "{key}");
        let cert = kc.cert_name().expect("self-signed certificate");
        assert!(crate::cert_name::is_cert_of(&cert, key), "{cert}");
        assert_eq!(cert.components()[key.len()].value.as_ref(), b"self");
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

    /// `sign_data` labels SignatureValue with the active signer's
    /// algorithm; HMAC signer must yield `SignatureHmacWithSha256`,
    /// not hardcoded Ed25519.
    #[test]
    fn sign_data_uses_signer_sigtype_hmac() {
        use crate::HmacSha256Signer;
        use ndn_packet::{Data, SignatureType, encode::DataBuilder};

        let identity: Name = "/test/c06/hmac".parse().unwrap();
        let key_name: Name = "/test/c06/hmac/KEY/k0".parse().unwrap();

        let mgr = Arc::new(SecurityManager::new());
        let signer = HmacSha256Signer::new(b"shared-secret", key_name.clone());
        mgr.install_signer(signer);

        let kc = KeyChain::from_parts(mgr, identity.clone(), key_name.clone());
        let builder = DataBuilder::new(identity.clone(), b"payload");
        let wire = kc.sign_data(builder).expect("sign_data must succeed");

        let data = Data::decode(wire).expect("Data must decode");
        let sig_info = data.sig_info().expect("SignatureInfo present");
        assert_eq!(
            sig_info.sig_type,
            SignatureType::SignatureHmacWithSha256,
            "sign_data must label the signature with the signer's sig_type, not hardcoded Ed25519"
        );
    }

    /// Same invariant for `sign_interest`.
    #[test]
    fn sign_interest_uses_signer_sigtype_hmac() {
        use crate::HmacSha256Signer;
        use ndn_packet::{Interest, SignatureType, encode::InterestBuilder};

        let identity: Name = "/test/c06/hmac-i".parse().unwrap();
        let key_name: Name = "/test/c06/hmac-i/KEY/k0".parse().unwrap();
        let interest_name: Name = "/test/c06/hmac-i/cmd".parse().unwrap();

        let mgr = Arc::new(SecurityManager::new());
        let signer = HmacSha256Signer::new(b"shared-secret", key_name.clone());
        mgr.install_signer(signer);

        let kc = KeyChain::from_parts(mgr, identity, key_name.clone());
        let builder = InterestBuilder::new(interest_name).app_parameters(b"p".to_vec());
        let wire = kc
            .sign_interest(builder)
            .expect("sign_interest must succeed");

        let interest = Interest::decode(wire).expect("Interest must decode");
        let sig_info = interest.sig_info().expect("InterestSignatureInfo present");
        assert_eq!(
            sig_info.sig_type,
            SignatureType::SignatureHmacWithSha256,
            "sign_interest must label the signature with the signer's sig_type, not hardcoded Ed25519"
        );
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

    /// `sign_interest` yields a non-empty signed region whose signature
    /// verifies with the signer's public key, and the SignatureType
    /// reflects the signer's algorithm.
    #[test]
    fn keychain_sign_interest_signed_region_verifies() {
        use crate::{
            Ed25519Signer, SecurityManager,
            verifier::{Ed25519Verifier, VerifyOutcome},
        };
        use ndn_packet::{Interest, SignatureType, encode::InterestBuilder};

        let identity: Name = "/test/h10/app".parse().unwrap();
        let key_name: Name = "/test/h10/app/KEY/k0".parse().unwrap();

        let signer = Ed25519Signer::from_seed(&[0xCCu8; 32], key_name.clone());
        let pk = signer.public_key_bytes();

        let mgr = Arc::new(SecurityManager::new());
        mgr.install_signer(signer);

        let kc = KeyChain::from_parts(mgr, identity.clone(), key_name.clone());
        let builder = InterestBuilder::new(identity.append("cmd")).app_parameters(b"payload");
        let wire = kc
            .sign_interest(builder)
            .expect("sign_interest must succeed");

        let interest = Interest::decode(wire).expect("Interest must decode");

        let sig_info = interest
            .sig_info()
            .expect("InterestSignatureInfo must be present");
        assert_eq!(
            sig_info.sig_type,
            SignatureType::SignatureEd25519,
            "sig_type must reflect the Ed25519Signer"
        );

        let region = interest
            .signed_region()
            .expect("signed_region must be non-empty");
        let sig = interest.sig_value().expect("sig_value must be present");

        let outcome = Ed25519Verifier.verify_sync(&region, sig, &pk);
        assert_eq!(
            outcome,
            VerifyOutcome::Valid,
            "Ed25519 signature over signed_region must verify"
        );
    }

    /// `validator()` defaults to `TrustSchema::hierarchical()`, not
    /// `accept_all()` — cross-namespace data is rejected.
    #[test]
    fn keychain_validator_uses_hierarchical() {
        use ndn_packet::Name;
        let kc = KeyChain::ephemeral("/com/example").unwrap();
        let validator = kc.validator();
        let schema = validator.schema_snapshot();

        let data_same_ns: Name = "/com/example/sensor/temp".parse().unwrap();
        let key_same_ns: Name = "/com/example/KEY/k1/self/v=0".parse().unwrap();
        assert!(
            schema.allows(&data_same_ns, &key_same_ns),
            "same-namespace data+key must be allowed"
        );

        let data_other_ns: Name = "/org/unrelated/data".parse().unwrap();
        assert!(
            !schema.allows(&data_other_ns, &key_same_ns),
            "cross-namespace data must be rejected by default validator"
        );
    }

    /// `SignerSelection::Digest` routes through the DigestSha256 fast
    /// path; produced wire decodes with `SignatureType::DigestSha256`.
    #[test]
    fn signing_info_digest() {
        use crate::SigningInfo;
        use ndn_packet::{Data, SignatureType, encode::DataBuilder};
        let kc = KeyChain::ephemeral("/com/example/alice").unwrap();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/alice/test"), b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::digest_sha256())
            .expect("digest sign_packet must succeed");
        let data = Data::decode(wire).expect("Data must decode");
        assert_eq!(
            data.sig_info().unwrap().sig_type,
            SignatureType::DigestSha256,
            "SignerSelection::Digest must produce DigestSha256 sig"
        );
    }

    /// `SignerSelection::Identity` for self resolves to the keychain's
    /// default signer and produces a verifiable signature.
    #[test]
    fn signing_info_identity_self() {
        use crate::SigningInfo;
        use ndn_packet::{Data, SignatureType, encode::DataBuilder};
        let kc = KeyChain::ephemeral("/com/example/bob").unwrap();
        let identity = kc.name().clone();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/bob/data"), b"payload");
        let wire = kc
            .sign_packet(builder, &SigningInfo::identity(identity))
            .expect("identity sign_packet must succeed");
        let data = Data::decode(wire).expect("Data must decode");
        let sig_info = data.sig_info().unwrap();
        assert_eq!(
            sig_info.sig_type,
            SignatureType::SignatureEd25519,
            "identity-default-key signature must be Ed25519"
        );
        let kl = sig_info.key_locator.as_ref().expect("KeyLocator present");
        assert_eq!(
            kl.to_string(),
            kc.key_name().to_string(),
            "KeyLocator must point at the identity's default key"
        );
    }

    /// `SignerSelection::Identity` for an identity with no registered key
    /// errors instead of signing with the keychain's own key.
    #[test]
    fn signing_info_identity_other_rejected() {
        use crate::SigningInfo;
        use ndn_packet::encode::DataBuilder;
        let kc = KeyChain::ephemeral("/com/example/alice").unwrap();
        let other: Name = "/com/example/bob".parse().unwrap();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/alice/data"), b"body");
        let err = kc.sign_packet(builder, &SigningInfo::identity(other));
        assert!(
            matches!(err, Err(TrustError::KeyStore(_))),
            "non-self identity must error; got {err:?}"
        );
    }

    /// `SignerSelection::Key` resolves a named key from the key store.
    #[test]
    fn signing_info_named_key() {
        use crate::{HmacSha256Signer, SigningInfo};
        use ndn_packet::{Data, SignatureType, encode::DataBuilder};
        let identity: Name = "/test/s12/named".parse().unwrap();
        let key_name: Name = "/test/s12/named/KEY/k0".parse().unwrap();
        let mgr = Arc::new(SecurityManager::new());
        mgr.install_signer(HmacSha256Signer::new(b"top-secret", key_name.clone()));
        let kc = KeyChain::from_parts(mgr, identity.clone(), key_name.clone());

        let builder = DataBuilder::new(identity.clone(), b"data");
        let wire = kc
            .sign_packet(builder, &SigningInfo::key(key_name.clone()))
            .expect("named-key sign_packet must succeed");
        let data = Data::decode(wire).unwrap();
        assert_eq!(
            data.sig_info().unwrap().sig_type,
            SignatureType::SignatureHmacWithSha256
        );
    }

    /// `SignerSelection::HmacKey` resolves a named HMAC key. The variant
    /// stays distinct from `Key` so future policy can target HMAC-only
    /// rules.
    #[test]
    fn signing_info_hmac_key() {
        use crate::{HmacSha256Signer, SigningInfo};
        use ndn_packet::{Data, SignatureType, encode::DataBuilder};
        let identity: Name = "/test/s12/hmac".parse().unwrap();
        let key_name: Name = "/test/s12/hmac/KEY/h0".parse().unwrap();
        let mgr = Arc::new(SecurityManager::new());
        mgr.install_signer(HmacSha256Signer::new(b"shared", key_name.clone()));
        let kc = KeyChain::from_parts(mgr, identity.clone(), key_name.clone());
        let builder = DataBuilder::new(identity, b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::hmac_key(key_name))
            .expect("hmac_key sign_packet must succeed");
        let data = Data::decode(wire).unwrap();
        assert_eq!(
            data.sig_info().unwrap().sig_type,
            SignatureType::SignatureHmacWithSha256
        );
    }

    /// `SignerSelection::Cert` resolves a cert by name, finds its key,
    /// and signs.
    #[test]
    fn signing_info_cert() {
        use crate::SigningInfo;
        use ndn_packet::{Data, encode::DataBuilder};
        let identity: Name = "/test/s12/cert".parse().unwrap();
        let key_name: Name = "/test/s12/cert/KEY/kc".parse().unwrap();
        let mgr = Arc::new(SecurityManager::new());
        mgr.generate_ed25519(key_name.clone()).unwrap();
        let pub_key = mgr
            .get_signer_sync(&key_name)
            .unwrap()
            .public_key()
            .unwrap();
        let cert = mgr
            .issue_self_signed(&key_name, pub_key, DEFAULT_CERT_VALIDITY_MS)
            .expect("issue self-signed cert");
        let cert_name = (*cert.name).clone();
        let kc = KeyChain::from_parts(mgr, identity.clone(), key_name);

        let builder = DataBuilder::new(ndn_packet::name!("/test/s12/cert/d"), b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::cert(cert_name))
            .expect("cert sign_packet must succeed");
        let _data = Data::decode(wire).expect("Data must decode");
    }

    /// `SignerSelection::Suggested` for a name under the keychain's own
    /// identity signs with the keychain's key.
    #[test]
    fn signing_info_suggested_own_namespace() {
        use crate::SigningInfo;
        use ndn_packet::{Data, encode::DataBuilder};
        let kc = KeyChain::ephemeral("/com/example/dave").unwrap();
        let for_name: Name = "/com/example/dave/some/data".parse().unwrap();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/dave/d"), b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::suggested(for_name))
            .expect("suggested sign_packet must succeed");
        let data = Data::decode(wire).unwrap();
        let kl = data.sig_info().unwrap().key_locator.as_ref().unwrap();
        assert_eq!(kl.to_string(), kc.key_name().to_string());
    }

    /// Keychain `/com/example/alice` whose manager also holds bob's key.
    fn alice_with_bob() -> (KeyChain, Name) {
        let kc = KeyChain::ephemeral("/com/example/alice").unwrap();
        let bob_key: Name = "/com/example/bob/KEY/b0".parse().unwrap();
        kc.manager_arc().generate_ed25519(bob_key.clone()).unwrap();
        (kc, bob_key)
    }

    fn key_locator_of(wire: Bytes) -> String {
        let data = ndn_packet::Data::decode(wire).unwrap();
        data.sig_info()
            .unwrap()
            .key_locator
            .as_ref()
            .unwrap()
            .to_string()
    }

    /// Multi-identity: `Identity(bob)` on alice's keychain signs with bob's
    /// key from the shared manager.
    #[test]
    fn signing_info_identity_resolves_registered_identity() {
        use crate::SigningInfo;
        use ndn_packet::encode::DataBuilder;
        let (kc, bob_key) = alice_with_bob();
        let bob: Name = "/com/example/bob".parse().unwrap();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/bob/d"), b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::identity(bob))
            .expect("registered identity must resolve");
        assert_eq!(key_locator_of(wire), bob_key.to_string());
    }

    /// `Suggested` picks the identity covering the packet name, and errors
    /// for a name no held identity covers instead of using alice's key.
    #[test]
    fn signing_info_suggested_resolves_covering_identity_or_errors() {
        use crate::SigningInfo;
        use ndn_packet::encode::DataBuilder;
        let (kc, bob_key) = alice_with_bob();

        let for_bob: Name = "/com/example/bob/notes/1".parse().unwrap();
        let builder = DataBuilder::new(for_bob.clone(), b"body");
        let wire = kc
            .sign_packet(builder, &SigningInfo::suggested(for_bob))
            .expect("bob's namespace must resolve to bob's key");
        assert_eq!(key_locator_of(wire), bob_key.to_string());

        let foreign: Name = "/org/unrelated/x".parse().unwrap();
        let builder = DataBuilder::new(foreign.clone(), b"body");
        let err = kc.sign_packet(builder, &SigningInfo::suggested(foreign));
        assert!(
            matches!(err, Err(TrustError::KeyStore(_))),
            "uncovered name must error; got {err:?}"
        );
    }

    /// `SignerSelection::Key` for an unknown key errors with
    /// `CertNotFound` rather than panicking or producing a bogus sig.
    #[test]
    fn signing_info_unknown_key_errors() {
        use crate::SigningInfo;
        use ndn_packet::encode::DataBuilder;
        let kc = KeyChain::ephemeral("/com/example/eve").unwrap();
        let ghost: Name = "/com/example/ghost/KEY/x".parse().unwrap();
        let builder = DataBuilder::new(ndn_packet::name!("/com/example/eve/d"), b"body");
        let err = kc.sign_packet(builder, &SigningInfo::key(ghost));
        assert!(
            matches!(err, Err(TrustError::CertNotFound { .. })),
            "unknown key must error; got {err:?}"
        );
    }

    /// `sign_packet` works for Interest builders too.
    #[test]
    fn signing_info_interest() {
        use crate::SigningInfo;
        use ndn_packet::{Interest, encode::InterestBuilder};
        let kc = KeyChain::ephemeral("/com/example/frank").unwrap();
        let identity = kc.name().clone();
        let builder = InterestBuilder::new(ndn_packet::name!("/com/example/frank/x"));
        let wire = kc
            .sign_packet(builder, &SigningInfo::identity(identity))
            .expect("interest sign_packet must succeed");
        let _interest = Interest::decode(wire).expect("Interest must decode");
    }

    /// A PIB key an earlier release stored under a certificate-shaped name
    /// (`ndn-sec keygen` / `ephemeral` wrote `<id>/KEY/<kid>/self/v=0` with
    /// an NDNC summary certificate of the same name) still loads and signs,
    /// and the KeyLocator it stamps resolves to that certificate's key.
    #[test]
    fn legacy_cert_named_pib_key_loads_and_signs() {
        use crate::verifier::{Ed25519Verifier, VerifyOutcome};
        use ndn_packet::{Data, encode::DataBuilder};

        let dir = tempfile::tempdir().unwrap();
        let pib = crate::pib::FilePib::new(dir.path()).unwrap();
        let legacy: Name = "/legacy/node/KEY/0001/self/v=0".parse().unwrap();
        let raw_pk = pib.generate_ed25519(&legacy).unwrap().public_key_bytes();
        let now = crate::validator::now_ns();
        let summary = Certificate {
            name: Arc::new(legacy.clone()),
            public_key: crate::spki::wrap_ed25519(&raw_pk),
            valid_from: now,
            valid_until: now + 3_600_000_000_000,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        pib.store_cert(&legacy, &summary).unwrap();

        let kc = KeyChain::open_or_create(dir.path(), "/legacy/node").unwrap();
        assert_eq!(kc.key_name(), &legacy, "legacy key reused, not replaced");
        let wire = kc
            .sign_data(DataBuilder::new(ndn_packet::name!("/legacy/node/d"), b"body"))
            .unwrap();
        let data = Data::decode(wire).unwrap();
        let locator = data.sig_info().unwrap().key_locator.as_ref().unwrap();
        let locator = Arc::new(locator.as_name().unwrap().clone());
        let cert = kc.cert_cache().get(&locator).expect("KeyLocator resolves");
        assert_eq!(crate::cert_name::key_name_of(&cert.name), crate::cert_name::key_name_of(&legacy));
        assert_eq!(
            Ed25519Verifier.verify_sync(
                data.signed_region(),
                data.sig_value(),
                &raw_pk,
            ),
            VerifyOutcome::Valid
        );
    }
}
