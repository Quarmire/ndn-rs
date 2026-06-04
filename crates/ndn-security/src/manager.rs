use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;

use crate::{
    TrustError, TrustSchema,
    cert_cache::{CertCache, Certificate},
    key_store::MemKeyStore,
    keyring::Keyring,
    signer::{Ed25519Signer, Signer},
    trust_context::SignedTrustContext,
};

/// Owns a key store, certificate cache, and a [`Keyring`] of trust contexts,
/// providing key generation, certificate issuance, and trust anchor management.
///
/// The flat trust-anchor API ([`add_trust_anchor`](Self::add_trust_anchor),
/// [`trust_anchor`](Self::trust_anchor), [`trust_anchor_names`](Self::trust_anchor_names),
/// …) is a **view over the keyring's ambient (root-namespace) context**;
/// named contexts are adopted directly on the [`keyring`](Self::keyring). An
/// engine shares this same `Arc<Keyring>` with its [`Validator`](crate::Validator),
/// so anchors inserted here are visible to validation without copying.
pub struct SecurityManager {
    keys: MemKeyStore,
    cert_cache: Arc<CertCache>,
    keyring: Arc<Keyring>,
}

impl SecurityManager {
    pub fn new() -> Self {
        // Ambient context starts with an empty (reject-all) schema and no
        // hierarchy floor; the engine sets the operative schema when it wires
        // this keyring into a validator. No warning is emitted (this is the
        // dedicated ambient path, not `SignedTrustContext::accept_all`).
        let ambient = Arc::new(SignedTrustContext::ambient(
            TrustSchema::new(),
            Arc::new(dashmap::DashMap::new()),
        ));
        Self {
            keys: MemKeyStore::new(),
            cert_cache: Arc::new(CertCache::new()),
            keyring: Arc::new(Keyring::with_ambient(ambient)),
        }
    }

    /// The keyring this manager owns. An engine wires this same handle into
    /// its [`Validator`](crate::Validator) so issued anchors and adopted
    /// contexts are seen by validation directly.
    pub fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }

    /// Shared cert-cache handle so an external `Validator` sees certs the
    /// CA inserts via [`certify`](Self::certify) without round-tripping
    /// over NDN.
    pub fn cert_cache_arc(&self) -> Arc<CertCache> {
        Arc::clone(&self.cert_cache)
    }

    /// Generate a new Ed25519 key pair from a random seed and store it.
    ///
    /// `key_name` should follow `/<identity>/KEY/<key-id>`.
    pub fn generate_ed25519(&self, key_name: Name) -> Result<Name, TrustError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| TrustError::KeyStore("system RNG unavailable".into()))?;
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        self.keys.add(Arc::new(key_name.clone()), signer);
        Ok(key_name)
    }

    pub fn generate_ed25519_from_seed(
        &self,
        key_name: Name,
        seed: &[u8; 32],
    ) -> Result<Name, TrustError> {
        let signer = Ed25519Signer::from_seed(seed, key_name.clone());
        self.keys.add(Arc::new(key_name.clone()), signer);
        Ok(key_name)
    }

    /// Register an **externally-held** signer under `key_name` — e.g. a
    /// `CustodianSigner` backed by the device enclave or a remote fob. The
    /// private key never enters the key store; `get_signer_sync(key_name)`
    /// returns this signer, so a [`KeyChain`](crate::KeyChain) (and an
    /// `ndn_identity::Identity`) built over this manager signs *through* the
    /// custodian. The seam for hardware/remote custody.
    pub fn register_signer(&self, key_name: Name, signer: Arc<dyn Signer>) {
        self.keys.add_arc(Arc::new(key_name), signer);
    }

    /// Generate a fresh ECDSA-P256 signing key. Use this instead of
    /// [`generate_ed25519`](Self::generate_ed25519) when the identity
    /// must be verifiable by ndn-cxx tooling, which doesn't support
    /// Ed25519.
    pub fn generate_ecdsa_p256(&self, key_name: Name) -> Result<Name, TrustError> {
        let signer = crate::EcdsaP256Signer::generate(key_name.clone())?;
        self.keys.add(Arc::new(key_name.clone()), signer);
        Ok(key_name)
    }

    /// Register a pre-built [`Signer`] (HMAC-SHA256, BLAKE3, YubiKey,
    /// NDNCERT-issued, …) under its own `key_name()`. Required so
    /// `KeyChain::sign_*` can read the active signer's `sig_type()`.
    pub fn install_signer<S: Signer>(&self, signer: S) {
        let key_name = Arc::new(signer.key_name().clone());
        self.keys.add(key_name, signer);
    }

    /// Issue a self-signed certificate and register it as a trust anchor.
    ///
    /// `validity_ms` is the lifetime in milliseconds; `u64::MAX` for
    /// non-expiring anchors. The resulting cert carries the full wire-
    /// format Data so it can be shipped across NDNCERT and other
    /// transports as a real Data TLV.
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
            now_ns.saturating_add(validity_ms.saturating_mul(1_000_000))
        };

        // Self-sign with the matching keystore key. Falls back to an
        // unsigned cert struct when the signer is missing; not expected
        // in practice but preserves no-key callers.
        let cert = match self.keys.get_signer_sync(key_name) {
            Ok(signer) => {
                let wire = futures::executor::block_on(encode_cert_data(
                    key_name,
                    &public_key_bytes,
                    signer.as_ref(),
                    now_ns,
                    valid_until,
                ))?;
                let data = ndn_packet::Data::decode(wire).map_err(|e| {
                    TrustError::KeyStore(format!("failed to decode self-signed cert: {e}"))
                })?;
                Certificate::decode(&data)?
            }
            Err(_) => Certificate {
                name: Arc::new(key_name.clone()),
                public_key: public_key_bytes,
                valid_from: now_ns,
                valid_until,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: ndn_packet::SignatureType::SignatureEd25519,
            },
        };

        self.cert_cache.insert(cert.clone());
        self.keyring.ambient().add_anchor(cert.clone());
        Ok(cert)
    }

    /// Issue a certificate for `subject_key` signed by `issuer_key`. Both
    /// must already exist in the key store; the result is cached.
    pub async fn certify(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
    ) -> Result<Certificate, TrustError> {
        self.certify_with_additional_description(
            subject_key_name,
            subject_public_key,
            issuer_key_name,
            validity_ms,
            None,
        )
        .await
    }

    /// As [`certify`](Self::certify), but embeds a non-critical
    /// `AdditionalDescription` (TLV 0x0102) in the issued cert's
    /// `SignatureInfo`. `additional_description` is the already-encoded
    /// value of that TLV (the concatenated `DescriptionEntry` elements).
    /// The bytes are covered by the issuer's signature. `ndn-cert` uses
    /// this to carry challenge attestations.
    pub async fn certify_with_additional_description(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
        additional_description: Option<&[u8]>,
    ) -> Result<Certificate, TrustError> {
        let issuer_signer = self.keys.get_signer_sync(issuer_key_name)?;

        let now_ns = now_ns();
        let valid_until = now_ns + validity_ms * 1_000_000;

        let wire = encode_cert_data_with_description(
            subject_key_name,
            &subject_public_key,
            issuer_signer.as_ref(),
            now_ns,
            valid_until,
            additional_description,
        )
        .await?;

        let data = ndn_packet::Data::decode(wire)
            .map_err(|e| TrustError::KeyStore(format!("failed to decode issued cert: {e}")))?;
        let cert = Certificate::decode(&data)?;

        self.cert_cache.insert(cert.clone());
        Ok(cert)
    }

    pub fn add_trust_anchor(&self, cert: Certificate) -> bool {
        if !cert.is_valid_now() {
            return false;
        }
        self.cert_cache.insert(cert.clone());
        self.keyring.ambient().add_anchor(cert)
    }

    /// Remove a trust anchor by name; returns whether anything was
    /// removed. Does not evict the cert from the cache — it can still
    /// participate in chain walks, just no longer as a root.
    pub fn remove_trust_anchor(&self, key_name: &Name) -> bool {
        let anchors = self.keyring.ambient().anchors();
        let key_arc = anchors
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.key()));
        if let Some(k) = key_arc {
            anchors.remove(&k).is_some()
        } else {
            false
        }
    }

    pub fn trust_anchor(&self, key_name: &Name) -> Option<Certificate> {
        self.keyring
            .ambient()
            .anchors()
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| r.value().clone())
    }

    pub fn trust_anchor_names(&self) -> Vec<Arc<Name>> {
        self.keyring
            .ambient()
            .anchors()
            .iter()
            .map(|r| Arc::clone(r.key()))
            .collect()
    }

    pub async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        use crate::key_store::KeyStore;
        self.keys.get_signer(key_name).await
    }

    pub fn get_signer_sync(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.keys.get_signer_sync(key_name)
    }

    /// Any one registered signer — the daemon's identity in the common
    /// single-identity case. `None` only before `auto_init` / `from_pib`.
    pub fn any_signer(&self) -> Option<Arc<dyn Signer>> {
        self.keys.any_signer()
    }

    pub fn cert_cache(&self) -> &CertCache {
        &self.cert_cache
    }

    /// Load an identity from a [`FilePib`](crate::pib::FilePib) along
    /// with its signing key, certificate, and trust anchors.
    pub fn from_pib(pib: &crate::pib::FilePib, identity: &Name) -> Result<Self, TrustError> {
        let mgr = SecurityManager::new();

        let signer = pib.get_signer(identity)?;
        mgr.keys.add_arc(Arc::new(identity.clone()), signer);

        if let Ok(cert) = pib.get_cert(identity) {
            mgr.cert_cache.insert(cert);
        }

        for anchor in pib.trust_anchors()? {
            mgr.add_trust_anchor(anchor);
        }

        Ok(mgr)
    }

    /// Auto-initialize from a PIB directory; generates a new identity if
    /// none exists, otherwise loads the first one found. The returned
    /// `bool` is `true` when a new identity was generated.
    pub fn auto_init(
        identity: &Name,
        pib_path: &std::path::Path,
    ) -> Result<(Self, bool), TrustError> {
        use crate::pib::FilePib;

        let pib = if pib_path.exists() {
            FilePib::open(pib_path)?
        } else {
            FilePib::new(pib_path)?
        };

        let existing_keys = pib.list_keys()?;
        if !existing_keys.is_empty() {
            let key_name = &existing_keys[0];
            let mgr = SecurityManager::from_pib(&pib, key_name)?;
            return Ok((mgr, false));
        }

        let key_name = append_key_component(identity);
        // ECDSA-P256 so the identity is verifiable by ndn-cxx tooling,
        // which doesn't support Ed25519. Ed25519 stays available via
        // explicit `pib.generate_ed25519` for ndn-rs-only deployments.
        let signer = pib.generate_ecdsa_p256(&key_name)?;

        let pk = signer.public_key().unwrap_or_default();
        let now_ns = now_ns();
        let one_year_ns = 365 * 24 * 3600 * 1_000_000_000u64;
        let cert = Certificate {
            name: Arc::new(key_name.clone()),
            public_key: pk,
            valid_from: now_ns,
            valid_until: now_ns.saturating_add(one_year_ns),
            issuer: Some(Arc::new(key_name.clone())),
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureSha256WithEcdsa,
        };
        pib.store_cert(&key_name, &cert)?;
        pib.add_trust_anchor(&key_name, &cert)?;

        let mgr = SecurityManager::from_pib(&pib, &key_name)?;
        Ok((mgr, true))
    }
}

fn append_key_component(identity: &Name) -> Name {
    use ndn_packet::NameComponent;
    let mut components: Vec<NameComponent> = identity.components().to_vec();
    components.push(NameComponent::generic(Bytes::from_static(b"KEY")));
    components.push(NameComponent::generic(Bytes::from_static(b"self")));
    Name::from_components(components)
}

impl Default for SecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode and sign a Certificate Format v2 Data packet.
///
/// Wire shape:
/// - Name must end with `KEY/<keyid>/<issuer>/<version>` (≥ 4 components).
/// - MetaInfo: `ContentType = Key (2)`, non-zero `FreshnessPeriod`.
/// - Content body: raw DER SubjectPublicKeyInfo bytes. Ed25519 is the
///   44-byte RFC 8410 envelope; see [`crate::spki::wrap_ed25519`].
/// - SignatureInfo: SignatureType, KeyLocator, and a `ValidityPeriod`
///   sub-TLV with 15-byte ASCII `YYYYMMDDTHHMMSS` `NotBefore` / `NotAfter`.
pub async fn encode_cert_data(
    subject_cert_name: &Name,
    subject_public_key: &[u8],
    issuer_signer: &dyn Signer,
    valid_from_ns: u64,
    valid_until_ns: u64,
) -> Result<Bytes, TrustError> {
    encode_cert_data_with_description(
        subject_cert_name,
        subject_public_key,
        issuer_signer,
        valid_from_ns,
        valid_until_ns,
        None,
    )
    .await
}

/// As [`encode_cert_data`], but also writes a non-critical
/// `AdditionalDescription` (TLV 0x0102) sub-TLV into `SignatureInfo`,
/// after `ValidityPeriod`. `additional_description` is the *value* of
/// that TLV — i.e. the concatenated `DescriptionEntry` (0x0200) elements,
/// already encoded by the caller. The bytes fall inside the signed region,
/// so the issuer's signature covers them; being non-critical and even-typed,
/// existing NDN verifiers that don't recognise it skip it cleanly.
pub async fn encode_cert_data_with_description(
    subject_cert_name: &Name,
    subject_public_key: &[u8],
    issuer_signer: &dyn Signer,
    valid_from_ns: u64,
    valid_until_ns: u64,
    additional_description: Option<&[u8]>,
) -> Result<Bytes, TrustError> {
    let mut signed = TlvWriter::new();

    write_name(&mut signed, subject_cert_name);

    signed.write_nested(tlv_type::META_INFO, |w| {
        w.write_tlv(tlv_type::CONTENT_TYPE, &2u64.to_be_bytes()); // KEY
        w.write_tlv(tlv_type::FRESHNESS_PERIOD, &3_600_000u64.to_be_bytes()); // 1h
    });

    // Wrap 32-byte Ed25519 keys; pass through longer keys as already-DER
    // SPKI from the caller.
    let spki_body: Bytes = if subject_public_key.len() == crate::spki::ED25519_KEY_LEN {
        let mut arr = [0u8; crate::spki::ED25519_KEY_LEN];
        arr.copy_from_slice(subject_public_key);
        crate::spki::wrap_ed25519(&arr)
    } else {
        Bytes::copy_from_slice(subject_public_key)
    };
    signed.write_tlv(tlv_type::CONTENT, &spki_body);

    let sig_type_code = issuer_signer.sig_type().code();
    let not_before = crate::iso8601::format_iso_basic(valid_from_ns);
    let not_after = crate::iso8601::format_iso_basic(valid_until_ns);
    signed.write_nested(tlv_type::SIGNATURE_INFO, |w| {
        w.write_tlv(tlv_type::SIGNATURE_TYPE, &[sig_type_code as u8]);
        w.write_nested(tlv_type::KEY_LOCATOR, |w| {
            write_name(w, issuer_signer.key_name());
        });
        w.write_nested(tlv_type::VALIDITY_PERIOD, |w| {
            w.write_tlv(tlv_type::NOT_BEFORE, &not_before);
            w.write_tlv(tlv_type::NOT_AFTER, &not_after);
        });
        if let Some(desc) = additional_description {
            w.write_tlv(tlv_type::ADDITIONAL_DESCRIPTION, desc);
        }
    });

    let signed_region = signed.finish();
    let signature = issuer_signer.sign(&signed_region).await?;

    let mut outer = TlvWriter::new();
    outer.write_nested(tlv_type::DATA, |w| {
        w.write_raw(&signed_region);
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &signature);
    });

    Ok(outer.finish())
}

fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

fn now_ns() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
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
            name: Arc::new(kn.clone()),
            public_key: Bytes::from_static(&[1u8; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        assert!(mgr.add_trust_anchor(cert.clone()));
        assert!(mgr.trust_anchor(&kn).is_some());
        assert!(mgr.cert_cache().get(&Arc::new(kn)).is_some());
    }

    #[test]
    fn n14_add_trust_anchor_rejects_invalid_validity_window() {
        let mgr = SecurityManager::new();
        let expired_name = key_name("expired-anchor");
        let not_yet_name = key_name("future-anchor");

        let mut expired = Certificate {
            name: Arc::new(expired_name.clone()),
            public_key: Bytes::from_static(&[1u8; 32]),
            valid_from: 0,
            valid_until: 1,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        assert!(!mgr.add_trust_anchor(expired.clone()));
        assert!(mgr.trust_anchor(&expired_name).is_none());
        assert!(mgr.cert_cache().get(&Arc::new(expired_name)).is_none());

        expired.name = Arc::new(not_yet_name.clone());
        expired.valid_from = u64::MAX - 1;
        expired.valid_until = u64::MAX;
        assert!(!mgr.add_trust_anchor(expired));
        assert!(mgr.trust_anchor(&not_yet_name).is_none());
        assert!(mgr.cert_cache().get(&Arc::new(not_yet_name)).is_none());
    }

    #[test]
    fn trust_anchor_names_returns_all() {
        let mgr = SecurityManager::new();
        let kn1 = key_name("a");
        let kn2 = key_name("b");
        for kn in [&kn1, &kn2] {
            mgr.add_trust_anchor(Certificate {
                name: Arc::new(kn.clone()),
                public_key: Bytes::from_static(&[0; 32]),
                valid_from: 0,
                valid_until: u64::MAX,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: ndn_packet::SignatureType::SignatureEd25519,
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
    }

    #[tokio::test]
    async fn get_signer_after_generate() {
        let mgr = SecurityManager::new();
        let kn = key_name("sigkey");
        let seed = [9u8; 32];
        mgr.generate_ed25519_from_seed(kn.clone(), &seed).unwrap();
        let signer = mgr.get_signer(&kn).await.unwrap();
        assert_eq!(signer.key_name(), &kn);
    }

    #[tokio::test]
    async fn certify_produces_signed_cert() {
        let mgr = SecurityManager::new();

        let ca_name = key_name("ca");
        let ca_seed = [1u8; 32];
        mgr.generate_ed25519_from_seed(ca_name.clone(), &ca_seed)
            .unwrap();

        let subj_name = key_name("subject");
        let subj_seed = [2u8; 32];
        mgr.generate_ed25519_from_seed(subj_name.clone(), &subj_seed)
            .unwrap();

        let subj_pk = Bytes::copy_from_slice(
            &crate::signer::Ed25519Signer::from_seed(&subj_seed, subj_name.clone())
                .public_key_bytes(),
        );

        let cert = mgr
            .certify(&subj_name, subj_pk.clone(), &ca_name, 60_000)
            .await
            .unwrap();

        assert_eq!(*cert.name, subj_name);
        assert_eq!(cert.public_key, subj_pk);
        assert!(cert.valid_until > cert.valid_from);

        assert!(mgr.cert_cache().get(&Arc::new(subj_name)).is_some());
    }

    #[tokio::test]
    async fn certify_fails_with_unknown_issuer() {
        let mgr = SecurityManager::new();

        let subj_name = key_name("subj");
        let ca_name = key_name("unknown_ca");
        let pk = Bytes::from_static(&[0xAA; 32]);

        let result = mgr.certify(&subj_name, pk, &ca_name, 60_000).await;
        assert!(result.is_err());
    }

    #[test]
    fn auto_init_generates_on_empty_pib() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let identity = key_name("router1");

        let (mgr, generated) = SecurityManager::auto_init(&identity, &pib_path).unwrap();
        assert!(generated);
        assert!(!mgr.trust_anchor_names().is_empty());

        let (_mgr2, generated2) = SecurityManager::auto_init(&identity, &pib_path).unwrap();
        assert!(!generated2);
    }
}
