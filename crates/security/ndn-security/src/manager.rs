use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;

use crate::{
    TrustError, TrustSchema,
    cert_cache::{CertCache, Certificate},
    keyring::Keyring,
    signer::{Ed25519Signer, Signer},
    trust_context::SignedTrustContext,
};

/// Owns the in-memory signer map, certificate cache, and a [`Keyring`] of
/// trust contexts, providing key generation, certificate issuance, and trust
/// anchor management.
///
/// The identities whose keys it holds are the device's **signing set**: a
/// packet without an explicit key is signed by the identity its name
/// selects ([`signer_for`](Self::signer_for)), so a device taking part in
/// several trusted prefixes signs each prefix's Data with that prefix's key.
///
/// The flat trust-anchor API ([`add_trust_anchor`](Self::add_trust_anchor),
/// [`trust_anchor`](Self::trust_anchor), [`trust_anchor_names`](Self::trust_anchor_names),
/// …) is a **view over the keyring's ambient (root-namespace) context**;
/// named contexts are adopted directly on the [`keyring`](Self::keyring). An
/// engine shares this same `Arc<Keyring>` with its [`Validator`](crate::Validator),
/// so anchors inserted here are visible to validation without copying.
pub struct SecurityManager {
    /// Signers by key name. Software keys and externally-held signers
    /// (custodian, YubiKey PIV, remote) all land here.
    keys: DashMap<Arc<Name>, Arc<dyn Signer>>,
    /// Identity → the key it signs with: the first key registered under
    /// `<identity>/KEY/`, unless one is registered as its signing key
    /// ([`register_identity_signer`](Self::register_identity_signer)).
    by_identity: DashMap<Name, IdentityKey>,
    /// Registration order of identities: the first one registered (the
    /// node identity, when loaded from a PIB) is preferred when several
    /// identities of one trusted prefix could sign.
    next_seq: AtomicU64,
    cert_cache: Arc<CertCache>,
    keyring: Arc<Keyring>,
}

/// An identity's signing key and when the identity was first registered.
#[derive(Clone)]
struct IdentityKey {
    key: Arc<Name>,
    seq: u64,
}

/// One identity the device signs as: its name, the key it signs with, and
/// that key's signer ([`SecurityManager::signing_identities`]).
#[derive(Clone)]
pub struct SigningIdentity {
    pub identity: Name,
    pub key: Name,
    pub signer: Arc<dyn Signer>,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningIdentity")
            .field("identity", &self.identity)
            .field("key", &self.key)
            .finish()
    }
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
        Self::with_keyring(Arc::new(Keyring::with_ambient(ambient)))
    }

    /// A manager whose signer choice ([`signer_for`](Self::signer_for))
    /// follows the trust contexts of `keyring`, a keyring shared with a
    /// validator or a host. Its key store and certificate cache start empty.
    pub fn with_keyring(keyring: Arc<Keyring>) -> Self {
        Self {
            keys: DashMap::new(),
            by_identity: DashMap::new(),
            next_seq: AtomicU64::new(0),
            cert_cache: Arc::new(CertCache::new()),
            keyring,
        }
    }

    /// Register `signer` under `key_name` and index it by its identity
    /// (the prefix before `KEY`): the identity's first key stays its signing
    /// key unless `make_identity_key`.
    fn insert_key(&self, key_name: Name, signer: Arc<dyn Signer>, make_identity_key: bool) {
        let key = Arc::new(key_name);
        // The signer first: an index entry always names a held key.
        self.keys.insert(Arc::clone(&key), signer);
        if let Some(identity) = identity_of_key(&key) {
            let mut entry = self
                .by_identity
                .entry(identity)
                .or_insert_with(|| IdentityKey {
                    key: Arc::clone(&key),
                    seq: self.next_seq.fetch_add(1, Ordering::Relaxed),
                });
            if make_identity_key {
                entry.key = key;
            }
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
        self.insert_key(key_name.clone(), Arc::new(signer), false);
        Ok(key_name)
    }

    pub fn generate_ed25519_from_seed(
        &self,
        key_name: Name,
        seed: &[u8; 32],
    ) -> Result<Name, TrustError> {
        let signer = Ed25519Signer::from_seed(seed, key_name.clone());
        self.insert_key(key_name.clone(), Arc::new(signer), false);
        Ok(key_name)
    }

    /// Register an **externally-held** signer under `key_name` — e.g. a
    /// `CustodianSigner` backed by the device enclave or a remote fob, or a
    /// YubiKey PIV slot signer (`yubikey::YubikeyPiv`, feature `yubikey-piv`). The
    /// private key never enters this manager; `get_signer_sync(key_name)`
    /// returns this signer, so a [`KeyChain`](crate::KeyChain) (and an
    /// `ndn_identity::Identity`) built over this manager signs *through* the
    /// custodian. The seam for hardware/remote custody.
    pub fn register_signer(&self, key_name: Name, signer: Arc<dyn Signer>) {
        self.insert_key(key_name, signer, false);
    }

    /// Register `signer` under `key_name` as the key its identity signs with
    /// from now on — a newly enrolled key of an identity that held another —
    /// adding the identity to the signing set if it is new
    /// ([`signer_for`](Self::signer_for)). The identity keeps its place in
    /// the registration order. Other identities are not touched.
    pub fn register_identity_signer(&self, key_name: Name, signer: Arc<dyn Signer>) {
        self.insert_key(key_name, signer, true);
    }

    /// Generate a fresh ECDSA-P256 signing key. Use this instead of
    /// [`generate_ed25519`](Self::generate_ed25519) when the identity
    /// must be verifiable by ndn-cxx tooling, which doesn't support
    /// Ed25519.
    pub fn generate_ecdsa_p256(&self, key_name: Name) -> Result<Name, TrustError> {
        let signer = crate::EcdsaP256Signer::generate(key_name.clone())?;
        self.insert_key(key_name.clone(), Arc::new(signer), false);
        Ok(key_name)
    }

    /// Register a pre-built [`Signer`] (HMAC-SHA256, BLAKE3, YubiKey,
    /// NDNCERT-issued, …) under its own `key_name()`. Required so
    /// `KeyChain::sign_*` can read the active signer's `sig_type()`.
    pub fn install_signer<S: Signer>(&self, signer: S) {
        let key_name = signer.key_name().clone();
        self.insert_key(key_name, Arc::new(signer), false);
    }

    /// Stop holding `key_name`: it no longer signs anything, and its identity
    /// signs with another key of it still held (the smallest name), or leaves
    /// the signing set when none is. Returns whether the key was held.
    pub fn remove_key(&self, key_name: &Name) -> bool {
        if self.keys.remove(key_name).is_none() {
            return false;
        }
        if let Some(identity) = identity_of_key(key_name) {
            let next = self
                .keys
                .iter()
                .filter(|r| identity_of_key(r.key()).as_ref() == Some(&identity))
                .map(|r| Arc::clone(r.key()))
                .min();
            match next {
                Some(key) => {
                    if let Some(mut entry) = self.by_identity.get_mut(&identity)
                        && entry.key.as_ref() == key_name
                    {
                        entry.key = key;
                    }
                }
                None => {
                    self.by_identity.remove(&identity);
                }
            }
        }
        true
    }

    /// Issue a self-signed certificate and register it as a trust anchor.
    ///
    /// The certificate of a `…/KEY/<id>` key is named `<key_name>/self/<version>`
    /// (NDN Certificate Format v2; [`crate::cert_name`]). A legacy key stored
    /// under a certificate-shaped name `…/KEY/<id>/<issuer>/<version>` (what
    /// earlier releases' `ephemeral` and `ndn-sec keygen` created) names the
    /// certificate itself, and so does a free-form key name (no `KEY`
    /// component), so the KeyLocator its signer stamps still resolves.
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
        futures::executor::block_on(self.issue_self_signed_async(
            key_name,
            public_key_bytes,
            validity_ms,
        ))
    }

    /// [`issue_self_signed`](Self::issue_self_signed) through the signer's
    /// async path, for callers already in async code (no nested executor)
    /// and for hardware / custodian signers.
    pub async fn issue_self_signed_async(
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
        let cert_name = if crate::cert_name::is_cert_name(key_name) {
            key_name.clone()
        } else {
            crate::cert_name::new_cert_name(key_name, crate::cert_name::SELF_ISSUER)
        };

        // Self-sign with the matching keystore key. Falls back to an
        // unsigned cert struct when the signer is missing; not expected
        // in practice but preserves no-key callers.
        let cert = match self.get_signer_sync(key_name) {
            Ok(signer) => {
                let wire = encode_cert_data(
                    &cert_name,
                    &public_key_bytes,
                    signer.as_ref(),
                    now_ns,
                    valid_until,
                )
                .await?;
                let data = ndn_packet::Data::decode(wire).map_err(|e| {
                    TrustError::KeyStore(format!("failed to decode self-signed cert: {e}"))
                })?;
                Certificate::decode(&data)?
            }
            Err(_) => Certificate {
                name: Arc::new(cert_name),
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
    /// must already exist in the key store; the result is cached. The
    /// certificate is named `<subject key>/NA/<version>` (ndn-cxx's default
    /// issuer id); [`certify_as`](Self::certify_as) picks the issuer id.
    pub async fn certify(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
    ) -> Result<Certificate, TrustError> {
        self.certify_as(
            subject_key_name,
            subject_public_key,
            issuer_key_name,
            validity_ms,
            crate::cert_name::DEFAULT_ISSUER,
            None,
        )
        .await
    }

    /// As [`certify`](Self::certify), but embeds a non-critical
    /// `AdditionalDescription` (TLV 0x0102) in the issued cert's
    /// `SignatureInfo`. `additional_description` is the already-encoded
    /// value of that TLV (the concatenated `DescriptionEntry` elements).
    /// The bytes are covered by the issuer's signature.
    pub async fn certify_with_additional_description(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
        additional_description: Option<&[u8]>,
    ) -> Result<Certificate, TrustError> {
        self.certify_as(
            subject_key_name,
            subject_public_key,
            issuer_key_name,
            validity_ms,
            crate::cert_name::DEFAULT_ISSUER,
            additional_description,
        )
        .await
    }

    /// Issue a certificate for the key `subject_key_name`, signed by
    /// `issuer_key_name` and named `<subject key>/<issuer_id>/<version>`
    /// with a fresh version ([`crate::cert_name::new_cert_name`]), so every
    /// certificate of a key — a renewal's included — has its own name.
    /// `ndn-cert`'s CA issues with [`crate::cert_name::NDNCERT_ISSUER`].
    pub async fn certify_as(
        &self,
        subject_key_name: &Name,
        subject_public_key: Bytes,
        issuer_key_name: &Name,
        validity_ms: u64,
        issuer_id: &str,
        additional_description: Option<&[u8]>,
    ) -> Result<Certificate, TrustError> {
        let issuer_signer = self.get_signer_sync(issuer_key_name)?;

        let now_ns = now_ns();
        let valid_until = now_ns.saturating_add(validity_ms.saturating_mul(1_000_000));
        let cert_name = crate::cert_name::new_cert_name(subject_key_name, issuer_id);

        let wire = encode_cert_data_with_description(
            &cert_name,
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

    /// Remove the trust anchor(s) of `name`'s key (`name` is a key name or
    /// a certificate name; see [`SignedTrustContext::anchor_for`]); returns
    /// whether anything was removed. Does not evict the cert from the cache —
    /// it can still participate in chain walks, just no longer as a root.
    pub fn remove_trust_anchor(&self, key_name: &Name) -> bool {
        let anchors = self.keyring.ambient().anchors();
        let key = crate::cert_name::key_name_of(key_name);
        let before = anchors.len();
        anchors.retain(|n, _| {
            !(n.as_ref() == key_name
                || crate::cert_name::key_name_of(n) == key
                || (n.len() == key_name.len() + 2 && n.has_prefix(key_name)))
        });
        anchors.len() != before
    }

    /// The ambient trust anchor of `key_name`'s key (a key name or a
    /// certificate name), see [`SignedTrustContext::anchor_for`].
    pub fn trust_anchor(&self, key_name: &Name) -> Option<Certificate> {
        self.keyring.ambient().anchor_for(key_name)
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
        self.get_signer_sync(key_name)
    }

    pub fn get_signer_sync(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.keys
            .get(key_name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| TrustError::CertNotFound {
                name: key_name.to_string(),
            })
    }

    /// Default key name of `identity`: the key it signs with — the first key
    /// registered under `<identity>/KEY/` (any naming form — `/KEY/<kid>`,
    /// `/KEY/self`, `/KEY/root`, legacy cert-named `/KEY/<kid>/self/v=0`),
    /// unless another was registered as its signing key
    /// ([`register_identity_signer`](Self::register_identity_signer)). `None`
    /// when no key of that identity is held.
    pub fn identity_key_name(&self, identity: &Name) -> Option<Name> {
        if let Some(entry) = self.by_identity.get(identity) {
            return Some(entry.key.as_ref().clone());
        }
        // The index keys a key by the prefix before its *first* `KEY`; an
        // identity that itself contains a `KEY` component is found by prefix.
        self.keys
            .iter()
            .filter(|r| is_key_of(r.key(), identity))
            .map(|r| r.key().as_ref().clone())
            .min()
    }

    /// Signer for `identity`'s default key (see
    /// [`identity_key_name`](Self::identity_key_name)). Errors rather than
    /// substituting another identity's key.
    pub fn identity_signer(&self, identity: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        let key_name = self.identity_key_name(identity).ok_or_else(|| {
            TrustError::KeyStore(format!("no key registered for identity {identity}"))
        })?;
        self.get_signer_sync(&key_name)
    }

    /// The signer for a packet named `name` that names no key of its own:
    /// the key of the identity [`signing_identity_for`](Self::signing_identity_for)
    /// chooses. Never another trusted prefix's key, never a default key.
    pub fn signer_for(&self, name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.signing_identity_for(name).map(|s| s.signer)
    }

    /// The identity that signs a packet named `name`:
    ///
    /// - when a trust context held in the [`keyring`](Self::keyring) (not
    ///   the ambient one) governs `name`, an identity of this device in that
    ///   namespace — the longest one that is a prefix of `name`, else the one
    ///   registered first (the node identity before others). The namespace's
    ///   authority keys (its anchor — the root — and its CA, see
    ///   [`signing_identities`](Self::signing_identities)) never sign this
    ///   way. None held: the device only follows the namespace, and the
    ///   error says to enroll in it;
    /// - otherwise the registered identity with the longest name that is a
    ///   prefix of `name`; none: the error says no identity covers `name`.
    pub fn signing_identity_for(&self, name: &Name) -> Result<SigningIdentity, TrustError> {
        let ctx = self.keyring.context_for(name);
        let held = !Arc::ptr_eq(&ctx, self.keyring.ambient());
        let refuse = |why: String| TrustError::NoSigningIdentity {
            name: name.to_string(),
            why,
        };
        let chosen = if held {
            let ns = ctx.namespace();
            let candidates: Vec<(Name, IdentityKey)> = self
                .by_identity
                .iter()
                .filter(|e| e.key().has_prefix(ns) && !is_authority(&ctx, e.key(), &e.value().key))
                .map(|e| (e.key().clone(), e.value().clone()))
                .collect();
            let covering = candidates
                .iter()
                .filter(|(identity, _)| name.has_prefix(identity))
                .max_by_key(|(identity, _)| identity.len());
            let first = || candidates.iter().min_by_key(|(_, k)| k.seq);
            covering.or_else(first).cloned().ok_or_else(|| {
                refuse(format!(
                    "this device follows {ns} (verify only); enroll in {ns} to publish under it"
                ))
            })?
        } else {
            self.by_identity
                .iter()
                .filter(|e| name.has_prefix(e.key()))
                .max_by_key(|e| e.key().len())
                .map(|e| (e.key().clone(), e.value().clone()))
                .ok_or_else(|| {
                    refuse(format!(
                        "no identity of this device covers {name}; sign with an explicit key or \
                         enroll in a trusted prefix that covers it"
                    ))
                })?
        };
        let (identity, entry) = chosen;
        let signer = self.get_signer_sync(&entry.key)?;
        Ok(SigningIdentity {
            identity,
            key: entry.key.as_ref().clone(),
            signer,
        })
    }

    /// Every identity this device signs as, sorted by identity: each
    /// registered identity with the key it signs with, except a held
    /// namespace's authority keys — its trust anchor (the root key, which
    /// signs only the anchor, the CA certificate and context versions, each
    /// on an operator's request) and its CA endpoint identity (`<ns>/CA`,
    /// which signs certificates).
    pub fn signing_identities(&self) -> Vec<SigningIdentity> {
        let mut out: Vec<SigningIdentity> = self
            .by_identity
            .iter()
            .filter(|e| {
                let ctx = self.keyring.context_for(e.key());
                Arc::ptr_eq(&ctx, self.keyring.ambient())
                    || !is_authority(&ctx, e.key(), &e.value().key)
            })
            .filter_map(|e| {
                let key = e.value().key.as_ref().clone();
                let signer = self.get_signer_sync(&key).ok()?;
                Some(SigningIdentity {
                    identity: e.key().clone(),
                    key,
                    signer,
                })
            })
            .collect();
        out.sort_by(|a, b| a.identity.cmp(&b.identity));
        out
    }

    pub fn cert_cache(&self) -> &CertCache {
        &self.cert_cache
    }

    /// Load a [`FilePib`](crate::pib::FilePib): `identity` (the node
    /// identity) first — the signer and certificates of its default key
    /// ([`FilePib::default_key`](crate::pib::FilePib::default_key), one of
    /// the keys stored under `<identity>/KEY/`) — then every other identity
    /// of the PIB whose default key has a currently valid certificate
    /// ([`load_pib_identities`](Self::load_pib_identities)), plus every PIB
    /// trust anchor.
    pub fn from_pib(pib: &crate::pib::FilePib, identity: &Name) -> Result<Self, TrustError> {
        let key_name = pib.default_key(identity)?.ok_or_else(|| {
            TrustError::KeyStore(format!(
                "no key for identity {identity} in PIB {}",
                pib.root().display()
            ))
        })?;
        Self::from_pib_key(pib, &key_name)
    }

    /// The node key `key_name` first, then the PIB's other signing
    /// identities, then its trust anchors.
    fn from_pib_key(pib: &crate::pib::FilePib, key_name: &Name) -> Result<Self, TrustError> {
        let mgr = SecurityManager::new();

        let signer = pib.get_signer(key_name)?;
        mgr.insert_key(key_name.clone(), signer, true);
        // Every stored certificate of the key (a renewed key's old and new
        // one); the cache resolves the key name to the newest valid one.
        for cert in pib.certs(key_name)? {
            mgr.cert_cache.insert(cert);
        }
        mgr.load_pib_identities(pib)?;

        for anchor in pib.trust_anchors()? {
            mgr.add_trust_anchor(anchor);
        }

        Ok(mgr)
    }

    /// Register every identity of `pib` not registered yet whose default key
    /// ([`FilePib::default_key`](crate::pib::FilePib::default_key)) has a
    /// currently valid certificate: its signer and all its certificates.
    /// Identities are taken in name order; each one skipped (no currently
    /// valid certificate, private key unreadable) is logged with why.
    /// Returns the identities registered.
    pub fn load_pib_identities(&self, pib: &crate::pib::FilePib) -> Result<Vec<Name>, TrustError> {
        let mut identities: Vec<Name> = pib
            .list_keys()?
            .iter()
            .filter_map(identity_of_key)
            .collect();
        identities.sort();
        identities.dedup();
        let mut loaded = Vec::new();
        for identity in identities {
            if self.by_identity.contains_key(&identity) {
                continue;
            }
            let Some(key) = pib.default_key(&identity)? else {
                continue;
            };
            let certs = pib.certs(&key)?;
            if !certs.iter().any(Certificate::is_valid_now) {
                let why = match certs.iter().map(|c| c.valid_until).max() {
                    Some(until) => format!(
                        "its certificate expired at {}; renew it or enroll the identity again",
                        String::from_utf8_lossy(&crate::iso8601::format_iso_basic(until))
                    ),
                    None => "it has no certificate (a key awaiting an enrollment's approval, \
                             or one never certified)"
                        .to_owned(),
                };
                tracing::info!(
                    target: "security",
                    identity = %identity,
                    key = %key,
                    "not signing as {identity}: {why}"
                );
                continue;
            }
            let signer = match pib.get_signer(&key) {
                Ok(signer) => signer,
                Err(e) => {
                    tracing::info!(
                        target: "security",
                        identity = %identity,
                        key = %key,
                        error = %e,
                        "not signing as {identity}: its private key is not in the PIB or cannot \
                         be read (a key held elsewhere, e.g. a root store, signs only through it)"
                    );
                    continue;
                }
            };
            self.insert_key(key.clone(), signer, true);
            for cert in certs {
                self.cert_cache.insert(cert);
            }
            loaded.push(identity);
        }
        Ok(loaded)
    }

    /// Auto-initialize `identity` from a PIB directory (created if absent).
    /// Loads the identity's key when the PIB holds one under
    /// `<identity>/KEY/`; otherwise generates `<identity>/KEY/<random key-id>`
    /// with a self-signed anchor certificate `<key>/self/<version>`. Either
    /// way `identity` is registered first, then the PIB's other identities
    /// with a currently valid certificate, as [`from_pib`](Self::from_pib)
    /// loads them. The returned `bool` is `true` when a new key was generated.
    pub fn auto_init(
        identity: &Name,
        pib_path: &std::path::Path,
    ) -> Result<(Self, bool), TrustError> {
        use crate::pib::FilePib;

        // `new` is idempotent: it creates only the missing sub-directories,
        // so a PIB directory that holds e.g. only adopted contexts still opens.
        let pib = FilePib::new(pib_path)?;

        if let Some(key_name) = pib.default_key(identity)? {
            let mgr = SecurityManager::from_pib_key(&pib, &key_name)?;
            return Ok((mgr, false));
        }

        let key_name = crate::cert_name::new_key_name(identity)?;
        // ECDSA-P256 so the identity is verifiable by ndn-cxx tooling,
        // which doesn't support Ed25519. Ed25519 stays available via
        // explicit `pib.generate_ed25519` for ndn-rs-only deployments.
        let signer = pib.generate_ecdsa_p256(&key_name)?;

        let pk = signer.public_key().unwrap_or_default();
        let now_ns = now_ns();
        let one_year_ns = 365 * 24 * 3600 * 1_000_000_000u64;
        let cert_name = crate::cert_name::new_cert_name(&key_name, crate::cert_name::SELF_ISSUER);
        let wire = futures::executor::block_on(encode_cert_data(
            &cert_name,
            &pk,
            &signer,
            now_ns,
            now_ns.saturating_add(one_year_ns),
        ))?;
        let data = ndn_packet::Data::decode(wire)
            .map_err(|e| TrustError::KeyStore(format!("failed to decode self-signed cert: {e}")))?;
        let cert = Certificate::decode(&data)?;
        pib.store_cert(&key_name, &cert)?;
        pib.add_trust_anchor(&key_name, &cert)?;

        let mgr = SecurityManager::from_pib_key(&pib, &key_name)?;
        Ok((mgr, true))
    }
}

/// Whether `key_name` is a key of `identity`: it starts with
/// `<identity>/KEY/` and names at least a key id after `KEY`. Accepts every
/// naming form in use — `/KEY/<kid>`, `/KEY/self`, `/KEY/root`, and the
/// cert-named `/KEY/<kid>/self/v=0` earlier `ndn-sec keygen` releases stored.
pub(crate) fn is_key_of(key_name: &Name, identity: &Name) -> bool {
    key_name.len() > identity.len() + 1
        && key_name.has_prefix(identity)
        && key_name.components()[identity.len()].value.as_ref() == b"KEY"
}

/// The identity owning `key_name` for the identity index: the prefix before
/// its first `KEY` component, provided a key id follows it.
fn identity_of_key(key_name: &Name) -> Option<Name> {
    let comps = key_name.components();
    let pos = comps.iter().position(|c| c.value.as_ref() == b"KEY")?;
    (pos + 1 < comps.len()).then(|| Name::from_components(comps[..pos].iter().cloned()))
}

/// Whether `key` of `identity` is an authority key of the held namespace
/// `ctx`: its trust anchor (the root, a recovery anchor) or its CA endpoint
/// identity. They sign certificates and context versions, never a packet
/// whose name chose its signer.
fn is_authority(ctx: &SignedTrustContext, identity: &Name, key: &Name) -> bool {
    ctx.is_anchor(key) || ctx.ca_endpoints().iter().any(|ca| ca == identity)
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

    /// A self-signed certificate is `<key>/self/<version>`, and the key name
    /// resolves to it as an anchor and from the cache.
    #[test]
    fn issue_self_signed_adds_anchor() {
        let mgr = SecurityManager::new();
        let kn: Name = "/alice/KEY/k1".parse().unwrap();
        let pk = Bytes::from_static(&[0xAB; 32]);
        let cert = mgr.issue_self_signed(&kn, pk, u64::MAX).unwrap();
        assert!(crate::cert_name::is_cert_name(&cert.name), "{}", cert.name);
        assert_eq!(cert.key_name(), kn);
        assert_eq!(cert.name.components()[kn.len()].value.as_ref(), b"self");
        assert!(cert.name.components()[kn.len() + 1].as_version().is_some());
        assert!(mgr.trust_anchor(&kn).is_some());
        assert!(mgr.trust_anchor(&cert.name).is_some());
        assert_eq!(mgr.cert_cache().get(&Arc::new(kn)).unwrap().name, cert.name);
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

    #[test]
    fn get_signer_missing_key_returns_cert_not_found() {
        let mgr = SecurityManager::new();
        assert!(matches!(
            mgr.get_signer_sync(&key_name("missing")),
            Err(TrustError::CertNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn certify_produces_signed_cert() {
        let mgr = SecurityManager::new();

        let ca_name = key_name("ca");
        let ca_seed = [1u8; 32];
        mgr.generate_ed25519_from_seed(ca_name.clone(), &ca_seed)
            .unwrap();

        let subj_name: Name = "/subject/KEY/k1".parse().unwrap();
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

        // `<subject key>/<issuer-id>/<version>`, found by the key name.
        assert!(cert.name.len() == subj_name.len() + 2 && cert.name.has_prefix(&subj_name));
        assert!(
            cert.name.components()[subj_name.len() + 1]
                .as_version()
                .is_some()
        );
        assert_eq!(cert.public_key, subj_pk);
        assert!(cert.valid_until > cert.valid_from);

        assert!(mgr.cert_cache().get(&Arc::new(subj_name)).is_some());
    }

    /// Each certificate of one key gets its own name, and the key name
    /// resolves to the newest one.
    #[tokio::test]
    async fn certify_as_names_each_certificate_of_a_key_apart() {
        let mgr = SecurityManager::new();
        let ca: Name = "/ns/CA/KEY/ca".parse().unwrap();
        let dev: Name = "/ns/member/d/KEY/k".parse().unwrap();
        mgr.generate_ed25519(ca.clone()).unwrap();
        let pk = Bytes::from_static(&[3; 32]);
        let first = mgr
            .certify_as(
                &dev,
                pk.clone(),
                &ca,
                60_000,
                crate::cert_name::NDNCERT_ISSUER,
                None,
            )
            .await
            .unwrap();
        let second = mgr
            .certify_as(
                &dev,
                pk,
                &ca,
                60_000,
                crate::cert_name::NDNCERT_ISSUER,
                None,
            )
            .await
            .unwrap();
        assert_ne!(first.name, second.name);
        for cert in [&first, &second] {
            assert_eq!(cert.key_name(), dev);
            assert_eq!(cert.name.components()[dev.len()].value.as_ref(), b"NDNCERT");
        }
        assert_eq!(
            mgr.cert_cache().get(&Arc::new(dev)).unwrap().name,
            second.name
        );
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

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The identity's single signer: (key name, public key).
    fn identity_signer(mgr: &SecurityManager, identity: &Name) -> (Name, Bytes) {
        let signer = mgr.identity_signer(identity).expect("identity signer");
        (signer.key_name().clone(), signer.public_key().unwrap())
    }

    /// A node's identity persisted to a FilePib comes back with the same
    /// signer after a restart, via both `auto_init` and `from_pib`.
    #[test]
    fn identity_reloads_with_same_signer_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let identity = n("/home/bob/phone");

        let (first, generated) = SecurityManager::auto_init(&identity, &pib_path).unwrap();
        assert!(generated);
        let (key, pk) = identity_signer(&first, &identity);
        assert!(
            is_key_of(&key, &identity) && key.len() == identity.len() + 2,
            "{key}"
        );
        // Its self-signed anchor is a cert-v2 certificate of the key.
        let anchor = first.trust_anchor(&key).expect("self anchor");
        assert!(
            crate::cert_name::is_cert_name(&anchor.name),
            "{}",
            anchor.name
        );
        assert_eq!(anchor.key_name(), key);
        assert_eq!(
            anchor.name.components()[key.len()].value.as_ref(),
            crate::cert_name::SELF_ISSUER.as_bytes()
        );
        drop(first);

        // Simulated restart: fresh managers over the same directory.
        let (again, generated) = SecurityManager::auto_init(&identity, &pib_path).unwrap();
        assert!(!generated);
        assert_eq!(
            identity_signer(&again, &identity),
            (key.clone(), pk.clone())
        );

        let pib = crate::pib::FilePib::open(&pib_path).unwrap();
        let loaded = SecurityManager::from_pib(&pib, &identity).unwrap();
        assert_eq!(identity_signer(&loaded, &identity), (key.clone(), pk));
        assert!(loaded.trust_anchor(&key).is_some(), "self anchor reloads");
    }

    /// With two identities in one PIB, the requested one is loaded with its
    /// own key — never whichever key the directory listing yields first —
    /// and the other one is loaded beside it.
    #[test]
    fn requested_identity_is_honoured_with_two_identities() {
        let dir = tempfile::tempdir().unwrap();
        let pib_path = dir.path().join("pib");
        let alice = n("/home/bob/alice");
        let carol = n("/home/bob/carol");

        let (a, _) = SecurityManager::auto_init(&alice, &pib_path).unwrap();
        let alice_key = identity_signer(&a, &alice);
        let (c, generated) = SecurityManager::auto_init(&carol, &pib_path).unwrap();
        assert!(
            generated,
            "carol has no key yet; alice's must not be reused"
        );
        let carol_key = identity_signer(&c, &carol);
        assert_ne!(alice_key.0, carol_key.0);

        let pib = crate::pib::FilePib::open(&pib_path).unwrap();
        for (identity, expected) in [(&alice, &alice_key), (&carol, &carol_key)] {
            let mgr = SecurityManager::from_pib(&pib, identity).unwrap();
            assert_eq!(&identity_signer(&mgr, identity), expected);
            let signing: Vec<Name> = mgr
                .signing_identities()
                .into_iter()
                .map(|s| s.identity)
                .collect();
            assert_eq!(signing, vec![alice.clone(), carol.clone()]);
            let (reloaded, generated) = SecurityManager::auto_init(identity, &pib_path).unwrap();
            assert!(!generated);
            assert_eq!(&identity_signer(&reloaded, identity), expected);
        }
        assert!(SecurityManager::from_pib(&pib, &n("/home/bob/dave")).is_err());
    }

    /// A PIB identity whose certificate is no longer valid is not loaded
    /// beside the node identity: it cannot sign anything that validates.
    #[test]
    fn identity_without_a_valid_certificate_is_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let pib = crate::pib::FilePib::new(dir.path()).unwrap();
        let node = n("/home/bob/node");
        SecurityManager::auto_init(&node, dir.path()).unwrap();
        let stale = n("/work/acme/member/node/KEY/k1");
        let signer = pib.generate_ed25519(&stale).unwrap();
        let cert = Certificate {
            name: Arc::new(stale.clone()),
            public_key: signer.public_key().unwrap(),
            valid_from: 0,
            valid_until: 1,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        pib.store_cert(&stale, &cert).unwrap();

        let mgr = SecurityManager::from_pib(&pib, &node).unwrap();
        assert!(
            mgr.identity_key_name(&n("/work/acme/member/node"))
                .is_none()
        );
        assert!(mgr.identity_key_name(&node).is_some());
    }

    /// Every key naming form already persisted in FilePibs loads for its
    /// identity: earlier `ndn-sec keygen` releases' cert-named `/KEY/<kid>/self/v=0`,
    /// `auto_init`'s `/KEY/self`, a namespace root's `/KEY/root`, and `/KEY/<kid>`.
    #[test]
    fn every_key_naming_form_loads_for_its_identity() {
        for (identity, legacy_key) in [
            ("/legacy/keygen", "/legacy/keygen/KEY/k0/self/v=0"),
            ("/legacy/router", "/legacy/router/KEY/self"),
            ("/legacy/hub", "/legacy/hub/KEY/root"),
            ("/legacy/plain", "/legacy/plain/KEY/0123abcd"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let pib = crate::pib::FilePib::new(dir.path()).unwrap();
            let identity = n(identity);
            let legacy_key = n(legacy_key);
            let signer = pib.generate_ecdsa_p256(&legacy_key).unwrap();
            let pk = signer.public_key().unwrap();
            let now = now_ns();
            let cert = Certificate {
                name: Arc::new(legacy_key.clone()),
                public_key: pk.clone(),
                valid_from: now,
                valid_until: now + 3_600_000_000_000,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: ndn_packet::SignatureType::SignatureSha256WithEcdsa,
            };
            pib.store_cert(&legacy_key, &cert).unwrap();
            pib.add_trust_anchor(&legacy_key, &cert).unwrap();

            let mgr = SecurityManager::from_pib(&pib, &identity).unwrap();
            assert_eq!(
                identity_signer(&mgr, &identity),
                (legacy_key.clone(), pk.clone())
            );

            let (mgr, generated) = SecurityManager::auto_init(&identity, dir.path()).unwrap();
            assert!(!generated, "legacy key must be reused, not replaced");
            assert_eq!(identity_signer(&mgr, &identity), (legacy_key, pk));
        }
    }

    /// The identity index resolves every naming form, and a key of a
    /// sub-identity (`/<ns>/CA/KEY/ca`) never answers for `/<ns>`.
    #[test]
    fn identity_index_resolves_every_naming_form() {
        let mgr = SecurityManager::new();
        for key in [
            "/a/KEY/k0/self/v=0",
            "/b/KEY/self",
            "/home/bob/CA/KEY/ca",
            "/home/bob/KEY/root",
            "/d/KEY/0123abcd",
        ] {
            mgr.generate_ed25519(n(key)).unwrap();
        }
        for (identity, key) in [
            ("/a", "/a/KEY/k0/self/v=0"),
            ("/b", "/b/KEY/self"),
            ("/home/bob", "/home/bob/KEY/root"),
            ("/home/bob/CA", "/home/bob/CA/KEY/ca"),
            ("/d", "/d/KEY/0123abcd"),
        ] {
            assert_eq!(mgr.identity_key_name(&n(identity)), Some(n(key)));
        }
        assert_eq!(mgr.identity_key_name(&n("/home")), None);
        assert_eq!(
            mgr.signer_for(&n("/home/bob/CA/issued/x"))
                .unwrap()
                .key_name(),
            &n("/home/bob/CA/KEY/ca")
        );
    }

    /// A trust context held for `namespace`, with `root` as its anchor and
    /// `<namespace>/CA` as its CA endpoint.
    fn hold(mgr: &SecurityManager, namespace: &str, root: &Name) {
        let pk = mgr.get_signer_sync(root).unwrap().public_key().unwrap();
        let anchor = mgr.issue_self_signed(root, pk, 3_600_000).unwrap();
        let ns = n(namespace);
        let ctx = SignedTrustContext::hierarchical(ns.clone())
            .with_version(1)
            .with_ca_endpoint(ns.append("CA"));
        ctx.add_anchor(anchor);
        assert!(mgr.keyring().adopt(Arc::new(ctx)));
    }

    /// The invariants of choosing a signer by name: a device that owns /a
    /// (its root and CA keys held), is a member of /a and of /c, and only
    /// follows /b signs each prefix's names with that prefix's device key —
    /// never the root or CA key, never another prefix's key — refuses /b
    /// with why, and refuses a name nothing covers.
    #[test]
    fn signer_is_chosen_by_name_per_trusted_prefix() {
        let mgr = SecurityManager::new();
        let a_root = n("/a/KEY/root");
        let a_ca = n("/a/CA/KEY/ca");
        let a_dev = n("/a/admin/desk/KEY/d1");
        let c_dev = n("/c/member/desk/KEY/d2");
        let b_root = n("/b/KEY/root");
        for key in [&a_root, &a_ca, &a_dev, &c_dev] {
            mgr.generate_ed25519(key.clone()).unwrap();
        }
        hold(&mgr, "/a", &a_root);
        // /b's root key is not this device's: hold /b with another manager's anchor.
        let other = SecurityManager::new();
        other.generate_ed25519(b_root.clone()).unwrap();
        hold(&other, "/b", &b_root);
        mgr.keyring()
            .adopt(other.keyring().contexts().into_iter().next().unwrap());
        // /c's root is elsewhere; only its context is held.
        let c = SecurityManager::new();
        c.generate_ed25519(n("/c/KEY/root")).unwrap();
        hold(&c, "/c", &n("/c/KEY/root"));
        mgr.keyring()
            .adopt(c.keyring().contexts().into_iter().next().unwrap());

        let key_for = |name: &str| mgr.signer_for(&n(name)).map(|s| s.key_name().clone());
        assert_eq!(key_for("/a/admin/desk/notes").unwrap(), a_dev);
        assert_eq!(
            key_for("/a/shared/notes").unwrap(),
            a_dev,
            "not the root key"
        );
        assert_eq!(key_for("/c/shared/x").unwrap(), c_dev);
        assert_eq!(key_for("/c/member/desk/y").unwrap(), c_dev);
        match key_for("/b/shared/x") {
            Err(TrustError::NoSigningIdentity { why, .. }) => {
                assert!(why.contains("follows /b"), "{why}")
            }
            other => panic!("following-only /b must refuse: {other:?}"),
        }
        match key_for("/x/y") {
            Err(TrustError::NoSigningIdentity { why, .. }) => {
                assert!(
                    why.contains("no identity of this device covers /x/y"),
                    "{why}"
                )
            }
            other => panic!("an uncovered name must refuse: {other:?}"),
        }
        let signing: Vec<Name> = mgr
            .signing_identities()
            .into_iter()
            .map(|s| s.identity)
            .collect();
        assert_eq!(
            signing,
            vec![n("/a/admin/desk"), n("/c/member/desk")],
            "the root and CA keys are no signing identities"
        );
    }

    /// An identity added later (an enrollment in /c) changes nothing about
    /// how /a's names are signed, and a newer key of an identity takes over
    /// only that identity.
    #[test]
    fn adding_an_identity_leaves_the_others() {
        let mgr = SecurityManager::new();
        let a_old = n("/a/member/x/KEY/k1");
        mgr.generate_ed25519(a_old.clone()).unwrap();
        let before = mgr.signer_for(&n("/a/member/x/data")).unwrap();
        let c_key = n("/c/member/x/KEY/k2");
        let c_signer: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(&[9; 32], c_key.clone()));
        mgr.register_identity_signer(c_key.clone(), c_signer);
        assert_eq!(
            mgr.signer_for(&n("/a/member/x/data")).unwrap().key_name(),
            before.key_name()
        );
        assert_eq!(
            mgr.signer_for(&n("/c/member/x/data")).unwrap().key_name(),
            &c_key
        );
        let a_new = n("/a/member/x/KEY/k3");
        mgr.register_identity_signer(
            a_new.clone(),
            Arc::new(Ed25519Signer::from_seed(&[8; 32], a_new.clone())),
        );
        assert_eq!(
            mgr.signer_for(&n("/a/member/x/data")).unwrap().key_name(),
            &a_new
        );
        assert_eq!(
            mgr.signer_for(&n("/c/member/x/data")).unwrap().key_name(),
            &c_key
        );
        // A removed key signs nothing; its identity falls back to a key it
        // still holds, or leaves the signing set.
        assert!(mgr.remove_key(&c_key));
        assert!(mgr.signer_for(&n("/c/member/x/data")).is_err());
        assert!(mgr.remove_key(&a_new));
        assert_eq!(
            mgr.signer_for(&n("/a/member/x/data")).unwrap().key_name(),
            &a_old
        );
        let left: Vec<Name> = mgr
            .signing_identities()
            .into_iter()
            .map(|s| s.identity)
            .collect();
        assert_eq!(left, vec![n("/a/member/x")]);
    }
}
