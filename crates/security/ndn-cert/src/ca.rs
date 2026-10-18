//! NDNCERT CA-side processor. Transport-agnostic; the Producer wiring lives
//! in `ndn-identity`. In-flight session state lives in [`DashMap`]; issued
//! certs and revocations are written through an optional
//! [`CaStore`](crate::store::CaStore) so they survive restarts.

use std::{sync::Arc, time::Duration};

use web_time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use dashmap::{DashMap, DashSet};
use ndn_security::{
    CertCache, Certificate, Keyring, SecurityManager, Signer, ValidationResult, Validator,
};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    ecdh::{EcdhKeypair, SessionKey, new_encryption_iv},
    error::CertError,
    store::CaStore,
    policy::{
        AcceptAllIssuance, IssuanceContext, IssuanceDecision, IssuancePolicy, NamespacePolicy,
        PolicyDecision, SingleKeyIdentity, attested,
    },
    protocol::{CertRequest, ErrorCode},
    tlv::{
        CaProfileTlv, ChallengeResponseTlv, NewRequestTlv, NewResponseTlv, ProbeResponseTlv,
        REVOKE_STATUS_NOT_FOUND, REVOKE_STATUS_REVOKED, REVOKE_STATUS_UNAUTHORIZED,
        RevokeRequestTlv, RevokeResponseTlv, STATUS_FAILURE, STATUS_PENDING, STATUS_SUCCESS,
        decode_challenge_plaintext,
    },
};

pub struct CaConfig {
    pub prefix: ndn_packet::Name,
    pub info: String,
    pub default_validity: Duration,
    pub max_validity: Duration,
    pub challenges: Vec<Box<dyn ChallengeHandler>>,
    /// Pre-challenge gate.
    pub policy: Box<dyn NamespacePolicy>,
    /// Post-challenge gate (the last stage before signing).
    pub issuance: Box<dyn IssuancePolicy>,
    /// When `true`, embed a [`crate::attestation::AttestationSet`] (recording
    /// how the challenge was satisfied) in each issued cert's
    /// `AdditionalDescription`. Default `false` — issued certs are
    /// byte-identical to the pre-attestation behaviour.
    pub emit_attestations: bool,
    /// Key name of the CA's signing key. It signs issued certs and every
    /// CA→requester response, and its certificate (looked up in the
    /// manager's cert cache, then its trust anchors) is the INFO
    /// `ca_certificate`. A CA whose key is certified by an offline root sets
    /// this explicitly. `None` falls back to the manager's first trust anchor
    /// — only well-defined when the manager holds exactly one anchor (the
    /// self-signed demo CA).
    pub signing_key: Option<ndn_packet::Name>,
}

impl CaConfig {
    /// Defaults `issuance` to [`AcceptAllIssuance`].
    pub fn new(
        prefix: ndn_packet::Name,
        info: String,
        default_validity: Duration,
        max_validity: Duration,
        challenges: Vec<Box<dyn ChallengeHandler>>,
        policy: Box<dyn NamespacePolicy>,
    ) -> Self {
        Self {
            prefix,
            info,
            default_validity,
            max_validity,
            challenges,
            policy,
            issuance: Box::new(AcceptAllIssuance),
            emit_attestations: false,
            signing_key: None,
        }
    }

    /// Enable embedding challenge attestations in issued certs (builder).
    pub fn emit_attestations(mut self, yes: bool) -> Self {
        self.emit_attestations = yes;
        self
    }

    /// Sign with the key named `key_name` (builder; see
    /// [`signing_key`](Self::signing_key)).
    pub fn with_signing_key(mut self, key_name: ndn_packet::Name) -> Self {
        self.signing_key = Some(key_name);
        self
    }
}

struct PendingRequest {
    cert_request: CertRequest,
    challenge_state: Option<ChallengeState>,
    challenge_type: Option<String>,
    /// When this session ends (Unix seconds): the NEW → CHALLENGE window
    /// after NEW, then the remaining time the last CHALLENGE answer
    /// advertised. A wait that outlives sessions (an admin's approval) is
    /// kept elsewhere ([`crate::approval::ApprovalStore`]).
    expires_at: u64,
    session_key: SessionKey,
    request_id_bytes: [u8; 8],
    encryption_iv: [u8; 12],
    decryption_iv: Option<[u8; 12]>,
}

pub struct CaState {
    config: CaConfig,
    manager: Arc<SecurityManager>,
    pending: DashMap<String, PendingRequest>,
    /// Revoked certificate names (canonical URIs) — and, for a certificate
    /// named after its key by an earlier release, that key name.
    revoked: DashSet<String>,
    /// Keys with a revoked certificate (canonical URIs): revoking one
    /// certificate of a key revokes the key, so its other certificates (a
    /// renewal's included) are refused too and it is never certified again.
    revoked_keys: DashSet<String>,
    /// Issued cert wire bytes, served on the cert-fetch Interest — and the
    /// certificates of earlier CAs of this CA's identity that a renewal's
    /// chain went through ([`accept_earlier_ca_certificates`](Self::accept_earlier_ca_certificates)).
    served_certs: DashMap<String, Vec<u8>>,
    /// Durable backing for `served_certs` / `revoked`; `None` keeps both
    /// in memory only.
    store: Option<Arc<dyn CaStore>>,
    /// Held from the single-key check to recording the issued cert, so two
    /// requests for one identity cannot both pass the check.
    issuing: tokio::sync::Mutex<()>,
    /// Single-key identities whose challenge is running. Another request for
    /// one of them is refused before its challenge runs, so the loser of a
    /// race spends no one-time token.
    in_flight: DashSet<String>,
    /// The trust contexts a renewal of a certificate issued by an earlier CA
    /// of this CA's identity is verified under; unset, the CA renews only
    /// the certificates it issued.
    earlier_ca: std::sync::OnceLock<Arc<Keyring>>,
}

impl CaState {
    /// In-memory CA: issued certs and revocations are lost on drop. Use
    /// [`with_store`](Self::with_store) for a CA that must survive restarts.
    pub fn new(config: CaConfig, manager: Arc<SecurityManager>) -> Self {
        let state = Self {
            config,
            manager,
            pending: DashMap::new(),
            revoked: DashSet::new(),
            revoked_keys: DashSet::new(),
            served_certs: DashMap::new(),
            store: None,
            issuing: tokio::sync::Mutex::new(()),
            in_flight: DashSet::new(),
            earlier_ca: std::sync::OnceLock::new(),
        };
        state.serve_own_certificate();
        state
    }

    /// CA backed by `store`: loads the previously issued certs (served again
    /// on cert-fetch) and the revocation set, then writes every new issuance
    /// and revocation through the store.
    pub fn with_store(
        config: CaConfig,
        manager: Arc<SecurityManager>,
        store: Arc<dyn CaStore>,
    ) -> Result<Self, CertError> {
        let snapshot = store.load()?;
        let mut state = Self::new(config, manager);
        for (name, wire) in snapshot.issued {
            state.served_certs.insert(name, wire);
        }
        for name in snapshot.revoked {
            state.insert_revoked(name);
        }
        state.store = Some(store);
        Ok(state)
    }

    /// Renew certificates issued by an earlier CA of this CA's identity —
    /// e.g. the CA of a root device that was replaced through a recovery
    /// kit — besides the ones this CA issued. Such a renewal carries the
    /// certificate and the issuer certificates of its chain
    /// ([`crate::renewal`]), verified under the trust contexts in `keyring`
    /// (the node's own): the certificate must chain to an anchor of its
    /// namespace's context under that context's schema, through no revoked
    /// key. This CA serves (and persists, with a store) the earlier CA's
    /// certificates of an accepted chain from then on, so validators that
    /// fetch them by key name from `<identity>` find them here. Set once: a
    /// later call is ignored.
    pub fn accept_earlier_ca_certificates(&self, keyring: Arc<Keyring>) {
        let _ = self.earlier_ca.set(keyring);
    }

    /// Serve the CA's own certificate on cert-fetch so requesters can walk
    /// an issued cert's chain up to the anchor they hold.
    fn serve_own_certificate(&self) {
        if let Some(cert) = self.ca_certificate()
            && cert.signed_region.is_some()
        {
            self.served_certs
                .insert(cert.name.to_string(), serialize_cert(&cert));
        }
    }

    /// Whether `key` is a key of this CA's identity other than the one it
    /// signs with — the key of an earlier CA of the same identity. The
    /// identity is the signing key name minus `KEY/<id>`. Certificates of
    /// such keys are never ones this CA issued.
    fn is_earlier_ca_key(&self, key: &ndn_packet::Name) -> bool {
        self.signing_key_name()
            .is_some_and(|own| is_other_key_of_identity(&own, key))
    }

    /// Drop the NDNCERT sessions whose own advertised time has run out.
    pub fn cleanup_expired(&self) {
        let now = now_secs();
        self.pending.retain(|_, v| v.expires_at >= now);
    }

    /// Whether `cert_name` (a certificate or key name, canonical URI) is
    /// revoked: it was revoked itself, or its key has a revoked certificate.
    pub fn is_revoked(&self, cert_name: &str) -> bool {
        self.revoked.contains(cert_name)
            || cert_name.parse::<ndn_packet::Name>().is_ok_and(|n| {
                self.revoked_keys
                    .contains(&ndn_security::cert_name::key_name_of(&n).to_string())
            })
    }

    fn insert_revoked(&self, cert_uri: String) {
        if let Ok(name) = cert_uri.parse::<ndn_packet::Name>() {
            self.revoked_keys
                .insert(ndn_security::cert_name::key_name_of(&name).to_string());
        }
        self.revoked.insert(cert_uri);
    }

    /// A valid, unrevoked certificate this CA issued under `identity` for a
    /// key other than `public_key`.
    fn certified_to_other_key(
        &self,
        identity: &ndn_packet::Name,
        public_key: &[u8],
    ) -> Option<Certificate> {
        let key_prefix = format!("{identity}/KEY/");
        self.served_certs.iter().find_map(|entry| {
            if !entry.key().starts_with(&key_prefix) || self.is_revoked(entry.key()) {
                return None;
            }
            let cert = deserialize_cert(entry.value())?;
            (cert.is_valid_now() && cert.public_key.as_ref() != public_key).then_some(cert)
        })
    }

    /// When the policy holds `req`'s identity to one key
    /// ([`IssuancePolicy::single_key_identity`]) and another key holds a
    /// valid, unrevoked certificate for it: the rule and that certificate.
    fn identity_taken(&self, req: &CertRequest) -> Option<(SingleKeyIdentity, Certificate)> {
        let key_name: ndn_packet::Name = req.name.parse().ok()?;
        let rule = self.config.issuance.single_key_identity(&key_name)?;
        let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.public_key)
            .ok()?;
        let held = self.certified_to_other_key(&rule.identity, &public_key)?;
        Some((rule, held))
    }

    /// Reserve `req`'s single-key identity while its challenge runs.
    /// `Err(identity)` when another request holds it; `Ok(None)` when no
    /// single-key rule applies.
    fn reserve_identity(&self, req: &CertRequest) -> Result<Option<InFlight<'_>>, String> {
        let Some(key_name) = req.name.parse::<ndn_packet::Name>().ok() else {
            return Ok(None);
        };
        let Some(rule) = self.config.issuance.single_key_identity(&key_name) else {
            return Ok(None);
        };
        let identity = rule.identity.to_string();
        if !self.in_flight.insert(identity.clone()) {
            return Err(identity);
        }
        Ok(Some(InFlight {
            set: &self.in_flight,
            identity,
        }))
    }

    /// The challenge types this CA offers: its configured handlers', plus
    /// the built-in [`RENEWAL_CHALLENGE`](crate::renewal::RENEWAL_CHALLENGE)
    /// when its issuance policy renews.
    fn offered_challenges(&self) -> Vec<String> {
        let mut offered: Vec<String> = self
            .config
            .challenges
            .iter()
            .map(|c| c.challenge_type().to_string())
            .collect();
        let renewal = crate::renewal::RENEWAL_CHALLENGE;
        if self.config.issuance.offers_renewal() && !offered.iter().any(|c| c == renewal) {
            offered.push(renewal.to_string());
        }
        offered
    }

    /// The built-in renewal challenge ([`crate::renewal`]): approved when
    /// `params` name a certificate this CA issued — or, when it
    /// [accepts them](Self::accept_earlier_ca_certificates), carry one an
    /// earlier CA of its identity issued that chains to the namespace root
    /// ([`earlier_ca_certificate`](Self::earlier_ca_certificate)) — for the
    /// request's key and public key, valid now, of a key with no revoked
    /// certificate, and prove that key with a signature over this exchange's
    /// request id and the certificate's name. The issuance policy then
    /// decides whether the role renews and for how long.
    async fn verify_renewal(
        &self,
        request_id: &str,
        req: &CertRequest,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> ChallengeOutcome {
        use crate::renewal::{CERT_NAME_PARAM, PROOF_PARAM, RENEWAL_CHALLENGE, renewal_proof_message};
        let deny = ChallengeOutcome::Denied;
        let param = |key: &str| params.get(key).and_then(|v| v.as_str());
        let (Some(cert_uri), Some(proof)) = (param(CERT_NAME_PARAM), param(PROOF_PARAM)) else {
            return deny(format!(
                "a renewal names the certificate it renews ({CERT_NAME_PARAM}) and proves \
                 possession of its key ({PROOF_PARAM})"
            ));
        };
        let (Ok(cert_name), Ok(key_name)) = (
            cert_uri.parse::<ndn_packet::Name>(),
            req.name.parse::<ndn_packet::Name>(),
        ) else {
            return deny(format!("{cert_uri:?} or {:?} is not an NDN name", req.name));
        };
        let own = self.ca_certificate().is_some_and(|ca| *ca.name == cert_name);
        let canonical = cert_name.to_string();
        // A certificate this CA issued: neither its own nor an earlier CA's
        // it serves.
        let issued_here =
            !own && !self.is_earlier_ca_key(&ndn_security::cert_name::key_name_of(&cert_name));
        let issued = issued_here
            .then(|| self.served_certs.get(&canonical))
            .flatten()
            .and_then(|wire| deserialize_cert(&wire));
        let (cert, earlier_cas) = match issued {
            Some(cert) => (cert, Vec::new()),
            None => match self.earlier_ca_certificate(&cert_name, params).await {
                Ok(found) => found,
                Err(reason) => return deny(reason),
            },
        };
        // The certificate renewed is `<key>/<issuer>/<version>`, or a
        // certificate an earlier release named after its key (`<key>`).
        if crate::context_update::key_name_of(&cert_name).as_ref() != Some(&key_name) {
            return deny(format!(
                "{cert_name} is not a certificate of {key_name}, the key this request certifies"
            ));
        }
        let same_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.public_key)
            .is_ok_and(|key| key == cert.public_key.as_ref());
        if !same_key {
            return deny(format!(
                "the request carries another public key than {cert_name}: renewal re-certifies \
                 the same key; a new key needs a new invite or an admin's approval"
            ));
        }
        if self.issued_under(&key_name).iter().any(|(_, revoked)| *revoked) {
            return deny(format!(
                "{key_name} is revoked at this CA, and a revoked key is never renewed: enroll a \
                 new key with a new invite"
            ));
        }
        if !cert.is_valid_now() {
            let iso = |ns| {
                let basic = ndn_security::iso8601::format_iso_basic(ns);
                format!("{}Z", String::from_utf8_lossy(&basic))
            };
            return deny(format!(
                "{cert_name} is not valid now (valid from {} until {}): renewal needs a current \
                 certificate, so an expired device needs a new invite",
                iso(cert.valid_from),
                iso(cert.valid_until)
            ));
        }
        let proven = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(proof) {
            Ok(sig) => {
                verify_possession(
                    &renewal_proof_message(request_id, &cert_name),
                    &sig,
                    &cert.public_key,
                )
                .await
            }
            Err(_) => false,
        };
        if !proven {
            return deny(format!(
                "the renewal proof does not verify under the key of {cert_name}"
            ));
        }
        self.serve_earlier_ca_certificates(earlier_cas);
        ChallengeOutcome::Approved {
            attestation: Some(crate::attestation::AttestationSet::single(
                crate::attestation::ChallengeAttestation::of_kind(RENEWAL_CHALLENGE)
                    .with_evidence("certificate", canonical.into()),
            )),
        }
    }

    /// The certificate `cert_name` a renewal names that this CA did not
    /// issue, taken when the CA [accepts earlier CAs'
    /// certificates](Self::accept_earlier_ca_certificates): the renewal
    /// carries it ([`CERTIFICATE_PARAM`](crate::renewal::CERTIFICATE_PARAM))
    /// with the issuer certificates of its chain
    /// ([`ISSUERS_PARAM`](crate::renewal::ISSUERS_PARAM)); it must be
    /// `cert_name`, issued by an earlier CA of this CA's identity, not revoked
    /// by its namespace's trust context, and chain to an anchor of that
    /// context under its schema — the walk refuses a revoked key on the way.
    /// Returns it with the earlier CA certificates (`(name URI, wire)`) its
    /// chain went through. `Err` is the reason to refuse.
    async fn earlier_ca_certificate(
        &self,
        cert_name: &ndn_packet::Name,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(Certificate, Vec<(String, Vec<u8>)>), String> {
        use crate::renewal::CERTIFICATE_PARAM;
        let not_issued = || {
            format!(
                "{cert_name} is not a certificate this CA issued: it renews only those; enroll \
                 with an invite instead"
            )
        };
        let (Some(keyring), Some(carried)) = (
            self.earlier_ca.get(),
            params.get(CERTIFICATE_PARAM).and_then(|v| v.as_str()),
        ) else {
            return Err(not_issued());
        };
        let data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(carried)
            .ok()
            .and_then(|wire| ndn_packet::Data::decode(bytes::Bytes::from(wire)).ok())
            .ok_or_else(|| {
                format!(
                    "the certificate the renewal carries ({CERTIFICATE_PARAM}) is not a Data packet"
                )
            })?;
        let cert = Certificate::decode(&data).map_err(|e| {
            format!("the certificate the renewal carries ({CERTIFICATE_PARAM}) is malformed: {e}")
        })?;
        if *cert.name != *cert_name {
            return Err(format!(
                "the renewal names {cert_name} but carries the certificate {}",
                cert.name
            ));
        }
        let issuer = cert.issuer.as_deref().map(ndn_security::cert_name::key_name_of);
        if !issuer.as_ref().is_some_and(|key| self.is_earlier_ca_key(key)) {
            return Err(format!(
                "{cert_name} is not a certificate this CA issued, nor one an earlier CA of its \
                 identity issued (its issuer is {}): it renews only those; enroll with an invite \
                 instead",
                issuer.map_or_else(|| "unnamed".to_string(), |key| key.to_string())
            ));
        }
        if keyring.context_for(cert_name).is_revoked(cert_name) {
            return Err(format!(
                "the trust context of its namespace revokes {cert_name}, and a revoked key is \
                 never renewed: enroll a new key with a new invite"
            ));
        }
        let no_chain = |why: String| {
            format!(
                "{cert_name} is not a certificate this CA issued, and it does not chain to the \
                 namespace root under this node's trust context: {why}"
            )
        };
        let validator = Validator::with_keyring(
            Arc::clone(keyring),
            Arc::new(CertCache::new()),
            None,
            EARLIER_CA_MAX_CHAIN,
        );
        for issuer in carried_issuers(params) {
            validator.cert_cache().insert(issuer);
        }
        let walked = match validator.validate_chain_cached(&data).await {
            // Only a certificate chain proves anything: a digest "signature"
            // validates whatever KeyLocator it names.
            (ValidationResult::Valid(safe), _) => match safe.trust_path() {
                ndn_security::safe_data::TrustPath::CertChain(walked) => walked.clone(),
                _ => return Err(no_chain("it is not signed by a certified key".into())),
            },
            (ValidationResult::Invalid(e), _) => return Err(no_chain(e.to_string())),
            (ValidationResult::Pending, missing) => {
                return Err(no_chain(format!(
                    "the renewal does not carry the certificate of {}, on its chain",
                    missing.map_or_else(|| "an issuer".to_string(), |name| name.to_string())
                )));
            }
        };
        // The KeyLocators the walk resolved, each to the newest valid
        // certificate of its key the renewal carried: those of earlier CAs.
        let earlier_cas = walked
            .iter()
            .filter(|locator| {
                self.is_earlier_ca_key(&ndn_security::cert_name::key_name_of(locator))
            })
            .filter_map(|locator| validator.cert_cache().get_valid(locator))
            .map(|ca| (ca.name.to_string(), serialize_cert(&ca)))
            .collect();
        Ok((cert, earlier_cas))
    }

    /// Serve `certs` — earlier CA certificates (`(name URI, wire)`) a
    /// renewal's chain went through — on cert-fetch from now on, written
    /// through the store as issued certificates are, so a restart keeps
    /// serving them. One already served is left as it is. A failed write is
    /// logged, and the certificate served until the CA stops: the renewal
    /// it proved does not depend on it.
    fn serve_earlier_ca_certificates(&self, certs: Vec<(String, Vec<u8>)>) {
        for (name, wire) in certs {
            if self.served_certs.contains_key(&name) {
                continue;
            }
            if let Some(store) = &self.store
                && let Err(e) = store.record_issued(&name, &wire)
            {
                tracing::warn!(
                    certificate = %name, error = %e,
                    "CA could not persist an earlier CA's certificate; it is served until restart"
                );
            }
            tracing::info!(
                certificate = %name,
                "CA serves an earlier CA's certificate of a renewed certificate's chain"
            );
            self.served_certs.insert(name, wire);
        }
    }

    /// Wire of the issued cert named exactly `cert_name` for cert-fetch;
    /// `None` once it (or its key) is revoked.
    pub fn get_served_cert(&self, cert_name: &str) -> Option<Vec<u8>> {
        if self.is_revoked(cert_name) {
            return None;
        }
        self.served_certs.get(cert_name).map(|r| r.clone())
    }

    /// Wire of the certificate a `CanBePrefix` cert-fetch for `prefix` (a key
    /// name, or a certificate name) is answered with: among the unrevoked
    /// certificates this CA serves under `prefix`, the newest one valid now
    /// (latest `valid_from`, then the later name). `None` when none is valid.
    pub fn served_cert_under(&self, prefix: &ndn_packet::Name) -> Option<Vec<u8>> {
        self.served_certs
            .iter()
            .filter(|e| !self.is_revoked(e.key()))
            .filter(|e| e.key().parse::<ndn_packet::Name>().is_ok_and(|n| n.has_prefix(prefix)))
            .filter_map(|e| Some((deserialize_cert(e.value())?, e.value().clone())))
            .filter(|(cert, _)| cert.is_valid_now())
            .max_by(|(a, _), (b, _)| (a.valid_from, &a.name).cmp(&(b.valid_from, &b.name)))
            .map(|(_, wire)| wire)
    }

    /// The certificate answering a cert-fetch Interest for `name`: with
    /// `can_be_prefix`, [`served_cert_under`](Self::served_cert_under) (a key
    /// name finds the key's newest valid certificate); without, exactly the
    /// certificate `name` ([`get_served_cert`](Self::get_served_cert)).
    pub fn cert_for_interest(&self, name: &ndn_packet::Name, can_be_prefix: bool) -> Option<Vec<u8>> {
        if can_be_prefix {
            self.served_cert_under(name)
        } else {
            self.get_served_cert(&name.to_string())
        }
    }

    /// The key the CA signs with: [`CaConfig::signing_key`] when set, else
    /// the manager's first trust anchor.
    pub fn signing_key_name(&self) -> Option<ndn_packet::Name> {
        match &self.config.signing_key {
            Some(key) => Some(key.clone()),
            None => self
                .manager
                .trust_anchor_names()
                .into_iter()
                .next()
                .map(|n| (*n).clone()),
        }
    }

    /// The certificate of [`signing_key_name`](Self::signing_key_name): from
    /// the manager's cert cache (a CA cert issued by a root) or its trust
    /// anchors (a self-signed CA).
    pub fn ca_certificate(&self) -> Option<Certificate> {
        let key = self.signing_key_name()?;
        let key = Arc::new(key);
        self.manager
            .cert_cache()
            .get(&key)
            .or_else(|| self.manager.trust_anchor(&key))
    }

    /// CA signing key + KeyLocator name for response Data (NDNCERT v0.3 §4.1
    /// requires every CA→requester Data be signed by the CA's identity key).
    /// `None` means the signing key or its certificate is not provisioned and
    /// the CA cannot issue.
    pub fn response_signer(&self) -> Option<(std::sync::Arc<dyn Signer>, ndn_packet::Name)> {
        let key_name = self.signing_key_name()?;
        let signer = self.manager.get_signer_sync(&key_name).ok()?;
        let cert = self.ca_certificate()?;
        Some((signer, (*cert.name).clone()))
    }

    pub fn handle_info(&self) -> Vec<u8> {
        let ca_certificate = self
            .ca_certificate()
            .map(|cert| bytes::Bytes::from(serialize_cert(&cert)))
            .unwrap_or_else(|| {
                tracing::warn!(
                    "CA has no signing certificate configured; INFO response has empty ca_certificate"
                );
                bytes::Bytes::new()
            });

        let profile = CaProfileTlv {
            ca_prefix: self.config.prefix.to_string(),
            ca_info: self.config.info.clone(),
            ca_certificate,
            max_validity_secs: self.config.max_validity.as_secs(),
            challenges: self.offered_challenges(),
        };
        profile.encode().to_vec()
    }

    /// `/<ca-prefix>/CA/PROBE` — namespace policy check, no state created.
    pub fn handle_probe(&self, requested_name: &str) -> Vec<u8> {
        let result: Result<ndn_packet::Name, _> = requested_name.parse();
        let resp = match result {
            Err(_) => ProbeResponseTlv {
                allowed: false,
                reason: Some(format!("invalid NDN name: {requested_name}")),
                max_suffix_length: None,
            },
            Ok(name) => match self
                .config
                .policy
                .evaluate(&name, None, &self.config.prefix)
            {
                PolicyDecision::Allow => ProbeResponseTlv {
                    allowed: true,
                    reason: None,
                    max_suffix_length: None,
                },
                PolicyDecision::Deny(reason) => ProbeResponseTlv {
                    allowed: false,
                    reason: Some(reason),
                    max_suffix_length: None,
                },
            },
        };
        resp.encode().to_vec()
    }

    /// `/<ca-prefix>/CA/NEW`. NDNCERT v0.3 §3.1 — the NEW→CHALLENGE window is
    /// 60s; after that, each session lasts what its last CHALLENGE answer
    /// advertised.
    pub async fn handle_new(&self, body: &[u8]) -> Result<Vec<u8>, CertError> {
        self.cleanup_expired();

        let new_req = NewRequestTlv::decode(bytes::Bytes::copy_from_slice(body))?;

        let cert_data = ndn_packet::Data::decode(new_req.cert_request).map_err(|_| {
            CertError::InvalidRequest(
                "cert_request is not a valid NDN Data packet (expected self-signed Certificate)"
                    .into(),
            )
        })?;
        let client_cert = Certificate::decode(&cert_data).map_err(|_| {
            CertError::InvalidRequest("cert_request does not decode as NDN Certificate".into())
        })?;

        // Cert name is `<identity>/KEY/<key-id>/cert-request/<version>`;
        // strip the trailing issuer-id + version to recover the key name.
        let cert_name_comps = client_cert.name.components();
        let key_name = if cert_name_comps.len() >= 2 {
            ndn_packet::Name::from_components(
                cert_name_comps[..cert_name_comps.len() - 2].iter().cloned(),
            )
        } else {
            (*client_cert.name).clone()
        };

        match self
            .config
            .policy
            .evaluate(&key_name, None, &self.config.prefix)
        {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => return Err(CertError::PolicyDenied(reason)),
        }

        if self.config.challenges.is_empty() {
            return Err(CertError::InvalidRequest(
                "CA has no challenge handlers".to_string(),
            ));
        }

        let public_key =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&client_cert.public_key);

        let not_before = client_cert.valid_from / 1_000_000;
        let not_after = client_cert.valid_until / 1_000_000;

        let req = CertRequest {
            name: key_name.to_string(),
            public_key,
            not_before,
            not_after,
        };

        let ca_kp = EcdhKeypair::generate();
        let ca_pub_bytes = ca_kp.public_key_bytes();
        let salt = EcdhKeypair::random_salt()?;
        let request_id_bytes = generate_request_id_bytes()?;

        let session_key = ca_kp.derive_session_key(&new_req.ecdh_pub, &salt, &request_id_bytes)?;

        let request_id_hex = bytes_to_hex(&request_id_bytes);

        self.pending.insert(
            request_id_hex,
            PendingRequest {
                cert_request: req,
                challenge_state: None,
                challenge_type: None,
                expires_at: now_secs() + NEW_TO_CHALLENGE_SECS,
                session_key,
                request_id_bytes,
                encryption_iv: new_encryption_iv()?,
                decryption_iv: None,
            },
        );

        let resp = NewResponseTlv {
            ecdh_pub: bytes::Bytes::from(ca_pub_bytes),
            salt,
            request_id: request_id_bytes,
            challenges: self.offered_challenges(),
        };
        Ok(resp.encode().to_vec())
    }

    /// `/<ca-prefix>/CA/CHALLENGE/<request_id>`. Body and response are
    /// AES-GCM-128 envelopes (NDNCERT v0.3 §3.2).
    pub async fn handle_challenge(
        &self,
        request_id: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, CertError> {
        let (
            cert_request,
            existing_state,
            existing_type,
            session_key,
            request_id_bytes,
            mut enc_iv,
            dec_iv,
        ) = {
            let pending = self
                .pending
                .get(request_id)
                .ok_or_else(|| CertError::RequestNotFound(request_id.to_string()))?;
            (
                pending.cert_request.clone(),
                pending.challenge_state.clone(),
                pending.challenge_type.clone(),
                pending.session_key.clone(),
                pending.request_id_bytes,
                pending.encryption_iv,
                pending.decryption_iv,
            )
        };

        let mut dec_iv_state = dec_iv;
        let plaintext = session_key.open_envelope(body, &request_id_bytes, &mut dec_iv_state)?;

        let (challenge_type, parameters) = decode_challenge_plaintext(&plaintext)?;

        if let Some(ref locked_type) = existing_type
            && locked_type != &challenge_type
        {
            return Err(CertError::CaFailure {
                code: ErrorCode::InvalidParameters.into(),
                info: format!("challenge type locked to '{locked_type}' for this request"),
            });
        }

        // The CA's built-in renewal, when its issuance policy renews; any
        // other type goes to the configured handler of that type.
        let renewal = challenge_type == crate::renewal::RENEWAL_CHALLENGE
            && self.config.issuance.offers_renewal();
        let handler = if renewal {
            None
        } else {
            Some(
                self.config
                    .challenges
                    .iter()
                    .find(|h| h.challenge_type() == challenge_type)
                    .ok_or_else(|| CertError::CaFailure {
                        code: ErrorCode::InvalidParameters.into(),
                        info: format!("unsupported challenge type: {challenge_type}"),
                    })?,
            )
        };

        // Reserve the identity first, so that of two concurrent requests for
        // one single-key identity the loser is refused here, before its
        // challenge runs, instead of after redeeming a one-time token. Held
        // until this step ends (past issuance).
        let _reservation = match self.reserve_identity(&cert_request) {
            Ok(r) => r,
            Err(identity) => {
                self.pending.remove(request_id);
                let response = refused(
                    ErrorCode::NameNotAllowed,
                    format!(
                        "another request for {identity} is being certified right now; refused \
                         before the `{challenge_type}` challenge ran, so nothing was redeemed"
                    ),
                );
                return session_key.seal_envelope(
                    &response.encode(),
                    &request_id_bytes,
                    &mut enc_iv,
                );
            }
        };

        // A request the single-key rule refuses whatever this challenge
        // proves is refused before the challenge runs, so it spends nothing:
        // a one-time token stays redeemable under another name.
        if let Some((rule, held)) = self.identity_taken(&cert_request)
            && !handler.is_some_and(|h| h.can_attest(rule.unless_attested))
        {
            self.pending.remove(request_id);
            let response = refused(
                ErrorCode::NameNotAllowed,
                identity_taken_reason(
                    &rule,
                    &held,
                    &format!(
                        "refused before the `{challenge_type}` challenge ran, so nothing was \
                         redeemed"
                    ),
                ),
            );
            return session_key.seal_envelope(&response.encode(), &request_id_bytes, &mut enc_iv);
        }

        let outcome = match handler {
            Some(handler) => {
                let state = match existing_state {
                    Some(s) => s,
                    None => {
                        let s = handler.begin(&cert_request).await?;
                        if let Some(mut entry) = self.pending.get_mut(request_id) {
                            entry.challenge_state = Some(s.clone());
                            entry.challenge_type = Some(challenge_type.clone());
                        }
                        s
                    }
                };
                handler.verify(&state, &parameters).await?
            }
            None => {
                self.verify_renewal(request_id, &cert_request, &parameters)
                    .await
            }
        };

        let response = match outcome {
            ChallengeOutcome::Denied(reason) => {
                self.pending.remove(request_id);
                ChallengeResponseTlv {
                    status: STATUS_FAILURE,
                    error_code: Some(7),
                    error_info: Some(reason),
                    ..Default::default()
                }
            }

            ChallengeOutcome::Expired(reason) => {
                self.pending.remove(request_id);
                refused(ErrorCode::RunOutOfTime, reason)
            }

            ChallengeOutcome::Pending {
                status_message,
                remaining_tries,
                remaining_time_secs,
                next_state,
            } => {
                let parameters = handler
                    .map(|h| h.pending_parameters(&next_state))
                    .unwrap_or_default();
                if let Some(mut entry) = self.pending.get_mut(request_id) {
                    entry.challenge_state = Some(next_state);
                    entry.decryption_iv = dec_iv_state;
                    entry.expires_at = now_secs() + u64::from(remaining_time_secs);
                }
                ChallengeResponseTlv {
                    status: STATUS_PENDING,
                    challenge_status: Some(status_message),
                    remaining_tries: Some(remaining_tries),
                    remaining_time_secs: Some(remaining_time_secs),
                    parameters,
                    ..Default::default()
                }
            }

            ChallengeOutcome::Approved { attestation } => {
                let (_, pending) = self
                    .pending
                    .remove(request_id)
                    .ok_or_else(|| CertError::RequestNotFound(request_id.to_string()))?;
                enc_iv = pending.encryption_iv;

                // The attestation the handler produced (a kind-only leaf when
                // it supplied none), stamped now. It is visible to the
                // IssuancePolicy regardless of `emit_attestations`, and embedded
                // in the cert only when emission is enabled.
                let mut attestation_set = attestation.unwrap_or_else(|| {
                    crate::attestation::AttestationSet::single(
                        crate::attestation::ChallengeAttestation::of_kind(&challenge_type),
                    )
                });
                attestation_set.stamp(now_secs());

                let issuance_ctx = IssuanceContext {
                    cert_request: &pending.cert_request,
                    challenge_type: &challenge_type,
                    attestation: Some(&attestation_set),
                    ca_prefix: &self.config.prefix,
                    default_validity: self.config.default_validity,
                    max_validity: self.config.max_validity,
                };
                match self.config.issuance.decide(&issuance_ctx) {
                    IssuanceDecision::Issue { validity } => {
                        // Check and record under one lock: of two requests
                        // for one identity, only the first is certified.
                        let _issuing = self.issuing.lock().await;
                        match self.identity_taken(&pending.cert_request) {
                            Some((rule, held))
                                if !attested(&issuance_ctx, rule.unless_attested) =>
                            {
                                refused(
                                    ErrorCode::NameNotAllowed,
                                    identity_taken_reason(
                                        &rule,
                                        &held,
                                        &format!(
                                            "the `{challenge_type}` challenge was met first, so \
                                             a one-time token it used is spent"
                                        ),
                                    ),
                                )
                            }
                            _ => {
                                self.issue(&pending.cert_request, validity, &attestation_set)
                                    .await?
                            }
                        }
                    }
                    IssuanceDecision::Deny(reason) => ChallengeResponseTlv {
                        status: STATUS_FAILURE,
                        // NDNCERT v0.3 has no distinct code for post-challenge
                        // policy denial; OutOfTries (7) is the closest match.
                        error_code: Some(7),
                        error_info: Some(reason),
                        ..Default::default()
                    },
                }
            }
        };

        let response_plaintext = response.encode();
        let encrypted =
            session_key.seal_envelope(&response_plaintext, &request_id_bytes, &mut enc_iv)?;

        if response.status == STATUS_PENDING
            && let Some(mut entry) = self.pending.get_mut(request_id)
        {
            entry.encryption_iv = enc_iv;
        }

        Ok(encrypted)
    }

    /// `/<ca-prefix>/CA/REVOKE`.
    pub async fn handle_revoke(&self, body: &[u8]) -> Vec<u8> {
        let status = self.do_revoke(body).await;
        RevokeResponseTlv {
            status,
            reason: None,
        }
        .encode()
        .to_vec()
    }

    /// Only certificates this CA issued (those it serves on cert-fetch, its
    /// own and earlier CAs' certificates excepted) can be revoked. The
    /// request's possession proof — a signature over the cert name — must
    /// verify under that cert's own key (its holder revokes it) or under the
    /// CA's signing key (the CA revokes any cert it issued); any other key is
    /// refused.
    async fn do_revoke(&self, body: &[u8]) -> u8 {
        let req = match RevokeRequestTlv::decode(bytes::Bytes::copy_from_slice(body)) {
            Ok(r) => r,
            Err(_) => return REVOKE_STATUS_UNAUTHORIZED,
        };

        let cert_name: ndn_packet::Name = match req.cert_name.parse() {
            Ok(n) => n,
            Err(_) => return REVOKE_STATUS_NOT_FOUND,
        };
        let own_key = self.signing_key_name();
        let key = ndn_security::cert_name::key_name_of(&cert_name);
        if own_key
            .as_ref()
            .is_some_and(|own| *own == key || is_other_key_of_identity(own, &key))
        {
            return REVOKE_STATUS_NOT_FOUND;
        }
        // Canonical URI: the key `served_certs`, `revoked` and the store use.
        // The request names one certificate, or a key: then any certificate
        // this CA issued for it (revoking one revokes the key).
        let cert_uri = cert_name.to_string();
        let Some(cert) = self
            .served_certs
            .get(&cert_uri)
            .and_then(|wire| deserialize_cert(&wire))
            .or_else(|| {
                self.served_certs.iter().find_map(|e| {
                    let cert = deserialize_cert(e.value())?;
                    ndn_security::cert_name::is_cert_of(&cert.name, &cert_name).then_some(cert)
                })
            })
        else {
            return REVOKE_STATUS_NOT_FOUND;
        };
        let (cert_uri, cert_name) = (cert.name.to_string(), (*cert.name).clone());

        // The proof signs the cert name exactly as the requester sent it.
        let signed = req.cert_name.as_bytes();
        let authorized = verify_possession(signed, &req.signature, &cert.public_key).await
            || match self.ca_certificate() {
                Some(ca) => verify_possession(signed, &req.signature, &ca.public_key).await,
                None => false,
            };
        if !authorized {
            return REVOKE_STATUS_UNAUTHORIZED;
        }

        if let Err(e) = self.mark_revoked(cert_uri, &cert_name) {
            tracing::error!(
                cert = %cert_name, error = %e,
                "CA could not persist revocation; it will be lost on restart"
            );
        }
        REVOKE_STATUS_REVOKED
    }

    /// Revoke `cert_name` (canonical URI `cert_uri`): refused on cert-fetch
    /// from now on, and no longer holding its identity under a single-key
    /// rule. Applied in memory even if the store write fails — the CA must
    /// refuse the cert now; the error says a restart would forget it.
    fn mark_revoked(&self, cert_uri: String, cert_name: &ndn_packet::Name) -> Result<(), CertError> {
        let persisted = match &self.store {
            Some(store) if !self.revoked.contains(&cert_uri) => store.record_revoked(&cert_uri),
            _ => Ok(()),
        };
        self.insert_revoked(cert_uri);
        // Every certificate of the key leaves the cache with it.
        self.manager
            .cert_cache()
            .remove(&ndn_security::cert_name::key_name_of(cert_name));
        persisted
    }

    /// The certificates this CA issued under `prefix` (an identity, a key
    /// name or a certificate name), its own and earlier CAs' certificates
    /// excepted, each with whether it is revoked (itself or through its key).
    pub fn issued_under(&self, prefix: &ndn_packet::Name) -> Vec<(ndn_packet::Name, bool)> {
        let own = self.signing_key_name();
        let mut issued: Vec<_> = self
            .served_certs
            .iter()
            .filter_map(|entry| {
                let name: ndn_packet::Name = entry.key().parse().ok()?;
                let key = ndn_security::cert_name::key_name_of(&name);
                let ca_cert = own
                    .as_ref()
                    .is_some_and(|own| *own == key || is_other_key_of_identity(own, &key));
                (name.has_prefix(prefix) && !ca_cert).then(|| (name, self.is_revoked(entry.key())))
            })
            .collect();
        issued.sort_by_key(|(name, _)| name.to_string());
        issued
    }

    /// Revoke, as this CA's operator, every certificate it issued under
    /// `prefix` — a key name covers each certificate of that key. No
    /// possession proof: this is the CA host's own administration (its
    /// local management socket decides who may ask), not the network
    /// `REVOKE` endpoint. Afterwards the CA no longer serves those
    /// certificates, and a single-key identity they held is free for a new
    /// key. Already revoked certificates are skipped.
    pub fn revoke_issued_under(&self, prefix: &ndn_packet::Name) -> CaRevocation {
        let mut outcome = CaRevocation::default();
        for (name, already) in self.issued_under(prefix) {
            if already {
                continue;
            }
            if let Err(e) = self.mark_revoked(name.to_string(), &name) {
                outcome.not_persisted.get_or_insert(e);
            }
            outcome.revoked.push(name);
        }
        outcome
    }

    /// Follow `ctx`, a version of a trust context the device running this
    /// CA holds now: when this is the CA of its namespace (identity
    /// `<ns>/CA`), stop serving every certificate it issued that `ctx`
    /// revokes, and record that in the store. Idempotent: certificates
    /// revoked already are skipped, so following the same version again
    /// changes nothing. `None` when this is not the CA of `ctx`'s namespace.
    pub fn follow_context(&self, ctx: &ndn_security::SignedTrustContext) -> Option<CaRevocation> {
        let ca_identity = ctx.namespace().clone().append("CA");
        let key = self.signing_key_name()?;
        if !(key.has_prefix(&ca_identity) && key.len() == ca_identity.len() + 2) {
            return None;
        }
        let mut followed = CaRevocation::default();
        for revoked in ctx.revocations() {
            let out = self.revoke_issued_under(revoked);
            followed.revoked.extend(out.revoked);
            if followed.not_persisted.is_none() {
                followed.not_persisted = out.not_persisted;
            }
        }
        if !followed.revoked.is_empty() {
            tracing::info!(
                target: "ca",
                namespace = %ctx.namespace(),
                version = ctx.version(),
                revoked = ?followed.revoked.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "the trust context revokes certificates this CA issued: no longer served, and \
                 their device names are free for a new key"
            );
        }
        if let Some(e) = &followed.not_persisted {
            tracing::warn!(
                target: "ca",
                namespace = %ctx.namespace(),
                version = ctx.version(),
                error = %e,
                "could not record a revocation in the CA store: it holds for this run, and the CA \
                 follows the stored trust context again at the next start"
            );
        }
        Some(followed)
    }

    /// Follow every trust context `keyring` holds ([`Self::follow_context`]):
    /// at the CA's start, for versions adopted while it did not run — one
    /// stored for the next start by a CLI that found no daemon, or a
    /// revocation its store could not record.
    pub fn follow_held(&self, keyring: &Keyring) {
        for ctx in keyring.contexts() {
            self.follow_context(&ctx);
        }
    }

    /// Mint, persist and serve the certificate for an approved request. It is
    /// named `<key>/NDNCERT/<version>` (NDN Certificate Format v2), so every
    /// certificate of a key — a renewal's included — has a name of its own and
    /// the requester fetches it by that name.
    async fn issue(
        &self,
        req: &CertRequest,
        validity: Duration,
        attestation_set: &crate::attestation::AttestationSet,
    ) -> Result<ChallengeResponseTlv, CertError> {
        let attestation_ad = if self.config.emit_attestations {
            attestation_set.encode_additional_description()
        } else {
            None
        };
        let cert = self
            .issue_certificate_with_validity(req, validity, attestation_ad.as_deref())
            .await?;
        let cert_name_str = cert.name.to_string();
        let cert_bytes = serialize_cert(&cert);

        // Persist before serving: a cert the CA cannot durably serve after a
        // restart is not issued.
        if let Some(store) = &self.store {
            store.record_issued(&cert_name_str, &cert_bytes)?;
        }
        self.served_certs.insert(cert_name_str.clone(), cert_bytes);

        Ok(ChallengeResponseTlv {
            status: STATUS_SUCCESS,
            issued_cert_name: Some(cert_name_str),
            ..Default::default()
        })
    }

    /// `policy_validity` is clamped to `max_validity` and the client's
    /// requested window (NDNCERT v0.3: `not_after <= min(now + max_validity,
    /// ca_cert.valid_until)`).
    async fn issue_certificate_with_validity(
        &self,
        req: &CertRequest,
        policy_validity: Duration,
        additional_description: Option<&[u8]>,
    ) -> Result<Certificate, CertError> {
        let subject_name: ndn_packet::Name = req
            .name
            .parse()
            .map_err(|_| CertError::Name(req.name.clone()))?;

        let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.public_key)
            .map_err(|_| CertError::InvalidRequest("invalid public key base64".to_string()))?;

        // A key with a revoked certificate is never certified again.
        if self.is_revoked(&req.name) {
            return Err(CertError::PolicyDenied(format!(
                "key {} has a revoked certificate",
                req.name
            )));
        }

        let ca_key_name = self.signing_key_name().ok_or_else(|| {
            CertError::InvalidRequest("CA has no signing key configured".to_string())
        })?;

        let max_validity_ms = self.config.max_validity.as_millis() as u64;
        let policy_ms = (policy_validity.as_millis() as u64).min(max_validity_ms);
        let requested_ms = req.not_after.saturating_sub(req.not_before);
        let validity_ms = if requested_ms > 0 {
            requested_ms.min(policy_ms)
        } else {
            policy_ms
        };

        let cert = self
            .manager
            .certify_as(
                &subject_name,
                bytes::Bytes::from(public_key),
                &ca_key_name,
                validity_ms,
                ndn_security::cert_name::NDNCERT_ISSUER,
                additional_description,
            )
            .await
            .map_err(CertError::Security)?;

        Ok(cert)
    }
}

/// Encode an issued certificate as an NDN `Data` TLV (Certificate Format v2).
/// Returns an empty `Vec` if the cert lacks wire bytes
/// (`signed_region` / `sig_value`).
pub fn serialize_cert(cert: &Certificate) -> Vec<u8> {
    use ndn_packet::tlv_type;
    use ndn_tlv::TlvWriter;
    match (&cert.signed_region, &cert.sig_value) {
        (Some(signed_region), Some(sig_value)) => {
            let mut w = TlvWriter::new();
            w.write_nested(tlv_type::DATA, |w| {
                w.write_raw(signed_region);
                w.write_tlv(tlv_type::SIGNATURE_VALUE, sig_value);
            });
            w.finish().to_vec()
        }
        _ => {
            tracing::warn!(
                "serialize_cert called on a cert with no wire bytes; \
                 returning empty (signed_region/sig_value missing)"
            );
            Vec::new()
        }
    }
}

/// Parses NDN `Data` wire bytes into a Certificate Format v2 cert.
pub fn deserialize_cert(data: &[u8]) -> Option<Certificate> {
    let bytes = bytes::Bytes::copy_from_slice(data);
    let parsed = ndn_packet::Data::decode(bytes).ok()?;
    Certificate::decode(&parsed).ok()
}

/// Whether `signature` over `message` verifies under `public_key`, an
/// Ed25519 or ECDSA-P256 certificate key (the algorithms NDN identities here
/// are minted with); a key of the other algorithm simply fails to verify.
async fn verify_possession(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    use ndn_packet::SignatureType;
    use ndn_security::{VerifyOutcome, verifier::verify_by_sig_type};
    for sig_type in [
        SignatureType::SignatureEd25519,
        SignatureType::SignatureSha256WithEcdsa,
    ] {
        if let Ok(VerifyOutcome::Valid) =
            verify_by_sig_type(sig_type, message, signature, public_key).await
        {
            return true;
        }
    }
    false
}

/// The NDNCERT 0.3 NEW → CHALLENGE window (§3.1), in seconds.
const NEW_TO_CHALLENGE_SECS: u64 = 60;

/// The longest chain an earlier CA's certificate is walked along to an
/// anchor, and the most issuer certificates taken from a renewal.
const EARLIER_CA_MAX_CHAIN: usize = 8;

/// The issuer certificates a renewal carries
/// ([`ISSUERS_PARAM`](crate::renewal::ISSUERS_PARAM)): a JSON array of
/// base64url (no padding) certificate Data wires, which arrives as JSON text
/// (every non-string CHALLENGE parameter does). Entries that do not decode
/// are skipped.
fn carried_issuers(params: &serde_json::Map<String, serde_json::Value>) -> Vec<Certificate> {
    let parsed: Vec<serde_json::Value>;
    let entries: &[serde_json::Value] = match params.get(crate::renewal::ISSUERS_PARAM) {
        Some(serde_json::Value::Array(entries)) => entries,
        Some(serde_json::Value::String(text)) => {
            parsed = serde_json::from_str(text).unwrap_or_default();
            &parsed
        }
        _ => &[],
    };
    entries
        .iter()
        .filter_map(serde_json::Value::as_str)
        .take(EARLIER_CA_MAX_CHAIN)
        .filter_map(|entry| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(entry)
                .ok()
        })
        .filter_map(|wire| deserialize_cert(&wire))
        .collect()
}

/// Whether `key` is another key of the identity `own` is a key of: `own` is
/// `<identity>/KEY/<id>`, `key` is `<identity>/KEY/<other id>`.
fn is_other_key_of_identity(own: &ndn_packet::Name, key: &ndn_packet::Name) -> bool {
    let (mine, theirs) = (own.components(), key.components());
    let n = mine.len();
    n >= 2
        && theirs.len() == n
        && mine[n - 2].typ == ndn_packet::tlv_type::NAME_COMPONENT
        && mine[n - 2].value.as_ref() == b"KEY"
        && mine[..n - 1] == theirs[..n - 1]
        && mine[n - 1] != theirs[n - 1]
}

fn generate_request_id_bytes() -> Result<[u8; 8], CertError> {
    let mut bytes = [0u8; 8];
    crate::ecdh::fill_random(&mut bytes)?;
    Ok(bytes)
}

/// What [`CaState::revoke_issued_under`] revoked.
#[derive(Debug, Default)]
pub struct CaRevocation {
    /// Certificates newly revoked (refused on cert-fetch from now on).
    pub revoked: Vec<ndn_packet::Name>,
    /// The first store write that failed: those revocations hold in memory
    /// only, until the CA restarts.
    pub not_persisted: Option<CertError>,
}

/// A single-key identity reserved by a running challenge; released on drop.
struct InFlight<'a> {
    set: &'a DashSet<String>,
    identity: String,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.set.remove(&self.identity);
    }
}

/// A CHALLENGE response refusing the request with `code` and `reason`.
fn refused(code: ErrorCode, reason: String) -> ChallengeResponseTlv {
    ChallengeResponseTlv {
        status: STATUS_FAILURE,
        error_code: Some(code.into()),
        error_info: Some(reason),
        ..Default::default()
    }
}

/// Why a key is not certified under `rule.identity`, which `held` certifies
/// for another key; `outcome` says what became of the request's challenge.
fn identity_taken_reason(rule: &SingleKeyIdentity, held: &Certificate, outcome: &str) -> String {
    let until = ndn_security::iso8601::format_iso_basic(held.valid_until);
    format!(
        "{} is already certified to another key ({}, valid until {}Z, not revoked); this CA \
         certifies a new key under it only once that certificate is revoked, or when an admin \
         approves the new key (the {} challenge); {outcome}",
        rule.identity,
        held.name,
        String::from_utf8_lossy(&until),
        rule.unless_attested,
    )
}

fn bytes_to_hex(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
