//! NDNCERT CA-side processor. Transport-agnostic; the Producer wiring lives
//! in `ndn-identity`. In-flight session state lives in [`DashMap`]; issued
//! certs and revocations are written through an optional
//! [`CaStore`](crate::store::CaStore) so they survive restarts.

use std::{sync::Arc, time::Duration};

use web_time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use dashmap::{DashMap, DashSet};
use ndn_security::{Certificate, SecurityManager, Signer};

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
    created_at: u64,
    session_key: SessionKey,
    request_id_bytes: [u8; 8],
    encryption_iv: [u8; 12],
    decryption_iv: Option<[u8; 12]>,
}

pub struct CaState {
    config: CaConfig,
    manager: Arc<SecurityManager>,
    pending: DashMap<String, PendingRequest>,
    revoked: DashSet<String>,
    /// Issued cert wire bytes, served on the cert-fetch Interest.
    served_certs: DashMap<String, Vec<u8>>,
    /// Durable backing for `served_certs` / `revoked`; `None` keeps both
    /// in memory only.
    store: Option<Arc<dyn CaStore>>,
    /// Held from the single-key check to recording the issued cert, so two
    /// requests for one identity cannot both pass the check.
    issuing: tokio::sync::Mutex<()>,
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
            served_certs: DashMap::new(),
            store: None,
            issuing: tokio::sync::Mutex::new(()),
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
            state.revoked.insert(name);
        }
        state.store = Some(store);
        Ok(state)
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

    pub fn cleanup_expired(&self, ttl_secs: u64) {
        let cutoff = now_secs().saturating_sub(ttl_secs);
        self.pending.retain(|_, v| v.created_at >= cutoff);
    }

    pub fn is_revoked(&self, cert_name: &str) -> bool {
        self.revoked.contains(cert_name)
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

    /// Wire of an issued cert for cert-fetch; `None` once it is revoked.
    pub fn get_served_cert(&self, cert_name: &str) -> Option<Vec<u8>> {
        if self.is_revoked(cert_name) {
            return None;
        }
        self.served_certs.get(cert_name).map(|r| r.clone())
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
            challenges: self
                .config
                .challenges
                .iter()
                .map(|c| c.challenge_type().to_string())
                .collect(),
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

    /// `/<ca-prefix>/CA/NEW`. NDNCERT v0.3 §3.1 — the NEW→CHALLENGE window is 60s.
    pub async fn handle_new(&self, body: &[u8]) -> Result<Vec<u8>, CertError> {
        self.cleanup_expired(60);

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
        let salt = EcdhKeypair::random_salt();
        let request_id_bytes = generate_request_id_bytes();

        let session_key = ca_kp.derive_session_key(&new_req.ecdh_pub, &salt, &request_id_bytes)?;

        let request_id_hex = bytes_to_hex(&request_id_bytes);

        self.pending.insert(
            request_id_hex,
            PendingRequest {
                cert_request: req,
                challenge_state: None,
                challenge_type: None,
                created_at: now_secs(),
                session_key,
                request_id_bytes,
                encryption_iv: new_encryption_iv(),
                decryption_iv: None,
            },
        );

        let resp = NewResponseTlv {
            ecdh_pub: bytes::Bytes::from(ca_pub_bytes),
            salt,
            request_id: request_id_bytes,
            challenges: self
                .config
                .challenges
                .iter()
                .map(|c| c.challenge_type().to_string())
                .collect(),
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
            return Err(CertError::InvalidRequest(format!(
                "challenge type locked to '{locked_type}' for this request"
            )));
        }

        let handler = self
            .config
            .challenges
            .iter()
            .find(|h| h.challenge_type() == challenge_type)
            .ok_or_else(|| {
                CertError::InvalidRequest(format!("unsupported challenge type: {challenge_type}"))
            })?;

        // A request the single-key rule refuses whatever this challenge
        // proves is refused before the challenge runs, so it spends nothing:
        // a one-time token stays redeemable under another name.
        if let Some((rule, held)) = self.identity_taken(&cert_request)
            && !handler.can_attest(rule.unless_attested)
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

        let outcome = handler.verify(&state, &parameters).await?;

        let response = match outcome {
            ChallengeOutcome::Denied(reason) => {
                self.pending.remove(request_id);
                ChallengeResponseTlv {
                    status: STATUS_FAILURE,
                    challenge_status: None,
                    remaining_tries: None,
                    remaining_time_secs: None,
                    issued_cert_name: None,
                    error_code: Some(7),
                    error_info: Some(reason),
                }
            }

            ChallengeOutcome::Pending {
                status_message,
                remaining_tries,
                remaining_time_secs,
                next_state,
            } => {
                if let Some(mut entry) = self.pending.get_mut(request_id) {
                    entry.challenge_state = Some(next_state);
                    entry.decryption_iv = dec_iv_state;
                }
                ChallengeResponseTlv {
                    status: STATUS_PENDING,
                    challenge_status: Some(status_message),
                    remaining_tries: Some(remaining_tries),
                    remaining_time_secs: Some(remaining_time_secs),
                    issued_cert_name: None,
                    error_code: None,
                    error_info: None,
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
                        challenge_status: None,
                        remaining_tries: None,
                        remaining_time_secs: None,
                        issued_cert_name: None,
                        // NDNCERT v0.3 has no distinct code for post-challenge
                        // policy denial; OutOfTries (7) is the closest match.
                        error_code: Some(7),
                        error_info: Some(reason),
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
    /// own cert excepted) can be revoked. The request's possession proof —
    /// a signature over the cert name — must verify under that cert's own
    /// key (its holder revokes it) or under the CA's signing key (the CA
    /// revokes any cert it issued); any other key is refused.
    async fn do_revoke(&self, body: &[u8]) -> u8 {
        let req = match RevokeRequestTlv::decode(bytes::Bytes::copy_from_slice(body)) {
            Ok(r) => r,
            Err(_) => return REVOKE_STATUS_UNAUTHORIZED,
        };

        let cert_name: ndn_packet::Name = match req.cert_name.parse() {
            Ok(n) => n,
            Err(_) => return REVOKE_STATUS_NOT_FOUND,
        };
        if self.signing_key_name().as_ref() == Some(&cert_name) {
            return REVOKE_STATUS_NOT_FOUND;
        }
        // Canonical URI: the key `served_certs`, `revoked` and the store use.
        let cert_uri = cert_name.to_string();
        let Some(cert) = self
            .served_certs
            .get(&cert_uri)
            .and_then(|wire| deserialize_cert(&wire))
        else {
            return REVOKE_STATUS_NOT_FOUND;
        };

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

        // Revoke in memory even if the write fails: the CA must refuse the
        // cert now; the error flags that a restart would forget it.
        if !self.is_revoked(&cert_uri)
            && let Some(store) = &self.store
            && let Err(e) = store.record_revoked(&cert_uri)
        {
            tracing::error!(
                cert = %cert_uri, error = %e,
                "CA could not persist revocation; it will be lost on restart"
            );
        }
        self.revoked.insert(cert_uri);
        self.manager.cert_cache().remove(&cert_name);
        REVOKE_STATUS_REVOKED
    }

    /// Mint, persist and serve the certificate for an approved request.
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
            challenge_status: None,
            remaining_tries: None,
            remaining_time_secs: None,
            issued_cert_name: Some(cert_name_str),
            error_code: None,
            error_info: None,
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

        if self.is_revoked(&req.name) {
            return Err(CertError::PolicyDenied(format!(
                "certificate {} has been revoked",
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
            .certify_with_additional_description(
                &subject_name,
                bytes::Bytes::from(public_key),
                &ca_key_name,
                validity_ms,
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

fn generate_request_id_bytes() -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    bytes
}

/// A CHALLENGE response refusing the request with `code` and `reason`.
fn refused(code: ErrorCode, reason: String) -> ChallengeResponseTlv {
    ChallengeResponseTlv {
        status: STATUS_FAILURE,
        challenge_status: None,
        remaining_tries: None,
        remaining_time_secs: None,
        issued_cert_name: None,
        error_code: Some(code.into()),
        error_info: Some(reason),
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
