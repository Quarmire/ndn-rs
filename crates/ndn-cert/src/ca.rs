//! NDNCERT CA-side processor. Transport-agnostic; the Producer wiring lives
//! in `ndn-identity`. All in-flight session state lives in [`DashMap`].

use std::{sync::Arc, time::Duration};

use web_time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use dashmap::{DashMap, DashSet};
use ndn_security::{Certificate, SecurityManager, Signer};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    ecdh::{EcdhKeypair, SessionKey, new_encryption_iv},
    error::CertError,
    policy::{
        AcceptAllIssuance, IssuanceContext, IssuanceDecision, IssuancePolicy, NamespacePolicy,
        PolicyDecision,
    },
    protocol::CertRequest,
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
        }
    }

    /// Enable embedding challenge attestations in issued certs (builder).
    pub fn emit_attestations(mut self, yes: bool) -> Self {
        self.emit_attestations = yes;
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
}

impl CaState {
    pub fn new(config: CaConfig, manager: Arc<SecurityManager>) -> Self {
        Self {
            config,
            manager,
            pending: DashMap::new(),
            revoked: DashSet::new(),
            served_certs: DashMap::new(),
        }
    }

    pub fn cleanup_expired(&self, ttl_secs: u64) {
        let cutoff = now_secs().saturating_sub(ttl_secs);
        self.pending.retain(|_, v| v.created_at >= cutoff);
    }

    pub fn is_revoked(&self, cert_name: &str) -> bool {
        self.revoked.contains(cert_name)
    }

    pub fn get_served_cert(&self, cert_name: &str) -> Option<Vec<u8>> {
        self.served_certs.get(cert_name).map(|r| r.clone())
    }

    /// CA signing key + KeyLocator name for response Data (NDNCERT v0.3 §4.1
    /// requires every CA→requester Data be signed by the CA's identity key).
    /// `None` means no anchor is provisioned and the CA cannot issue.
    pub fn response_signer(&self) -> Option<(std::sync::Arc<dyn Signer>, ndn_packet::Name)> {
        let key_name_arc = self.manager.trust_anchor_names().into_iter().next()?;
        let signer = self.manager.get_signer_sync(key_name_arc.as_ref()).ok()?;
        let cert = self.manager.trust_anchor(key_name_arc.as_ref())?;
        Some((signer, (*cert.name).clone()))
    }

    pub fn handle_info(&self) -> Vec<u8> {
        let ca_certificate = self
            .manager
            .trust_anchor_names()
            .first()
            .and_then(|name| self.manager.trust_anchor(name))
            .map(|cert| bytes::Bytes::from(serialize_cert(&cert)))
            .unwrap_or_else(|| {
                tracing::warn!(
                    "CA has no trust anchor configured; INFO response has empty ca_certificate"
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
                        let attestation_ad = if self.config.emit_attestations {
                            attestation_set.encode_additional_description()
                        } else {
                            None
                        };
                        let cert = self
                            .issue_certificate_with_validity(
                                &pending.cert_request,
                                validity,
                                attestation_ad.as_deref(),
                            )
                            .await?;
                        let cert_name_str = cert.name.to_string();
                        let cert_bytes = serialize_cert(&cert);

                        self.served_certs.insert(cert_name_str.clone(), cert_bytes);

                        ChallengeResponseTlv {
                            status: STATUS_SUCCESS,
                            challenge_status: None,
                            remaining_tries: None,
                            remaining_time_secs: None,
                            issued_cert_name: Some(cert_name_str),
                            error_code: None,
                            error_info: None,
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

    async fn do_revoke(&self, body: &[u8]) -> u8 {
        let req = match RevokeRequestTlv::decode(bytes::Bytes::copy_from_slice(body)) {
            Ok(r) => r,
            Err(_) => return REVOKE_STATUS_UNAUTHORIZED,
        };

        let cert_name_parsed: ndn_packet::Name = match req.cert_name.parse() {
            Ok(n) => n,
            Err(_) => return REVOKE_STATUS_NOT_FOUND,
        };

        let anchor = self.manager.trust_anchor(&cert_name_parsed);
        let public_key = match anchor {
            Some(c) => c.public_key,
            None => return REVOKE_STATUS_NOT_FOUND,
        };

        use ndn_security::{Ed25519Verifier, Verifier, VerifyOutcome};
        let outcome = Ed25519Verifier
            .verify(req.cert_name.as_bytes(), &req.signature, &public_key)
            .await;

        match outcome {
            Ok(VerifyOutcome::Valid) => {
                self.revoked.insert(req.cert_name);
                REVOKE_STATUS_REVOKED
            }
            _ => REVOKE_STATUS_UNAUTHORIZED,
        }
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

        let ca_key_names = self.manager.trust_anchor_names();
        let ca_key_name = ca_key_names.first().ok_or_else(|| {
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
                ca_key_name.as_ref(),
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

fn generate_request_id_bytes() -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let _ = getrandom::getrandom(&mut bytes);
    bytes
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
