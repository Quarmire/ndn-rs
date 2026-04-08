//! CA-side stateless logic for NDNCERT.
//!
//! [`CaState`] processes incoming protocol messages and returns responses.
//! It is deliberately stateless with respect to the network — all in-flight
//! requests are held in a [`DashMap`]. The network wiring (Producer) lives
//! in `ndn-identity`.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use dashmap::{DashMap, DashSet};
use ndn_security::{Certificate, SecurityManager};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    ecdh::{EcdhKeypair, SessionKey},
    error::CertError,
    policy::{NamespacePolicy, PolicyDecision},
    protocol::{
        CaProfile, CertRequest, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
    },
    tlv::{
        ChallengeResponseTlv, NewRequestTlv, NewResponseTlv, STATUS_FAILURE, STATUS_PENDING,
        STATUS_SUCCESS,
    },
};

/// Configuration for an NDNCERT CA.
pub struct CaConfig {
    /// NDN name prefix for this CA (e.g. `/com/acme/fleet/CA`).
    pub prefix: ndn_packet::Name,
    /// Human-readable description.
    pub info: String,
    /// Default certificate lifetime.
    pub default_validity: Duration,
    /// Maximum certificate lifetime the CA will issue.
    pub max_validity: Duration,
    /// Supported challenge handlers (first match wins on preference).
    pub challenges: Vec<Box<dyn ChallengeHandler>>,
    /// Namespace policy.
    pub policy: Box<dyn NamespacePolicy>,
}

/// In-flight enrollment request stored between NEW and CHALLENGE.
struct PendingRequest {
    cert_request: CertRequest,
    /// Challenge state — `None` until the first CHALLENGE request arrives.
    /// `begin()` is deferred so the client's chosen challenge type is used.
    challenge_state: Option<ChallengeState>,
    /// Challenge type selected by the client (set on first CHALLENGE).
    challenge_type: Option<String>,
    created_at: u64,
    /// AES-GCM-128 session key derived from ECDH + HKDF.
    session_key: SessionKey,
    /// 8-byte request identifier (raw bytes, used as HKDF info and AAD).
    request_id_bytes: [u8; 8],
}

/// The stateless CA processor.
///
/// Holds in-flight request state and the signing identity.
/// All methods take `&self` and are safe to call from concurrent tasks.
pub struct CaState {
    config: CaConfig,
    manager: Arc<SecurityManager>,
    pending: DashMap<String, PendingRequest>,
    /// Certificate names that have been revoked.
    revoked: DashSet<String>,
}

impl CaState {
    pub fn new(config: CaConfig, manager: Arc<SecurityManager>) -> Self {
        Self {
            config,
            manager,
            pending: DashMap::new(),
            revoked: DashSet::new(),
        }
    }

    /// Remove pending requests older than `ttl_secs`.
    ///
    /// Called lazily from [`handle_new`] to amortize cleanup cost.
    /// Per NDNCERT 0.3, the NEW→CHALLENGE window is 60 seconds.
    pub fn cleanup_expired(&self, ttl_secs: u64) {
        let cutoff = now_secs().saturating_sub(ttl_secs);
        self.pending.retain(|_, v| v.created_at >= cutoff);
    }

    /// Check whether a certificate name has been revoked.
    pub fn is_revoked(&self, cert_name: &str) -> bool {
        self.revoked.contains(cert_name)
    }

    /// Handle a CA INFO request — return the CA's profile.
    pub fn handle_info(&self) -> Vec<u8> {
        // Populate the CA's public key from the first registered trust anchor.
        let public_key = self
            .manager
            .trust_anchor_names()
            .first()
            .and_then(|name| self.manager.trust_anchor(name))
            .map(|cert| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cert.public_key)
            })
            .unwrap_or_else(|| {
                tracing::warn!(
                    "CA has no trust anchor configured; INFO response has empty public_key"
                );
                String::new()
            });

        let profile = CaProfile {
            ca_prefix: self.config.prefix.to_string(),
            ca_info: self.config.info.clone(),
            public_key,
            challenges: self
                .config
                .challenges
                .iter()
                .map(|c| c.challenge_type().to_string())
                .collect(),
            default_validity_secs: self.config.default_validity.as_secs(),
            max_validity_secs: self.config.max_validity.as_secs(),
        };
        serde_json::to_vec(&profile).unwrap_or_default()
    }

    /// Handle a PROBE request — check namespace policy without creating state.
    ///
    /// Route: `/<ca-prefix>/CA/PROBE`; requested name in ApplicationParameters.
    pub fn handle_probe(&self, requested_name: &str) -> Vec<u8> {
        let result: Result<ndn_packet::Name, _> = requested_name.parse();
        let resp = match result {
            Err(_) => ProbeResponse {
                allowed: false,
                reason: Some(format!("invalid NDN name: {requested_name}")),
                max_suffix_length: None,
            },
            Ok(name) => match self.config.policy.evaluate(&name, None, &self.config.prefix) {
                PolicyDecision::Allow => ProbeResponse {
                    allowed: true,
                    reason: None,
                    max_suffix_length: None,
                },
                PolicyDecision::Deny(reason) => ProbeResponse {
                    allowed: false,
                    reason: Some(reason),
                    max_suffix_length: None,
                },
            },
        };
        serde_json::to_vec(&resp).unwrap_or_default()
    }

    /// Handle a NEW request — validate, perform ECDH, store state, return challenges.
    ///
    /// Body: TLV-encoded [`NewRequestTlv`] (ECDH pub key + cert request bytes).
    /// Returns: TLV-encoded [`NewResponseTlv`] (CA ECDH pub key + salt + request_id + challenges).
    pub async fn handle_new(&self, body: &[u8]) -> Result<Vec<u8>, CertError> {
        // Amortized cleanup: remove requests that missed the 60-second window.
        self.cleanup_expired(60);

        // Decode TLV request.
        let new_req = NewRequestTlv::decode(bytes::Bytes::copy_from_slice(body))?;

        // Decode cert request from binary blob embedded in the TLV.
        let req = decode_cert_request_bytes(&new_req.cert_request)?;

        // Parse and policy-check the requested identity name.
        let name: ndn_packet::Name = req
            .name
            .parse()
            .map_err(|_| CertError::Name(format!("invalid name: {}", req.name)))?;

        match self.config.policy.evaluate(&name, None, &self.config.prefix) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => return Err(CertError::PolicyDenied(reason)),
        }

        if self.config.challenges.is_empty() {
            return Err(CertError::InvalidRequest(
                "CA has no challenge handlers".to_string(),
            ));
        }

        // ECDH key agreement: generate CA ephemeral keypair, derive session key.
        let ca_kp = EcdhKeypair::generate();
        let ca_pub_bytes = ca_kp.public_key_bytes();
        let salt = EcdhKeypair::random_salt();
        let request_id_bytes = generate_request_id_bytes();

        let session_key = ca_kp.derive_session_key(&new_req.ecdh_pub, &salt, &request_id_bytes)?;

        let request_id_hex = bytes_to_hex(&request_id_bytes);

        // Store pending request with session key.
        self.pending.insert(
            request_id_hex,
            PendingRequest {
                cert_request: req,
                challenge_state: None,
                challenge_type: None,
                created_at: now_secs(),
                session_key,
                request_id_bytes,
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

    /// Handle a CHALLENGE request — decrypt parameters, verify, issue or deny.
    ///
    /// Body: TLV-encoded [`ChallengeRequestTlv`] (encrypted challenge parameters).
    /// Returns: TLV-encoded [`ChallengeResponseTlv`].
    pub async fn handle_challenge(
        &self,
        request_id: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, CertError> {
        use crate::tlv::ChallengeRequestTlv;

        let chal_tlv = ChallengeRequestTlv::decode(bytes::Bytes::copy_from_slice(body))?;

        // Validate that the request_id in the TLV matches the Interest name component.
        let req_id_from_tlv = bytes_to_hex(&chal_tlv.request_id);
        if req_id_from_tlv != request_id {
            return Err(CertError::InvalidRequest(
                "request_id in TLV does not match Interest name".into(),
            ));
        }

        // Read current state without holding a DashMap reference across await points.
        let (cert_request, existing_state, existing_type, session_key, request_id_bytes) = {
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
            )
        };

        // Decrypt challenge parameters with the ECDH-derived session key.
        let params_json = session_key.decrypt(
            &chal_tlv.iv,
            &chal_tlv.encrypted_payload,
            &chal_tlv.auth_tag,
            &request_id_bytes,
        )?;
        let parameters: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&params_json)?;

        let challenge_type = &chal_tlv.selected_challenge;

        // Reject challenge-type switching mid-enrollment.
        if let Some(ref locked_type) = existing_type
            && locked_type != challenge_type
        {
            return Err(CertError::InvalidRequest(format!(
                "challenge type locked to '{}' for this request",
                locked_type
            )));
        }

        // Find the handler matching the client's chosen challenge type.
        let handler = self
            .config
            .challenges
            .iter()
            .find(|h| h.challenge_type() == challenge_type)
            .ok_or_else(|| {
                CertError::InvalidRequest(format!(
                    "unsupported challenge type: {challenge_type}",
                ))
            })?;

        // On first CHALLENGE: call begin() to initialize state, lock in challenge type.
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

        match outcome {
            ChallengeOutcome::Denied(reason) => {
                self.pending.remove(request_id);
                Ok(ChallengeResponseTlv {
                    status: STATUS_FAILURE,
                    challenge_status: None,
                    remaining_tries: None,
                    remaining_time_secs: None,
                    issued_cert_name: None,
                    error_code: Some(7), // OutOfTries
                    error_info: Some(reason),
                    iv: None,
                    encrypted_payload: None,
                    auth_tag: None,
                }
                .encode()
                .to_vec())
            }

            ChallengeOutcome::Pending {
                status_message,
                remaining_tries,
                remaining_time_secs,
                next_state,
            } => {
                if let Some(mut entry) = self.pending.get_mut(request_id) {
                    entry.challenge_state = Some(next_state);
                }
                Ok(ChallengeResponseTlv {
                    status: STATUS_PENDING,
                    challenge_status: Some(status_message),
                    remaining_tries: Some(remaining_tries),
                    remaining_time_secs: Some(remaining_time_secs),
                    issued_cert_name: None,
                    error_code: None,
                    error_info: None,
                    iv: None,
                    encrypted_payload: None,
                    auth_tag: None,
                }
                .encode()
                .to_vec())
            }

            ChallengeOutcome::Approved => {
                let (_, pending) = self
                    .pending
                    .remove(request_id)
                    .ok_or_else(|| CertError::RequestNotFound(request_id.to_string()))?;

                let cert = self.issue_certificate(&pending.cert_request).await?;
                let cert_name = cert.name.to_string();
                let cert_bytes = serialize_cert(&cert);

                // Embed the serialized cert in `encrypted_payload` (unencrypted on success —
                // the session is complete and no further encryption is needed).
                Ok(ChallengeResponseTlv {
                    status: STATUS_SUCCESS,
                    challenge_status: None,
                    remaining_tries: None,
                    remaining_time_secs: None,
                    issued_cert_name: Some(cert_name),
                    error_code: None,
                    error_info: None,
                    iv: None,
                    encrypted_payload: Some(bytes::Bytes::from(cert_bytes)),
                    auth_tag: None,
                }
                .encode()
                .to_vec())
            }
        }
    }

    /// Handle a REVOKE request.
    ///
    /// Route: `/<ca-prefix>/CA/REVOKE`; body is a JSON-encoded [`RevokeRequest`].
    pub async fn handle_revoke(&self, body: &[u8]) -> Vec<u8> {
        let resp = self.do_revoke(body).await;
        serde_json::to_vec(&resp).unwrap_or_default()
    }

    async fn do_revoke(&self, body: &[u8]) -> RevokeResponse {
        let req: RevokeRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(_) => return RevokeResponse { status: RevokeStatus::Unauthorized },
        };

        // Verify the requester proves possession of the certificate being revoked.
        // They must sign the cert_name bytes with the corresponding private key.
        let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.signature)
        {
            Ok(b) => b,
            Err(_) => return RevokeResponse { status: RevokeStatus::Unauthorized },
        };

        // Find the cert in CA trust anchors to get its public key.
        let cert_name_parsed: ndn_packet::Name = match req.cert_name.parse() {
            Ok(n) => n,
            Err(_) => return RevokeResponse { status: RevokeStatus::NotFound },
        };

        let anchor = self.manager.trust_anchor(&cert_name_parsed);
        let public_key = match anchor {
            Some(c) => c.public_key,
            None => return RevokeResponse { status: RevokeStatus::NotFound },
        };

        // Verify: requester signed cert_name with the cert's private key.
        use ndn_security::{Ed25519Verifier, VerifyOutcome, Verifier};
        let outcome = Ed25519Verifier
            .verify(req.cert_name.as_bytes(), &sig_bytes, &public_key)
            .await;

        match outcome {
            Ok(VerifyOutcome::Valid) => {
                self.revoked.insert(req.cert_name);
                RevokeResponse { status: RevokeStatus::Revoked }
            }
            _ => RevokeResponse { status: RevokeStatus::Unauthorized },
        }
    }

    /// Issue a certificate for an approved request.
    async fn issue_certificate(&self, req: &CertRequest) -> Result<Certificate, CertError> {
        let subject_name: ndn_packet::Name = req
            .name
            .parse()
            .map_err(|_| CertError::Name(req.name.clone()))?;

        let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&req.public_key)
            .map_err(|_| CertError::InvalidRequest("invalid public key base64".to_string()))?;

        // Refuse to re-issue a revoked certificate.
        if self.is_revoked(&req.name) {
            return Err(CertError::PolicyDenied(format!(
                "certificate {} has been revoked",
                req.name
            )));
        }

        // Find the CA signing key
        let ca_key_names = self.manager.trust_anchor_names();
        let ca_key_name = ca_key_names.first().ok_or_else(|| {
            CertError::InvalidRequest("CA has no signing key configured".to_string())
        })?;

        // Determine validity from the client's request, capped at the configured maximum.
        // Per NDNCERT 0.3: not_after <= min(now + max_validity, ca_cert.valid_until).
        let max_validity_ms = self.config.max_validity.as_millis() as u64;
        let requested_ms = req.not_after.saturating_sub(req.not_before);
        let validity_ms = if requested_ms > 0 {
            requested_ms.min(max_validity_ms)
        } else {
            self.config
                .default_validity
                .as_millis()
                .min(self.config.max_validity.as_millis()) as u64
        };

        let cert = self
            .manager
            .certify(
                &subject_name,
                bytes::Bytes::from(public_key),
                ca_key_name.as_ref(),
                validity_ms,
            )
            .await
            .map_err(CertError::Security)?;

        Ok(cert)
    }
}

/// Encode a certificate as a minimal byte blob for transport.
///
/// Format: [8 bytes: valid_from][8 bytes: valid_until][4 bytes: pubkey_len][pubkey]
///         [4 bytes: name_len][name_utf8]
fn serialize_cert(cert: &Certificate) -> Vec<u8> {
    let name_bytes = cert.name.to_string().into_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&cert.valid_from.to_be_bytes());
    out.extend_from_slice(&cert.valid_until.to_be_bytes());
    out.extend_from_slice(&(cert.public_key.len() as u32).to_be_bytes());
    out.extend_from_slice(&cert.public_key);
    out.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&name_bytes);
    out
}

/// Deserialize a certificate from the transport byte blob.
pub fn deserialize_cert(data: &[u8]) -> Option<Certificate> {
    if data.len() < 20 {
        return None;
    }
    let valid_from = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let valid_until = u64::from_be_bytes(data[8..16].try_into().ok()?);
    let pk_len = u32::from_be_bytes(data[16..20].try_into().ok()?) as usize;
    if data.len() < 20 + pk_len + 4 {
        return None;
    }
    let public_key = bytes::Bytes::copy_from_slice(&data[20..20 + pk_len]);
    let name_len =
        u32::from_be_bytes(data[20 + pk_len..24 + pk_len].try_into().ok()?) as usize;
    let name_bytes = data.get(24 + pk_len..24 + pk_len + name_len)?;
    let name_str = std::str::from_utf8(name_bytes).ok()?;
    let name: ndn_packet::Name = name_str.parse().ok()?;
    Some(Certificate {
        name: std::sync::Arc::new(name),
        public_key,
        valid_from,
        valid_until,
        issuer: None,
        signed_region: None,
        sig_value: None,
    })
}

fn generate_request_id_bytes() -> [u8; 8] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes).unwrap_or(());
    bytes
}

fn bytes_to_hex(bytes: &[u8; 8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a binary-encoded cert request blob from [`NewRequestTlv::cert_request`].
///
/// Format: `[8 not_before][8 not_after][4 pubkey_len][pubkey][4 name_len][name_utf8]`
/// Exposed as `pub(crate)` for unit-testing in `client.rs`.
#[cfg(test)]
pub(crate) fn decode_cert_request_bytes_pub(data: &[u8]) -> Result<CertRequest, CertError> {
    decode_cert_request_bytes(data)
}

fn decode_cert_request_bytes(data: &[u8]) -> Result<CertRequest, CertError> {
    if data.len() < 20 {
        return Err(CertError::InvalidRequest(
            "cert request too short".into(),
        ));
    }
    let not_before = u64::from_be_bytes(data[0..8].try_into().unwrap());
    let not_after = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let pk_len = u32::from_be_bytes(data[16..20].try_into().unwrap()) as usize;
    if data.len() < 20 + pk_len + 4 {
        return Err(CertError::InvalidRequest(
            "cert request truncated at pubkey".into(),
        ));
    }
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&data[20..20 + pk_len]);
    let name_len =
        u32::from_be_bytes(data[20 + pk_len..24 + pk_len].try_into().unwrap()) as usize;
    if data.len() < 24 + pk_len + name_len {
        return Err(CertError::InvalidRequest(
            "cert request truncated at name".into(),
        ));
    }
    let name = std::str::from_utf8(&data[24 + pk_len..24 + pk_len + name_len])
        .map_err(|_| CertError::InvalidRequest("invalid name UTF-8 in cert request".into()))?
        .to_string();
    Ok(CertRequest { name, public_key, not_before, not_after })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[allow(dead_code)]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
