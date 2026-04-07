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
use dashmap::DashMap;
use ndn_security::{Certificate, SecurityManager};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    policy::{NamespacePolicy, PolicyDecision},
    protocol::{
        CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, NewResponse,
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
    challenge_state: ChallengeState,
    #[allow(dead_code)]
    challenge_type: String,
    #[allow(dead_code)]
    created_at: u64,
}

/// The stateless CA processor.
///
/// Holds in-flight request state and the signing identity.
/// All methods take `&self` and are safe to call from concurrent tasks.
pub struct CaState {
    config: CaConfig,
    manager: Arc<SecurityManager>,
    pending: DashMap<String, PendingRequest>,
}

impl CaState {
    pub fn new(config: CaConfig, manager: Arc<SecurityManager>) -> Self {
        Self {
            config,
            manager,
            pending: DashMap::new(),
        }
    }

    /// Handle a CA INFO request — return the CA's profile.
    pub fn handle_info(&self) -> Vec<u8> {
        let profile = CaProfile {
            ca_prefix: self.config.prefix.to_string(),
            ca_info: self.config.info.clone(),
            public_key: String::new(), // filled by identity layer
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

    /// Handle a NEW request — validate, store state, return request ID + challenges.
    pub async fn handle_new(&self, body: &[u8]) -> Result<Vec<u8>, CertError> {
        let req: CertRequest = serde_json::from_slice(body)?;

        // Parse requested name
        let name: ndn_packet::Name = req
            .name
            .parse()
            .map_err(|_| CertError::Name(format!("invalid name: {}", req.name)))?;

        // Policy check
        match self.config.policy.evaluate(&name, None, &self.config.prefix) {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny(reason) => return Err(CertError::PolicyDenied(reason)),
        }

        // Generate request ID
        let request_id = generate_request_id();

        // Pick the first available challenge
        let handler = self
            .config
            .challenges
            .first()
            .ok_or_else(|| CertError::InvalidRequest("CA has no challenge handlers".to_string()))?;

        let state = handler.begin(&req).await?;

        self.pending.insert(
            request_id.clone(),
            PendingRequest {
                cert_request: req,
                challenge_state: state,
                challenge_type: handler.challenge_type().to_string(),
                created_at: now_secs(),
            },
        );

        let resp = NewResponse {
            request_id,
            challenges: self
                .config
                .challenges
                .iter()
                .map(|c| c.challenge_type().to_string())
                .collect(),
        };
        Ok(serde_json::to_vec(&resp)?)
    }

    /// Handle a CHALLENGE request — verify, issue or deny.
    pub async fn handle_challenge(
        &self,
        request_id: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, CertError> {
        let challenge_req: ChallengeRequest = serde_json::from_slice(body)?;

        let pending = self
            .pending
            .get(request_id)
            .ok_or_else(|| CertError::RequestNotFound(request_id.to_string()))?;

        // Find the handler for the requested challenge type
        let handler = self
            .config
            .challenges
            .iter()
            .find(|h| h.challenge_type() == challenge_req.challenge_type)
            .ok_or_else(|| {
                CertError::InvalidRequest(format!(
                    "unsupported challenge type: {}",
                    challenge_req.challenge_type
                ))
            })?;

        let outcome = handler
            .verify(&pending.challenge_state, &challenge_req.parameters)
            .await?;

        // Drop the pending borrow before issuing
        drop(pending);

        match outcome {
            ChallengeOutcome::Denied(reason) => {
                self.pending.remove(request_id);
                let resp = ChallengeResponse {
                    status: ChallengeStatus::Denied,
                    certificate: None,
                    error: Some(reason),
                };
                Ok(serde_json::to_vec(&resp)?)
            }
            ChallengeOutcome::Approved => {
                let pending = self
                    .pending
                    .remove(request_id)
                    .ok_or_else(|| CertError::RequestNotFound(request_id.to_string()))?
                    .1;

                let cert = self.issue_certificate(&pending.cert_request).await?;
                let cert_bytes = serialize_cert(&cert);

                let resp = ChallengeResponse {
                    status: ChallengeStatus::Approved,
                    certificate: Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cert_bytes),
                    ),
                    error: None,
                };
                Ok(serde_json::to_vec(&resp)?)
            }
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

        // Find the CA signing key
        let ca_key_names = self.manager.trust_anchor_names();
        let ca_key_name = ca_key_names.first().ok_or_else(|| {
            CertError::InvalidRequest("CA has no signing key configured".to_string())
        })?;

        // Determine validity (cap at configured maximum)
        let validity_ms = self
            .config
            .default_validity
            .as_millis()
            .min(self.config.max_validity.as_millis()) as u64;

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

fn generate_request_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).unwrap_or(());
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
