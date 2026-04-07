//! Client-side enrollment session for NDNCERT.
//!
//! [`EnrollmentSession`] manages the client's state machine through the
//! protocol exchange. It produces serialized request bodies and consumes
//! serialized response bodies. The network I/O is provided by the caller
//! (the `ndn-identity` crate).

use base64::Engine;
use ndn_packet::Name;
use ndn_security::Certificate;

use crate::{
    ca::deserialize_cert,
    error::CertError,
    protocol::{CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, NewResponse},
};

/// Session state.
#[derive(Debug, Clone, PartialEq)]
enum SessionState {
    Init,
    AwaitingChallenge {
        request_id: String,
        challenges: Vec<String>,
    },
    Complete,
}

/// Client-side NDNCERT enrollment session.
///
/// Usage:
/// 1. Create with [`EnrollmentSession::new`]
/// 2. Call [`new_request_body`](Self::new_request_body) to get the body for the `/CA/NEW` Interest
/// 3. Feed the response to [`handle_new_response`](Self::handle_new_response)
/// 4. Build the challenge parameters and call [`challenge_request_body`](Self::challenge_request_body)
/// 5. Feed the response to [`handle_challenge_response`](Self::handle_challenge_response)
/// 6. On success, retrieve the certificate with [`certificate`](Self::certificate)
pub struct EnrollmentSession {
    name: Name,
    public_key: Vec<u8>,
    validity_secs: u64,
    state: SessionState,
    certificate: Option<Certificate>,
}

impl EnrollmentSession {
    pub fn new(name: Name, public_key: Vec<u8>, validity_secs: u64) -> Self {
        Self {
            name,
            public_key,
            validity_secs,
            state: SessionState::Init,
            certificate: None,
        }
    }

    /// Build the JSON body for the `/CA/NEW` Interest's ApplicationParameters.
    pub fn new_request_body(&self) -> Result<Vec<u8>, CertError> {
        let now_ms = now_ms();
        let req = CertRequest {
            name: self.name.to_string(),
            public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&self.public_key),
            not_before: now_ms,
            not_after: now_ms + self.validity_secs * 1000,
        };
        Ok(serde_json::to_vec(&req)?)
    }

    /// Process the `/CA/NEW` response and advance state.
    pub fn handle_new_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let resp: NewResponse = serde_json::from_slice(body)?;
        if resp.request_id.is_empty() {
            return Err(CertError::InvalidRequest("empty request_id".to_string()));
        }
        if resp.challenges.is_empty() {
            return Err(CertError::InvalidRequest("no challenges offered".to_string()));
        }
        self.state = SessionState::AwaitingChallenge {
            request_id: resp.request_id,
            challenges: resp.challenges,
        };
        Ok(())
    }

    /// The request ID assigned by the CA (available after [`handle_new_response`](Self::handle_new_response)).
    pub fn request_id(&self) -> Option<&str> {
        match &self.state {
            SessionState::AwaitingChallenge { request_id, .. } => Some(request_id),
            _ => None,
        }
    }

    /// The challenge types offered by the CA.
    pub fn offered_challenges(&self) -> &[String] {
        match &self.state {
            SessionState::AwaitingChallenge { challenges, .. } => challenges,
            _ => &[],
        }
    }

    /// Build the JSON body for the `/CA/CHALLENGE/<id>` Interest.
    pub fn challenge_request_body(
        &self,
        challenge_type: &str,
        parameters: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<u8>, CertError> {
        let request_id = match &self.state {
            SessionState::AwaitingChallenge { request_id, .. } => request_id.clone(),
            _ => return Err(CertError::InvalidRequest("not in challenge state".to_string())),
        };
        let req = ChallengeRequest {
            request_id,
            challenge_type: challenge_type.to_string(),
            parameters,
        };
        Ok(serde_json::to_vec(&req)?)
    }

    /// Process the challenge response and advance state.
    pub fn handle_challenge_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let resp: ChallengeResponse = serde_json::from_slice(body)?;
        match resp.status {
            ChallengeStatus::Denied => {
                let reason = resp.error.unwrap_or_else(|| "challenge denied".to_string());
                Err(CertError::ChallengeFailed(reason))
            }
            ChallengeStatus::Approved => {
                let cert_b64 = resp.certificate.ok_or_else(|| {
                    CertError::InvalidRequest("approved but no certificate returned".to_string())
                })?;
                let cert_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&cert_b64)
                    .map_err(|_| CertError::InvalidRequest("invalid cert base64".to_string()))?;
                let cert = deserialize_cert(&cert_bytes).ok_or_else(|| {
                    CertError::InvalidRequest("could not decode certificate".to_string())
                })?;
                self.certificate = Some(cert);
                self.state = SessionState::Complete;
                Ok(())
            }
        }
    }

    /// Whether the session has completed successfully.
    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }

    /// The issued certificate (available after successful completion).
    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }

    /// Consume the session and return the issued certificate.
    pub fn into_certificate(self) -> Option<Certificate> {
        self.certificate
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_request_body_roundtrip() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let pubkey = vec![0u8; 32];
        let session = EnrollmentSession::new(name, pubkey, 86400);
        let body = session.new_request_body().unwrap();
        let req: crate::protocol::CertRequest = serde_json::from_slice(&body).unwrap();
        assert_eq!(req.name, "/com/acme/alice/KEY/v=0");
        assert_eq!(req.public_key.len(), 43); // 32 bytes base64url no-pad
    }
}
