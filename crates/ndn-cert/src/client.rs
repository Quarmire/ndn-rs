//! Client-side enrollment session for NDNCERT.
//!
//! [`EnrollmentSession`] manages the client's state machine through the
//! protocol exchange. It produces serialized request bodies and consumes
//! serialized response bodies. The network I/O is provided by the caller
//! (the `ndn-identity` crate).

use ndn_packet::Name;
use ndn_security::Certificate;

use crate::{
    ca::deserialize_cert,
    ecdh::{EcdhKeypair, SessionKey},
    error::CertError,
    tlv::{
        ChallengeRequestTlv, ChallengeResponseTlv, NewRequestTlv, NewResponseTlv,
        STATUS_FAILURE, STATUS_PENDING, STATUS_SUCCESS,
    },
};

/// Session state.
#[derive(Debug, Clone, PartialEq)]
enum SessionState {
    Init,
    AwaitingChallenge {
        request_id: String,
        challenges: Vec<String>,
    },
    /// A challenge round is in progress; another CHALLENGE request is required.
    Challenging {
        request_id: String,
        challenge_type: String,
        status_message: String,
        remaining_tries: u8,
        remaining_time_secs: u32,
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
/// 6. For multi-round challenges (email), repeat steps 4–5 with updated parameters
/// 7. On success, retrieve the certificate with [`certificate`](Self::certificate)
pub struct EnrollmentSession {
    name: Name,
    public_key: Vec<u8>,
    validity_secs: u64,
    state: SessionState,
    certificate: Option<Certificate>,
    /// ECDH ephemeral keypair — generated in `new_request_body`, consumed in `handle_new_response`.
    ecdh_keypair: Option<EcdhKeypair>,
    /// AES-GCM-128 session key derived from ECDH + HKDF (available after NEW response).
    session_key: Option<SessionKey>,
    /// 8-byte request identifier (raw bytes, for TLV encoding and AES-GCM AAD).
    request_id_bytes: Option<[u8; 8]>,
}

impl EnrollmentSession {
    pub fn new(name: Name, public_key: Vec<u8>, validity_secs: u64) -> Self {
        Self {
            name,
            public_key,
            validity_secs,
            state: SessionState::Init,
            certificate: None,
            ecdh_keypair: None,
            session_key: None,
            request_id_bytes: None,
        }
    }

    /// Build the TLV body for the `/CA/NEW` Interest's ApplicationParameters.
    ///
    /// Generates a fresh P-256 ephemeral ECDH key pair; the private part is
    /// held in `self` until the CA responds with its own public key.
    pub fn new_request_body(&mut self) -> Result<Vec<u8>, CertError> {
        let kp = EcdhKeypair::generate();
        let ecdh_pub_bytes = kp.public_key_bytes();
        self.ecdh_keypair = Some(kp);

        let now_ms = now_ms();
        let cert_request = encode_cert_request_bytes(
            now_ms,
            now_ms + self.validity_secs * 1000,
            &self.public_key,
            &self.name.to_string(),
        );

        let tlv = NewRequestTlv {
            ecdh_pub: bytes::Bytes::from(ecdh_pub_bytes),
            cert_request: bytes::Bytes::from(cert_request),
        };
        Ok(tlv.encode().to_vec())
    }

    /// Process the `/CA/NEW` TLV response and advance state.
    ///
    /// Performs ECDH key agreement with the CA's ephemeral public key and
    /// derives the shared AES-GCM-128 session key.
    pub fn handle_new_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let resp = NewResponseTlv::decode(bytes::Bytes::copy_from_slice(body))?;

        if resp.challenges.is_empty() {
            return Err(CertError::InvalidRequest("no challenges offered".to_string()));
        }

        let kp = self
            .ecdh_keypair
            .take()
            .ok_or_else(|| CertError::InvalidRequest("no ECDH keypair — call new_request_body first".into()))?;

        let session_key = kp.derive_session_key(&resp.ecdh_pub, &resp.salt, &resp.request_id)?;

        let request_id_hex: String = resp.request_id.iter().map(|b| format!("{b:02x}")).collect();

        self.session_key = Some(session_key);
        self.request_id_bytes = Some(resp.request_id);
        self.state = SessionState::AwaitingChallenge {
            request_id: request_id_hex,
            challenges: resp.challenges,
        };
        Ok(())
    }

    /// The request ID assigned by the CA (available after [`handle_new_response`](Self::handle_new_response)).
    pub fn request_id(&self) -> Option<&str> {
        match &self.state {
            SessionState::AwaitingChallenge { request_id, .. }
            | SessionState::Challenging { request_id, .. } => Some(request_id),
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

    /// Status message from an in-progress challenge (e.g. "Code sent to user@example.com").
    pub fn challenge_status_message(&self) -> Option<&str> {
        match &self.state {
            SessionState::Challenging { status_message, .. } => Some(status_message),
            _ => None,
        }
    }

    /// Remaining attempts for an in-progress challenge.
    pub fn remaining_tries(&self) -> Option<u8> {
        match &self.state {
            SessionState::Challenging { remaining_tries, .. } => Some(*remaining_tries),
            _ => None,
        }
    }

    /// Build the TLV body for the `/CA/CHALLENGE/<id>` Interest.
    ///
    /// `parameters` is JSON-encoded and AES-GCM encrypted with the session key.
    pub fn challenge_request_body(
        &self,
        challenge_type: &str,
        parameters: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<u8>, CertError> {
        let request_id_bytes = self
            .request_id_bytes
            .ok_or_else(|| CertError::InvalidRequest("not in challenge state".to_string()))?;

        let session_key = self
            .session_key
            .as_ref()
            .ok_or_else(|| CertError::InvalidRequest("no session key — call handle_new_response first".into()))?;

        let params_json = serde_json::to_vec(&parameters)?;
        let (iv, encrypted_payload, auth_tag) =
            session_key.encrypt(&params_json, &request_id_bytes)?;

        let tlv = ChallengeRequestTlv {
            request_id: request_id_bytes,
            selected_challenge: challenge_type.to_string(),
            iv,
            encrypted_payload,
            auth_tag,
        };
        Ok(tlv.encode().to_vec())
    }

    /// Process the challenge TLV response and advance state.
    ///
    /// Returns `Ok(())` on both success and `Pending` (another round needed).
    /// Check [`is_complete`](Self::is_complete) to know if the session is done.
    /// Check [`challenge_status_message`](Self::challenge_status_message) for the next prompt.
    pub fn handle_challenge_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let resp = ChallengeResponseTlv::decode(bytes::Bytes::copy_from_slice(body))?;
        match resp.status {
            STATUS_FAILURE => {
                let reason = resp
                    .error_info
                    .unwrap_or_else(|| "challenge denied".to_string());
                Err(CertError::ChallengeFailed(reason))
            }
            STATUS_PENDING => {
                let request_id = self.request_id().unwrap_or_default().to_string();
                let challenge_type = match &self.state {
                    SessionState::Challenging { challenge_type, .. } => challenge_type.clone(),
                    _ => String::new(),
                };
                self.state = SessionState::Challenging {
                    request_id,
                    challenge_type,
                    status_message: resp
                        .challenge_status
                        .unwrap_or_else(|| "Challenge in progress".to_string()),
                    remaining_tries: resp.remaining_tries.unwrap_or(0),
                    remaining_time_secs: resp.remaining_time_secs.unwrap_or(0),
                };
                Ok(())
            }
            STATUS_SUCCESS => {
                let cert_bytes = resp.encrypted_payload.ok_or_else(|| {
                    CertError::InvalidRequest("approved but no certificate returned".to_string())
                })?;
                let cert = deserialize_cert(&cert_bytes).ok_or_else(|| {
                    CertError::InvalidRequest("could not decode certificate".to_string())
                })?;
                self.certificate = Some(cert);
                self.state = SessionState::Complete;
                Ok(())
            }
            other => Err(CertError::InvalidRequest(format!(
                "unexpected challenge response status: {other}"
            ))),
        }
    }

    /// Whether the session has completed successfully.
    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }

    /// Whether another CHALLENGE round is required.
    pub fn needs_another_round(&self) -> bool {
        matches!(self.state, SessionState::Challenging { .. })
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

/// Encode a cert request as a flat byte blob for [`NewRequestTlv::cert_request`].
///
/// Format: `[8 not_before][8 not_after][4 pubkey_len][pubkey][4 name_len][name_utf8]`
fn encode_cert_request_bytes(
    not_before: u64,
    not_after: u64,
    public_key: &[u8],
    name: &str,
) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut out = Vec::with_capacity(20 + public_key.len() + 4 + name_bytes.len());
    out.extend_from_slice(&not_before.to_be_bytes());
    out.extend_from_slice(&not_after.to_be_bytes());
    out.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    out.extend_from_slice(public_key);
    out.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(name_bytes);
    out
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
    use base64::Engine as _;

    use super::*;

    #[test]
    fn new_request_body_is_valid_tlv() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let pubkey = vec![0x42u8; 32];
        let mut session = EnrollmentSession::new(name, pubkey, 86400);
        let body = session.new_request_body().unwrap();
        // Must decode as valid NewRequestTlv.
        let req = NewRequestTlv::decode(bytes::Bytes::from(body)).unwrap();
        assert_eq!(req.ecdh_pub.len(), 65);
        assert_eq!(req.ecdh_pub[0], 0x04); // uncompressed P-256 point marker
        // Verify the binary cert_request contains the correct name.
        let cr_bytes = &req.cert_request;
        let pk_len = 32usize;
        let name_len =
            u32::from_be_bytes(cr_bytes[20 + pk_len..24 + pk_len].try_into().unwrap()) as usize;
        let name_str =
            std::str::from_utf8(&cr_bytes[24 + pk_len..24 + pk_len + name_len]).unwrap();
        assert_eq!(name_str, "/com/acme/alice/KEY/v=0");
    }

    #[test]
    fn encode_decode_cert_request_bytes_roundtrip() {
        let name = "/com/acme/bob/KEY/v=1";
        let pubkey = vec![0xAAu8; 32];
        let not_before = 1_700_000_000_000u64;
        let not_after = 1_700_086_400_000u64;
        let encoded = encode_cert_request_bytes(not_before, not_after, &pubkey, name);
        let decoded = crate::ca::decode_cert_request_bytes_pub(&encoded).unwrap();
        assert_eq!(decoded.name, name);
        assert_eq!(decoded.not_before, not_before);
        assert_eq!(decoded.not_after, not_after);
        // public_key stored as base64url
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&decoded.public_key)
            .unwrap();
        assert_eq!(raw, pubkey);
    }
}
