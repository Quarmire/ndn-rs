//! NDNCERT client-side enrollment state machine. Network I/O is provided by
//! the caller (the `ndn-identity` crate).

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::{Signer, encode_cert_data};

use crate::{
    ecdh::{EcdhKeypair, SessionKey, new_encryption_iv},
    error::CertError,
    tlv::{
        ChallengeResponseTlv, NewRequestTlv, NewResponseTlv, STATUS_CHALLENGE, STATUS_FAILURE,
        STATUS_PENDING, STATUS_SUCCESS, TLV_SELECTED_CHALLENGE, encode_challenge_parameters,
    },
};

#[derive(Debug, Clone, PartialEq)]
enum SessionState {
    Init,
    AwaitingChallenge {
        request_id: String,
        challenges: Vec<String>,
    },
    Challenging {
        request_id: String,
        challenge_type: String,
        status_message: String,
        remaining_tries: u8,
        remaining_time_secs: u32,
    },
    Complete,
}

/// Client enrollment driver.
///
/// 1. `new` → `new_request_body` (async, builds self-signed cert_request).
/// 2. `handle_new_response` (derives the session key).
/// 3. `challenge_request_body` → `handle_challenge_response`; repeat for multi-round.
/// 4. On success, fetch the cert at [`issued_cert_name`](Self::issued_cert_name).
///
/// Callers must sign every NEW and CHALLENGE Interest with [`signer`](Self::signer).
pub struct EnrollmentSession {
    name: Name,
    signer: Arc<dyn Signer>,
    validity_secs: u64,
    state: SessionState,
    issued_cert_name: Option<Name>,
    ecdh_keypair: Option<EcdhKeypair>,
    session_key: Option<SessionKey>,
    request_id_bytes: Option<[u8; 8]>,
    encryption_iv: Option<[u8; 12]>,
    decryption_iv: Option<[u8; 12]>,
}

impl EnrollmentSession {
    pub fn new(name: Name, signer: Arc<dyn Signer>, validity_secs: u64) -> Self {
        Self {
            name,
            signer,
            validity_secs,
            state: SessionState::Init,
            issued_cert_name: None,
            ecdh_keypair: None,
            session_key: None,
            request_id_bytes: None,
            encryption_iv: None,
            decryption_iv: None,
        }
    }

    pub fn signer(&self) -> &Arc<dyn Signer> {
        &self.signer
    }

    /// ApplicationParameters body for `/<ca>/CA/NEW`. Generates a fresh
    /// P-256 ECDH keypair and a self-signed cert_request named
    /// `<key_name>/cert-request/<version-ms>`.
    pub async fn new_request_body(&mut self) -> Result<Vec<u8>, CertError> {
        let kp = EcdhKeypair::generate();
        let ecdh_pub_bytes = kp.public_key_bytes();
        self.ecdh_keypair = Some(kp);

        let public_key = self
            .signer
            .public_key()
            .ok_or_else(|| CertError::InvalidRequest("signer has no public key".into()))?;

        let now_ns = now_ns();
        let valid_until_ns =
            now_ns.saturating_add(self.validity_secs.saturating_mul(1_000_000_000));
        let cert_name = self
            .name
            .clone()
            .append("cert-request")
            .append_version(now_ns / 1_000_000);

        let cert_wire = encode_cert_data(
            &cert_name,
            &public_key,
            self.signer.as_ref(),
            now_ns,
            valid_until_ns,
        )
        .await
        .map_err(|e| CertError::InvalidRequest(format!("cert_request encoding failed: {e}")))?;

        let tlv = NewRequestTlv {
            ecdh_pub: bytes::Bytes::from(ecdh_pub_bytes),
            cert_request: cert_wire,
        };
        Ok(tlv.encode().to_vec())
    }

    pub fn handle_new_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let resp = NewResponseTlv::decode(bytes::Bytes::copy_from_slice(body))?;

        if resp.challenges.is_empty() {
            return Err(CertError::InvalidRequest(
                "no challenges offered".to_string(),
            ));
        }

        let kp = self.ecdh_keypair.take().ok_or_else(|| {
            CertError::InvalidRequest("no ECDH keypair — call new_request_body first".into())
        })?;

        let session_key = kp.derive_session_key(&resp.ecdh_pub, &resp.salt, &resp.request_id)?;

        let request_id_hex: String = resp.request_id.iter().map(|b| format!("{b:02x}")).collect();

        self.session_key = Some(session_key);
        self.request_id_bytes = Some(resp.request_id);
        self.encryption_iv = Some(new_encryption_iv());
        self.state = SessionState::AwaitingChallenge {
            request_id: request_id_hex,
            challenges: resp.challenges,
        };
        Ok(())
    }

    pub fn request_id(&self) -> Option<&str> {
        match &self.state {
            SessionState::AwaitingChallenge { request_id, .. }
            | SessionState::Challenging { request_id, .. } => Some(request_id),
            _ => None,
        }
    }

    /// Raw bytes to append as the CHALLENGE Interest name component.
    pub fn request_id_bytes(&self) -> Option<&[u8; 8]> {
        self.request_id_bytes.as_ref()
    }

    pub fn offered_challenges(&self) -> &[String] {
        match &self.state {
            SessionState::AwaitingChallenge { challenges, .. } => challenges,
            _ => &[],
        }
    }

    pub fn challenge_status_message(&self) -> Option<&str> {
        match &self.state {
            SessionState::Challenging { status_message, .. } => Some(status_message),
            _ => None,
        }
    }

    pub fn remaining_tries(&self) -> Option<u8> {
        match &self.state {
            SessionState::Challenging {
                remaining_tries, ..
            } => Some(*remaining_tries),
            _ => None,
        }
    }

    /// ApplicationParameters for `/<ca>/CA/CHALLENGE/<request-id-bytes>`.
    /// Returns an AES-GCM envelope; plaintext is
    /// `{SelectedChallenge, ParameterKey, ParameterValue, ...}`.
    pub fn challenge_request_body(
        &mut self,
        challenge_type: &str,
        parameters: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<u8>, CertError> {
        let request_id_bytes = self
            .request_id_bytes
            .ok_or_else(|| CertError::InvalidRequest("not in challenge state".to_string()))?;

        let session_key = self.session_key.as_ref().ok_or_else(|| {
            CertError::InvalidRequest("no session key — call handle_new_response first".into())
        })?;

        let iv_state = self.encryption_iv.as_mut().ok_or_else(|| {
            CertError::InvalidRequest("no encryption IV — call handle_new_response first".into())
        })?;

        let mut plaintext_writer = ndn_tlv::TlvWriter::new();
        plaintext_writer.write_tlv(TLV_SELECTED_CHALLENGE, challenge_type.as_bytes());
        let params_bytes = encode_challenge_parameters(&parameters);
        plaintext_writer.write_raw(&params_bytes);
        let plaintext = plaintext_writer.finish();

        let envelope = session_key.seal_envelope(&plaintext, &request_id_bytes, iv_state)?;
        Ok(envelope)
    }

    /// Returns `Ok(())` on both Success and Pending — check
    /// [`is_complete`](Self::is_complete) / [`needs_another_round`](Self::needs_another_round).
    pub fn handle_challenge_response(&mut self, body: &[u8]) -> Result<(), CertError> {
        let request_id_bytes = self
            .request_id_bytes
            .ok_or_else(|| CertError::InvalidRequest("not in challenge state".to_string()))?;

        let session_key = self.session_key.as_ref().ok_or_else(|| {
            CertError::InvalidRequest("no session key — call handle_new_response first".into())
        })?;

        let plaintext =
            session_key.open_envelope(body, &request_id_bytes, &mut self.decryption_iv)?;

        let resp = ChallengeResponseTlv::decode(bytes::Bytes::from(plaintext))?;
        match resp.status {
            STATUS_FAILURE => {
                let reason = resp
                    .error_info
                    .unwrap_or_else(|| "challenge denied".to_string());
                Err(CertError::ChallengeFailed(reason))
            }
            // STATUS_CHALLENGE (CA awaits requester) and STATUS_PENDING
            // (CA busy with async work) both require another round.
            s if s == STATUS_CHALLENGE || s == STATUS_PENDING => {
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
                let cert_name_str = resp.issued_cert_name.ok_or_else(|| {
                    CertError::InvalidRequest(
                        "approved but no IssuedCertName in response".to_string(),
                    )
                })?;
                let cert_name: Name = cert_name_str
                    .parse()
                    .map_err(|_| CertError::Name(format!("invalid cert name: {cert_name_str}")))?;
                self.issued_cert_name = Some(cert_name);
                self.state = SessionState::Complete;
                Ok(())
            }
            other => Err(CertError::InvalidRequest(format!(
                "unexpected challenge response status: {other}"
            ))),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.state == SessionState::Complete
    }

    pub fn needs_another_round(&self) -> bool {
        matches!(self.state, SessionState::Challenging { .. })
    }

    pub fn issued_cert_name(&self) -> Option<&Name> {
        self.issued_cert_name.as_ref()
    }
}

fn now_ns() -> u64 {
    // `web_time` shims `std::time` on wasm32 (reads `Date.now()`); native
    // targets re-export `std::time` unchanged.
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ndn_security::Ed25519Signer;

    use super::*;
    use crate::tlv::{ChallengeRequestTlv, NewRequestTlv, decode_challenge_plaintext};

    fn make_test_session() -> EnrollmentSession {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let seed = [0x42u8; 32];
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, name.clone()));
        EnrollmentSession::new(name, signer, 86400)
    }

    #[tokio::test]
    async fn new_request_body_is_self_signed_cert() {
        let mut session = make_test_session();
        let body = session.new_request_body().await.unwrap();

        let req = NewRequestTlv::decode(bytes::Bytes::from(body)).unwrap();
        assert_eq!(req.ecdh_pub.len(), 65);
        assert_eq!(req.ecdh_pub[0], 0x04);

        let data = ndn_packet::Data::decode(req.cert_request)
            .expect("cert_request must be a valid NDN Data TLV");
        let cert = ndn_security::Certificate::decode(&data)
            .expect("cert_request must decode as NDN Certificate");

        let comps = cert.name.components();
        assert!(
            comps.len() >= 2,
            "cert name must have at least issuer + version components"
        );
        let issuer_bytes = &comps[comps.len() - 2].value;
        assert_eq!(
            issuer_bytes.as_ref(),
            b"cert-request",
            "issuer component must be 'cert-request'"
        );

        let expected_pk = {
            let seed = [0x42u8; 32];
            let kn: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
            Ed25519Signer::from_seed(&seed, kn).public_key_bytes()
        };
        assert_eq!(
            cert.public_key.as_ref(),
            &expected_pk,
            "cert public key must match signer"
        );
    }

    #[test]
    fn challenge_request_is_envelope_with_selected_challenge_first() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let seed = [0x42u8; 32];
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, name.clone()));
        let mut session = EnrollmentSession::new(name, signer, 86400);

        let test_key = SessionKey { key: [0u8; 16] };
        let request_id_bytes = [0xABu8; 8];
        session.session_key = Some(test_key.clone());
        session.request_id_bytes = Some(request_id_bytes);
        session.encryption_iv = Some([0u8; 12]);
        session.state = SessionState::AwaitingChallenge {
            request_id: "abababababababab".to_string(),
            challenges: vec!["pin".to_string()],
        };

        let mut params = serde_json::Map::new();
        params.insert(
            "code".to_string(),
            serde_json::Value::String("ABC123".to_string()),
        );

        let envelope_bytes = session.challenge_request_body("pin", params).unwrap();

        let tlv = ChallengeRequestTlv::decode(bytes::Bytes::from(envelope_bytes)).unwrap();
        assert_eq!(tlv.iv.len(), 12);
        assert_eq!(tlv.auth_tag.len(), 16);

        let mut dec_iv = None;
        let plaintext = test_key
            .open_envelope(
                &{
                    let mut v = Vec::new();
                    v.extend_from_slice(&tlv.encode());
                    v
                },
                &request_id_bytes,
                &mut dec_iv,
            )
            .unwrap();

        let (ctype, params_out) = decode_challenge_plaintext(&plaintext).unwrap();
        assert_eq!(ctype, "pin");
        assert_eq!(
            params_out.get("code").and_then(|v| v.as_str()),
            Some("ABC123")
        );
    }

    #[test]
    fn pin_round1_status_challenge_is_pending() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let seed = [0xAAu8; 32];
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, name.clone()));
        let mut session = EnrollmentSession::new(name, signer, 86400);

        let test_key = SessionKey { key: [0u8; 16] };
        let request_id_bytes = [0xDDu8; 8];
        session.session_key = Some(test_key.clone());
        session.request_id_bytes = Some(request_id_bytes);
        session.encryption_iv = Some([0u8; 12]);
        session.state = SessionState::AwaitingChallenge {
            request_id: "dddddddddddddddd".to_string(),
            challenges: vec!["pin".to_string()],
        };

        let round1_resp = ChallengeResponseTlv {
            status: crate::tlv::STATUS_CHALLENGE,
            challenge_status: Some("need-code".to_string()),
            remaining_tries: Some(3),
            remaining_time_secs: Some(300),
            issued_cert_name: None,
            error_code: None,
            error_info: None,
        };
        let plaintext = round1_resp.encode();
        let mut ca_iv = crate::ecdh::new_encryption_iv();
        let encrypted = test_key
            .seal_envelope(&plaintext, &request_id_bytes, &mut ca_iv)
            .unwrap();

        session.handle_challenge_response(&encrypted).unwrap();
        assert!(
            !session.is_complete(),
            "session must not be complete after round 1"
        );
        assert!(
            session.needs_another_round(),
            "session must need another round"
        );
        assert_eq!(session.challenge_status_message(), Some("need-code"));
        assert_eq!(session.remaining_tries(), Some(3));
    }

    #[test]
    fn challenge_response_decrypted_before_parsing() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let seed = [0x11u8; 32];
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, name.clone()));
        let mut session = EnrollmentSession::new(name, signer, 86400);

        let test_key = SessionKey { key: [0u8; 16] };
        let request_id_bytes = [0xBBu8; 8];
        session.session_key = Some(test_key.clone());
        session.request_id_bytes = Some(request_id_bytes);
        session.encryption_iv = Some([0u8; 12]);
        session.state = SessionState::AwaitingChallenge {
            request_id: "bbbbbbbbbbbbbbbb".to_string(),
            challenges: vec!["pin".to_string()],
        };

        let plaintext_resp = ChallengeResponseTlv {
            status: STATUS_SUCCESS,
            challenge_status: None,
            remaining_tries: None,
            remaining_time_secs: None,
            issued_cert_name: Some("/com/acme/alice/KEY/v=0/CA/v=1".to_string()),
            error_code: None,
            error_info: None,
        };
        let plaintext_bytes = plaintext_resp.encode();
        let mut ca_iv = crate::ecdh::new_encryption_iv();
        let encrypted = test_key
            .seal_envelope(&plaintext_bytes, &request_id_bytes, &mut ca_iv)
            .unwrap();

        session.handle_challenge_response(&encrypted).unwrap();
        assert!(session.is_complete());
        assert_eq!(
            session.issued_cert_name().map(|n| n.to_string()).as_deref(),
            Some("/com/acme/alice/KEY/v=0/CA/v=1")
        );
    }

    #[test]
    fn issued_cert_name_set_on_success() {
        let name: Name = "/com/acme/alice/KEY/v=0".parse().unwrap();
        let seed = [0x33u8; 32];
        let signer = Arc::new(Ed25519Signer::from_seed(&seed, name.clone()));
        let mut session = EnrollmentSession::new(name, signer, 86400);

        let test_key = SessionKey { key: [0u8; 16] };
        let request_id_bytes = [0xCCu8; 8];
        session.session_key = Some(test_key.clone());
        session.request_id_bytes = Some(request_id_bytes);
        session.encryption_iv = Some([0u8; 12]);
        session.state = SessionState::AwaitingChallenge {
            request_id: "cccccccccccccccc".to_string(),
            challenges: vec!["pin".to_string()],
        };

        let cert_uri = "/com/acme/alice/KEY/v=0/cert-request/v=1";
        let resp = ChallengeResponseTlv {
            status: STATUS_SUCCESS,
            challenge_status: None,
            remaining_tries: None,
            remaining_time_secs: None,
            issued_cert_name: Some(cert_uri.to_string()),
            error_code: None,
            error_info: None,
        };
        let plaintext = resp.encode();
        let mut ca_iv = crate::ecdh::new_encryption_iv();
        let encrypted = test_key
            .seal_envelope(&plaintext, &request_id_bytes, &mut ca_iv)
            .unwrap();

        session.handle_challenge_response(&encrypted).unwrap();
        assert!(session.is_complete());
        assert_eq!(
            session.issued_cert_name().map(|n| n.to_string()).as_deref(),
            Some(cert_uri)
        );
    }
}
