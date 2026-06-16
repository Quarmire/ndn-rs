//! NDNCERT possession challenge — client signs the request nonce with the
//! private key of a cert already trusted by the CA (renewal, sub-namespace
//! enrollment, factory-key bootstrap).

use std::{future::Future, pin::Pin, sync::Arc};

use base64::Engine;
use ndn_security::{Certificate, Ed25519Verifier, Verifier, VerifyOutcome};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// Client submits `{ "cert_name": "<uri>", "signature": "<base64url>" }`;
/// signature is over the request nonce, key is the matching cert in `trusted_certs`.
pub struct PossessionChallenge {
    trusted_certs: Arc<Vec<Certificate>>,
}

impl PossessionChallenge {
    pub fn new(trusted_certs: Vec<Certificate>) -> Self {
        Self {
            trusted_certs: Arc::new(trusted_certs),
        }
    }
}

impl ChallengeHandler for PossessionChallenge {
    fn challenge_type(&self) -> &'static str {
        "possession"
    }

    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        let nonce = req.name.clone();
        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "possession".to_string(),
                data: serde_json::json!({ "nonce": nonce }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        let cert_name_str = parameters
            .get("cert_name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let signature_b64 = parameters
            .get("signature")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let nonce = state
            .data
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let trusted = self.trusted_certs.clone();

        Box::pin(async move {
            let cert_name_str = cert_name_str
                .ok_or_else(|| CertError::InvalidRequest("missing 'cert_name'".to_string()))?;
            let signature_b64 = signature_b64
                .ok_or_else(|| CertError::InvalidRequest("missing 'signature'".to_string()))?;

            let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&signature_b64)
                .map_err(|_| CertError::InvalidRequest("invalid base64 signature".to_string()))?;

            let cert = trusted.iter().find(|c| c.name.to_string() == cert_name_str);
            let cert = match cert {
                Some(c) => c,
                None => {
                    return Ok(ChallengeOutcome::Denied(format!(
                        "certificate not trusted: {cert_name_str}"
                    )));
                }
            };

            let outcome = Ed25519Verifier
                .verify(nonce.as_bytes(), &sig_bytes, &cert.public_key)
                .await
                .map_err(CertError::Security)?;

            match outcome {
                VerifyOutcome::Valid => Ok(ChallengeOutcome::Approved { attestation: None }),
                VerifyOutcome::Invalid => Ok(ChallengeOutcome::Denied(
                    "signature verification failed".to_string(),
                )),
            }
        })
    }
}
