//! NDNCERT client-side enrollment driver wired to `ndn-app::Consumer`.

use std::sync::Arc;

use ndn_cert::EnrollmentSession;
use ndn_packet::{Name, encode::InterestBuilder};
use ndn_security::{SecurityManager, Signer};

use crate::{error::IdentityError, facade::Identity};

#[derive(Debug, Clone)]
pub enum ChallengeParams {
    Token {
        token: String,
    },
    Possession {
        cert_name: String,
        /// Ed25519 signature over the request_id bytes.
        signature: Vec<u8>,
    },
    /// Named custom challenge parameters.
    Custom {
        challenge_type: String,
        parameters: serde_json::Map<String, serde_json::Value>,
    },
    /// Raw parameters for custom challenge types.
    Raw(serde_json::Map<String, serde_json::Value>),
}

impl ChallengeParams {
    pub fn challenge_type(&self) -> &str {
        match self {
            ChallengeParams::Token { .. } => "token",
            ChallengeParams::Possession { .. } => "possession",
            ChallengeParams::Custom { challenge_type, .. } => challenge_type,
            ChallengeParams::Raw(_) => "raw",
        }
    }

    pub fn to_map(&self) -> serde_json::Map<String, serde_json::Value> {
        use base64::Engine as _;
        match self {
            ChallengeParams::Token { token } => {
                let mut m = serde_json::Map::new();
                m.insert("token".to_string(), token.clone().into());
                m
            }
            ChallengeParams::Possession {
                cert_name,
                signature,
            } => {
                let mut m = serde_json::Map::new();
                m.insert("cert_name".to_string(), cert_name.clone().into());
                m.insert(
                    "signature".to_string(),
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(signature)
                        .into(),
                );
                m
            }
            ChallengeParams::Custom { parameters, .. } => parameters.clone(),
            ChallengeParams::Raw(map) => map.clone(),
        }
    }
}

pub struct EnrollConfig {
    /// Should end with `/KEY/v=<n>`.
    pub name: Name,
    pub ca_prefix: Name,
    pub validity_secs: u64,
    pub challenge: ChallengeParams,
    /// PIB path; ephemeral when `None`.
    pub storage: Option<std::path::PathBuf>,
}

/// Always errors with `Enrollment(...)` — use [`NdncertClient`] for the
/// connected exchange.
pub async fn run_enrollment(config: EnrollConfig) -> Result<Identity, IdentityError> {
    let manager = SecurityManager::new();

    let key_name = manager.generate_ed25519(config.name.clone())?;
    let signer = manager.get_signer_sync(&key_name)?;

    let mut session = EnrollmentSession::new(config.name.clone(), signer, config.validity_secs);

    let new_body = session.new_request_body().await?;
    let _ = new_body;

    Err(IdentityError::Enrollment(
        "direct enrollment requires a connected CA; use NdncertClient for network enrollment"
            .to_string(),
    ))
}

/// Connected NDNCERT client driving an `ndn-app::Consumer`.
pub struct NdncertClient {
    consumer: ndn_app::Consumer,
    ca_prefix: Name,
}

impl NdncertClient {
    pub fn new(consumer: ndn_app::Consumer, ca_prefix: Name) -> Self {
        Self {
            consumer,
            ca_prefix,
        }
    }

    pub async fn fetch_ca_profile(&mut self) -> Result<ndn_cert::CaProfile, IdentityError> {
        let info_name = self.ca_prefix.clone().append("CA").append("INFO");
        let data = self.consumer.fetch(info_name).await?;
        let content = data.content().ok_or_else(|| {
            IdentityError::Enrollment("CA INFO response has no content".to_string())
        })?;
        let profile: ndn_cert::CaProfile = serde_json::from_slice(content)
            .map_err(|e| IdentityError::Enrollment(e.to_string()))?;
        Ok(profile)
    }

    /// Drives INFO → NEW → CHALLENGE → cert-fetch and returns the issued cert.
    pub async fn enroll(
        &mut self,
        name: Name,
        signer: Arc<dyn Signer>,
        validity_secs: u64,
        challenge: ChallengeParams,
    ) -> Result<ndn_security::Certificate, IdentityError> {
        let mut session = EnrollmentSession::new(name.clone(), Arc::clone(&signer), validity_secs);

        let new_body = session.new_request_body().await?;
        let new_name = self
            .ca_prefix
            .clone()
            .append("CA")
            .append("NEW")
            .append_version(now_ms());

        let new_data = self
            .consumer
            .fetch_with(InterestBuilder::new(new_name).app_parameters(new_body))
            .await?;
        let new_content = new_data
            .content()
            .ok_or_else(|| IdentityError::Enrollment("NEW response has no content".to_string()))?;
        session.handle_new_response(new_content)?;

        let request_id_raw = session
            .request_id_bytes()
            .ok_or_else(|| IdentityError::Enrollment("no request_id from CA".to_string()))?
            .to_vec();

        let challenge_type = challenge.challenge_type().to_string();
        let params = challenge.to_map();
        let challenge_body = session.challenge_request_body(&challenge_type, params)?;
        let challenge_name = self
            .ca_prefix
            .clone()
            .append("CA")
            .append("CHALLENGE")
            .append(&request_id_raw);

        let challenge_data = self
            .consumer
            .fetch_with(InterestBuilder::new(challenge_name).app_parameters(challenge_body))
            .await?;
        let challenge_content = challenge_data.content().ok_or_else(|| {
            IdentityError::Enrollment("CHALLENGE response has no content".to_string())
        })?;
        session.handle_challenge_response(challenge_content)?;

        if !session.is_complete() {
            return Err(IdentityError::Enrollment(
                "enrollment did not complete in one round".to_string(),
            ));
        }

        let cert_name = session
            .issued_cert_name()
            .ok_or_else(|| {
                IdentityError::Enrollment("no issued cert name after completion".to_string())
            })?
            .clone();

        let cert_data = self.consumer.fetch(cert_name).await?;
        let cert_bytes = cert_data.content().ok_or_else(|| {
            IdentityError::Enrollment("cert fetch response has no content".to_string())
        })?;

        ndn_cert::ca::deserialize_cert(cert_bytes).ok_or_else(|| {
            IdentityError::Enrollment("could not decode issued certificate".to_string())
        })
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
