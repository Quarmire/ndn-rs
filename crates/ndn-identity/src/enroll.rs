//! NDNCERT enrollment — interactive certificate issuance via the NDNCERT protocol.

use base64::Engine;
use ndn_cert::EnrollmentSession;
use ndn_packet::{Name, encode::InterestBuilder};
use ndn_security::SecurityManager;

use crate::{error::IdentityError, identity::NdnIdentity};

/// Parameters for a specific challenge type.
#[derive(Debug, Clone)]
pub enum ChallengeParams {
    /// Token challenge: submit a pre-provisioned token.
    Token { token: String },
    /// Possession challenge: prove ownership of an existing certificate.
    Possession {
        cert_name: String,
        /// Ed25519 signature over the request_id bytes.
        signature: Vec<u8>,
    },
    /// Raw key-value parameters for custom or future challenge types.
    Raw(serde_json::Map<String, serde_json::Value>),
}

impl ChallengeParams {
    pub fn challenge_type(&self) -> &str {
        match self {
            ChallengeParams::Token { .. } => "token",
            ChallengeParams::Possession { .. } => "possession",
            ChallengeParams::Raw(_) => "raw",
        }
    }

    pub fn to_map(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            ChallengeParams::Token { token } => {
                let mut m = serde_json::Map::new();
                m.insert("token".to_string(), token.clone().into());
                m
            }
            ChallengeParams::Possession { cert_name, signature } => {
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
            ChallengeParams::Raw(map) => map.clone(),
        }
    }
}

/// Configuration for NDNCERT enrollment.
pub struct EnrollConfig {
    /// The NDN name to enroll (should end with `/KEY/v=<n>`).
    pub name: Name,
    /// The CA prefix (e.g. `/com/acme/fleet/CA`).
    pub ca_prefix: Name,
    /// Certificate validity in seconds.
    pub validity_secs: u64,
    /// The challenge response to use.
    pub challenge: ChallengeParams,
    /// Optional storage path for the resulting PIB.
    pub storage: Option<std::path::PathBuf>,
}

/// Run the full NDNCERT enrollment exchange.
///
/// This uses an in-process loopback for now (real network fetch is wired
/// in `NdncertCa::serve`). For external CA enrollment, use a connected Consumer.
pub async fn run_enrollment(config: EnrollConfig) -> Result<NdnIdentity, IdentityError> {
    let manager = SecurityManager::new();

    // Generate the key.
    let key_name = manager.generate_ed25519(config.name.clone())?;
    let signer = manager.get_signer_sync(&key_name)?;
    let pubkey = signer
        .public_key()
        .ok_or_else(|| IdentityError::Enrollment("signer has no public key".to_string()))?;

    // Build the enrollment session.
    let mut session =
        EnrollmentSession::new(config.name.clone(), pubkey.to_vec(), config.validity_secs);

    let new_body = session.new_request_body()?;

    // In a real implementation, this would send an Interest to config.ca_prefix/CA/NEW
    // and receive a Data response. For now this returns an error to signal that
    // a connected CA is required.
    // The NdncertClient (below) provides the connected version.
    let _ = new_body;

    Err(IdentityError::Enrollment(
        "direct enrollment requires a connected CA; use NdncertClient for network enrollment"
            .to_string(),
    ))
}

/// A connected NDNCERT client that exchanges protocol messages over the NDN network.
pub struct NdncertClient {
    consumer: ndn_app::Consumer,
    ca_prefix: Name,
}

impl NdncertClient {
    pub fn new(consumer: ndn_app::Consumer, ca_prefix: Name) -> Self {
        Self { consumer, ca_prefix }
    }

    /// Fetch the CA profile.
    pub async fn fetch_ca_profile(&mut self) -> Result<ndn_cert::CaProfile, IdentityError> {
        let info_name = self.ca_prefix.clone().append("CA").append("INFO");
        let data = self.consumer.fetch(info_name).await?;
        let content = data
            .content()
            .ok_or_else(|| IdentityError::Enrollment("CA INFO response has no content".to_string()))?;
        let profile: ndn_cert::CaProfile = serde_json::from_slice(content)
            .map_err(|e| IdentityError::Enrollment(e.to_string()))?;
        Ok(profile)
    }

    /// Run the full enrollment exchange and return the issued certificate.
    pub async fn enroll(
        &mut self,
        name: Name,
        public_key: Vec<u8>,
        validity_secs: u64,
        challenge: ChallengeParams,
    ) -> Result<ndn_security::Certificate, IdentityError> {
        let mut session = EnrollmentSession::new(name.clone(), public_key, validity_secs);

        // Step 1: NEW
        let new_body = session.new_request_body()?;
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

        let request_id = session
            .request_id()
            .ok_or_else(|| IdentityError::Enrollment("no request_id from CA".to_string()))?
            .to_string();

        // Step 2: CHALLENGE
        let challenge_type = challenge.challenge_type().to_string();
        let params = challenge.to_map();
        let challenge_body = session.challenge_request_body(&challenge_type, params)?;
        let challenge_name = self
            .ca_prefix
            .clone()
            .append("CA")
            .append("CHALLENGE")
            .append(&request_id);

        let challenge_data = self
            .consumer
            .fetch_with(InterestBuilder::new(challenge_name).app_parameters(challenge_body))
            .await?;
        let challenge_content = challenge_data
            .content()
            .ok_or_else(|| {
                IdentityError::Enrollment("CHALLENGE response has no content".to_string())
            })?;
        session.handle_challenge_response(challenge_content)?;

        session
            .into_certificate()
            .ok_or_else(|| IdentityError::Enrollment("no certificate returned".to_string()))
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
