//! [`NdncertClient`]: the `ndn-app::Consumer`-backed NDNCERT client — a
//! [`CaExchange`] over a consumer connection driving the shared
//! [`ndn_cert::client::enroll`] NEW → CHALLENGE driver.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{CaExchange, CertError};
use ndn_packet::{Data, Name};
use ndn_security::Signer;

use crate::error::IdentityError;

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

/// Connected NDNCERT client over an `ndn-app::Consumer`.
pub struct NdncertClient {
    consumer: ndn_app::Consumer,
    ca_prefix: Name,
}

impl CaExchange for NdncertClient {
    async fn express(&mut self, interest: Bytes) -> Result<Data, CertError> {
        self.consumer
            .fetch_wire(interest, ndn_app::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| CertError::Transport(e.to_string()))
    }
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

    /// Enroll `signer`'s key with a single CHALLENGE round carrying
    /// `challenge`, then fetch and decode the issued cert.
    pub async fn enroll(
        &mut self,
        signer: Arc<dyn Signer>,
        validity_secs: u64,
        challenge: ChallengeParams,
    ) -> Result<ndn_security::Certificate, IdentityError> {
        let ca_prefix = self.ca_prefix.clone();
        let challenge_type = challenge.challenge_type().to_owned();
        let mut params = Some(challenge.to_map());
        let cert_name = ndn_cert::client::enroll(
            self,
            &ca_prefix,
            signer,
            validity_secs,
            &challenge_type,
            |_| std::future::ready(Ok(params.take())),
        )
        .await?;

        let cert_data =
            ndn_cert::client::fetch_issued_cert_via(self, &ca_prefix, &cert_name).await?;
        Ok(ndn_security::Certificate::decode(&cert_data)?)
    }
}
