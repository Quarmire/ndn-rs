//! Auto-approve every request. Demos and integration tests only — production
//! deployments use [`pin`](super::pin), [`token`](super::token),
//! [`email`](super::email), or [`possession`](super::possession).

use std::{future::Future, pin::Pin};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

#[derive(Default, Clone, Copy)]
pub struct NopChallenge;

impl NopChallenge {
    pub fn new() -> Self {
        Self
    }
}

impl ChallengeHandler for NopChallenge {
    fn challenge_type(&self) -> &'static str {
        "nop"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "nop".to_string(),
                data: serde_json::Value::Null,
            })
        })
    }

    fn verify<'a>(
        &'a self,
        _state: &'a ChallengeState,
        _parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(async move { Ok(ChallengeOutcome::Approved { attestation: None }) })
    }
}
