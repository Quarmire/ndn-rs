//! Pluggable challenge framework for NDNCERT.

pub mod possession;
pub mod token;

use std::{future::Future, pin::Pin};

use crate::{error::CertError, protocol::CertRequest};

/// Opaque per-challenge state stored by the CA between request steps.
#[derive(Debug, Clone)]
pub struct ChallengeState {
    pub challenge_type: String,
    pub data: serde_json::Value,
}

/// Outcome returned by [`ChallengeHandler::verify`].
pub enum ChallengeOutcome {
    /// Challenge passed — proceed to issue the certificate.
    Approved,
    /// Challenge failed — reject the request with this reason.
    Denied(String),
}

/// A pluggable challenge handler for the NDNCERT CA.
pub trait ChallengeHandler: Send + Sync {
    /// The challenge type identifier (e.g. `"possession"`, `"token"`).
    fn challenge_type(&self) -> &'static str;

    /// Prepare initial challenge state for a new enrollment request.
    ///
    /// Called when the CA selects this challenge for a request. The returned
    /// [`ChallengeState`] is stored and passed back to [`verify`](Self::verify).
    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>>;

    /// Verify the client's challenge response.
    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>>;
}
