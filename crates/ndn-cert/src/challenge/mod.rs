//! Pluggable challenge framework for NDNCERT.

pub mod email;
pub mod pin;
pub mod possession;
pub mod token;
pub mod yubikey;

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
    /// Challenge requires another round (e.g. email: code was sent, awaiting submission).
    ///
    /// The CA returns this with updated state; the client submits another CHALLENGE
    /// request with the next parameters.
    Pending {
        /// Human-readable status for the client (e.g. "Code sent to user@example.com").
        status_message: String,
        /// How many more attempts the client may make before the request is rejected.
        remaining_tries: u8,
        /// Seconds remaining before the challenge expires.
        remaining_time_secs: u32,
        /// Updated challenge state to store for the next round.
        next_state: ChallengeState,
    },
    /// Challenge failed — reject the request with this reason.
    Denied(String),
}

/// A pluggable challenge handler for the NDNCERT CA.
pub trait ChallengeHandler: Send + Sync {
    /// The challenge type identifier (e.g. `"possession"`, `"token"`, `"pin"`, `"email"`).
    fn challenge_type(&self) -> &'static str;

    /// Prepare initial challenge state for a new enrollment request.
    ///
    /// Called on the first CHALLENGE request for a given enrollment. The returned
    /// [`ChallengeState`] is stored and passed back to [`verify`](Self::verify).
    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>>;

    /// Verify the client's challenge response.
    ///
    /// May return [`ChallengeOutcome::Pending`] to indicate another round is needed
    /// (e.g. the email was sent and the client must submit the code). The CA will
    /// store `next_state` and call `verify` again on the next CHALLENGE request.
    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>>;
}
