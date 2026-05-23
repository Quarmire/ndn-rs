//! Pluggable challenge framework for NDNCERT.

pub mod combinator;
pub mod device_approval;
pub mod email;
pub mod nop;
pub mod pin;
pub mod possession;
pub mod token;
#[cfg(feature = "yubikey-challenge")]
pub mod yubikey;

use std::{future::Future, pin::Pin};

use crate::{
    attestation::{AttestationSet, ChallengeAttestation},
    error::CertError,
    protocol::CertRequest,
};

/// Opaque per-challenge state stored by the CA between request steps.
#[derive(Debug, Clone)]
pub struct ChallengeState {
    pub challenge_type: String,
    pub data: serde_json::Value,
}

#[derive(Debug)]
pub enum ChallengeOutcome {
    /// The challenge passed. `attestation` is the evidence to embed in the
    /// issued cert (when the CA has `emit_attestations` enabled); `None`
    /// lets the CA synthesise a kind-only leaf from [`challenge_type`].
    ///
    /// Handlers provide attestation *here*, at satisfaction time, because
    /// composite handlers (`any-of`) lose the satisfying sub's context by
    /// the time the CA could ask for it.
    ///
    /// [`challenge_type`]: ChallengeHandler::challenge_type
    Approved {
        attestation: Option<AttestationSet>,
    },
    /// Another CHALLENGE round required (e.g. email: code sent, awaiting submission).
    Pending {
        status_message: String,
        remaining_tries: u8,
        remaining_time_secs: u32,
        next_state: ChallengeState,
    },
    Denied(String),
}

pub trait ChallengeHandler: Send + Sync {
    /// e.g. `"possession"`, `"token"`, `"pin"`, `"email"`.
    fn challenge_type(&self) -> &'static str;

    /// Called once on the first CHALLENGE request; the returned state is
    /// passed back to [`verify`](Self::verify) on each round.
    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>>;

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>>;
}

/// The leaves of `attestation`, or a single kind-only leaf naming
/// `fallback_kind` when a sub-handler supplied no attestation. Used by
/// composite handlers to assemble per-sub leaves.
pub(crate) fn leaves_or_default(
    attestation: Option<AttestationSet>,
    fallback_kind: &str,
) -> Vec<ChallengeAttestation> {
    match attestation {
        Some(set) => set.leaves,
        None => vec![ChallengeAttestation::of_kind(fallback_kind)],
    }
}
