//! PIN/OTP challenge — client proves identity by submitting a pre-shared PIN.
//!
//! The PIN is known to both the CA (pre-provisioned at device manufacture time
//! or via out-of-band admin workflow) and the device operator. It is never stored
//! in plaintext on the CA — only the SHA-256 hash is retained.
//!
//! # YubiKey HOTP integration
//!
//! When paired with a YubiKey configured in HOTP mode (slot 2, long-press), this
//! challenge enables secure headless bootstrapping:
//!
//! 1. Admin provisions the YubiKey HOTP seed via the dashboard (→ `ykpersonalize`)
//! 2. YubiKey is plugged into the headless router
//! 3. Router starts enrollment; enrollment client reads from `stdin`
//! 4. Operator presses the YubiKey button → 44-char OTP emitted via USB HID
//! 5. Enrollment client captures the code and submits it as `{ "code": "..." }`
//! 6. CA verifies hash → certificate issued
//!
//! The `max_tries` limit protects against brute-force; set to 1 for HOTP
//! where each press generates a unique non-replayable code.

use std::{future::Future, pin::Pin};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// NDNCERT PIN/OTP challenge handler.
///
/// Single-round: the client submits `{ "code": "<pin>" }` and the CA checks
/// the SHA-256 hash against the stored value.
pub struct PinChallenge {
    /// SHA-256 hash of the expected PIN/OTP.
    pin_hash: [u8; 32],
    /// Maximum number of incorrect attempts before the request is denied.
    max_tries: u8,
}

impl PinChallenge {
    /// Create a challenge from a plaintext PIN (hashed internally).
    pub fn new(pin: &str) -> Self {
        Self::new_with_max_tries(pin, 3)
    }

    /// Create a challenge with an explicit attempt limit.
    pub fn new_with_max_tries(pin: &str, max_tries: u8) -> Self {
        use ring::digest::{SHA256, digest};
        let hash = digest(&SHA256, pin.as_bytes());
        let mut pin_hash = [0u8; 32];
        pin_hash.copy_from_slice(hash.as_ref());
        Self { pin_hash, max_tries }
    }
}

impl ChallengeHandler for PinChallenge {
    fn challenge_type(&self) -> &'static str {
        "pin"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        let max_tries = self.max_tries;
        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "pin".to_string(),
                data: serde_json::json!({ "remaining_tries": max_tries }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        use ring::digest::{SHA256, digest};

        let code = parameters
            .get("code")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let remaining_tries = state
            .data
            .get("remaining_tries")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u8;
        let pin_hash = self.pin_hash;

        Box::pin(async move {
            let code = match code {
                Some(c) => c,
                None => return Ok(ChallengeOutcome::Denied("missing 'code' parameter".to_string())),
            };

            let submitted_hash = digest(&SHA256, code.as_bytes());
            let matches = submitted_hash.as_ref() == pin_hash;

            if matches {
                Ok(ChallengeOutcome::Approved)
            } else if remaining_tries <= 1 {
                Ok(ChallengeOutcome::Denied("PIN verification failed: no attempts remaining".to_string()))
            } else {
                let new_tries = remaining_tries - 1;
                Ok(ChallengeOutcome::Pending {
                    status_message: format!("Incorrect PIN — {new_tries} attempt(s) remaining"),
                    remaining_tries: new_tries,
                    remaining_time_secs: 300,
                    next_state: ChallengeState {
                        challenge_type: "pin".to_string(),
                        data: serde_json::json!({ "remaining_tries": new_tries }),
                    },
                })
            }
        })
    }
}
