//! NDNCERT PIN/OTP challenge. Client submits `{ "code": "<pin>" }`; CA
//! compares its SHA-256 against the stored hash (plaintext PIN is never
//! retained). Pairs with YubiKey HOTP (slot 2) for headless bootstrap;
//! set `max_tries = 1` for HOTP so each code is single-use.

use std::{future::Future, pin::Pin};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

pub struct PinChallenge {
    pin_hash: [u8; 32],
    max_tries: u8,
}

impl PinChallenge {
    pub fn new(pin: &str) -> Self {
        Self::new_with_max_tries(pin, 3)
    }

    pub fn new_with_max_tries(pin: &str, max_tries: u8) -> Self {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(pin.as_bytes());
        Self {
            pin_hash: hash.into(),
            max_tries,
        }
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
        use sha2::Digest;

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
                None => {
                    return Ok(ChallengeOutcome::Denied(
                        "missing 'code' parameter".to_string(),
                    ));
                }
            };

            let submitted_hash = sha2::Sha256::digest(code.as_bytes());
            let matches = submitted_hash.as_slice() == pin_hash;

            if matches {
                Ok(ChallengeOutcome::Approved { attestation: None })
            } else if remaining_tries <= 1 {
                Ok(ChallengeOutcome::Denied(
                    "PIN verification failed: no attempts remaining".to_string(),
                ))
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
