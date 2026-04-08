//! Email challenge — CA sends a one-time code to an email address, client submits it.
//!
//! This is the primary challenge type described in the NDNCERT paper (ndn-0050-1).
//! It is a two-round exchange:
//!
//! **Round 1** — First CHALLENGE request: client provides `{ "email": "user@example.com" }`.
//!   CA generates a 6-digit OTP, sends it to the address, stores a hash + expiry, and
//!   responds with `Processing` status.
//!
//! **Round 2** — Second CHALLENGE request: client provides `{ "email": "...", "code": "123456" }`.
//!   CA checks the hash and remaining attempts.
//!
//! # Email delivery
//!
//! The `EmailSender` trait is deliberately transport-agnostic so callers can
//! plug in any delivery mechanism (SMTP via `lettre`, HTTP webhook, mock for tests).

use std::{future::Future, pin::Pin, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use ring::digest::{SHA256, digest};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// Abstraction over email delivery.
pub trait EmailSender: Send + Sync {
    /// Send `code` to `address`. Returns an error string on failure.
    fn send<'a>(
        &'a self,
        address: &'a str,
        code: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// NDNCERT email challenge handler.
pub struct EmailChallenge {
    sender: Arc<dyn EmailSender>,
    /// How long the OTP is valid after being sent, in seconds.
    code_ttl_secs: u32,
    /// Maximum incorrect attempts before the request is denied.
    max_tries: u8,
}

impl EmailChallenge {
    pub fn new(sender: Arc<dyn EmailSender>) -> Self {
        Self {
            sender,
            code_ttl_secs: 300,
            max_tries: 3,
        }
    }

    pub fn with_ttl(mut self, ttl_secs: u32) -> Self {
        self.code_ttl_secs = ttl_secs;
        self
    }

    pub fn with_max_tries(mut self, max_tries: u8) -> Self {
        self.max_tries = max_tries;
        self
    }
}

impl ChallengeHandler for EmailChallenge {
    fn challenge_type(&self) -> &'static str {
        "email"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        let max_tries = self.max_tries;
        let code_ttl_secs = self.code_ttl_secs;
        Box::pin(async move {
            // begin() is called before the first CHALLENGE parameters arrive.
            // We return a state that signals "awaiting email address".
            Ok(ChallengeState {
                challenge_type: "email".to_string(),
                data: serde_json::json!({
                    "phase": "awaiting_email",
                    "remaining_tries": max_tries,
                    "code_ttl_secs": code_ttl_secs,
                }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        let email = parameters
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let code = parameters
            .get("code")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let state = state.clone();
        let sender = Arc::clone(&self.sender);
        let code_ttl_secs = self.code_ttl_secs;

        Box::pin(async move {
            let email = email.ok_or_else(|| {
                CertError::InvalidRequest("missing 'email' parameter".to_string())
            })?;

            let phase = state.data.get("phase").and_then(|v| v.as_str()).unwrap_or("");
            let remaining_tries = state
                .data
                .get("remaining_tries")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u8;

            match phase {
                "awaiting_email" => {
                    // Round 1: send the OTP to the provided email address.
                    let otp = generate_otp();
                    sender
                        .send(&email, &otp)
                        .await
                        .map_err(|e| CertError::InvalidRequest(format!("email send failed: {e}")))?;

                    let otp_hash = sha256_hex(&otp);
                    let expires_at = now_secs() + code_ttl_secs as u64;

                    Ok(ChallengeOutcome::Pending {
                        status_message: format!("Code sent to {email}"),
                        remaining_tries,
                        remaining_time_secs: code_ttl_secs,
                        next_state: ChallengeState {
                            challenge_type: "email".to_string(),
                            data: serde_json::json!({
                                "phase": "awaiting_code",
                                "email": email,
                                "otp_hash": otp_hash,
                                "expires_at": expires_at,
                                "remaining_tries": remaining_tries,
                            }),
                        },
                    })
                }

                "awaiting_code" => {
                    // Round 2: verify the submitted code.
                    let expires_at = state
                        .data
                        .get("expires_at")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    if now_secs() > expires_at {
                        return Ok(ChallengeOutcome::Denied(
                            "email code expired; please restart enrollment".to_string(),
                        ));
                    }

                    let code = match code {
                        Some(c) => c,
                        None => {
                            return Ok(ChallengeOutcome::Denied(
                                "missing 'code' parameter".to_string(),
                            ))
                        }
                    };

                    let stored_hash = state
                        .data
                        .get("otp_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if sha256_hex(&code) == stored_hash {
                        Ok(ChallengeOutcome::Approved)
                    } else if remaining_tries <= 1 {
                        Ok(ChallengeOutcome::Denied(
                            "incorrect code: no attempts remaining".to_string(),
                        ))
                    } else {
                        let new_tries = remaining_tries - 1;
                        let remaining_time = expires_at.saturating_sub(now_secs()) as u32;
                        Ok(ChallengeOutcome::Pending {
                            status_message: format!(
                                "Incorrect code — {new_tries} attempt(s) remaining"
                            ),
                            remaining_tries: new_tries,
                            remaining_time_secs: remaining_time,
                            next_state: ChallengeState {
                                challenge_type: "email".to_string(),
                                data: serde_json::json!({
                                    "phase": "awaiting_code",
                                    "email": email,
                                    "otp_hash": stored_hash,
                                    "expires_at": expires_at,
                                    "remaining_tries": new_tries,
                                }),
                            },
                        })
                    }
                }

                _ => Ok(ChallengeOutcome::Denied("unknown challenge phase".to_string())),
            }
        })
    }
}

/// Generate a 6-digit numeric OTP.
fn generate_otp() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    rng.fill(&mut buf).unwrap_or(());
    let n = u32::from_be_bytes(buf) % 1_000_000;
    format!("{n:06}")
}

/// SHA-256 hash of a string, returned as lowercase hex.
fn sha256_hex(input: &str) -> String {
    let h = digest(&SHA256, input.as_bytes());
    h.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
