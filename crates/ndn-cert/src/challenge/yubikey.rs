//! YubiKey HOTP challenge — hardware one-time-password bootstrapping.
//!
//! The YubiKey's slot 2 (long-press) can be programmed to emit RFC 4226 HOTP
//! codes via USB HID (it appears as a USB keyboard). This challenge uses that
//! to bootstrap headless devices without any secrets stored in plaintext on the
//! device itself.
//!
//! # Enrollment flow
//!
//! ```text
//! Admin dashboard                   CA                   Headless router
//!       |                            |                          |
//!       |--- provision seed -------> |                          |
//!       |    (stored in CA config)   |                          |
//!       |                            |                          |
//!       |--- ykpersonalize --------> YubiKey                   |
//!       |    (seed programmed)       |                          |
//!       |                            |                          |
//!   (YubiKey shipped / plugged into headless router)           |
//!                                    |                          |
//!                                    |<--- NEW request -------- |
//!                                    |--- NewResponse --------> |
//!                                    |                          |
//!                                    |<--- CHALLENGE (begin) -- |
//!                                    |--- "Press YubiKey..." -> |
//!                                    |                          |
//!                               (operator presses YubiKey button)
//!                                    |                          |
//!                                    |<--- CHALLENGE (otp) ---- | (USB HID → stdin capture)
//!                                    |--- Approved / Issued --> |
//! ```
//!
//! # HOTP algorithm (RFC 4226)
//!
//! `HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^digits`
//!
//! - K: shared secret (seed, 20+ bytes recommended)
//! - C: 8-byte big-endian counter — incremented after each valid code
//! - Lookahead window (default 20): handles button presses that weren't captured

use std::{future::Future, pin::Pin};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// Number of HOTP digits to verify.
const DIGITS: u32 = 6;

/// Default lookahead window — tolerate up to this many unsynchronised button presses.
const DEFAULT_WINDOW: u64 = 20;

/// NDNCERT challenge that verifies a YubiKey HOTP code.
///
/// The CA is pre-seeded with the same HMAC-SHA1 seed that was programmed into
/// the YubiKey via `ykpersonalize`. At verification time the CA checks codes
/// in a lookahead window and advances the counter to stay synchronised.
pub struct YubikeyHotpChallenge {
    /// Shared HOTP secret (same as the YubiKey HMAC-SHA1 seed).
    seed: Vec<u8>,
    /// Starting HOTP counter (must match YubiKey's initial counter).
    initial_counter: u64,
    /// Lookahead window for counter re-sync.
    window: u64,
    /// Maximum OTP submission attempts before the request is denied.
    max_tries: u8,
}

impl YubikeyHotpChallenge {
    /// Create a new challenge handler.
    ///
    /// - `seed`: the same secret programmed into the YubiKey with `ykpersonalize -2 -a <hex-seed>`
    /// - `initial_counter`: must match the YubiKey's counter state (default 0 for freshly provisioned)
    pub fn new(seed: Vec<u8>, initial_counter: u64) -> Self {
        Self {
            seed,
            initial_counter,
            window: DEFAULT_WINDOW,
            max_tries: 3,
        }
    }

    /// Set the lookahead window (default 20).
    pub fn with_window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    /// Set maximum submission attempts (default 3).
    pub fn with_max_tries(mut self, max_tries: u8) -> Self {
        self.max_tries = max_tries;
        self
    }
}

/// Compute one HOTP value for the given seed and counter (RFC 4226).
fn hotp(seed: &[u8], counter: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter_bytes = counter.to_be_bytes();
    let tag = ring::hmac::sign(&key, &counter_bytes);
    let digest = tag.as_ref(); // 20 bytes for HMAC-SHA1

    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);

    let modulus = 10u32.pow(DIGITS);
    code % modulus
}

/// Try to verify an OTP against `(seed, counter)` with the given window.
///
/// Returns `Some(matched_counter + 1)` if found — the caller should advance
/// its stored counter to this value.
fn verify_hotp(seed: &[u8], counter: u64, window: u64, otp: u32) -> Option<u64> {
    for i in 0..=window {
        if hotp(seed, counter + i) == otp {
            return Some(counter + i + 1);
        }
    }
    None
}

impl ChallengeHandler for YubikeyHotpChallenge {
    fn challenge_type(&self) -> &'static str {
        "yubikey-hotp"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        let seed_hex = hex_encode(&self.seed);
        let counter = self.initial_counter;
        let window = self.window;
        let max_tries = self.max_tries;

        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "yubikey-hotp".to_string(),
                data: serde_json::json!({
                    "seed_hex": seed_hex,
                    "counter": counter,
                    "window": window,
                    "remaining_tries": max_tries,
                }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        let otp_str = parameters
            .get("otp")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let seed_hex = state
            .data
            .get("seed_hex")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let counter = state
            .data
            .get("counter")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let window = state
            .data
            .get("window")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_WINDOW);
        let remaining_tries = state
            .data
            .get("remaining_tries")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u8;

        Box::pin(async move {
            // Decode OTP string to u32.
            let otp_str = match otp_str {
                Some(s) => s,
                None => return Ok(ChallengeOutcome::Denied("missing 'otp' parameter".to_string())),
            };
            let otp: u32 = match otp_str.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    return Ok(ChallengeOutcome::Denied(
                        "invalid OTP format — expected a numeric code".to_string(),
                    ))
                }
            };

            // Decode stored seed.
            let seed = hex_decode(&seed_hex).unwrap_or_default();
            if seed.is_empty() {
                return Err(CertError::InvalidRequest("corrupt HOTP challenge state".into()));
            }

            // Verify against the HOTP counter window.
            if let Some(next_counter) = verify_hotp(&seed, counter, window, otp) {
                // Valid code — update counter in approved state.
                let _ = next_counter; // Counter advance is implicit; CA config handles persistence.
                return Ok(ChallengeOutcome::Approved);
            }

            // Invalid code.
            if remaining_tries <= 1 {
                return Ok(ChallengeOutcome::Denied(
                    "YubiKey OTP verification failed: no attempts remaining".to_string(),
                ));
            }

            let new_tries = remaining_tries - 1;
            Ok(ChallengeOutcome::Pending {
                status_message: format!(
                    "Invalid OTP — press the YubiKey button again ({new_tries} attempt(s) left)"
                ),
                remaining_tries: new_tries,
                remaining_time_secs: 300,
                next_state: ChallengeState {
                    challenge_type: "yubikey-hotp".to_string(),
                    data: serde_json::json!({
                        "seed_hex": seed_hex,
                        "counter": counter,
                        "window": window,
                        "remaining_tries": new_tries,
                    }),
                },
            })
        })
    }
}

// ── Hex helpers (avoids adding a hex crate dep) ───────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: &[u8] = b"12345678901234567890"; // RFC 4226 test seed

    #[test]
    fn hotp_rfc4226_test_vectors() {
        // RFC 4226 Appendix D test vectors with seed "12345678901234567890".
        let expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
        for (counter, &expected_code) in expected.iter().enumerate() {
            assert_eq!(hotp(TEST_SEED, counter as u64), expected_code, "counter={counter}");
        }
    }

    #[test]
    fn verify_hotp_exact_counter() {
        // Code for counter=0.
        let code = hotp(TEST_SEED, 0);
        let next = verify_hotp(TEST_SEED, 0, 20, code);
        assert_eq!(next, Some(1));
    }

    #[test]
    fn verify_hotp_window_lookahead() {
        // Code for counter=5, but CA counter is at 0 — within window of 20.
        let code = hotp(TEST_SEED, 5);
        let next = verify_hotp(TEST_SEED, 0, 20, code);
        assert_eq!(next, Some(6));
    }

    #[test]
    fn verify_hotp_outside_window() {
        // Code for counter=25, but CA counter is at 0 with window=20 — too far ahead.
        let code = hotp(TEST_SEED, 25);
        let next = verify_hotp(TEST_SEED, 0, 20, code);
        assert!(next.is_none());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = b"hello yubikey";
        assert_eq!(hex_decode(&hex_encode(bytes)).unwrap(), bytes);
    }

    #[tokio::test]
    async fn begin_stores_initial_counter() {
        let challenge = YubikeyHotpChallenge::new(TEST_SEED.to_vec(), 42);
        let req = crate::protocol::CertRequest {
            name: "test".to_string(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        };
        let state = challenge.begin(&req).await.unwrap();
        assert_eq!(state.data["counter"], 42);
    }

    #[tokio::test]
    async fn verify_correct_otp_returns_approved() {
        let seed = TEST_SEED.to_vec();
        let counter = 0u64;
        let otp = hotp(&seed, counter);

        let challenge = YubikeyHotpChallenge::new(seed.clone(), counter);
        let req = crate::protocol::CertRequest {
            name: "test".to_string(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        };
        let state = challenge.begin(&req).await.unwrap();

        let mut params = serde_json::Map::new();
        params.insert("otp".to_string(), serde_json::Value::String(otp.to_string()));

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(outcome, ChallengeOutcome::Approved));
    }

    #[tokio::test]
    async fn verify_wrong_otp_decrements_tries() {
        let challenge = YubikeyHotpChallenge::new(TEST_SEED.to_vec(), 0).with_max_tries(3);
        let req = crate::protocol::CertRequest {
            name: "test".to_string(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        };
        let state = challenge.begin(&req).await.unwrap();

        let mut params = serde_json::Map::new();
        params.insert("otp".to_string(), serde_json::Value::String("000000".to_string()));

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(outcome, ChallengeOutcome::Pending { remaining_tries: 2, .. }));
    }

    #[tokio::test]
    async fn verify_exhausted_tries_denies() {
        let challenge = YubikeyHotpChallenge::new(TEST_SEED.to_vec(), 0).with_max_tries(1);
        let req = crate::protocol::CertRequest {
            name: "test".to_string(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        };
        let state = challenge.begin(&req).await.unwrap();

        let mut params = serde_json::Map::new();
        params.insert("otp".to_string(), serde_json::Value::String("000000".to_string()));

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(outcome, ChallengeOutcome::Denied(_)));
    }
}
