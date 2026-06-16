//! YubiKey HOTP challenge — RFC 4226 HMAC-SHA1 OTP submitted as
//! `{ "otp": "<digits>" }`. Slot 2 of the YubiKey is provisioned with the
//! same seed (via `ykpersonalize`). The CA scans a lookahead window to
//! tolerate uncaptured button presses.

use std::{future::Future, pin::Pin};

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

const DIGITS: u32 = 6;
const DEFAULT_WINDOW: u64 = 20;

pub struct YubikeyHotpChallenge {
    seed: Vec<u8>,
    initial_counter: u64,
    window: u64,
    max_tries: u8,
}

impl YubikeyHotpChallenge {
    /// `initial_counter` must match the YubiKey's counter state.
    pub fn new(seed: Vec<u8>, initial_counter: u64) -> Self {
        Self {
            seed,
            initial_counter,
            window: DEFAULT_WINDOW,
            max_tries: 3,
        }
    }

    pub fn with_window(mut self, window: u64) -> Self {
        self.window = window;
        self
    }

    pub fn with_max_tries(mut self, max_tries: u8) -> Self {
        self.max_tries = max_tries;
        self
    }
}

/// RFC 4226 HOTP value.
fn hotp(seed: &[u8], counter: u64) -> u32 {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, seed);
    let counter_bytes = counter.to_be_bytes();
    let tag = ring::hmac::sign(&key, &counter_bytes);
    let digest = tag.as_ref();

    // RFC 4226 §5.3 dynamic truncation.
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

/// Returns `Some(matched_counter + 1)` — the caller should persist this
/// as the new counter.
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
            let otp_str = match otp_str {
                Some(s) => s,
                None => {
                    return Ok(ChallengeOutcome::Denied(
                        "missing 'otp' parameter".to_string(),
                    ));
                }
            };
            let otp: u32 = match otp_str.trim().parse() {
                Ok(n) => n,
                Err(_) => {
                    return Ok(ChallengeOutcome::Denied(
                        "invalid OTP format — expected a numeric code".to_string(),
                    ));
                }
            };

            let seed = hex_decode(&seed_hex).unwrap_or_default();
            if seed.is_empty() {
                return Err(CertError::InvalidRequest(
                    "corrupt HOTP challenge state".into(),
                ));
            }

            if let Some(next_counter) = verify_hotp(&seed, counter, window, otp) {
                let _ = next_counter;
                return Ok(ChallengeOutcome::Approved { attestation: None });
            }

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

    const TEST_SEED: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_rfc4226_test_vectors() {
        // RFC 4226 Appendix D.
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, &expected_code) in expected.iter().enumerate() {
            assert_eq!(
                hotp(TEST_SEED, counter as u64),
                expected_code,
                "counter={counter}"
            );
        }
    }

    #[test]
    fn verify_hotp_exact_counter() {
        let code = hotp(TEST_SEED, 0);
        let next = verify_hotp(TEST_SEED, 0, 20, code);
        assert_eq!(next, Some(1));
    }

    #[test]
    fn verify_hotp_window_lookahead() {
        let code = hotp(TEST_SEED, 5);
        let next = verify_hotp(TEST_SEED, 0, 20, code);
        assert_eq!(next, Some(6));
    }

    #[test]
    fn verify_hotp_outside_window() {
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
        params.insert(
            "otp".to_string(),
            serde_json::Value::String(otp.to_string()),
        );

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(outcome, ChallengeOutcome::Approved { .. }));
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
        params.insert(
            "otp".to_string(),
            serde_json::Value::String("000000".to_string()),
        );

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(
            outcome,
            ChallengeOutcome::Pending {
                remaining_tries: 2,
                ..
            }
        ));
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
        params.insert(
            "otp".to_string(),
            serde_json::Value::String("000000".to_string()),
        );

        let outcome = challenge.verify(&state, &params).await.unwrap();
        assert!(matches!(outcome, ChallengeOutcome::Denied(_)));
    }
}
