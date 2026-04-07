//! Token challenge — client proves identity by submitting a pre-provisioned
//! one-time token.
//!
//! Tokens are issued out-of-band (e.g. at factory time, via a management UI)
//! and are consumed on successful use. This is the primary challenge type for
//! fleet zero-touch provisioning.

use std::{future::Future, pin::Pin, sync::Arc};

use dashmap::DashMap;

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// Thread-safe store of valid one-time enrollment tokens.
#[derive(Default, Clone)]
pub struct TokenStore {
    tokens: Arc<DashMap<String, ()>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a token to the store.
    pub fn add(&self, token: impl Into<String>) {
        self.tokens.insert(token.into(), ());
    }

    /// Add multiple tokens.
    pub fn add_many(&self, tokens: impl IntoIterator<Item = impl Into<String>>) {
        for t in tokens {
            self.add(t);
        }
    }

    /// Check if a token exists and consume it (one-time use).
    pub fn consume(&self, token: &str) -> bool {
        self.tokens.remove(token).is_some()
    }

    /// Number of remaining tokens.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

/// NDNCERT token challenge handler.
pub struct TokenChallenge {
    store: TokenStore,
}

impl TokenChallenge {
    pub fn new(store: TokenStore) -> Self {
        Self { store }
    }
}

impl ChallengeHandler for TokenChallenge {
    fn challenge_type(&self) -> &'static str {
        "token"
    }

    fn begin<'a>(
        &'a self,
        _req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            Ok(ChallengeState {
                challenge_type: "token".to_string(),
                data: serde_json::Value::Null,
            })
        })
    }

    fn verify<'a>(
        &'a self,
        _state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        let token = parameters
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Box::pin(async move {
            match token {
                None => Ok(ChallengeOutcome::Denied("missing 'token' parameter".to_string())),
                Some(t) => {
                    if self.store.consume(&t) {
                        Ok(ChallengeOutcome::Approved)
                    } else {
                        Ok(ChallengeOutcome::Denied("invalid or expired token".to_string()))
                    }
                }
            }
        })
    }
}
