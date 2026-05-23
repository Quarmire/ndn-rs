//! One-time token challenge. Tokens are provisioned out-of-band and consumed
//! on successful use.

use std::{future::Future, pin::Pin, sync::Arc};

use dashmap::DashMap;

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

#[derive(Default, Clone)]
pub struct TokenStore {
    tokens: Arc<DashMap<String, ()>>,
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, token: impl Into<String>) {
        self.tokens.insert(token.into(), ());
    }

    pub fn add_many(&self, tokens: impl IntoIterator<Item = impl Into<String>>) {
        for t in tokens {
            self.add(t);
        }
    }

    /// Returns true and removes the token if present.
    pub fn consume(&self, token: &str) -> bool {
        self.tokens.remove(token).is_some()
    }

    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

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
                None => Ok(ChallengeOutcome::Denied(
                    "missing 'token' parameter".to_string(),
                )),
                Some(t) => {
                    if self.store.consume(&t) {
                        Ok(ChallengeOutcome::Approved { attestation: None })
                    } else {
                        Ok(ChallengeOutcome::Denied(
                            "invalid or expired token".to_string(),
                        ))
                    }
                }
            }
        })
    }
}
