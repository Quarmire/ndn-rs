//! One-time token challenge. Tokens are provisioned out-of-band and consumed
//! on successful use.
//!
//! Each minted token carries optional bounds that shrink a leaked QR's blast
//! radius (see `trust-context-model-2026-05-25.md` §6):
//!
//! - **Single-use** — [`consume`](TokenStore::consume) removes on success, so a
//!   redeemed token is inert.
//! - **TTL** — an expired token is rejected (and reaped) at challenge time.
//! - **Name scope** — a token authorizes a cert only under a constrained name
//!   prefix; a request for a name outside the scope is rejected.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use dashmap::DashMap;
use ndn_packet::Name;

use crate::{
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    protocol::CertRequest,
};

/// Bounds attached to a minted token.
#[derive(Clone, Debug, Default)]
struct TokenMeta {
    /// Absolute expiry in ns since the Unix epoch; `None` = never expires.
    expires_at_ns: Option<u64>,
    /// Name prefix the issued cert must fall under; `None` = unscoped.
    scope: Option<Name>,
}

/// Outcome of checking a presented token against the store.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenCheck {
    /// Valid and consumed.
    Ok,
    /// Not in the store (never issued, or already redeemed).
    NotFound,
    /// Past its TTL (reaped on this check).
    Expired,
    /// The requested name is not under the token's scope (boxed: a `Name` is
    /// much larger than the other variants).
    OutOfScope(Box<Name>),
}

#[derive(Default, Clone)]
pub struct TokenStore {
    tokens: Arc<DashMap<String, TokenMeta>>,
}

fn now_ns() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

impl TokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an unbounded token (no TTL, no scope) — back-compat.
    pub fn add(&self, token: impl Into<String>) {
        self.tokens.insert(token.into(), TokenMeta::default());
    }

    pub fn add_many(&self, tokens: impl IntoIterator<Item = impl Into<String>>) {
        for t in tokens {
            self.add(t);
        }
    }

    /// Mint a token bounded by an optional TTL and/or name scope.
    pub fn add_scoped(&self, token: impl Into<String>, ttl: Option<Duration>, scope: Option<Name>) {
        let expires_at_ns = ttl.map(|d| now_ns().saturating_add(d.as_nanos() as u64));
        self.tokens.insert(
            token.into(),
            TokenMeta {
                expires_at_ns,
                scope,
            },
        );
    }

    /// Single-use consume with no scope check. Expired tokens are reaped and
    /// rejected. Returns `true` only on [`TokenCheck::Ok`].
    pub fn consume(&self, token: &str) -> bool {
        matches!(self.check_and_consume(token, None), TokenCheck::Ok)
    }

    /// Single-use consume enforcing TTL and (if set) that `request_name` is
    /// under the token's scope. The token is consumed only when valid and
    /// in-scope; an out-of-scope or expired token is *not* silently accepted.
    pub fn consume_for(&self, token: &str, request_name: &Name) -> TokenCheck {
        self.check_and_consume(token, Some(request_name))
    }

    fn check_and_consume(&self, token: &str, request_name: Option<&Name>) -> TokenCheck {
        let Some(meta) = self.tokens.get(token).map(|r| r.value().clone()) else {
            return TokenCheck::NotFound;
        };
        if let Some(exp) = meta.expires_at_ns
            && now_ns() > exp
        {
            self.tokens.remove(token);
            return TokenCheck::Expired;
        }
        if let Some(scope) = &meta.scope {
            let in_scope = request_name.map(|n| n.has_prefix(scope)).unwrap_or(false);
            if !in_scope {
                return TokenCheck::OutOfScope(Box::new(scope.clone()));
            }
        }
        self.tokens.remove(token);
        TokenCheck::Ok
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
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move {
            // Stash the requested name so `verify` can enforce token scope
            // against it (the requester can't influence this — it's the name
            // they asked to certify).
            Ok(ChallengeState {
                challenge_type: "token".to_string(),
                data: serde_json::json!({ "request_name": req.name }),
            })
        })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        let token = parameters
            .get("token")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let request_name = state
            .data
            .get("request_name")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Name>().ok());
        Box::pin(async move {
            let Some(t) = token else {
                return Ok(ChallengeOutcome::Denied(
                    "missing 'token' parameter".to_string(),
                ));
            };
            // With a known request name, enforce TTL + scope; without one
            // (e.g. invoked as a combinator sub where the name isn't threaded),
            // fall back to single-use + TTL only — the CA's NamespacePolicy
            // still gates the prefix.
            let check = match &request_name {
                Some(name) => self.store.consume_for(&t, name),
                None if self.store.consume(&t) => TokenCheck::Ok,
                None => TokenCheck::NotFound,
            };
            match check {
                TokenCheck::Ok => Ok(ChallengeOutcome::Approved { attestation: None }),
                TokenCheck::Expired => Ok(ChallengeOutcome::Denied("token expired".to_string())),
                TokenCheck::OutOfScope(scope) => Ok(ChallengeOutcome::Denied(format!(
                    "token is scoped to {scope}; requested name is outside it"
                ))),
                TokenCheck::NotFound => Ok(ChallengeOutcome::Denied(
                    "invalid or already-redeemed token".to_string(),
                )),
            }
        })
    }
}
