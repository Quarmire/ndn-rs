//! One-time token challenge. Tokens are provisioned out-of-band and consumed
//! on successful use.
//!
//! Each minted token carries optional bounds that shrink a leaked QR's blast
//! radius (see `trust-context-model-2026-05-25.md` §6):
//!
//! - **Single-use** — [`consume`](TokenStore::consume) removes on success, so a
//!   redeemed token is inert. A store built with
//!   [`with_store`](TokenStore::with_store) also records each redemption (as a
//!   hash) in the CA's [`CaStore`] before approving it, and drops tokens
//!   recorded there when they are added again, so a token stays spent across
//!   CA restarts even while it is still listed in the configuration.
//! - **TTL** — an expired token is rejected (and reaped) at challenge time.
//! - **Name scope** — a token authorizes a cert only under a constrained name
//!   prefix; a request for a name outside the scope is rejected. A redeemed
//!   scoped token's attestation leaf records the scope (evidence
//!   [`TOKEN_SCOPE_EVIDENCE`](crate::policy::TOKEN_SCOPE_EVIDENCE)), so an
//!   issuance policy such as [`RolePolicy`](crate::RolePolicy) can tell a
//!   guest invite from a member invite.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use dashmap::{DashMap, DashSet};
use ndn_packet::Name;

use crate::{
    attestation::{AttestationSet, ChallengeAttestation},
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    policy::TOKEN_SCOPE_EVIDENCE,
    protocol::CertRequest,
    roles::{Role, role_prefix, token_expiry, token_role},
    store::CaStore,
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
    /// Valid, but the redemption could not be persisted; the token was not
    /// consumed (fail closed: an unrecorded redemption would be reusable
    /// after a restart).
    NotRecorded(String),
}

/// An invite token of a role a namespace CA certifies only on an admin's
/// approval ([`TokenStore::add_invite_tokens`]).
#[derive(Debug, thiserror::Error)]
#[error(
    "[ca] token '{token}' names the {role} role, but a namespace CA never issues \
     {role} certificates on a token alone; remove it from the config. A {role} \
     device asks with `ndn-fwd enroll <anchor link> --role {role}` and an admin \
     approves it (`ndn-fwd approvals approve <code>`)"
)]
pub struct ApprovalRoleToken {
    pub token: String,
    pub role: Role,
}

#[derive(Default, Clone)]
pub struct TokenStore {
    tokens: Arc<DashMap<String, TokenMeta>>,
    /// Hashes ([`token_hash`]) of redeemed tokens; tracked only with `persist`.
    redeemed: Arc<DashSet<String>>,
    /// Durable record of redemptions; `None` keeps them in memory only.
    persist: Option<Arc<dyn CaStore>>,
}

/// What a redemption is persisted as: hex SHA-256 over the domain-separated
/// token, so the store never holds a usable token.
fn token_hash(token: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ndncert-token-redemption/v1\0");
    h.update(token.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
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

    /// A store whose redemptions persist in `store`: the tokens it recorded
    /// as redeemed (in an earlier run) are refused when added, and every new
    /// redemption is recorded before it is approved.
    pub fn with_store(store: Arc<dyn CaStore>) -> Result<Self, CertError> {
        let redeemed = DashSet::new();
        for hash in store.redeemed_tokens()? {
            redeemed.insert(hash);
        }
        Ok(Self {
            tokens: Arc::default(),
            redeemed: Arc::new(redeemed),
            persist: Some(store),
        })
    }

    /// Add an unbounded token (no TTL, no scope) — back-compat.
    pub fn add(&self, token: impl Into<String>) {
        self.insert(token.into(), TokenMeta::default());
    }

    pub fn add_many(&self, tokens: impl IntoIterator<Item = impl Into<String>>) {
        for t in tokens {
            self.add(t);
        }
    }

    /// Mint a token bounded by an optional TTL and/or name scope.
    pub fn add_scoped(&self, token: impl Into<String>, ttl: Option<Duration>, scope: Option<Name>) {
        let expires_at_ns = ttl.map(|d| now_ns().saturating_add(d.as_nanos() as u64));
        self.insert(
            token.into(),
            TokenMeta {
                expires_at_ns,
                scope,
            },
        );
    }

    /// Add the CA's invite `tokens`. A token naming a role (`member-…`,
    /// `guest-…`, as `ndn-fwd-tokens new --role` mints them) is scoped to
    /// `<namespace>/<role>`: it certifies only names under that prefix; one
    /// minted with an expiry ([`token_expiry`]) is redeemable until then
    /// (past: refused). Other tokens are unscoped, except on a namespace
    /// CA (`namespace_ca`).
    ///
    /// On a namespace CA the issuance policy ([`RolePolicy`](crate::RolePolicy))
    /// admits a token only for a member or a guest, after the challenge has
    /// consumed it. So every token is scoped there: the scope check refuses a
    /// request the policy would refuse *before* the token is spent. Unscoped
    /// tokens are scoped to `<namespace>/member` (the only role the policy
    /// grants them), and `admin-…` / `node-…` tokens, which could never issue
    /// anything, are refused ([`ApprovalRoleToken`]; the tokens before it
    /// are added).
    pub fn add_invite_tokens(
        &self,
        tokens: impl IntoIterator<Item = impl AsRef<str>>,
        namespace: &Name,
        namespace_ca: bool,
    ) -> Result<(), ApprovalRoleToken> {
        for token in tokens {
            let token = token.as_ref();
            let role = match token_role(token) {
                Some(role @ (Role::Admin | Role::Node)) if namespace_ca => {
                    return Err(ApprovalRoleToken {
                        token: token.to_string(),
                        role,
                    });
                }
                None if namespace_ca => Some(Role::Member),
                role => role,
            };
            let ttl = token_expiry(token).map(|at| {
                let now = now_ns() / 1_000_000_000;
                Duration::from_secs(at.saturating_sub(now))
            });
            self.add_scoped(token, ttl, role.map(|role| role_prefix(namespace, role)));
        }
        Ok(())
    }

    fn insert(&self, token: String, meta: TokenMeta) {
        if !self.redeemed.is_empty() && self.redeemed.contains(&token_hash(&token)) {
            tracing::debug!("token challenge: skipping a token that was already redeemed");
            return;
        }
        self.tokens.insert(token, meta);
    }

    /// Single-use consume with no scope check. Expired tokens are reaped and
    /// rejected. Returns `true` only on [`TokenCheck::Ok`].
    pub fn consume(&self, token: &str) -> bool {
        matches!(self.check_and_consume(token, None), TokenCheck::Ok)
    }

    /// [`consume`](Self::consume), telling why a refused token was refused.
    pub fn redeem(&self, token: &str) -> TokenCheck {
        self.check_and_consume(token, None)
    }

    /// Whether `token` is issued, unexpired and unredeemed (consumes nothing).
    pub fn is_live(&self, token: &str) -> bool {
        self.tokens
            .get(token)
            .is_some_and(|m| m.expires_at_ns.is_none_or(|exp| now_ns() <= exp))
    }

    /// Single-use consume enforcing TTL and (if set) that `request_name` is
    /// under the token's scope. The token is consumed only when valid and
    /// in-scope; an out-of-scope or expired token is *not* silently accepted.
    pub fn consume_for(&self, token: &str, request_name: &Name) -> TokenCheck {
        self.check_and_consume(token, Some(request_name))
    }

    /// The name scope of the live token `token`, if it has one.
    pub fn scope_of(&self, token: &str) -> Option<Name> {
        self.tokens.get(token).and_then(|m| m.scope.clone())
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
        // Claim the token atomically: of two concurrent redemptions only one
        // removes it.
        let Some((token_owned, meta)) = self.tokens.remove(token) else {
            return TokenCheck::NotFound;
        };
        if let Some(store) = &self.persist {
            let hash = token_hash(token);
            if let Err(e) = store.record_redeemed_token(&hash) {
                tracing::error!(error = %e, "token challenge: could not persist redemption");
                self.tokens.insert(token_owned, meta);
                return TokenCheck::NotRecorded(e.to_string());
            }
            self.redeemed.insert(hash);
        }
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
            let scope = self.store.scope_of(&t);
            let check = match &request_name {
                Some(name) => self.store.consume_for(&t, name),
                None if self.store.consume(&t) => TokenCheck::Ok,
                None => TokenCheck::NotFound,
            };
            match check {
                TokenCheck::Ok => Ok(ChallengeOutcome::Approved {
                    attestation: scope.map(|scope| {
                        AttestationSet::single(ChallengeAttestation::of_kind("token").with_evidence(
                            TOKEN_SCOPE_EVIDENCE,
                            serde_json::Value::String(scope.to_string()),
                        ))
                    }),
                }),
                TokenCheck::Expired => Ok(ChallengeOutcome::Denied("token expired".to_string())),
                TokenCheck::OutOfScope(scope) => Ok(ChallengeOutcome::Denied(format!(
                    "token is scoped to {scope}; requested name is outside it"
                ))),
                TokenCheck::NotFound => Ok(ChallengeOutcome::Denied(
                    "invalid or already-redeemed token".to_string(),
                )),
                TokenCheck::NotRecorded(_) => Ok(ChallengeOutcome::Denied(
                    "the CA could not record the token redemption; try again".to_string(),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::token_with_expiry;

    fn ns() -> Name {
        "/home/bob".parse().unwrap()
    }

    /// On a namespace CA an admin or node token could never issue anything,
    /// so it is refused instead of letting requests spend it.
    #[test]
    fn a_namespace_ca_refuses_admin_and_node_tokens() {
        for t in ["admin-a1", "node-n1"] {
            let err = TokenStore::new().add_invite_tokens([t], &ns(), true).unwrap_err();
            assert_eq!(err.token, t);
            assert!(err.to_string().contains("never issues"), "{err}");
            assert!(TokenStore::new().add_invite_tokens([t], &ns(), false).is_ok(), "{t}");
        }
    }

    /// A role token is scoped to its role; an untagged one is unscoped,
    /// except on a namespace CA, where it is a member token.
    #[test]
    fn invite_tokens_are_scoped_by_role() {
        let store = TokenStore::new();
        store
            .add_invite_tokens(["guest-g1", "invite-1"], &ns(), true)
            .unwrap();
        assert_eq!(store.scope_of("guest-g1"), Some("/home/bob/guest".parse().unwrap()));
        assert_eq!(store.scope_of("invite-1"), Some("/home/bob/member".parse().unwrap()));
        let store = TokenStore::new();
        store
            .add_invite_tokens(["guest-g1", "invite-1"], &ns(), false)
            .unwrap();
        assert_eq!(store.scope_of("guest-g1"), Some("/home/bob/guest".parse().unwrap()));
        assert_eq!(store.scope_of("invite-1"), None);
    }

    /// A token minted with an expiry is redeemable until then, not after.
    #[test]
    fn invite_tokens_carry_their_expiry() {
        let past = token_with_expiry("member-m1", 1);
        let future = token_with_expiry("member-m2", u64::from(u32::MAX));
        let store = TokenStore::new();
        store.add_invite_tokens([&past, &future], &ns(), true).unwrap();
        assert!(!store.is_live(&past));
        assert!(store.is_live(&future));
    }
}
