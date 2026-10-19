//! One-time token challenge over a CA's invites ([`TokenStore`]). Invites
//! are made at runtime ([`CaInvites::create`](crate::invites::CaInvites::create))
//! and their tokens consumed on successful use.
//!
//! Each token carries bounds that shrink a leaked QR's blast radius (see
//! `trust-context-model-2026-05-25.md` §6):
//!
//! - **Single-use** — a redeemed invite is marked redeemed, so its token is
//!   inert. A store built with [`with_store`](TokenStore::with_store) keeps
//!   its invites in the CA's [`CaStore`] (a hash of each token, never the
//!   token) and records every change there before it takes effect, so an
//!   invite survives a CA restart and a redeemed or withdrawn one stays
//!   refused.
//! - **Expiry** — an expired invite is refused at challenge time.
//! - **Name scope** — a token authorizes a cert only under a constrained name
//!   prefix (`/<ns>/<role>` for an invite); a request for a name outside the
//!   scope is refused without spending the token. A redeemed scoped token's
//!   attestation leaf records the scope (evidence
//!   [`TOKEN_SCOPE_EVIDENCE`]), so an
//!   issuance policy such as [`RolePolicy`](crate::RolePolicy) can tell a
//!   guest invite from a member invite.
//!
//! The challenge's denials start with a stable [`TokenDenial`] code.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use parking_lot::{Mutex, MutexGuard, RwLock};

use ndn_packet::Name;

use crate::{
    approval::now_secs,
    attestation::{AttestationSet, ChallengeAttestation},
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState},
    error::CertError,
    invites::{
        ENDED_INVITE_RETENTION_SECS, InviteEntry, InviteEvent, InviteEventKind, InviteInfo,
        InviteObserver, InviteRecord, InviteState, TokenDenial,
    },
    policy::TOKEN_SCOPE_EVIDENCE,
    protocol::CertRequest,
    roles::{Role, token_expired},
    store::CaStore,
};

/// Outcome of checking a presented token against the store.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenCheck {
    /// Valid and consumed.
    Ok,
    /// Not an invite of this store.
    NotFound,
    /// Redeemed already.
    Redeemed,
    /// Withdrawn by a trust administrator.
    Withdrawn,
    /// Past its expiry.
    Expired,
    /// The requested name is not under the token's scope (boxed: a `Name` is
    /// much larger than the other variants).
    OutOfScope(Box<Name>),
    /// Valid, but the redemption could not be persisted; the token was not
    /// consumed (fail closed: an unrecorded redemption would be reusable
    /// after a restart).
    NotRecorded(String),
}

/// Why [`TokenStore::withdraw`] withdrew nothing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum WithdrawError {
    #[error("no such invite")]
    Unknown,
    #[error("the invite was redeemed already")]
    AlreadyRedeemed(Box<InviteEntry>),
    #[error("the invite was withdrawn already")]
    AlreadyWithdrawn(Box<InviteEntry>),
    #[error("the withdrawal could not be recorded: {0}")]
    NotRecorded(String),
}

/// One invite held in memory: its record and its parsed scope.
struct Entry {
    record: InviteRecord,
    scope: Option<Name>,
}

#[derive(Default)]
struct Inner {
    /// The invites, by token hash.
    entries: Mutex<HashMap<String, Entry>>,
    /// Durable record of the invites; `None` keeps them in memory only.
    persist: Option<Arc<dyn CaStore>>,
    observer: RwLock<Option<InviteObserver>>,
}

/// A CA's invites, by token: what its `token` challenge redeems. Cloning
/// shares the store.
#[derive(Default, Clone)]
pub struct TokenStore {
    inner: Arc<Inner>,
}

/// What an invite is stored as: hex SHA-256 over the domain-separated
/// token, so the store never holds a usable token.
fn token_hash(token: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ndncert-token-redemption/v1\0");
    h.update(token.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether an invite expiring at `expires_secs` (`None`: never) is still
/// redeemable at `now_secs`: while `now < expiry` ([`token_expired`], the
/// invitee's rule too).
fn live_at(expires_secs: Option<u64>, now_secs: u64) -> bool {
    expires_secs.is_none_or(|exp| !token_expired(exp, now_secs))
}

/// How the scope of a token is checked when it is redeemed.
#[derive(Clone, Copy)]
enum ScopeCheck<'a> {
    /// The certificate is asked for this name: it must be under the scope.
    Name(&'a Name),
    /// The name is unknown: a scoped token is refused.
    Unknown,
    /// The token is redeemed beside an admin's approval, which decides the
    /// role: any of the CA's invites will do.
    Ignored,
}

impl TokenStore {
    /// An in-memory store (nothing persists).
    pub fn new() -> Self {
        Self::default()
    }

    /// A store whose invites persist in `store`: the invites it recorded (in
    /// an earlier run) are loaded — refusing to start on one it cannot read,
    /// which could otherwise be redeemed again — and every change is recorded
    /// before it takes effect. Invites that ended more than
    /// [`ENDED_INVITE_RETENTION_SECS`] ago are forgotten.
    pub fn with_store(store: Arc<dyn CaStore>) -> Result<Self, CertError> {
        let now = now_secs();
        let mut entries = HashMap::new();
        for record in store.invite_records()? {
            if record
                .ended_at(now)
                .is_some_and(|at| now.saturating_sub(at) > ENDED_INVITE_RETENTION_SECS)
            {
                match store.remove_invite(&record.id) {
                    Ok(()) => continue,
                    Err(e) => tracing::warn!(
                        id = %record.id, error = %e,
                        "token challenge: could not forget a long-ended invite"
                    ),
                }
            }
            let scope = match &record.info.scope {
                Some(scope) => Some(scope.parse::<Name>().map_err(|_| {
                    CertError::Storage(format!("invite {}: unreadable scope {scope:?}", record.id))
                })?),
                None => None,
            };
            entries.insert(record.token_hash.clone(), Entry { record, scope });
        }
        Ok(Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(entries),
                persist: Some(store),
                observer: RwLock::default(),
            }),
        })
    }

    /// Call `observer` with every change of an invite once it is recorded
    /// (replacing an earlier observer).
    pub fn set_observer(&self, observer: InviteObserver) {
        *self.inner.observer.write() = Some(observer);
    }

    fn notify(&self, kind: InviteEventKind, invite: InviteEntry) {
        let observer = self.inner.observer.read().clone();
        if let Some(observer) = observer {
            observer(&InviteEvent { kind, invite });
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.inner.entries.lock()
    }

    /// Record a token the caller chose: no expiry, no scope (a CA that
    /// provisions its own tokens, tests). Invites are made by
    /// [`CaInvites::create`](crate::invites::CaInvites::create).
    pub fn add(&self, token: &str) -> Result<InviteEntry, CertError> {
        self.insert(token, None, None, None, None, "")
    }

    /// Record a token the caller chose, bounded by an optional TTL and/or
    /// name scope.
    pub fn add_scoped(
        &self,
        token: &str,
        ttl: Option<Duration>,
        scope: Option<Name>,
    ) -> Result<InviteEntry, CertError> {
        let expires_secs = ttl.map(|d| {
            let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
            now_secs().saturating_add(secs)
        });
        let role = scope
            .as_ref()
            .and_then(|s| s.components().last())
            .and_then(Role::from_component);
        self.insert(token, role, scope, expires_secs, None, "")
    }

    /// Record the invite of `token`, persisted before it is held. Refuses a
    /// token already held.
    pub(crate) fn insert(
        &self,
        token: &str,
        role: Option<Role>,
        scope: Option<Name>,
        expires_secs: Option<u64>,
        device: Option<String>,
        created_by: &str,
    ) -> Result<InviteEntry, CertError> {
        let hash = token_hash(token);
        let now = now_secs();
        let mut entries = self.entries();
        if entries.contains_key(&hash) {
            return Err(CertError::InvalidRequest(
                "this token is held already".into(),
            ));
        }
        let id = loop {
            let mut bytes = [0u8; 4];
            crate::ecdh::fill_random(&mut bytes)?;
            let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            if !entries.values().any(|e| e.record.id == id) {
                break id;
            }
        };
        let record = InviteRecord {
            id,
            token_hash: hash.clone(),
            info: InviteInfo {
                role: role.map(|r| r.as_str().to_owned()),
                scope: scope.as_ref().map(Name::to_string),
                created_secs: now,
                expires_secs,
                device,
                created_by: created_by.to_owned(),
                state: InviteState::Outstanding,
                ended_secs: None,
                redeemed_for: None,
            },
        };
        if let Some(store) = &self.inner.persist {
            store.record_invite(&record)?;
        }
        let entry = record.entry(now);
        entries.insert(hash, Entry { record, scope });
        drop(entries);
        self.notify(InviteEventKind::Created, entry.clone());
        Ok(entry)
    }

    /// Every invite held (outstanding, and ended ones still listed), oldest
    /// first.
    pub fn list(&self) -> Vec<InviteEntry> {
        let now = now_secs();
        let mut listed: Vec<(u64, InviteEntry)> = self
            .entries()
            .values()
            .map(|e| (e.record.info.created_secs, e.record.entry(now)))
            .collect();
        listed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
        listed.into_iter().map(|(_, e)| e).collect()
    }

    /// Withdraw the invite `id` (outstanding or expired): its token is
    /// refused from now on. Recorded before it takes effect.
    pub fn withdraw(&self, id: &str) -> Result<InviteEntry, WithdrawError> {
        let now = now_secs();
        let mut entries = self.entries();
        let Some(entry) = entries.values_mut().find(|e| e.record.id == id) else {
            return Err(WithdrawError::Unknown);
        };
        match entry.record.info.state {
            InviteState::Redeemed => {
                return Err(WithdrawError::AlreadyRedeemed(Box::new(
                    entry.record.entry(now),
                )));
            }
            InviteState::Withdrawn => {
                return Err(WithdrawError::AlreadyWithdrawn(Box::new(
                    entry.record.entry(now),
                )));
            }
            InviteState::Outstanding | InviteState::Expired => {}
        }
        let mut record = entry.record.clone();
        record.info.state = InviteState::Withdrawn;
        record.info.ended_secs = Some(now);
        if let Some(store) = &self.inner.persist {
            store
                .record_invite(&record)
                .map_err(|e| WithdrawError::NotRecorded(e.to_string()))?;
        }
        let listed = record.entry(now);
        entry.record = record;
        drop(entries);
        self.notify(InviteEventKind::Withdrawn, listed.clone());
        Ok(listed)
    }

    /// Consume `token` beside an admin's approval (`device-approval` with an
    /// invite): any outstanding invite of this CA, whatever its scope — the
    /// approval decides the role. Telling why a refused token was refused.
    pub fn redeem(&self, token: &str) -> TokenCheck {
        self.claim(token, ScopeCheck::Ignored)
    }

    /// Single-use consume without a requested name: a scoped token is
    /// refused. Returns `true` only on [`TokenCheck::Ok`].
    pub fn consume(&self, token: &str) -> bool {
        matches!(self.claim(token, ScopeCheck::Unknown), TokenCheck::Ok)
    }

    /// Whether `token` is an outstanding, unexpired invite (consumes
    /// nothing).
    pub fn is_live(&self, token: &str) -> bool {
        self.entries().get(&token_hash(token)).is_some_and(|e| {
            e.record.info.state == InviteState::Outstanding
                && live_at(e.record.info.expires_secs, now_secs())
        })
    }

    /// Single-use consume enforcing the expiry and (if set) that
    /// `request_name` is under the token's scope. The token is consumed only
    /// when valid and in scope; an out-of-scope or expired token is *not*
    /// silently accepted, and stays as it was.
    pub fn consume_for(&self, token: &str, request_name: &Name) -> TokenCheck {
        self.claim(token, ScopeCheck::Name(request_name))
    }

    /// The name scope of the token `token`, if it has one.
    pub fn scope_of(&self, token: &str) -> Option<Name> {
        self.entries()
            .get(&token_hash(token))
            .and_then(|e| e.scope.clone())
    }

    fn claim(&self, token: &str, scope_check: ScopeCheck<'_>) -> TokenCheck {
        let now = now_secs();
        let mut entries = self.entries();
        let Some(entry) = entries.get_mut(&token_hash(token)) else {
            return TokenCheck::NotFound;
        };
        match entry.record.info.state {
            InviteState::Redeemed => return TokenCheck::Redeemed,
            InviteState::Withdrawn => return TokenCheck::Withdrawn,
            InviteState::Outstanding | InviteState::Expired => {}
        }
        if !live_at(entry.record.info.expires_secs, now) {
            return TokenCheck::Expired;
        }
        let redeemed_for = match (scope_check, &entry.scope) {
            (ScopeCheck::Name(name), Some(scope)) if !name.has_prefix(scope) => {
                return TokenCheck::OutOfScope(Box::new(scope.clone()));
            }
            (ScopeCheck::Unknown, Some(scope)) => {
                return TokenCheck::OutOfScope(Box::new(scope.clone()));
            }
            (ScopeCheck::Name(name), _) => Some(name.to_string()),
            _ => None,
        };
        let mut record = entry.record.clone();
        record.info.state = InviteState::Redeemed;
        record.info.ended_secs = Some(now);
        record.info.redeemed_for = redeemed_for;
        if let Some(store) = &self.inner.persist
            && let Err(e) = store.record_invite(&record)
        {
            tracing::error!(error = %e, "token challenge: could not persist redemption");
            return TokenCheck::NotRecorded(e.to_string());
        }
        let listed = record.entry(now);
        entry.record = record;
        drop(entries);
        self.notify(InviteEventKind::Redeemed, listed);
        TokenCheck::Ok
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
            let deny =
                |d: TokenDenial, sentence: &str| Ok(ChallengeOutcome::Denied(d.reason(sentence)));
            let Some(t) = token else {
                return deny(TokenDenial::Missing, "missing 'token' parameter");
            };
            // With a known request name, enforce the expiry + scope; without
            // one (e.g. invoked as a combinator sub where the name isn't
            // threaded), single-use + expiry, and a scoped token is refused.
            let scope = self.store.scope_of(&t);
            let check = match &request_name {
                Some(name) => self.store.consume_for(&t, name),
                None => self.store.claim(&t, ScopeCheck::Unknown),
            };
            match check {
                TokenCheck::Ok => Ok(ChallengeOutcome::Approved {
                    attestation: scope.map(|scope| {
                        AttestationSet::single(
                            ChallengeAttestation::of_kind("token").with_evidence(
                                TOKEN_SCOPE_EVIDENCE,
                                serde_json::Value::String(scope.to_string()),
                            ),
                        )
                    }),
                }),
                TokenCheck::Expired => deny(TokenDenial::Expired, "the invite expired"),
                TokenCheck::OutOfScope(scope) => deny(
                    TokenDenial::OutOfScope,
                    &format!("the invite is scoped to {scope}; the requested name is outside it"),
                ),
                TokenCheck::NotFound => deny(
                    TokenDenial::Unknown,
                    "the token is not an invite of this CA",
                ),
                TokenCheck::Redeemed => {
                    deny(TokenDenial::Redeemed, "the invite was redeemed already")
                }
                TokenCheck::Withdrawn => deny(TokenDenial::Withdrawn, "the invite was withdrawn"),
                TokenCheck::NotRecorded(_) => deny(
                    TokenDenial::NotRecorded,
                    "the CA could not record the redemption; the invite was not used, try again",
                ),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The CA redeems while `now < expiry`: at the expiry second itself the
    /// invite is expired, as the invitee reads it.
    #[test]
    fn a_token_is_redeemable_only_before_its_expiry() {
        let until: u64 = 1_700_000_000;
        assert!(live_at(Some(until), until - 1));
        assert!(!live_at(Some(until), until));
        assert!(!live_at(Some(until), until + 1));
        assert!(live_at(None, u64::MAX));
        let store = TokenStore::new();
        store
            .insert(
                "member-m3",
                Some(Role::Member),
                None,
                Some(now_secs()),
                None,
                "",
            )
            .unwrap();
        assert!(!store.is_live("member-m3"));
        assert_eq!(store.redeem("member-m3"), TokenCheck::Expired);
    }

    /// Beside an admin's approval any invite of the CA will do (the approval
    /// decides the role); without a requested name a scoped token is refused.
    #[test]
    fn scope_is_checked_by_name_ignored_beside_an_approval() {
        let store = TokenStore::new();
        store
            .add_scoped("member-a", None, Some(name("/home/bob/member")))
            .unwrap();
        store
            .add_scoped("member-b", None, Some(name("/home/bob/member")))
            .unwrap();
        assert!(!store.consume("member-a"));
        assert!(store.is_live("member-a"), "a refused token is not spent");
        assert_eq!(store.redeem("member-a"), TokenCheck::Ok);
        assert_eq!(
            store.consume_for("member-b", &name("/home/bob/admin/x")),
            TokenCheck::OutOfScope(Box::new(name("/home/bob/member")))
        );
        assert_eq!(
            store.consume_for("member-b", &name("/home/bob/member/x")),
            TokenCheck::Ok
        );
    }

    /// The observer sees every change, never the token.
    #[test]
    fn the_observer_sees_created_redeemed_and_withdrawn() {
        let store = TokenStore::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        store.set_observer(Arc::new(move |e: &InviteEvent| {
            sink.lock().push((e.kind, e.invite.id.clone()));
        }));
        let a = store.add("tok-a").unwrap();
        let b = store.add("tok-b").unwrap();
        assert!(store.consume("tok-a"));
        store.withdraw(&b.id).unwrap();
        let seen = seen.lock();
        assert_eq!(
            *seen,
            [
                (InviteEventKind::Created, a.id.clone()),
                (InviteEventKind::Created, b.id.clone()),
                (InviteEventKind::Redeemed, a.id),
                (InviteEventKind::Withdrawn, b.id),
            ]
        );
    }
}
