//! A CA's invites: made at runtime by a trust administrator of the CA's
//! host, kept durably in the CA's store, redeemed once by the `token`
//! challenge ([`TokenStore`]).
//!
//! [`CaInvites::create`] is the one way an invite is made: it draws a random
//! token scoped to `/<ns>/<role>` (a member or a guest — a namespace never
//! admits an admin or a relay by invite: those roles are certified on an
//! admin's approval), records it and returns the invite once — its id, the
//! token and the `ndn-trust://invite` link carrying the CA prefix, the
//! identity namespace, the token, the namespace's expected fingerprint and,
//! optionally, a device-name hint. The store keeps only a hash of the token
//! with the invite's metadata ([`InviteRecord`]), so it never holds a usable
//! token; [`CaInvites::list`] shows the invites without tokens and
//! [`CaInvites::withdraw`] ends one by id.
//!
//! Every change is recorded before it takes effect (fail closed): an invite
//! that could not be recorded is not made, a redemption that could not be
//! recorded is refused (the token stays usable), a withdrawal that could not
//! be recorded leaves the invite outstanding.
//!
//! The device-name hint is the invitee's default device name, not a
//! constraint: the token's scope is the role prefix, and the invitee may
//! enroll under another name there.
//!
//! Refusals are [`TrustRefusal`]s with the codes of the `invites` section of
//! [`crate::report::code`]; when the CA's `token` challenge refuses a token,
//! its denial starts with a stable [`TokenDenial`] code, which the enrolling
//! device reads back with [`TokenDenial::of_reason`].

use std::sync::Arc;

use ndn_packet::Name;
use ndn_trust_envelope::TrustEnvelope;

use crate::challenge::token::{TokenStore, WithdrawError};
use crate::report::{TrustRefusal, code};
use crate::roles::{Role, role_prefix, role_token, token_with_expiry, validate_device_name};

/// How long an ended invite (redeemed, withdrawn, or expired) stays
/// listed before the CA forgets it at its next start.
pub const ENDED_INVITE_RETENTION_SECS: u64 = 30 * 86_400;

/// Random bytes in an invite's token (128 bits: unguessable, and the link
/// still fits one QR code).
const TOKEN_BYTES: usize = 16;

/// Where an invite stands. A record is stored `outstanding`, `redeemed` or
/// `withdrawn`; `expired` is an outstanding invite past its expiry, as
/// listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InviteState {
    Outstanding,
    Expired,
    Redeemed,
    Withdrawn,
}

impl InviteState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outstanding => "outstanding",
            Self::Expired => "expired",
            Self::Redeemed => "redeemed",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One invite as the CA's store keeps it: a hash of its token, never the
/// token itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InviteRecord {
    pub id: String,
    /// Hex SHA-256 over the domain-separated token.
    pub token_hash: String,
    #[serde(flatten)]
    pub info: InviteInfo,
}

/// An invite as listed: everything but its token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InviteInfo {
    /// The role it admits (`member`, `guest`); absent for a token provisioned
    /// without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The name prefix it certifies under (`/<ns>/<role>`); absent:
    /// unscoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// When it was made (Unix seconds).
    pub created_secs: u64,
    /// When it stops being redeemable (Unix seconds); absent: never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_secs: Option<u64>,
    /// The device name the inviter suggested (a hint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Who made it: the local operator the kernel attested, when made over
    /// management.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_by: String,
    pub state: InviteState,
    /// When it was redeemed or withdrawn (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_secs: Option<u64>,
    /// The name it certified, once redeemed (when the CA knew it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redeemed_for: Option<String>,
}

/// An invite with its id, as listed by [`CaInvites::list`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InviteEntry {
    pub id: String,
    #[serde(flatten)]
    pub info: InviteInfo,
}

impl InviteRecord {
    /// The record as listed at `now_secs`: an outstanding invite past its
    /// expiry is `expired`.
    pub fn entry(&self, now_secs: u64) -> InviteEntry {
        let mut info = self.info.clone();
        if info.state == InviteState::Outstanding
            && info
                .expires_secs
                .is_some_and(|exp| crate::roles::token_expired(exp, now_secs))
        {
            info.state = InviteState::Expired;
        }
        InviteEntry {
            id: self.id.clone(),
            info,
        }
    }

    /// When the invite ended (redeemed, withdrawn, or its expiry), if it
    /// did by `now_secs`.
    pub fn ended_at(&self, now_secs: u64) -> Option<u64> {
        match self.info.state {
            InviteState::Redeemed | InviteState::Withdrawn => {
                Some(self.info.ended_secs.unwrap_or(self.info.created_secs))
            }
            _ => self
                .info
                .expires_secs
                .filter(|&exp| crate::roles::token_expired(exp, now_secs)),
        }
    }
}

/// What [`CaInvites::create`] is asked for (the `ca/invite-create` request,
/// as JSON).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InviteRequest {
    /// `member` or `guest`.
    pub role: String,
    /// How long the invite can be redeemed, in seconds from now; absent:
    /// until redeemed or withdrawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// The device name to suggest to the invitee (a valid device name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

/// A new invite, returned once: the only time its token is shown.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CreatedInvite {
    pub id: String,
    /// The prefix of the CA that made it (as invite events name it).
    pub ca: String,
    /// The namespace it admits to.
    pub namespace: String,
    #[serde(flatten)]
    pub info: InviteInfo,
    /// The one-time token (also inside the link).
    pub token: String,
    /// The `ndn-trust://invite/…` link to hand to the invitee.
    pub link: String,
}

/// The invites of one CA, as `ca/invite-list` answers them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaInviteListing {
    /// The CA's prefix.
    pub ca: String,
    /// The namespace its invites admit to.
    pub namespace: String,
    /// Oldest first, without tokens.
    pub invites: Vec<InviteEntry>,
}

/// What a CA's invite links name about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteIssuer {
    /// The CA's prefix (its NDNCERT names are `<ca_prefix>/CA/…`).
    pub ca_prefix: Name,
    /// The namespace `/<ns>` its invites scope tokens under.
    pub namespace: Name,
    /// The fingerprint of the namespace's root anchor, carried by every link
    /// so the invitee adopts the right trust context; `None` for a CA
    /// without a namespace trust context (an ephemeral demo CA).
    pub expected_fingerprint: Option<[u8; 32]>,
}

/// What happened to an invite ([`InviteEvent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteEventKind {
    Created,
    Withdrawn,
    Redeemed,
}

/// A change of an invite, after it is recorded. Never carries the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteEvent {
    pub kind: InviteEventKind,
    pub invite: InviteEntry,
}

/// Called with every [`InviteEvent`] of a [`TokenStore`]
/// ([`TokenStore::set_observer`]).
pub type InviteObserver = Arc<dyn Fn(&InviteEvent) + Send + Sync>;

/// Why the CA's `token` challenge refused a token: the stable code its
/// denial starts with (`<code>: <sentence>`), so the enrolling device can
/// tell a spent invite from a withdrawn or expired one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenDenial {
    /// No parameter carried a token.
    Missing,
    /// Not an invite of this CA.
    Unknown,
    Redeemed,
    Withdrawn,
    Expired,
    /// The name asked for is outside the invite's scope.
    OutOfScope,
    /// The CA could not record the redemption; the invite was not used.
    NotRecorded,
}

impl TokenDenial {
    const ALL: [TokenDenial; 7] = [
        Self::Missing,
        Self::Unknown,
        Self::Redeemed,
        Self::Withdrawn,
        Self::Expired,
        Self::OutOfScope,
        Self::NotRecorded,
    ];

    /// The stable code: `invite-missing`, `invite-unknown`,
    /// `invite-redeemed`, `invite-withdrawn`, `invite-expired`,
    /// `invite-out-of-scope`, `invite-not-recorded`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "invite-missing",
            Self::Unknown => "invite-unknown",
            Self::Redeemed => "invite-redeemed",
            Self::Withdrawn => "invite-withdrawn",
            Self::Expired => "invite-expired",
            Self::OutOfScope => "invite-out-of-scope",
            Self::NotRecorded => "invite-not-recorded",
        }
    }

    /// The denial text the CA answers: the code, then `sentence`.
    pub fn reason(self, sentence: &str) -> String {
        format!("{}: {sentence}", self.as_str())
    }

    /// The denial a CA's refusal text carries, if it is one: at its start,
    /// or after a wrapper's `…: ` prefix (a combinator's sub-challenge
    /// denial).
    pub fn of_reason(reason: &str) -> Option<Self> {
        let parts: Vec<&str> = reason.split(": ").collect();
        let (_, prefixes) = parts.split_last()?;
        prefixes
            .iter()
            .find_map(|part| Self::ALL.into_iter().find(|d| d.as_str() == part.trim()))
    }
}

/// A CA's invites: its [`TokenStore`] (the `token` challenge redeems from
/// it) and what its links name. Cloning shares the store.
#[derive(Clone)]
pub struct CaInvites {
    tokens: TokenStore,
    issuer: InviteIssuer,
}

impl CaInvites {
    pub fn new(tokens: TokenStore, issuer: InviteIssuer) -> Self {
        Self { tokens, issuer }
    }

    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    pub fn issuer(&self) -> &InviteIssuer {
        &self.issuer
    }

    /// Make an invite: a random token for a `member` or `guest` of the
    /// namespace, redeemable once, until `ttl_secs` from now when given;
    /// recorded before it is returned. `created_by` is who asked (the local
    /// operator; empty when unknown).
    pub fn create(
        &self,
        request: &InviteRequest,
        created_by: &str,
    ) -> Result<CreatedInvite, TrustRefusal> {
        let namespace = &self.issuer.namespace;
        let role: Role = request.role.trim().parse().map_err(|e: crate::RoleError| {
            TrustRefusal::new(code::INVITE_ROLE_UNKNOWN, e.to_string())
                .with("role", request.role.trim())
        })?;
        if !matches!(role, Role::Member | Role::Guest) {
            return Err(TrustRefusal::new(
                code::INVITE_ROLE_NEEDS_APPROVAL,
                format!(
                    "{namespace} certifies {role} devices only on an admin's approval, never by \
                     an invite: invite a member or a guest, or have the device ask for the {role} \
                     role with the namespace's anchor link"
                ),
            )
            .with("role", role)
            .with("namespace", namespace));
        }
        let now = crate::approval::now_secs();
        let expires_secs = match request.ttl_secs {
            None => None,
            Some(ttl) => match now.checked_add(ttl) {
                Some(at) if ttl > 0 => Some(at),
                _ => {
                    return Err(TrustRefusal::new(
                        code::INVITE_EXPIRY_INVALID,
                        "an invite's lifetime must be a positive number of seconds",
                    )
                    .with("ttl_secs", ttl));
                }
            },
        };
        let device = match request.device.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(device) => {
                validate_device_name(device).map_err(|e| {
                    TrustRefusal::new(
                        code::INVITE_DEVICE_INVALID,
                        format!("{device:?} is not a device name: {e}"),
                    )
                    .with("device", device)
                    .with("error", &e)
                })?;
                Some(device.to_owned())
            }
        };
        let not_made = |e: crate::CertError| {
            TrustRefusal::new(
                code::INVITE_NOT_MADE,
                format!("no random token could be drawn ({e}); no invite was made"),
            )
            .with("error", &e)
        };
        let mut secret = [0u8; TOKEN_BYTES];
        crate::ecdh::fill_random(&mut secret).map_err(not_made)?;
        let secret: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let mut token = role_token(role, &secret);
        // The expiry travels inside the token too, so the invitee refuses an
        // expired invite before asking the CA.
        if let Some(at) = expires_secs {
            token = token_with_expiry(&token, at);
        }
        let scope = role_prefix(namespace, role);
        let entry = self
            .tokens
            .insert(
                &token,
                Some(role),
                Some(scope.clone()),
                expires_secs,
                device.clone(),
                created_by,
            )
            .map_err(|e| match e {
                crate::CertError::Storage(e) => TrustRefusal::new(
                    code::INVITE_NOT_RECORDED,
                    format!("the CA could not record the invite ({e}); no invite was made"),
                )
                .with("error", e),
                other => not_made(other),
            })?;
        let envelope = TrustEnvelope::Invite {
            ca_prefix: self.issuer.ca_prefix.to_string(),
            identity_namespace: scope.to_string(),
            token: token.clone(),
            ttl_secs: expires_secs.map(|at| at.saturating_sub(now)),
            anchor_fingerprint: self.issuer.expected_fingerprint,
            device,
        };
        Ok(CreatedInvite {
            id: entry.id,
            ca: self.issuer.ca_prefix.to_string(),
            namespace: namespace.to_string(),
            info: entry.info,
            token,
            link: envelope.to_uri(),
        })
    }

    /// Every invite the CA holds (outstanding, and ended ones it still
    /// lists), oldest first, without tokens.
    pub fn list(&self) -> Vec<InviteEntry> {
        self.tokens.list()
    }

    /// [`list`](Self::list) with the CA it is of.
    pub fn listing(&self) -> CaInviteListing {
        CaInviteListing {
            ca: self.issuer.ca_prefix.to_string(),
            namespace: self.issuer.namespace.to_string(),
            invites: self.list(),
        }
    }

    /// Whether `name` names this CA: its namespace or its prefix.
    pub fn is_named(&self, name: &Name) -> bool {
        &self.issuer.namespace == name || &self.issuer.ca_prefix == name
    }

    /// Withdraw the outstanding (or expired) invite `id`: its token is
    /// refused from now on. Recorded before it takes effect.
    pub fn withdraw(&self, id: &str) -> Result<InviteEntry, TrustRefusal> {
        let id = id.trim();
        self.tokens.withdraw(id).map_err(|e| match e {
            WithdrawError::Unknown => TrustRefusal::new(
                code::INVITE_UNKNOWN,
                format!("the CA holds no invite {id:?}"),
            )
            .with("id", id),
            WithdrawError::AlreadyRedeemed(entry) => {
                let mut refusal = TrustRefusal::new(
                    code::INVITE_ALREADY_REDEEMED,
                    format!(
                        "invite {id} was redeemed already, so there is nothing to withdraw; to \
                         remove the device it admitted, revoke its certificate"
                    ),
                )
                .with("id", id)
                .with("ended_secs", entry.info.ended_secs.unwrap_or_default());
                if let Some(name) = &entry.info.redeemed_for {
                    refusal = refusal.with("redeemed_for", name);
                }
                refusal
            }
            WithdrawError::AlreadyWithdrawn(entry) => TrustRefusal::new(
                code::INVITE_ALREADY_WITHDRAWN,
                format!("invite {id} was withdrawn already"),
            )
            .with("id", id)
            .with("ended_secs", entry.info.ended_secs.unwrap_or_default()),
            WithdrawError::NotRecorded(e) => TrustRefusal::new(
                code::INVITE_NOT_RECORDED,
                format!(
                    "the CA could not record the withdrawal ({e}); invite {id} is still \
                     outstanding"
                ),
            )
            .with("error", e),
        })
    }
}

/// The invites of every CA a host runs (one daemon may run the CA of each
/// namespace it is the root of): what the `ca/invite-*` verbs act on. A
/// request names its CA by namespace or prefix; naming none is enough when
/// the host runs one CA.
#[derive(Clone, Default)]
pub struct HostInvites {
    cas: Vec<CaInvites>,
}

impl HostInvites {
    pub fn new(cas: Vec<CaInvites>) -> Self {
        Self { cas }
    }

    pub fn cas(&self) -> &[CaInvites] {
        &self.cas
    }

    /// The CA `ca` names (its namespace or prefix); with none named, the
    /// host's only CA.
    pub fn select(&self, ca: Option<&Name>) -> Result<&CaInvites, TrustRefusal> {
        let held = || {
            self.cas
                .iter()
                .map(|c| c.issuer.namespace.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match (ca, self.cas.as_slice()) {
            (_, []) => Err(TrustRefusal::new(
                code::INVITE_NO_CA,
                "this node runs no CA, so it makes no invites",
            )),
            (None, [only]) => Ok(only),
            (None, several) => Err(TrustRefusal::new(
                code::INVITE_SEVERAL_CAS,
                format!(
                    "this node runs the CAs of {}: name the namespace whose invite it is",
                    held()
                ),
            )
            .with("namespaces", held())
            .with("count", several.len())),
            (Some(name), cas) => cas.iter().find(|c| c.is_named(name)).ok_or_else(|| {
                TrustRefusal::new(
                    code::INVITE_CA_UNKNOWN,
                    format!(
                        "this node runs no CA of {name}; it runs the CAs of {}",
                        held()
                    ),
                )
                .with("requested", name)
                .with("namespaces", held())
            }),
        }
    }

    /// [`CaInvites::create`] at the CA `ca` names ([`select`](Self::select)).
    pub fn create(
        &self,
        ca: Option<&Name>,
        request: &InviteRequest,
        created_by: &str,
    ) -> Result<CreatedInvite, TrustRefusal> {
        self.select(ca)?.create(request, created_by)
    }

    /// The invites of the CA `ca` names, or of every CA of the host when
    /// none is named (a listing is never ambiguous).
    pub fn list(&self, ca: Option<&Name>) -> Result<Vec<CaInviteListing>, TrustRefusal> {
        match ca {
            None if !self.cas.is_empty() => Ok(self.cas.iter().map(CaInvites::listing).collect()),
            _ => Ok(vec![self.select(ca)?.listing()]),
        }
    }

    /// [`CaInvites::withdraw`] at the CA `ca` names
    /// ([`select`](Self::select)).
    pub fn withdraw(&self, ca: Option<&Name>, id: &str) -> Result<InviteEntry, TrustRefusal> {
        self.select(ca)?.withdraw(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InviteLink;
    use crate::challenge::token::TokenCheck;
    use crate::store::{CaStore, FileCaStore};

    fn ns() -> Name {
        "/home/bob".parse().unwrap()
    }

    fn issuer() -> InviteIssuer {
        InviteIssuer {
            ca_prefix: ns(),
            namespace: ns(),
            expected_fingerprint: Some([7; 32]),
        }
    }

    fn request(role: &str) -> InviteRequest {
        InviteRequest {
            role: role.into(),
            ..Default::default()
        }
    }

    fn open(dir: &std::path::Path) -> CaInvites {
        let store: Arc<dyn CaStore> = Arc::new(FileCaStore::open(dir).unwrap());
        CaInvites::new(TokenStore::with_store(store).unwrap(), issuer())
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The link carries the CA, the role prefix, the token, the expected
    /// fingerprint and the hint; the invitee reads them back.
    #[test]
    fn the_link_names_what_the_invitee_needs() {
        let invites = CaInvites::new(TokenStore::new(), issuer());
        let made = invites
            .create(
                &InviteRequest {
                    role: "guest".into(),
                    ttl_secs: Some(3600),
                    device: Some("tv".into()),
                },
                "uid 1000 (alice)",
            )
            .unwrap();
        let link = InviteLink::from_uri(&made.link).unwrap();
        assert_eq!(link.role, Role::Guest);
        assert_eq!(link.identity_prefix, name("/home/bob/guest"));
        assert_eq!(link.token, made.token);
        assert_eq!(link.expected_fingerprint, Some([7; 32]));
        assert_eq!(link.device_hint.as_deref(), Some("tv"));
        assert_eq!(link.expires_at_secs, made.info.expires_secs);
        assert_eq!(made.info.state, InviteState::Outstanding);
        assert_eq!(made.info.created_by, "uid 1000 (alice)");
    }

    /// Invites survive a reopen of the store; the store holds no token;
    /// a redeemed invite stays redeemed and a withdrawn one withdrawn.
    #[test]
    fn invites_persist_across_reopen_and_the_store_holds_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let (kept, spent, gone) = {
            let invites = open(dir.path());
            let kept = invites.create(&request("member"), "").unwrap();
            let spent = invites.create(&request("member"), "").unwrap();
            let gone = invites.create(&request("guest"), "").unwrap();
            assert_eq!(
                invites
                    .tokens()
                    .consume_for(&spent.token, &name("/home/bob/member/laptop")),
                TokenCheck::Ok
            );
            invites.withdraw(&gone.id).unwrap();
            (kept, spent, gone)
        };
        for entry in std::fs::read_dir(dir.path().join("invites")).unwrap() {
            let stored = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for made in [&kept, &spent, &gone] {
                assert!(!stored.contains(&made.token), "a token is stored: {stored}");
            }
        }
        let invites = open(dir.path());
        let state = |id: &str| {
            invites
                .list()
                .into_iter()
                .find(|e| e.id == id)
                .map(|e| e.info.state)
        };
        assert_eq!(state(&kept.id), Some(InviteState::Outstanding));
        assert_eq!(state(&spent.id), Some(InviteState::Redeemed));
        assert_eq!(state(&gone.id), Some(InviteState::Withdrawn));
        let tokens = invites.tokens();
        assert_eq!(
            tokens.consume_for(&spent.token, &name("/home/bob/member/phone")),
            TokenCheck::Redeemed
        );
        assert_eq!(
            tokens.consume_for(&gone.token, &name("/home/bob/guest/phone")),
            TokenCheck::Withdrawn
        );
        assert_eq!(
            tokens.consume_for(&kept.token, &name("/home/bob/member/phone")),
            TokenCheck::Ok
        );
    }

    /// An invite is redeemed once.
    #[test]
    fn an_invite_is_single_use() {
        let invites = CaInvites::new(TokenStore::new(), issuer());
        let made = invites.create(&request("member"), "").unwrap();
        let tokens = invites.tokens();
        assert_eq!(
            tokens.consume_for(&made.token, &name("/home/bob/member/a")),
            TokenCheck::Ok
        );
        assert_eq!(
            tokens.consume_for(&made.token, &name("/home/bob/member/b")),
            TokenCheck::Redeemed
        );
        let listed = invites.list();
        assert_eq!(listed[0].info.state, InviteState::Redeemed);
        assert_eq!(
            listed[0].info.redeemed_for.as_deref(),
            Some("/home/bob/member/a")
        );
    }

    /// A withdrawn invite is refused; withdrawing again, or a redeemed or
    /// unknown invite, is refused with its code.
    #[test]
    fn withdraw_ends_an_invite() {
        let invites = CaInvites::new(TokenStore::new(), issuer());
        let made = invites.create(&request("guest"), "").unwrap();
        assert_eq!(
            invites.withdraw(&made.id).unwrap().info.state,
            InviteState::Withdrawn
        );
        assert!(!invites.tokens().is_live(&made.token));
        assert!(
            invites
                .withdraw(&made.id)
                .unwrap_err()
                .is(code::INVITE_ALREADY_WITHDRAWN)
        );
        assert!(
            invites
                .withdraw("nope")
                .unwrap_err()
                .is(code::INVITE_UNKNOWN)
        );
        let used = invites.create(&request("member"), "").unwrap();
        invites
            .tokens()
            .consume_for(&used.token, &name("/home/bob/member/x"));
        let refusal = invites.withdraw(&used.id).unwrap_err();
        assert!(refusal.is(code::INVITE_ALREADY_REDEEMED));
        assert_eq!(refusal.param("redeemed_for"), Some("/home/bob/member/x"));
    }

    /// An expired invite is refused and listed as expired; a lifetime of
    /// zero is refused.
    #[test]
    fn an_invite_expires() {
        let tokens = TokenStore::new();
        let now = crate::approval::now_secs();
        let entry = tokens
            .insert(
                "member-ab-until1",
                Some(Role::Member),
                Some(name("/home/bob/member")),
                Some(now),
                None,
                "",
            )
            .unwrap();
        assert_eq!(
            tokens.consume_for("member-ab-until1", &name("/home/bob/member/a")),
            TokenCheck::Expired
        );
        assert_eq!(tokens.list()[0].info.state, InviteState::Expired);
        assert_eq!(tokens.list()[0].id, entry.id);
        let invites = CaInvites::new(TokenStore::new(), issuer());
        let zero = InviteRequest {
            ttl_secs: Some(0),
            ..request("member")
        };
        assert!(
            invites
                .create(&zero, "")
                .unwrap_err()
                .is(code::INVITE_EXPIRY_INVALID)
        );
        let huge = InviteRequest {
            ttl_secs: Some(u64::MAX),
            ..request("member")
        };
        assert!(
            invites
                .create(&huge, "")
                .unwrap_err()
                .is(code::INVITE_EXPIRY_INVALID)
        );
    }

    /// A namespace never admits an admin or a relay by invite; an unknown
    /// role or device name is refused.
    #[test]
    fn approval_roles_and_bad_requests_are_refused() {
        let invites = CaInvites::new(TokenStore::new(), issuer());
        for role in ["admin", "node"] {
            let refusal = invites.create(&request(role), "").unwrap_err();
            assert!(refusal.is(code::INVITE_ROLE_NEEDS_APPROVAL), "{role}");
            assert_eq!(refusal.param("role"), Some(role));
        }
        assert!(
            invites
                .create(&request("boss"), "")
                .unwrap_err()
                .is(code::INVITE_ROLE_UNKNOWN)
        );
        let bad_device = InviteRequest {
            device: Some("KEY".into()),
            ..request("member")
        };
        assert!(
            invites
                .create(&bad_device, "")
                .unwrap_err()
                .is(code::INVITE_DEVICE_INVALID)
        );
        assert!(invites.list().is_empty(), "nothing refused was made");
    }

    /// A member invite certifies only members, a guest invite only guests;
    /// a refused request does not spend the invite.
    #[test]
    fn an_invite_certifies_only_its_role() {
        let invites = CaInvites::new(TokenStore::new(), issuer());
        let guest = invites.create(&request("guest"), "").unwrap();
        let tokens = invites.tokens();
        assert!(matches!(
            tokens.consume_for(&guest.token, &name("/home/bob/member/tv")),
            TokenCheck::OutOfScope(_)
        ));
        assert_eq!(
            tokens.consume_for(&guest.token, &name("/home/bob/guest/tv")),
            TokenCheck::Ok
        );
    }

    /// An invite that could not be recorded is not made.
    #[test]
    fn an_unrecorded_invite_is_not_made() {
        struct NoInvites;
        impl CaStore for NoInvites {
            fn load(&self) -> Result<crate::CaSnapshot, crate::CertError> {
                Ok(Default::default())
            }
            fn record_issued(&self, _: &str, _: &[u8]) -> Result<(), crate::CertError> {
                Ok(())
            }
            fn record_revoked(&self, _: &str) -> Result<(), crate::CertError> {
                Ok(())
            }
            fn invite_records(&self) -> Result<Vec<InviteRecord>, crate::CertError> {
                Ok(Vec::new())
            }
        }
        let invites = CaInvites::new(
            TokenStore::with_store(Arc::new(NoInvites)).unwrap(),
            issuer(),
        );
        let refusal = invites.create(&request("member"), "").unwrap_err();
        assert!(refusal.is(code::INVITE_NOT_RECORDED));
        assert!(invites.list().is_empty());
    }

    /// The challenge's denial codes read back.
    #[test]
    fn token_denials_read_back() {
        for d in TokenDenial::ALL {
            assert_eq!(
                TokenDenial::of_reason(&d.reason("anything: at all")),
                Some(d)
            );
        }
        assert_eq!(TokenDenial::of_reason("token expired"), None);
    }

    /// Ended invites are forgotten at a start once past the retention.
    #[test]
    fn long_ended_invites_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn CaStore> = Arc::new(FileCaStore::open(dir.path()).unwrap());
        let now = crate::approval::now_secs();
        let old = now - ENDED_INVITE_RETENTION_SECS - 1;
        let mut info = InviteInfo {
            role: Some("member".into()),
            scope: Some("/home/bob/member".into()),
            created_secs: old - 10,
            expires_secs: None,
            device: None,
            created_by: String::new(),
            state: InviteState::Withdrawn,
            ended_secs: Some(old),
            redeemed_for: None,
        };
        store
            .record_invite(&InviteRecord {
                id: "old".into(),
                token_hash: "00".into(),
                info: info.clone(),
            })
            .unwrap();
        info.ended_secs = Some(now);
        store
            .record_invite(&InviteRecord {
                id: "recent".into(),
                token_hash: "01".into(),
                info,
            })
            .unwrap();
        let tokens = TokenStore::with_store(Arc::clone(&store)).unwrap();
        let ids: Vec<String> = tokens.list().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, ["recent"]);
        assert_eq!(store.invite_records().unwrap().len(), 1);
    }

    /// A host with several CAs makes and withdraws an invite only at the
    /// CA named (by namespace or prefix); a listing names every CA.
    #[test]
    fn a_host_with_several_cas_names_the_ca() {
        let acme = InviteIssuer {
            ca_prefix: name("/work/acme/ca"),
            namespace: name("/work/acme"),
            expected_fingerprint: None,
        };
        let host = HostInvites::new(vec![
            CaInvites::new(TokenStore::new(), issuer()),
            CaInvites::new(TokenStore::new(), acme),
        ]);
        let refusal = host.create(None, &request("member"), "").unwrap_err();
        assert!(refusal.is(code::INVITE_SEVERAL_CAS));
        assert_eq!(refusal.param("count"), Some("2"));
        assert_eq!(refusal.param("namespaces"), Some("/home/bob, /work/acme"));
        let refusal = host
            .create(Some(&name("/elsewhere")), &request("member"), "")
            .unwrap_err();
        assert!(refusal.is(code::INVITE_CA_UNKNOWN));
        assert_eq!(refusal.param("requested"), Some("/elsewhere"));

        let made = host
            .create(Some(&name("/work/acme/ca")), &request("guest"), "")
            .unwrap();
        assert_eq!(
            (made.ca.as_str(), made.namespace.as_str()),
            ("/work/acme/ca", "/work/acme")
        );
        let link = InviteLink::from_uri(&made.link).unwrap();
        assert_eq!(link.identity_prefix, name("/work/acme/guest"));
        let listed = host.list(None).unwrap();
        let counts: Vec<(&str, usize)> = listed
            .iter()
            .map(|l| (l.namespace.as_str(), l.invites.len()))
            .collect();
        assert_eq!(counts, [("/home/bob", 0), ("/work/acme", 1)]);
        assert!(
            host.withdraw(Some(&ns()), &made.id)
                .unwrap_err()
                .is(code::INVITE_UNKNOWN),
            "another CA's invite"
        );
        host.withdraw(Some(&name("/work/acme")), &made.id).unwrap();

        let none = HostInvites::default();
        assert!(none.list(None).unwrap_err().is(code::INVITE_NO_CA));
        let one = HostInvites::new(vec![CaInvites::new(TokenStore::new(), issuer())]);
        assert_eq!(
            one.create(None, &request("member"), "").unwrap().namespace,
            "/home/bob"
        );
    }
}
