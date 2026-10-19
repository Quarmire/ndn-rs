//! Enrollment by an admin's approval (`docs/specs/personal-namespace.md` F2).
//!
//! The person's gesture is "add this device" on the new device and "yes,
//! that's my device" on an admin device. The only thing they compare is a
//! short **verification code** shown on both screens
//! ([`verification_code`]): derived from the CA, the requesting key and the
//! request id, so another key's request shows another code.
//!
//! **An approval binds to a key, not to an NDNCERT session.** The CA keeps
//! one durable [`ApprovalRecord`] per requesting key ([`ApprovalStore`],
//! persisted through its [`CaStore`]): request id, key, public-key digest,
//! role and device, code, created / expires, and the state — pending,
//! approved (by whom, with what evidence) or denied (by whom, why). NDNCERT
//! sessions (their ECDH secrets) stay in memory and are never persisted:
//! the requester asks with a **fresh** NEW → CHALLENGE(`device-approval`)
//! exchange each time ([`poll_approval`]), naming the request it resumes
//! ([`REQUEST_PARAM`]); once the record says approved, that exchange issues
//! the certificate at once. Either side may restart in between.
//!
//! While it waits, the requester keeps one **held status Interest**
//! outstanding, `<ca>/CA/STATUS/<request id>` ([`request_status`]): the CA
//! holds it until the request's record changes (decided, expired) or the
//! Interest is about to expire, then answers with the request's state,
//! signed by the CA key ([`ApprovalService::hold_status`],
//! [`ApprovalService::answer_status`]). A decision reaches a waiting device
//! at once, with one small Interest per [`STATUS_LIFETIME`] while nothing
//! happens. The Interest is unsigned and carries no parameters, so relays
//! aggregate identical ones; the answer is never fresh (no FreshnessPeriod),
//! so no Content Store answers the next one with an old state. The CA holds
//! at most [`MAX_HELD_PER_REQUEST`] per request and [`MAX_HELD_STATUS`] in
//! all, and Nacks more (`Congestion`). A requester acts on a denial or an
//! expiry (deleting its key) only from an answer that chains to the
//! namespace root under its schema, which only the CA key signs.
//!
//! Who decides:
//!
//! - **a local operator of the CA host** — authenticated by the kernel's
//!   peer credentials on the management socket — through
//!   [`ApprovalStore::decide_locally`]. The record names that operator
//!   ([`Approver::LocalOperator`]); the attestation claims no signature.
//! - **a current admin device**, from anywhere: it signs a decision Data
//!   `<requester key>/ndncert-approve/<request id>` (content: the code it
//!   showed) or `<requester key>/ndncert-deny/<request id>` (content: the
//!   reason) with its admin key ([`decision_data`]) and pushes it to
//!   `<ca>/CA/APPROVAL` ([`push_decision`]). The CA validates it under the
//!   namespace's trust context — signature, chain, schema (`#approve` /
//!   `#deny <= #admin`), revocation — and records the approver's key with the
//!   signed Data as evidence ([`Approver::AdminKey`]). The admin device learns
//!   what is pending from `<ca>/CA/PENDING` ([`fetch_pending`]), a CA-signed
//!   list answered only to an Interest signed by a current admin key.
//!
//! A pending request expires after the CA's TTL (policy in data, `[ca]
//! approval_request_ttl_days`); the requester is then told so, with what to
//! do. A decided record is kept one TTL after the decision, so a requester
//! that was offline still learns the outcome.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    CertCache, Certificate, InterestValidationOutcome, Keyring, ReplayCheck, ReplayGuard, Signer,
    ValidationResult, Validator, secure_fs,
};
use serde::{Deserialize, Serialize};

use crate::client::{CaExchange, ChallengeExchange};
use crate::error::CertError;
use crate::invite::{IssuedCertificate, check_chain, check_issued};
use crate::store::CaStore;

/// Name component of an admin's signed approval: `<key>/ndncert-approve/<id>`.
pub const APPROVE_COMPONENT: &str = "ndncert-approve";
/// Name component of an admin's signed denial: `<key>/ndncert-deny/<id>`.
pub const DENY_COMPONENT: &str = "ndncert-deny";
/// `<ca>/CA/APPROVAL`: where an admin device pushes a signed decision.
pub const APPROVAL_ENDPOINT: &str = "APPROVAL";
/// `<ca>/CA/PENDING`: the CA-signed list of pending requests.
pub const PENDING_ENDPOINT: &str = "PENDING";
/// `<ca>/CA/STATUS/<request id>`: a requester's held status Interest.
pub const STATUS_ENDPOINT: &str = "STATUS";
/// The lifetime of a requester's status Interest. The CA answers it before
/// it expires, so a waiting device sends one per lifetime while nothing
/// happens. A CA that stops answers what it holds
/// ([`ApprovalService::release_held`]); one that crashed loses it, and the
/// device sends the next one when it expires: within one lifetime.
pub const STATUS_LIFETIME: Duration = Duration::from_secs(30);
/// The lifetime of a requester's status Interest after the CA answered
/// early (it stopped), Nacked, or did not answer: short, so the device
/// finds the CA within seconds of its return; it goes back to
/// [`STATUS_LIFETIME`] once the CA holds one again.
pub const STATUS_PROBE_LIFETIME: Duration = Duration::from_secs(4);
/// The CA answers a held status Interest this long before the Interest
/// would expire, so the answer travels back while the PIT entries on the
/// way still exist; a status Interest that lives no longer than this is
/// answered at once (a "check now").
pub const STATUS_ANSWER_MARGIN: Duration = Duration::from_secs(2);
/// The longest the CA holds one status Interest, whatever its lifetime.
pub const MAX_STATUS_HOLD: Duration = Duration::from_secs(60);
/// Status Interests the CA holds at once for one request (a requester keeps
/// one; a restarted requester's earlier one may still be held, and devices
/// behind different relays are not aggregated).
pub const MAX_HELD_PER_REQUEST: usize = 4;
/// Status Interests the CA holds at once in all.
pub const MAX_HELD_STATUS: usize = 1024;
/// Requests a CA holds waiting for a decision at once: the held-STATUS
/// budget serves this many ([`MAX_HELD_STATUS`] / [`MAX_HELD_PER_REQUEST`]),
/// so unauthenticated requesters cannot starve real devices of it.
pub const MAX_PENDING: usize = MAX_HELD_STATUS / MAX_HELD_PER_REQUEST;
/// Requests waiting at once under one prefix (the parent of the key's
/// identity, e.g. one role of a namespace), so one flood cannot take the
/// whole [`MAX_PENDING`] budget.
pub const MAX_PENDING_PER_PREFIX: usize = 32;
/// How far the SignatureTime of a `<ca>/CA/PENDING` Interest may be from
/// the CA's clock (the NDN signed-Interest grace period, ndn-cxx's
/// default). Beyond it the Interest is refused as replayed or stale.
pub const LISTING_SIG_TIME_GRACE: Duration = Duration::from_secs(120);
/// Listing Interests the CA remembers per admin key (SignatureNonce,
/// SignatureTime), and admin keys it remembers: bounded, and filled only
/// by Interests whose signature verified. An admin lists far fewer than
/// this many times within one [`LISTING_SIG_TIME_GRACE`].
const LISTING_REPLAY_PER_KEY: usize = 64;
const LISTING_REPLAY_KEYS: usize = 256;

/// Consumes a new request's one-time invite (see
/// [`ApprovalStore::open_request`]); `Err` says why and what to do.
pub(crate) type Redeem<'r> = Box<dyn FnOnce() -> Result<(), String> + 'r>;

/// The prefix [`MAX_PENDING_PER_PREFIX`] counts under: the parent of the
/// key's identity (`/ns/role/device/KEY/x` → `/ns/role`).
fn pending_group(key_uri: &str) -> &str {
    let identity = key_uri.rsplit_once("/KEY/").map_or(key_uri, |(id, _)| id);
    identity
        .rsplit_once('/')
        .map_or(identity, |(parent, _)| parent)
}
/// The challenge type of enrollment by approval.
pub const DEVICE_APPROVAL: &str = "device-approval";
/// CHALLENGE parameter naming the request a poll resumes.
pub const REQUEST_PARAM: &str = "request";
/// CHALLENGE response parameter: the verification code of the request.
pub const CODE_PARAM: &str = "code";
/// CHALLENGE response parameter: when the pending request expires (Unix s).
pub const EXPIRES_PARAM: &str = "expires";
/// CHALLENGE parameter: an invite token, when the CA requires one beside
/// the approval.
pub const TOKEN_PARAM: &str = "token";
/// How long the CA keeps one poll's NDNCERT session: the requester never
/// reuses it — the next poll is a new exchange — so it is short.
pub const POLL_SESSION_SECS: u32 = 60;
/// How long a request waits for a decision when the CA sets nothing.
pub const DEFAULT_REQUEST_TTL: Duration = Duration::from_secs(7 * 86_400);
/// Exchanges [`poll_approval`] makes at most: NEW, CHALLENGE, the issued
/// certificate and the issuer certificates of its chain.
pub const POLL_MAX_EXCHANGES: u32 = 3 + crate::invite::MAX_ISSUER_FETCHES as u32;

/// One request for an admin's approval, as the CA keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Random, unique across restarts (16 hex digits).
    pub request_id: String,
    /// The CA the request was made to.
    pub ca_prefix: String,
    /// The key to certify, `/<ns>/<role>/<device>/KEY/<id>`.
    pub key_name: String,
    /// Hex SHA-256 of the key's public key.
    pub public_key_sha256: String,
    /// The role the key asks for, when it follows the namespace layout.
    #[serde(default)]
    pub role: Option<String>,
    /// The device name, when it follows the namespace layout.
    #[serde(default)]
    pub device: Option<String>,
    /// The verification code ([`verification_code`]), `"482 913"`.
    pub code: String,
    pub created_secs: u64,
    /// Pending: when it expires undecided. Decided: until when the decision
    /// is kept for the requester to learn.
    pub expires_secs: u64,
    /// An invite token was redeemed with this request (the CA requires one
    /// beside the approval for its role).
    #[serde(default)]
    pub invite: bool,
    #[serde(flatten)]
    pub state: ApprovalState,
}

/// Where a request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ApprovalState {
    Pending,
    Approved {
        by: Approver,
        at_secs: u64,
    },
    Denied {
        by: Approver,
        at_secs: u64,
        reason: String,
    },
}

impl ApprovalState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved { .. } => "approved",
            Self::Denied { .. } => "denied",
        }
    }
}

/// Who decided a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Approver {
    /// A local operator of the CA host, attested by the kernel on its
    /// management socket (`uid 1000 (alice)`). No signature exists.
    LocalOperator { who: String },
    /// An admin device's key, which signed the decision Data kept as
    /// evidence (base64url, no padding, of the Data wire).
    AdminKey { key: String, evidence: String },
}

impl Approver {
    /// `approver_kind` evidence value of the attestation leaf.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocalOperator { .. } => "local-operator",
            Self::AdminKey { .. } => "admin-key",
        }
    }

    /// Who, in words.
    pub fn describe(&self) -> String {
        match self {
            Self::LocalOperator { who } => format!("the CA host's local operator {who}"),
            Self::AdminKey { key, .. } => format!("admin key {key}"),
        }
    }
}

impl ApprovalRecord {
    pub fn is_pending(&self) -> bool {
        self.state == ApprovalState::Pending
    }

    /// `<role> device <device>` or the key name, for messages.
    pub fn subject(&self) -> String {
        match (&self.role, &self.device) {
            (Some(role), Some(device)) => format!("{role} device {device:?} ({})", self.key_name),
            _ => self.key_name.clone(),
        }
    }
}

/// The verification code both screens show: six digits (`"482 913"`) from
/// SHA-256 over the CA prefix, the requester's public key and the request
/// id. Not a secret; another key gives another code.
pub fn verification_code(ca_prefix: &Name, public_key: &[u8], request_id: &str) -> String {
    code_from_digest(ca_prefix, &sha256(public_key), request_id)
}

fn code_from_digest(ca_prefix: &Name, public_key_sha256: &[u8], request_id: &str) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"ndncert-approval-code/v1\0");
    h.update(ca_prefix.to_string().as_bytes());
    h.update([0]);
    h.update(public_key_sha256);
    h.update([0]);
    h.update(request_id.as_bytes());
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

/// A typed code (`482913`, `482 913`, `482-913`) in its shown form, or
/// `None` if it is not six digits.
pub fn normalize_code(typed: &str) -> Option<String> {
    let digits: String = typed.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    (digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{} {}", &digits[..3], &digits[3..]))
}

/// What an approver decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Deny { reason: String },
}

/// Why a decision or a listing changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalKind {
    /// No such request (or code).
    NotFound,
    /// The request is already decided, or the code is ambiguous.
    Conflict,
    /// The signer may not decide (signature, chain, schema, revocation).
    Unauthorized,
    /// The decision is malformed or names another request or key.
    BadRequest,
    /// The CA could not record it durably.
    Storage,
}

/// A refused decision or listing: what is wrong and what to do instead.
/// `code` (an approval code of [`crate::report::code`]) and `params` say it
/// as data; a CA that sends none is read by its `kind`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{reason}")]
pub struct ApprovalRefusal {
    pub kind: RefusalKind,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub params: crate::report::Params,
    /// The neutral sentence.
    pub reason: String,
}

impl ApprovalRefusal {
    /// With the parameter `key` = `value`.
    pub fn with(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.params.insert(key.to_owned(), value.to_string());
        self
    }
}

/// A refusal of `kind` with the generic approval code of that kind (its
/// reason says what failed).
fn refuse(kind: RefusalKind, reason: impl Into<String>) -> ApprovalRefusal {
    use crate::report::code;
    let generic = match kind {
        RefusalKind::NotFound => code::APPROVAL_NOT_FOUND,
        RefusalKind::Conflict => code::APPROVAL_CONFLICT,
        RefusalKind::Unauthorized => code::APPROVAL_UNAUTHORIZED,
        RefusalKind::BadRequest => code::APPROVAL_BAD_DECISION,
        RefusalKind::Storage => code::APPROVAL_NOT_RECORDED,
    };
    refuse_as(kind, generic, reason)
}

/// A refusal of `kind` with the approval code `code`.
fn refuse_as(
    kind: RefusalKind,
    code: crate::report::RefusalCode,
    reason: impl Into<String>,
) -> ApprovalRefusal {
    ApprovalRefusal {
        kind,
        code: code.code.to_owned(),
        params: crate::report::Params::new(),
        reason: reason.into(),
    }
}

/// Why a request could not be opened or resumed (told to the requester).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpenRefusal {
    /// The request is gone or expired: ask again.
    Expired(String),
    /// Anything else, with what to do.
    Refused(String),
}

/// The CA's durable approval records (see the module docs). Cheap to
/// clone; clones share the records.
#[derive(Clone)]
pub struct ApprovalStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    ca_prefix: Name,
    /// The namespace whose role layout device keys follow (the CA prefix
    /// for a namespace CA); `None` when keys follow no layout.
    namespace: Option<Name>,
    ttl: Duration,
    records: Mutex<HashMap<String, ApprovalRecord>>,
    persist: Option<Arc<dyn CaStore>>,
    /// Bumped whenever a record is decided or removed: held status
    /// Interests wait on it ([`ApprovalService::answer_status`]).
    changed: tokio::sync::watch::Sender<u64>,
    /// Told of every record opened or decided ([`ApprovalStore::set_observer`]).
    observer: parking_lot::RwLock<Option<ApprovalObserver>>,
}

/// Told of a request record the moment it is opened (pending) or decided
/// (approved / denied), once it is durable.
pub type ApprovalObserver = Arc<dyn Fn(&ApprovalRecord) + Send + Sync>;

impl ApprovalStore {
    /// Records in memory only: lost on restart (tests, ephemeral demo CAs).
    pub fn new(ca_prefix: Name, namespace: Option<Name>, ttl: Duration) -> Self {
        Self::build(ca_prefix, namespace, ttl, HashMap::new(), None)
    }

    /// Records persisted in `store` ([`CaStore::record_approval`]) and loaded
    /// from it now, so pending requests survive a restart of the CA.
    pub fn with_store(
        ca_prefix: Name,
        namespace: Option<Name>,
        ttl: Duration,
        store: Arc<dyn CaStore>,
    ) -> Result<Self, CertError> {
        let records = store
            .approval_records()?
            .into_iter()
            .map(|r| (r.request_id.clone(), r))
            .collect();
        let me = Self::build(ca_prefix, namespace, ttl, records, Some(store));
        me.prune();
        Ok(me)
    }

    fn build(
        ca_prefix: Name,
        namespace: Option<Name>,
        ttl: Duration,
        records: HashMap<String, ApprovalRecord>,
        persist: Option<Arc<dyn CaStore>>,
    ) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                ca_prefix,
                namespace,
                ttl,
                records: Mutex::new(records),
                persist,
                changed: tokio::sync::watch::Sender::new(0),
                observer: parking_lot::RwLock::new(None),
            }),
        }
    }

    pub fn ca_prefix(&self) -> &Name {
        &self.inner.ca_prefix
    }

    /// How long a request waits for a decision.
    pub fn ttl(&self) -> Duration {
        self.inner.ttl
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ApprovalRecord>> {
        self.inner.records.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn save(&self, record: &ApprovalRecord) -> Result<(), CertError> {
        match &self.inner.persist {
            Some(store) => store.record_approval(record),
            None => Ok(()),
        }
    }

    fn forget(&self, records: &mut HashMap<String, ApprovalRecord>, id: &str) {
        if let Some(store) = &self.inner.persist
            && let Err(e) = store.remove_approval(id)
        {
            tracing::warn!(request = id, error = %e, "could not remove an approval record");
        }
        records.remove(id);
        self.changed();
    }

    /// Wake every held status Interest to look at its record again.
    fn changed(&self) {
        self.inner.changed.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// Tell `observer` of every request record opened or decided from now
    /// on (the host's change notifications); replaces an earlier one.
    pub fn set_observer(&self, observer: ApprovalObserver) {
        *self.inner.observer.write() = Some(observer);
    }

    fn observed(&self, record: &ApprovalRecord) {
        let observer = self.inner.observer.read().clone();
        if let Some(observer) = observer {
            observer(record);
        }
    }

    /// The state of request `request_id` as a requester is told it
    /// ([`RequestStatus`]): a request this CA holds no record of, or one
    /// pending past its expiry, is expired.
    pub fn status(&self, request_id: &str) -> RequestStatus {
        let Some(record) = self.get(request_id) else {
            return RequestStatus::Expired {
                request_id: request_id.to_owned(),
                reason: gone_reason(&self.inner.ca_prefix, request_id),
            };
        };
        let request_id = record.request_id;
        let key_name = record.key_name;
        match record.state {
            ApprovalState::Pending if now_secs() > record.expires_secs => RequestStatus::Expired {
                reason: expired_reason(&request_id, record.expires_secs),
                request_id,
            },
            ApprovalState::Pending => RequestStatus::Pending {
                request_id,
                key_name,
                expires_secs: record.expires_secs,
            },
            ApprovalState::Approved { .. } => RequestStatus::Approved {
                request_id,
                key_name,
            },
            ApprovalState::Denied { by, reason, .. } => RequestStatus::Denied {
                reason: denial_reason(&request_id, &by, &reason),
                request_id,
                key_name,
            },
        }
    }

    /// Every record, oldest first.
    pub fn records(&self) -> Vec<ApprovalRecord> {
        self.prune();
        let mut all: Vec<ApprovalRecord> = self.lock().values().cloned().collect();
        all.sort_by(|a, b| (a.created_secs, &a.request_id).cmp(&(b.created_secs, &b.request_id)));
        all
    }

    /// The pending records not yet expired, oldest first.
    pub fn pending(&self) -> Vec<ApprovalRecord> {
        let now = now_secs();
        self.records()
            .into_iter()
            .filter(|r| r.is_pending() && now <= r.expires_secs)
            .collect()
    }

    pub fn get(&self, request_id: &str) -> Option<ApprovalRecord> {
        self.lock().get(request_id).cloned()
    }

    /// The pending request `target` names: its request id, or its
    /// verification code (in any spacing).
    pub fn find_pending(&self, target: &str) -> Result<ApprovalRecord, ApprovalRefusal> {
        find_in(&self.pending(), target)
    }

    /// Drop decided records past their keep time, and pending ones one TTL
    /// past their expiry (until then a poll is told the request expired).
    pub fn prune(&self) {
        let now = now_secs();
        let grace = self.inner.ttl.as_secs();
        let mut records = self.lock();
        let stale: Vec<String> = records
            .values()
            .filter(|r| {
                let keep_until = if r.is_pending() {
                    r.expires_secs.saturating_add(grace)
                } else {
                    r.expires_secs
                };
                now > keep_until
            })
            .map(|r| r.request_id.clone())
            .collect();
        for id in stale {
            self.forget(&mut records, &id);
        }
    }

    /// The record a poll for `key_name` (with `public_key`) is about:
    /// `resume` names the request it continues; without it, the key's
    /// current record, or a new one. `invite` runs only for a new one:
    /// `Ok(None)` when no invite is needed, `Ok(Some(redeem))` when one is,
    /// and `redeem` consumes it — called only once the new record is saved,
    /// so a storage failure never burns the one-time invite.
    pub(crate) fn open_request<'r>(
        &self,
        key_name: &Name,
        public_key: &[u8],
        resume: Option<&str>,
        invite: impl FnOnce() -> Result<Option<Redeem<'r>>, String>,
    ) -> Result<ApprovalRecord, OpenRefusal> {
        self.prune();
        let now = now_secs();
        let digest = hex(&sha256(public_key));
        let key_uri = key_name.to_string();
        let mut records = self.lock();
        if let Some(id) = resume {
            let Some(record) = records.get(id).cloned() else {
                return Err(OpenRefusal::Expired(gone_reason(&self.inner.ca_prefix, id)));
            };
            if record.key_name != key_uri || record.public_key_sha256 != digest {
                return Err(OpenRefusal::Refused(format!(
                    "request {id} was made for another key ({}), not {key_uri}",
                    record.key_name
                )));
            }
            if record.is_pending() && now > record.expires_secs {
                self.forget(&mut records, id);
                return Err(OpenRefusal::Expired(expired_reason(
                    id,
                    record.expires_secs,
                )));
            }
            return Ok(record);
        }
        let current = records
            .values()
            .find(|r| r.key_name == key_uri && r.public_key_sha256 == digest)
            .cloned();
        if let Some(record) = current {
            if !(record.is_pending() && now > record.expires_secs) {
                return Ok(record);
            }
            self.forget(&mut records, &record.request_id);
        }
        let live: Vec<&ApprovalRecord> = records
            .values()
            .filter(|r| r.is_pending() && now <= r.expires_secs)
            .collect();
        if let Some(other) = live.iter().find(|r| r.key_name == key_uri) {
            return Err(OpenRefusal::Refused(format!(
                "request {} for {key_uri} (another public key) is already waiting for an \
                 admin's decision; only one request per key name may wait: if it is yours, \
                 resume it; otherwise ask an admin to deny it, or wait until it expires at {}",
                other.request_id,
                iso_secs(other.expires_secs)
            )));
        }
        if live.len() >= MAX_PENDING {
            return Err(OpenRefusal::Refused(format!(
                "this CA already holds {MAX_PENDING} requests waiting for an admin's decision; \
                 nothing is pending for {key_uri}: ask an admin to decide the waiting requests, \
                 then ask again"
            )));
        }
        let group = pending_group(&key_uri);
        if live
            .iter()
            .filter(|r| pending_group(&r.key_name) == group)
            .count()
            >= MAX_PENDING_PER_PREFIX
        {
            return Err(OpenRefusal::Refused(format!(
                "{MAX_PENDING_PER_PREFIX} requests under {group} are already waiting for an \
                 admin's decision; nothing is pending for {key_uri}: ask an admin to decide \
                 them, then ask again"
            )));
        }
        let request_id = new_request_id().map_err(|e| {
            OpenRefusal::Refused(format!(
                "the CA could not draw a random request id ({e}); nothing is pending and any \
                 invite was not used: ask again later"
            ))
        })?;
        let redeem = invite().map_err(OpenRefusal::Refused)?;
        let device = self
            .inner
            .namespace
            .as_ref()
            .and_then(|ns| crate::roles::parse_device_key(ns, key_name));
        let record = ApprovalRecord {
            code: verification_code(&self.inner.ca_prefix, public_key, &request_id),
            request_id: request_id.clone(),
            ca_prefix: self.inner.ca_prefix.to_string(),
            key_name: key_uri,
            public_key_sha256: digest,
            role: device.as_ref().map(|d| d.role.to_string()),
            device: device.map(|d| d.device),
            created_secs: now,
            expires_secs: now.saturating_add(self.inner.ttl.as_secs()),
            invite: redeem.is_some(),
            state: ApprovalState::Pending,
        };
        self.save(&record).map_err(|e| {
            OpenRefusal::Refused(format!(
                "the CA could not record the request durably ({e}); nothing is pending and \
                 any invite was not used: ask again once the CA operator has fixed its storage"
            ))
        })?;
        // The invite is consumed only now that the request is durable; if
        // consuming it fails, the request goes again.
        if let Some(redeem) = redeem
            && let Err(why) = redeem()
        {
            self.forget(&mut records, &request_id);
            return Err(OpenRefusal::Refused(why));
        }
        records.insert(request_id, record.clone());
        drop(records);
        self.observed(&record);
        tracing::info!(
            request = %record.request_id,
            key = %record.key_name,
            code = %record.code,
            "approval request opened"
        );
        Ok(record)
    }

    /// Decide the pending request `target` (request id or code) as the CA
    /// host's local operator `who` (`uid 1000 (alice)`), whom the caller
    /// authenticated (kernel peer credentials on the management socket).
    pub fn decide_locally(
        &self,
        target: &str,
        decision: Decision,
        who: &str,
    ) -> Result<ApprovalRecord, ApprovalRefusal> {
        let record = self.find_pending(target)?;
        self.record_decision(
            &record.request_id,
            decision,
            Approver::LocalOperator {
                who: who.to_owned(),
            },
        )
    }

    fn record_decision(
        &self,
        request_id: &str,
        decision: Decision,
        by: Approver,
    ) -> Result<ApprovalRecord, ApprovalRefusal> {
        let now = now_secs();
        let mut records = self.lock();
        let Some(current) = records.get(request_id) else {
            return Err(refuse(
                RefusalKind::NotFound,
                format!("no request {request_id} at this CA"),
            )
            .with("target", request_id));
        };
        if !current.is_pending() {
            return Err(refuse_as(
                RefusalKind::Conflict,
                crate::report::code::APPROVAL_DECIDED,
                format!(
                    "request {request_id} is already {}; a decision is final",
                    current.state.as_str()
                ),
            )
            .with("request", request_id)
            .with("state", current.state.as_str()));
        }
        if now > current.expires_secs {
            let expired = iso_secs(current.expires_secs);
            return Err(refuse_as(
                RefusalKind::Conflict,
                crate::report::code::APPROVAL_EXPIRED,
                format!("request {request_id} expired at {expired}; the device must ask again"),
            )
            .with("request", request_id)
            .with("expired", expired));
        }
        let mut record = current.clone();
        record.state = match decision {
            Decision::Approve => ApprovalState::Approved { by, at_secs: now },
            Decision::Deny { reason } => ApprovalState::Denied {
                by,
                at_secs: now,
                reason,
            },
        };
        record.expires_secs = now.saturating_add(self.inner.ttl.as_secs());
        self.save(&record).map_err(|e| {
            refuse(
                RefusalKind::Storage,
                format!("the CA could not record the decision durably ({e}); nothing changed"),
            )
        })?;
        records.insert(request_id.to_owned(), record.clone());
        drop(records);
        // Held status Interests for it are answered now.
        self.changed();
        self.observed(&record);
        tracing::info!(
            request = %record.request_id,
            key = %record.key_name,
            state = record.state.as_str(),
            "approval request decided"
        );
        Ok(record)
    }

    /// Record a decision an admin device signed (see [`decision_data`]):
    /// `params` is the decision Data wire followed by certificates of its
    /// signer's chain. It must name a pending request and its key, carry the
    /// request's code (an approval) or a reason (a denial), and validate
    /// under the trust contexts in `keyring` — signature, chain to the
    /// namespace root, schema (only an admin key may decide), revocation —
    /// with the given certificates and `trusted` (the CA's own) as the only
    /// ones the walk may use; each hop's signature is verified, so a supplied
    /// certificate is never trusted by itself. `is_revoked` adds the CA's own
    /// revocations (applied before a context version carries them).
    pub async fn apply_signed(
        &self,
        params: &[u8],
        keyring: &Arc<Keyring>,
        trusted: &[Certificate],
        is_revoked: impl Fn(&Name) -> bool,
    ) -> Result<ApprovalRecord, ApprovalRefusal> {
        let bad = |why: String| refuse(RefusalKind::BadRequest, why);
        let mut packets = split_tlvs(params).into_iter();
        let decision_wire = packets
            .next()
            .ok_or_else(|| bad("the push carries no decision Data".into()))?;
        let data = Data::decode(decision_wire)
            .map_err(|e| bad(format!("the decision is not a Data packet: {e}")))?;
        let (key_name, kind, request_id) = parse_decision_name(&data.name).ok_or_else(|| {
            bad(format!(
                "{} is not a decision name <key>/{APPROVE_COMPONENT}|{DENY_COMPONENT}/<request id>",
                data.name
            ))
        })?;
        // Only an authorized admin learns anything about the request: the
        // signature, chain and admin role are checked before the record is
        // compared, and no refusal echoes the record's code or key.
        let signer = validate_admin_data(&data, packets, keyring, trusted, &is_revoked).await?;
        let record = self.get(&request_id).ok_or_else(|| {
            refuse(
                RefusalKind::NotFound,
                format!("this CA holds no request {request_id} (expired, or never made here)"),
            )
        })?;
        if record.key_name != key_name.to_string() {
            return Err(bad(format!(
                "request {request_id} is not for {key_name}; nothing changed: check the request \
                 id and key on the device"
            )));
        }
        let content = data
            .content()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default();
        let decision = if kind == APPROVE_COMPONENT {
            if normalize_code(&content).as_deref() != Some(record.code.as_str()) {
                return Err(bad(format!(
                    "the approval's code does not match request {request_id}; nothing changed: \
                     re-read the code shown on the device and approve the request showing it"
                )));
            }
            Decision::Approve
        } else {
            Decision::Deny {
                reason: if content.trim().is_empty() {
                    "no reason given".to_owned()
                } else {
                    content
                },
            }
        };
        let evidence = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data.raw());
        self.record_decision(
            &request_id,
            decision,
            Approver::AdminKey {
                key: signer.to_string(),
                evidence,
            },
        )
    }

    /// Authorize a `<ca>/CA/PENDING` listing: `interest` must be signed by a
    /// current admin key of the namespace (validated as
    /// [`apply_signed`](Self::apply_signed) validates a decision; its
    /// ApplicationParameters carry certificates of the signer's chain), and
    /// fresh by the NDN signed-Interest rule ([`check_listing_fresh`]),
    /// recorded in `replay`. Returns the signer's key name.
    pub async fn authorize_listing(
        &self,
        interest: &Interest,
        keyring: &Arc<Keyring>,
        trusted: &[Certificate],
        is_revoked: impl Fn(&Name) -> bool,
        replay: &ReplayGuard,
    ) -> Result<Name, ApprovalRefusal> {
        let unauthorized = |why: String| refuse(RefusalKind::Unauthorized, why);
        let signer = interest
            .sig_info()
            .and_then(|s| s.key_locator_name())
            .ok_or_else(|| {
                unauthorized(
                    "the pending list is answered only to an Interest signed by an admin key"
                        .into(),
                )
            })?;
        let certs = interest
            .app_parameters()
            .map(|p| split_tlvs(p))
            .unwrap_or_default();
        let validator = walk_validator(keyring, trusted, certs.into_iter());
        match validator.validate_interest_chain(interest).await {
            InterestValidationOutcome::Valid => {}
            InterestValidationOutcome::Invalid(e) => {
                return Err(unauthorized(format!(
                    "{signer} may not list pending requests: {e} (only a current admin key of \
                     the namespace may)"
                )));
            }
            InterestValidationOutcome::Pending => {
                return Err(unauthorized(format!(
                    "the certificate of {signer} did not come with the Interest; send the \
                     signer's certificate chain in its ApplicationParameters"
                )));
            }
        }
        let key = ndn_security::cert_name::key_name_of(&signer);
        if is_revoked(&key) {
            return Err(unauthorized(format!("{key} is revoked at this CA")));
        }
        // Only now that the signature verified, so nothing unverified
        // fills the record.
        check_listing_fresh(interest, replay, now_ms())?;
        Ok(key)
    }
}

/// The NDN signed-Interest rule for a PENDING Interest whose signature
/// verified: it carries SignatureTime and SignatureNonce, its SignatureTime
/// is within [`LISTING_SIG_TIME_GRACE`] of `now_ms`, and the same key did
/// not send the same (SignatureNonce, SignatureTime) before (`replay`
/// records them). Older replays fall outside the window.
pub fn check_listing_fresh(
    interest: &Interest,
    replay: &ReplayGuard,
    now_ms: u64,
) -> Result<(), ApprovalRefusal> {
    let unauthorized = |why: String| refuse(RefusalKind::Unauthorized, why);
    let Some((sig, time)) = interest
        .sig_info()
        .filter(|sig| sig.sig_nonce.is_some())
        .and_then(|sig| sig.sig_time.map(|time| (sig, time)))
    else {
        return Err(unauthorized(
            "the PENDING Interest lacks SignatureTime or SignatureNonce; sign it as an NDN \
             signed Interest with both"
                .into(),
        ));
    };
    let grace_ms = LISTING_SIG_TIME_GRACE.as_millis() as u64;
    if now_ms.abs_diff(time) > grace_ms {
        return Err(unauthorized(format!(
            "the PENDING Interest was signed at {time} ms, more than {} s from this CA's clock \
             ({now_ms} ms): it is replayed, or the signer's clock is off",
            LISTING_SIG_TIME_GRACE.as_secs()
        )));
    }
    match replay.check(sig) {
        ReplayCheck::Fresh => Ok(()),
        ReplayCheck::Replay | ReplayCheck::NoAntiReplayFields => Err(unauthorized(
            "the PENDING Interest repeats an earlier one of its key (same SignatureNonce and \
             SignatureTime): a replay; sign a new Interest"
                .into(),
        )),
    }
}

/// Why the CA at `ca_prefix` has no request `id` (told to its requester).
fn gone_reason(ca_prefix: &Name, id: &str) -> String {
    format!(
        "this CA ({ca_prefix}) holds no request {id}: it expired and was removed, or the CA was \
         replaced since. Nothing is pending any more; ask again and have an admin approve the \
         new request"
    )
}

/// Why request `id`, pending until `expires_secs`, ended.
fn expired_reason(id: &str, expires_secs: u64) -> String {
    format!(
        "request {id} expired at {} without an admin's decision; ask again and have an admin \
         approve the new request",
        iso_secs(expires_secs)
    )
}

/// What the requester of request `id` is told when `by` denied it.
pub(crate) fn denial_reason(id: &str, by: &Approver, reason: &str) -> String {
    format!(
        "{} denied request {id}: {reason}. Nothing was certified; ask that admin, or ask again \
         later with a new request",
        by.describe()
    )
}

/// A request's state as the CA tells its requester (the content of the
/// CA-signed answer to `<ca>/CA/STATUS/<request id>`, JSON). Expired
/// covers a request the CA holds no record of. A denial's or an expiry's
/// `reason` says why and what to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum RequestStatus {
    Pending {
        request_id: String,
        key_name: String,
        expires_secs: u64,
    },
    /// The next NEW → CHALLENGE exchange ([`poll_approval`]) issues the
    /// certificate.
    Approved {
        request_id: String,
        key_name: String,
    },
    Denied {
        request_id: String,
        key_name: String,
        reason: String,
    },
    Expired {
        request_id: String,
        reason: String,
    },
}

impl RequestStatus {
    pub fn request_id(&self) -> &str {
        match self {
            Self::Pending { request_id, .. }
            | Self::Approved { request_id, .. }
            | Self::Denied { request_id, .. }
            | Self::Expired { request_id, .. } => request_id,
        }
    }

    /// The key the request is for; `None` for an expired one (the CA may
    /// hold no record of it).
    pub fn key_name(&self) -> Option<&str> {
        match self {
            Self::Pending { key_name, .. }
            | Self::Approved { key_name, .. }
            | Self::Denied { key_name, .. } => Some(key_name),
            Self::Expired { .. } => None,
        }
    }
}

/// The name of request `request_id`'s status at the CA `ca_prefix`:
/// `<ca>/CA/STATUS/<request id>`.
pub fn status_name(ca_prefix: &Name, request_id: &str) -> Name {
    ca_prefix
        .clone()
        .append("CA")
        .append(STATUS_ENDPOINT)
        .append(request_id)
}

/// The request id of a status Interest `name` under `ca_prefix`
/// (`<ca>/CA/STATUS/<request id>`, nothing after it), if it is one.
pub fn status_request_id(ca_prefix: &Name, name: &Name) -> Option<String> {
    let comps = name.components();
    let n = ca_prefix.len();
    if comps.len() != n + 3 || !name.has_prefix(ca_prefix) {
        return None;
    }
    (comps[n].value.as_ref() == b"CA" && comps[n + 1].value.as_ref() == STATUS_ENDPOINT.as_bytes())
        .then(|| {
            std::str::from_utf8(&comps[n + 2].value)
                .ok()
                .map(str::to_owned)
        })
        .flatten()
}

/// How long the CA holds a status Interest of `lifetime` (`None`: the
/// default 4 s of NDN): until [`STATUS_ANSWER_MARGIN`] before it expires,
/// at most [`MAX_STATUS_HOLD`]; zero (answered at once) when it lives no
/// longer than the margin.
pub fn status_hold(lifetime: Option<Duration>) -> Duration {
    lifetime
        .unwrap_or(Duration::from_secs(4))
        .min(MAX_STATUS_HOLD + STATUS_ANSWER_MARGIN)
        .saturating_sub(STATUS_ANSWER_MARGIN)
}

/// How many status Interests the CA holds, per request and in all.
#[derive(Default)]
struct HeldCounts {
    total: usize,
    per_request: HashMap<String, usize>,
}

/// The status Interests a CA holds (shared by an [`ApprovalService`]'s
/// clones).
struct Holds {
    counts: Mutex<HeldCounts>,
    /// Woken when the last held one is given back.
    idle: tokio::sync::Notify,
    /// Set when the CA stops ([`ApprovalService::release_held`]): every
    /// status Interest is then answered at once.
    stopping: tokio::sync::watch::Sender<bool>,
}

impl Default for Holds {
    fn default() -> Self {
        Self {
            counts: Mutex::default(),
            idle: tokio::sync::Notify::new(),
            stopping: tokio::sync::watch::Sender::new(false),
        }
    }
}

impl Holds {
    fn counts(&self) -> std::sync::MutexGuard<'_, HeldCounts> {
        self.counts.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// One status Interest the CA holds ([`ApprovalService::hold_status`]);
/// its slot is given back when it is dropped — by the producer, once the
/// answer is sent (or the task dropped).
pub struct HeldStatus {
    request_id: String,
    holds: Arc<Holds>,
}

impl HeldStatus {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl Drop for HeldStatus {
    fn drop(&mut self) {
        let mut counts = self.holds.counts();
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.per_request.get_mut(&self.request_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.per_request.remove(&self.request_id);
            }
        }
        if counts.total == 0 {
            self.holds.idle.notify_waiters();
        }
    }
}

fn find_in(pending: &[ApprovalRecord], target: &str) -> Result<ApprovalRecord, ApprovalRefusal> {
    let target = target.trim();
    if let Some(r) = pending.iter().find(|r| r.request_id == target) {
        return Ok(r.clone());
    }
    let Some(code) = normalize_code(target) else {
        return Err(refuse_as(
            RefusalKind::NotFound,
            crate::report::code::APPROVAL_UNKNOWN_TARGET,
            format!(
                "no pending request {target:?}: give the request id or the six-digit code the \
                 list of pending requests shows"
            ),
        )
        .with("target", target));
    };
    let matches: Vec<&ApprovalRecord> = pending.iter().filter(|r| r.code == code).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(refuse_as(
            RefusalKind::NotFound,
            crate::report::code::APPROVAL_NO_CODE_MATCH,
            format!(
                "no pending request shows the code {code}: check the code on the new device \
                 against the list of pending requests (a request that expired or was decided is \
                 not pending)"
            ),
        )
        .with("code", &code)),
        _ => Err(refuse_as(
            RefusalKind::Conflict,
            crate::report::code::APPROVAL_AMBIGUOUS,
            format!(
                "several pending requests show the code {code}: decide by request id (the list \
                 of pending requests shows them)"
            ),
        )
        .with("code", &code)),
    }
}

/// `(key, component, request id)` of `<key>/ndncert-approve|deny/<id>`.
fn parse_decision_name(name: &Name) -> Option<(Name, &'static str, String)> {
    let comps = name.components();
    let n = comps.len();
    if n < 3 {
        return None;
    }
    let kind = match comps[n - 2].value.as_ref() {
        b"ndncert-approve" => APPROVE_COMPONENT,
        b"ndncert-deny" => DENY_COMPONENT,
        _ => return None,
    };
    let id = std::str::from_utf8(&comps[n - 1].value).ok()?.to_owned();
    Some((
        Name::from_components(comps[..n - 2].iter().cloned()),
        kind,
        id,
    ))
}

/// A validator over `keyring` whose chain walk may use only `trusted` and
/// the certificates in `supplied` (Data wires; undecodable ones skipped).
fn walk_validator(
    keyring: &Arc<Keyring>,
    trusted: &[Certificate],
    supplied: impl Iterator<Item = Bytes>,
) -> Validator {
    let cache = Arc::new(CertCache::new());
    for cert in trusted {
        cache.insert(cert.clone());
    }
    for wire in supplied.take(MAX_SUPPLIED_CERTS) {
        if let Some(cert) = Data::decode(wire)
            .ok()
            .and_then(|d| Certificate::decode(&d).ok())
        {
            cache.insert(cert);
        }
    }
    Validator::with_keyring(Arc::clone(keyring), cache, None, MAX_SUPPLIED_CERTS + 2)
}

/// Certificates a push or listing may carry.
const MAX_SUPPLIED_CERTS: usize = 6;

async fn validate_admin_data(
    data: &Data,
    certs: impl Iterator<Item = Bytes>,
    keyring: &Arc<Keyring>,
    trusted: &[Certificate],
    is_revoked: &impl Fn(&Name) -> bool,
) -> Result<Name, ApprovalRefusal> {
    let unauthorized = |why: String| refuse(RefusalKind::Unauthorized, why);
    let signer = data
        .sig_info()
        .and_then(|s| s.key_locator_name())
        .ok_or_else(|| unauthorized("the decision names no signer (KeyLocator)".into()))?;
    let validator = walk_validator(keyring, trusted, certs);
    match validator.validate_chain_cached(data).await {
        (ValidationResult::Valid(_), _) => {}
        (ValidationResult::Invalid(e), _) => {
            return Err(unauthorized(format!(
                "the decision signed by {signer} was refused: {e}. Only a current admin key of \
                 the namespace may decide; nothing changed"
            )));
        }
        (ValidationResult::Pending, missing) => {
            return Err(unauthorized(format!(
                "the decision's chain needs {}, which did not come with it; push the signer's \
                 certificate chain with the decision",
                missing
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| signer.to_string())
            )));
        }
    }
    let key = ndn_security::cert_name::key_name_of(&signer);
    if is_revoked(&key) {
        return Err(unauthorized(format!(
            "{key} is revoked at this CA; nothing changed"
        )));
    }
    Ok(key)
}

/// Split concatenated TLV elements (whole elements, header included).
fn split_tlvs(bytes: &[u8]) -> Vec<Bytes> {
    let buf = Bytes::copy_from_slice(bytes);
    let mut reader = ndn_tlv::TlvReader::new(buf.clone());
    let mut out = Vec::new();
    while !reader.is_empty() {
        let start = reader.position();
        let Ok(_) = reader.read_type() else { break };
        let Ok(len) = reader.read_length() else { break };
        if reader.read_bytes(len).is_err() {
            break;
        }
        out.push(buf.slice(start..reader.position()));
    }
    out
}

/// The CA side of `<ca>/CA/APPROVAL`, `<ca>/CA/PENDING` and
/// `<ca>/CA/STATUS/<request id>`, transport agnostic: the producer passes
/// each Interest and signs the returned content with the CA key.
#[derive(Clone)]
pub struct ApprovalService {
    store: ApprovalStore,
    keyring: Arc<Keyring>,
    ca: Arc<crate::CaState>,
    /// The status Interests held now (shared by clones).
    holds: Arc<Holds>,
    /// The PENDING Interests seen per admin key (shared by clones).
    listings: Arc<ReplayGuard>,
}

/// The CA's answer to a pushed decision (JSON content).
// Boxing would change the public API; these are cold control-plane results.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum DecisionAnswer {
    Recorded { record: ApprovalRecord },
    Refused(ApprovalRefusal),
}

/// The CA's answer to a pending listing (JSON content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ListingAnswer {
    Listed { records: Vec<ApprovalRecord> },
    Refused(ApprovalRefusal),
}

impl ApprovalService {
    /// `keyring`: the trust contexts decisions are validated under (the
    /// node's own, holding the namespace's); `ca`: the CA whose certificate
    /// and revocations join the check.
    pub fn new(store: ApprovalStore, keyring: Arc<Keyring>, ca: Arc<crate::CaState>) -> Self {
        Self {
            store,
            keyring,
            ca,
            holds: Arc::default(),
            listings: Arc::new(ReplayGuard::with_capacities(
                LISTING_REPLAY_PER_KEY,
                LISTING_REPLAY_KEYS,
                false,
            )),
        }
    }

    pub fn store(&self) -> &ApprovalStore {
        &self.store
    }

    fn trusted(&self) -> Vec<Certificate> {
        self.ca.ca_certificate().into_iter().collect()
    }

    /// `<ca>/CA/APPROVAL`: `params` is the Interest's ApplicationParameters.
    pub async fn handle_decision(&self, params: &[u8]) -> Vec<u8> {
        let ca = Arc::clone(&self.ca);
        let answer = match self
            .store
            .apply_signed(params, &self.keyring, &self.trusted(), |k| {
                ca.is_revoked(&k.to_string())
            })
            .await
        {
            Ok(record) => DecisionAnswer::Recorded { record },
            Err(refusal) => {
                tracing::warn!(reason = %refusal.reason, "approval decision refused");
                DecisionAnswer::Refused(refusal)
            }
        };
        serde_json::to_vec(&answer).unwrap_or_default()
    }

    /// `<ca>/CA/PENDING`: the pending requests, to a current admin key.
    pub async fn handle_listing(&self, interest: &Interest) -> Vec<u8> {
        let ca = Arc::clone(&self.ca);
        let answer = match self
            .store
            .authorize_listing(
                interest,
                &self.keyring,
                &self.trusted(),
                |k| ca.is_revoked(&k.to_string()),
                &self.listings,
            )
            .await
        {
            Ok(_) => ListingAnswer::Listed {
                records: self.store.pending(),
            },
            Err(refusal) => {
                tracing::warn!(reason = %refusal.reason, "pending listing refused");
                ListingAnswer::Refused(refusal)
            }
        };
        serde_json::to_vec(&answer).unwrap_or_default()
    }

    /// `<ca>/CA/STATUS/<request id>` asked to be answered at once (a hold
    /// of zero, [`status_hold`]): the request's state now. It takes no held
    /// slot, so a requester's checks never crowd out the status Interests
    /// held for that request.
    pub fn status_now(&self, request_id: &str) -> Vec<u8> {
        serde_json::to_vec(&self.store.status(request_id)).unwrap_or_default()
    }

    /// Take a slot to hold a status Interest for `request_id`; refused (the
    /// producer Nacks it, `Congestion`) when [`MAX_HELD_PER_REQUEST`] are
    /// held for it or [`MAX_HELD_STATUS`] in all. The refusal says why.
    pub fn hold_status(&self, request_id: &str) -> Result<HeldStatus, String> {
        let mut counts = self.holds.counts();
        if counts.total >= MAX_HELD_STATUS {
            return Err(format!(
                "this CA already holds {MAX_HELD_STATUS} status Interests (its limit); the status \
                 of request {request_id} is refused for now, and its requester asks again after \
                 backing off"
            ));
        }
        let for_request = counts.per_request.get(request_id).copied().unwrap_or(0);
        if for_request >= MAX_HELD_PER_REQUEST {
            return Err(format!(
                "this CA already holds {MAX_HELD_PER_REQUEST} status Interests for request \
                 {request_id} (its limit per request); one more is refused: one device keeps one \
                 outstanding, so several devices or a restarted one are asking, and they are \
                 answered when the request is decided"
            ));
        }
        counts.total += 1;
        counts
            .per_request
            .insert(request_id.to_owned(), for_request + 1);
        Ok(HeldStatus {
            request_id: request_id.to_owned(),
            holds: Arc::clone(&self.holds),
        })
    }

    /// `<ca>/CA/STATUS/<request id>`: the request's state ([`RequestStatus`],
    /// JSON) once it is decided or expires, or after `hold` (see
    /// [`status_hold`]) with the state then — pending. Answered at once
    /// when it is no longer pending, or when the CA stops
    /// ([`release_held`](Self::release_held)). The caller drops `held` once
    /// the answer is sent.
    pub async fn answer_status(&self, held: &HeldStatus, hold: Duration) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + hold;
        // Subscribed before the record is read: a decision recorded (or
        // the CA stopping) in between is seen as a change.
        let mut changes = self.store.inner.changed.subscribe();
        let mut stopping = self.holds.stopping.subscribe();
        let status = loop {
            let status = self.store.status(held.request_id());
            let RequestStatus::Pending { expires_secs, .. } = &status else {
                break status;
            };
            let now = tokio::time::Instant::now();
            if now >= deadline || *stopping.borrow_and_update() {
                break status;
            }
            // Woken by a change, the CA stopping, at the deadline, or when
            // the request expires undecided (just after its expiry second).
            // The senders live as long as this service, so neither wait
            // ends early but on a change.
            let until_expiry = Duration::from_secs(expires_secs.saturating_sub(now_secs()) + 1);
            let wake = deadline.min(now + until_expiry);
            let decided = std::pin::pin!(changes.changed());
            let stopped = std::pin::pin!(stopping.changed());
            let _ = tokio::time::timeout_at(wake, futures::future::select(decided, stopped)).await;
        };
        serde_json::to_vec(&status).unwrap_or_default()
    }

    /// The CA stops: every status Interest it holds is answered now with
    /// the request's state (and any arriving later at once), so a waiting
    /// device asks again — of the restarted CA — instead of waiting out its
    /// Interest. Returns once all are answered, or after `within`. Call it
    /// while the faces still forward.
    pub async fn release_held(&self, within: Duration) {
        self.holds.stopping.send_replace(true);
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let idle = self.holds.idle.notified();
            let mut idle = std::pin::pin!(idle);
            idle.as_mut().enable();
            let left = self.holds.counts().total;
            if left == 0 {
                return;
            }
            if tokio::time::timeout_at(deadline, idle).await.is_err() {
                tracing::warn!(
                    held = left,
                    "the CA stops with status Interests still unanswered; their devices ask \
                     again when those expire"
                );
                return;
            }
        }
    }
}

/// The name of an admin's signed decision on `record`.
pub fn decision_name(record: &ApprovalRecord, decision: &Decision) -> Result<Name, CertError> {
    let key: Name = record
        .key_name
        .parse()
        .map_err(|_| CertError::Name(record.key_name.clone()))?;
    let component = match decision {
        Decision::Approve => APPROVE_COMPONENT,
        Decision::Deny { .. } => DENY_COMPONENT,
    };
    Ok(key.append(component).append(record.request_id.as_str()))
}

/// The decision Data an admin device signs with `admin` (its admin key,
/// named in the KeyLocator): an approval carries the code the approver saw,
/// a denial its reason.
pub async fn decision_data(
    record: &ApprovalRecord,
    decision: &Decision,
    admin: &Arc<dyn Signer>,
) -> Result<Bytes, CertError> {
    let content = match decision {
        Decision::Approve => record.code.clone(),
        Decision::Deny { reason } => reason.clone(),
    };
    let signer = Arc::clone(admin);
    let key_locator = admin.key_name().clone();
    DataBuilder::new(decision_name(record, decision)?, content.as_bytes())
        .sign_fallible(signer.sig_type(), Some(&key_locator), |region| {
            let region = region.to_vec();
            async move { signer.sign(&region).await }
        })
        .await
        .map_err(CertError::Security)
}

/// Why an admin device's listing or decision did not happen.
#[derive(Debug, thiserror::Error)]
pub enum ApproverError {
    #[error(
        "could not reach the CA {ca_prefix}/CA ({detail}): this device needs a face and a route \
         for {ca_prefix} toward a forwarder that serves it"
    )]
    CaUnreachable { ca_prefix: String, detail: String },
    #[error("the CA refused: {0}")]
    Refused(ApprovalRefusal),
    #[error("the CA's answer was refused ({0}); nothing is trusted from it")]
    BadAnswer(String),
    #[error("signing with the admin key failed: {0}")]
    Signing(String),
}

impl ApproverError {
    fn from_cert(e: CertError, ca_prefix: &Name) -> Self {
        match e {
            CertError::Security(e) => Self::Signing(e.to_string()),
            other => Self::CaUnreachable {
                ca_prefix: ca_prefix.to_string(),
                detail: other.to_string(),
            },
        }
    }
}

/// The CA's answer Data, checked: it chains to the root of `namespace`
/// under its schema (a `<ca>/CA/…` Data only the CA key may sign).
async fn checked_answer<E, T>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    interest: Bytes,
) -> Result<T, ApproverError>
where
    E: CaExchange + ?Sized,
    T: serde::de::DeserializeOwned,
{
    let data = exchange
        .express(interest)
        .await
        .map_err(|e| ApproverError::from_cert(e, ca_prefix))?;
    check_chain(&data, keyring, exchange, namespace)
        .await
        .map_err(|e| match e {
            crate::invite::IssuedCheckError::Exchange(e) => ApproverError::from_cert(e, ca_prefix),
            crate::invite::IssuedCheckError::Refused(why)
            | crate::invite::IssuedCheckError::Signing(why) => ApproverError::BadAnswer(why),
        })?;
    let content = data.content().map(|c| c.as_ref()).unwrap_or_default();
    serde_json::from_slice(content)
        .map_err(|e| ApproverError::BadAnswer(format!("unreadable answer: {e}")))
}

/// Concatenated Data wires.
fn concat(wires: &[Bytes]) -> Vec<u8> {
    wires.iter().flat_map(|w| w.iter().copied()).collect()
}

/// The pending requests at the CA `ca_prefix` of `namespace`, asked as the
/// admin key `admin` (its certificate chain `admin_chain`, certificate
/// first, travels with the Interest so the CA can check it). The answer is
/// checked under the trust contexts in `keyring`.
pub async fn fetch_pending<E>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    admin: &Arc<dyn Signer>,
    admin_chain: &[Bytes],
) -> Result<Vec<ApprovalRecord>, ApproverError>
where
    E: CaExchange + ?Sized,
{
    let name = ca_prefix.clone().append("CA").append(PENDING_ENDPOINT);
    let signer = Arc::clone(admin);
    let key_locator = admin.key_name().clone();
    let interest = InterestBuilder::new(name)
        .must_be_fresh()
        .app_parameters(concat(admin_chain))
        .sign_fallible(signer.sig_type(), Some(&key_locator), |region| {
            let region = region.to_vec();
            async move { signer.sign(&region).await }
        })
        .await
        .map_err(|e| ApproverError::Signing(e.to_string()))?;
    match checked_answer(exchange, keyring, namespace, ca_prefix, interest).await? {
        ListingAnswer::Listed { records } => Ok(records),
        ListingAnswer::Refused(refusal) => Err(ApproverError::Refused(refusal)),
    }
}

/// Decide `record` as the admin key `admin`: sign the decision Data and push
/// it, with `admin_chain`, to `<ca>/CA/APPROVAL`. Returns the record as the
/// CA now holds it. The decision Data is the authority; the push Interest
/// is only its carrier.
pub async fn push_decision<E>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    record: &ApprovalRecord,
    decision: &Decision,
    admin: &Arc<dyn Signer>,
    admin_chain: &[Bytes],
) -> Result<ApprovalRecord, ApproverError>
where
    E: CaExchange + ?Sized,
{
    let ca_prefix: Name = record
        .ca_prefix
        .parse()
        .map_err(|_| ApproverError::BadAnswer(format!("bad CA prefix {}", record.ca_prefix)))?;
    let decision = decision_data(record, decision, admin)
        .await
        .map_err(|e| ApproverError::Signing(e.to_string()))?;
    let mut wires = vec![decision];
    wires.extend_from_slice(admin_chain);
    let interest = InterestBuilder::new(ca_prefix.clone().append("CA").append(APPROVAL_ENDPOINT))
        .must_be_fresh()
        .app_parameters(concat(&wires))
        .build();
    match checked_answer(exchange, keyring, namespace, &ca_prefix, interest).await? {
        DecisionAnswer::Recorded { record } => Ok(record),
        DecisionAnswer::Refused(refusal) => Err(ApproverError::Refused(refusal)),
    }
}

/// Find the record `target` (request id or code) names in `pending`.
pub fn find_pending_in(
    pending: &[ApprovalRecord],
    target: &str,
) -> Result<ApprovalRecord, ApprovalRefusal> {
    find_in(pending, target)
}

/// The prefix of the CA of `ctx`'s namespace: the CA endpoint the context
/// names (`/<ns>/CA`, served under `/<ns>`), else the namespace itself.
/// Where a requester asks for an admin's approval.
pub fn ca_prefix_of(ctx: &ndn_security::SignedTrustContext) -> Name {
    ctx.ca_endpoints()
        .first()
        .map(|endpoint| {
            let comps = endpoint.components();
            match comps.split_last() {
                Some((last, parent)) if last.value.as_ref() == b"CA" => {
                    Name::from_components(parent.iter().cloned())
                }
                _ => endpoint.clone(),
            }
        })
        .unwrap_or_else(|| ctx.namespace().clone())
}

/// The certificate chain an admin key sends with a listing or a decision
/// ([`fetch_pending`], [`push_decision`]): its certificate `cert` (signed
/// Data `cert_data`), then each issuer certificate found in `kept` (signed
/// Data wires kept from its enrollment or renewal, the newest valid one per
/// issuer key), up to the number of certificates the CA takes. The CA
/// walks it to the namespace root.
pub fn admin_chain(cert_data: &Data, cert: &Certificate, kept: &[Bytes]) -> Vec<Bytes> {
    let kept: Vec<(&Bytes, Certificate)> = kept
        .iter()
        .filter_map(|wire| {
            let cert = Certificate::decode(&Data::decode(wire.clone()).ok()?).ok()?;
            Some((wire, cert))
        })
        .collect();
    let mut chain = vec![cert_data.raw().clone()];
    let mut issuer = cert.issuer.clone();
    while let Some(issuer_name) = issuer.take()
        && chain.len() < MAX_SUPPLIED_CERTS
    {
        let issuer_key = ndn_security::cert_name::key_name_of(&issuer_name);
        let Some((wire, next)) = kept
            .iter()
            .filter(|(_, c)| c.name.has_prefix(&issuer_key) && c.is_valid_now())
            .max_by_key(|(_, c)| c.valid_from)
        else {
            break;
        };
        chain.push((*wire).clone());
        // A self-signed issuer ends the chain.
        if next
            .issuer
            .as_deref()
            .map(ndn_security::cert_name::key_name_of)
            == Some(issuer_key)
        {
            break;
        }
        issuer = next.issuer.clone();
    }
    chain
}

/// One poll's outcome for the requester.
// Boxing would change the public API; these are cold control-plane results.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ApprovalPoll {
    /// Approved: the certificate, fetched and checked.
    Issued(IssuedCertificate),
    /// Still waiting for an admin.
    Pending(PendingRequest),
}

/// A request waiting for an admin, as the requester sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub request_id: String,
    /// Computed here from this device's own key; the admin's screen shows
    /// the CA's, which matches only for this key.
    pub code: String,
    /// When it expires undecided (Unix seconds); `0` if the CA did not say.
    pub expires_secs: u64,
}

/// Why a poll did not end pending or issued.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalEnrollError {
    /// The CHALLENGE answer says an admin denied the request. That answer
    /// is not signed, so it ends nothing: only a CA-signed STATUS answer
    /// ([`request_status`]) ends a request (not final).
    #[error("{0}")]
    Denied(String),
    /// The CHALLENGE answer says the request expired or is gone: ask again.
    /// Unsigned, like [`Self::Denied`] (not final).
    #[error("{0}")]
    Expired(String),
    #[error(
        "could not reach the CA {ca_prefix}/CA ({detail}): this device needs a face and a route \
         for {ca_prefix} toward a forwarder that serves it; it keeps asking"
    )]
    CaUnreachable { ca_prefix: String, detail: String },
    #[error(
        "the CA refused this device name: {0}. Ask under another device name, or revoke that \
         certificate first"
    )]
    NameRefused(String),
    #[error("the CA refused the request: {0}")]
    CaRefused(String),
    #[error("signing the request with the device key failed: {0}")]
    Signing(String),
    /// The certificate the CA issued failed its checks (not final: the
    /// device's trust context may be out of date, and the approval stands).
    #[error(
        "the certificate the CA issued was refused ({0}): if this device's trust context is out \
         of date, refresh it (adopt the namespace's current context), then ask again"
    )]
    IssuedCertificate(String),
    /// An answer about the request did not chain to the namespace root
    /// under its schema (only the CA key signs `<ca>/CA/…`), or was about
    /// another request or key: nothing was done on it (not final).
    #[error(
        "an answer about this request was not trusted ({0}); nothing was done on it, and this \
         device asks the CA again"
    )]
    UntrustedAnswer(String),
}

impl ApprovalEnrollError {
    /// Whether this error alone may end a request (delete its key). The
    /// NEW and CHALLENGE answers are not signed by the CA, so nothing they
    /// say — a denial, an expiry, a refusal, an unreadable answer — and no
    /// failed check of the issued certificate (the device may hold a stale
    /// context) is final: the request is kept and asked about again until a
    /// CA-signed STATUS answer ([`request_status`]) says denied or expired.
    /// Only a local failure of the device key to sign is final.
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Signing(_))
    }

    fn from_cert(e: CertError, ca_prefix: &Name) -> Self {
        match e {
            CertError::Transport(detail) => Self::CaUnreachable {
                ca_prefix: ca_prefix.to_string(),
                detail,
            },
            CertError::Refused { name, reason } => Self::CaUnreachable {
                ca_prefix: ca_prefix.to_string(),
                detail: format!(
                    "this node's forwarder refused the Data answering {name} ({reason})"
                ),
            },
            CertError::PolicyDenied(reason) => Self::NameRefused(reason),
            CertError::Security(e) => Self::Signing(e.to_string()),
            other => Self::CaRefused(other.to_string()),
        }
    }
}

/// Ask the CA at `ca_prefix` (of `namespace`, whose trust context
/// `keyring` holds) to certify `device_key` on an admin's approval — one
/// fresh NEW → CHALLENGE(`device-approval`) exchange. `resume`: the request
/// this poll continues (`None` opens one, or finds the key's current one);
/// `token`: an invite token, when the CA requires one beside the approval
/// (redeemed only when the request is opened). Approved: the certificate is
/// fetched and checked (it certifies `device_key`, is valid now, chains to
/// the namespace root under its schema). Nothing is stored.
pub async fn poll_approval<E>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    device_key: Arc<dyn Signer>,
    resume: Option<&str>,
    token: Option<&str>,
) -> Result<ApprovalPoll, ApprovalEnrollError>
where
    E: CaExchange + ?Sized,
{
    let mut params = serde_json::Map::new();
    if let Some(id) = resume {
        params.insert(REQUEST_PARAM.into(), id.into());
    }
    if let Some(token) = token {
        params.insert(TOKEN_PARAM.into(), token.into());
    }
    let public_key = device_key
        .public_key()
        .ok_or_else(|| ApprovalEnrollError::Signing("the device key has no public key".into()))?;
    let outcome = crate::client::one_challenge_round(
        exchange,
        ca_prefix,
        Arc::clone(&device_key),
        0,
        DEVICE_APPROVAL,
        params,
    )
    .await;
    let cert_name = match outcome {
        Ok(ChallengeExchange::Issued(name)) => name,
        Ok(ChallengeExchange::Pending { parameters, status }) => {
            let param = |k: &str| {
                parameters
                    .get(k)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            };
            let request_id = param(REQUEST_PARAM).ok_or_else(|| {
                ApprovalEnrollError::CaRefused(format!(
                    "the CA answered pending without naming the request ({status})"
                ))
            })?;
            let code = verification_code(ca_prefix, &public_key, &request_id);
            if let Some(theirs) = param(CODE_PARAM)
                && theirs != code
            {
                return Err(ApprovalEnrollError::CaRefused(format!(
                    "the CA shows the code {theirs} for request {request_id}, but this device's \
                     key gives {code}: the CA holds another key's request under this name"
                )));
            }
            let expires_secs = param(EXPIRES_PARAM)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return Ok(ApprovalPoll::Pending(PendingRequest {
                request_id,
                code,
                expires_secs,
            }));
        }
        Err(CertError::ChallengeFailed(reason)) => return Err(ApprovalEnrollError::Denied(reason)),
        Err(CertError::ChallengeExpired(reason)) => {
            return Err(ApprovalEnrollError::Expired(reason));
        }
        Err(e) => return Err(ApprovalEnrollError::from_cert(e, ca_prefix)),
    };
    let data = crate::client::fetch_issued_cert_via(exchange, ca_prefix, &cert_name)
        .await
        .map_err(|e| ApprovalEnrollError::from_cert(e, ca_prefix))?;
    let checked = |e: crate::invite::IssuedCheckError| match e {
        crate::invite::IssuedCheckError::Refused(why) => {
            ApprovalEnrollError::IssuedCertificate(why)
        }
        crate::invite::IssuedCheckError::Signing(e) => ApprovalEnrollError::Signing(e),
        crate::invite::IssuedCheckError::Exchange(e) => {
            ApprovalEnrollError::from_cert(e, ca_prefix)
        }
    };
    let mut issued = check_issued(&data, device_key.as_ref())
        .await
        .map_err(checked)?;
    issued.issuers = check_chain(&data, keyring, exchange, namespace)
        .await
        .map_err(checked)?;
    Ok(ApprovalPoll::Issued(issued))
}

/// Wait for request `request_id` (made for `key_name`) at the CA
/// `ca_prefix` of `namespace`: one status Interest
/// `<ca>/CA/STATUS/<request id>` of `lifetime` ([`STATUS_LIFETIME`] for a
/// device that waits; up to [`STATUS_ANSWER_MARGIN`] to ask without
/// waiting), which the CA holds until the request is decided or expires, or
/// until shortly before the Interest expires. The answer is trusted only if
/// it chains to the root of `namespace` (whose trust context `keyring`
/// holds) under its schema — only the CA key signs `<ca>/CA/…` — and is
/// about this request and key; else [`ApprovalEnrollError::UntrustedAnswer`]
/// (nothing may be done on it). No answer, or a Nack, is
/// [`ApprovalEnrollError::CaUnreachable`].
pub async fn request_status<E>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    namespace: &Name,
    ca_prefix: &Name,
    request_id: &str,
    key_name: &str,
    lifetime: Duration,
) -> Result<RequestStatus, ApprovalEnrollError>
where
    E: CaExchange + ?Sized,
{
    let name = status_name(ca_prefix, request_id);
    // Unsigned and without parameters: every requester's status Interest
    // for the request is the same, so relays aggregate them. MustBeFresh:
    // the answer carries no FreshnessPeriod, so no cached state answers it.
    let interest = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .lifetime(lifetime)
        .build();
    let data = exchange
        .express(interest)
        .await
        .map_err(|e| ApprovalEnrollError::from_cert(e, ca_prefix))?;
    let untrusted = ApprovalEnrollError::UntrustedAnswer;
    if *data.name != name {
        return Err(untrusted(format!(
            "the answer is named {}, not {name}",
            data.name
        )));
    }
    check_chain(&data, keyring, exchange, namespace)
        .await
        .map_err(|e| match e {
            crate::invite::IssuedCheckError::Exchange(e) => {
                ApprovalEnrollError::from_cert(e, ca_prefix)
            }
            crate::invite::IssuedCheckError::Refused(why)
            | crate::invite::IssuedCheckError::Signing(why) => {
                untrusted(format!("the answer to {name} is not the CA's: {why}"))
            }
        })?;
    let content = data.content().map(|c| c.as_ref()).unwrap_or_default();
    let status: RequestStatus = serde_json::from_slice(content)
        .map_err(|e| untrusted(format!("the CA's answer to {name} is unreadable: {e}")))?;
    if status.request_id() != request_id {
        return Err(untrusted(format!(
            "the CA's answer to {name} is about request {}",
            status.request_id()
        )));
    }
    if let Some(theirs) = status.key_name()
        && theirs != key_name
    {
        return Err(untrusted(format!(
            "the CA's answer says request {request_id} is for {theirs}, not {key_name}"
        )));
    }
    Ok(status)
}

/// A requester's durable record of a request it made (the daemon keeps one
/// per request under `<pib>/requests/`, [`RequestStore`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutgoingRequest {
    pub namespace: String,
    pub ca_prefix: String,
    /// The identity asked for, `/<ns>/<role>/<device>`.
    pub identity: String,
    /// The key generated for it (kept in the requester's key store).
    pub key_name: String,
    pub request_id: String,
    pub code: String,
    pub created_secs: u64,
    /// When the CA expires the request undecided (Unix s; `0`: unknown).
    pub expires_secs: u64,
    #[serde(flatten)]
    pub state: OutgoingState,
}

/// How long past its expiry a pending [`OutgoingRequest`] is still waited
/// for (clock skew; a CA briefly offline whose signed answer then says
/// expired). Past it the requester ends the request itself
/// ([`RequestStore::expire_overdue`]): the CA never answered, and it forgets
/// requests by then.
pub const OUTGOING_EXPIRY_GRACE: Duration = Duration::from_secs(86_400);

impl OutgoingRequest {
    /// Pending past its expiry plus [`OUTGOING_EXPIRY_GRACE`] at `now`
    /// (Unix s): no CA answer will come.
    pub fn overdue(&self, now: u64) -> bool {
        self.state == OutgoingState::Pending
            && self.expires_secs != 0
            && now
                > self
                    .expires_secs
                    .saturating_add(OUTGOING_EXPIRY_GRACE.as_secs())
    }
}

/// Where an outgoing request stands. An ended request's `reason` says why
/// and what to do, as a [`Detail`](crate::report::Detail) (codes in
/// `ndn-rs/docs/specs/mgmt-trust.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum OutgoingState {
    Pending,
    Issued {
        certificate: String,
    },
    Denied {
        reason: crate::report::Detail,
    },
    Expired {
        reason: crate::report::Detail,
    },
    /// Approved, but the certificate could not be kept, or the request
    /// ended on a final failure.
    Failed {
        reason: crate::report::Detail,
    },
}

impl OutgoingState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued { .. } => "issued",
            Self::Denied { .. } => "denied",
            Self::Expired { .. } => "expired",
            Self::Failed { .. } => "failed",
        }
    }

    /// The state a request ends in after the final poll error `e`; `reason`
    /// says why and what to do (the caller adds what it did with the key).
    pub fn ended(e: &ApprovalEnrollError, reason: crate::report::Detail) -> Self {
        match e {
            ApprovalEnrollError::Denied(_) => Self::Denied { reason },
            ApprovalEnrollError::Expired(_) => Self::Expired { reason },
            _ => Self::Failed { reason },
        }
    }
}

/// Directory of [`OutgoingRequest`]s, one owner-only JSON file per key.
pub struct RequestStore {
    dir: PathBuf,
}

impl RequestStore {
    /// Open (creating if needed) the store at `dir` (`<pib>/requests`).
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CertError> {
        let dir = dir.into();
        secure_fs::create_private_dir_all(&dir).map_err(|e| io_err(&dir, e))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, key_name: &str) -> PathBuf {
        self.dir
            .join(format!("{}.json", hex(&sha256(key_name.as_bytes()))))
    }

    pub fn save(&self, request: &OutgoingRequest) -> Result<(), CertError> {
        let path = self.path(&request.key_name);
        let json = serde_json::to_vec_pretty(request)?;
        secure_fs::write_private(&path, json).map_err(|e| io_err(&path, e))
    }

    pub fn remove(&self, key_name: &str) -> Result<(), CertError> {
        let path = self.path(key_name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&path, e)),
        }
    }

    /// Every record, oldest first; unreadable files are skipped with a
    /// warning.
    pub fn list(&self) -> Result<Vec<OutgoingRequest>, CertError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(|e| io_err(&self.dir, e))? {
            let path = entry.map_err(|e| io_err(&self.dir, e))?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
            {
                Ok(r) => out.push(r),
                Err(e) => tracing::warn!(path = %path.display(), error = %e,
                    "skipping an unreadable outgoing request record"),
            }
        }
        out.sort_by_key(|r: &OutgoingRequest| r.created_secs);
        Ok(out)
    }

    /// The request for `identity` still pending, if any: asking again while
    /// one is pending answers with it (no second key, no second request).
    /// An [overdue](OutgoingRequest::overdue) one is not: a new request may
    /// go out ([`expire_overdue`](Self::expire_overdue) ends it).
    pub fn outstanding(&self, identity: &str) -> Result<Option<OutgoingRequest>, CertError> {
        let now = now_secs();
        Ok(self.list()?.into_iter().find(|r| {
            r.identity == identity && r.state == OutgoingState::Pending && !r.overdue(now)
        }))
    }

    /// End every [overdue](OutgoingRequest::overdue) pending request as
    /// expired (the CA never answered before it expired; ask again) and
    /// delete the sealed key kept beside it. Returns those ended: the
    /// caller deletes their keys from its own key store, if it keeps them.
    pub fn expire_overdue(&self) -> Result<Vec<OutgoingRequest>, CertError> {
        let now = now_secs();
        let mut ended = Vec::new();
        for mut r in self.list()?.into_iter().filter(|r| r.overdue(now)) {
            let expired = iso_secs(r.expires_secs);
            r.state = OutgoingState::Expired {
                reason: crate::report::Detail::new(
                    crate::report::detail_code::REQUEST_UNANSWERED,
                    format!(
                        "the CA never answered before request {} expired (at {expired}); ask \
                         again",
                        r.request_id
                    ),
                )
                .with("request", &r.request_id)
                .with("expired", expired),
            };
            self.remove_sealed_key(&r.key_name)?;
            self.save(&r)?;
            ended.push(r);
        }
        Ok(ended)
    }

    fn key_path(&self, key_name: &str) -> PathBuf {
        self.dir
            .join(format!("{}.key", hex(&sha256(key_name.as_bytes()))))
    }

    /// Keep the request's key `key_name` beside its record, `sealed` by the
    /// caller (a password-encrypted PKCS#8 or SafeBag), owner-only: for a
    /// requester with no key store of its own (an app's embedded engine;
    /// the daemon keeps its keys in the PIB).
    pub fn save_sealed_key(&self, key_name: &str, sealed: &[u8]) -> Result<(), CertError> {
        let path = self.key_path(key_name);
        secure_fs::write_private(&path, sealed).map_err(|e| io_err(&path, e))
    }

    /// The sealed key [`save_sealed_key`](Self::save_sealed_key) kept for
    /// `key_name`, if any.
    pub fn sealed_key(&self, key_name: &str) -> Result<Option<Vec<u8>>, CertError> {
        let path = self.key_path(key_name);
        match std::fs::read(&path) {
            Ok(sealed) => Ok(Some(sealed)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&path, e)),
        }
    }

    /// Delete (shred) the sealed key kept for `key_name`; none is fine.
    pub fn remove_sealed_key(&self, key_name: &str) -> Result<(), CertError> {
        let path = self.key_path(key_name);
        secure_fs::shred_file(&path).map_err(|e| io_err(&path, e))
    }
}

fn io_err(path: &Path, e: std::io::Error) -> CertError {
    CertError::Storage(format!("{}: {e}", path.display()))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 8 random bytes as hex. A failing system RNG is an error, never an id of
/// zeros that the next failure would repeat.
fn new_request_id() -> Result<String, CertError> {
    let mut bytes = [0u8; 8];
    crate::ecdh::fill_random(&mut bytes)?;
    Ok(hex(&bytes))
}

fn now_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) fn now_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `20261017T120000Z`.
pub fn iso_secs(secs: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(secs.saturating_mul(1_000_000_000));
    format!("{}Z", String::from_utf8_lossy(&basic))
}
