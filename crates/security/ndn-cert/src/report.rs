//! What the trust-admin operations of a device in a personal namespace
//! report: adopting a trust context, enrolling, refreshing held contexts,
//! taking a version made on the device, renewing certificates, the device's
//! membership in each namespace it holds ([`MembershipInfo`], and
//! [`MembershipEvent`] when one changes) — and why one changed nothing
//! ([`TrustRefusal`]).
//!
//! Plain data with a stable JSON form (the `ndn-fwd` management verbs carry
//! them in the ControlResponse status text; `ndn-mgmt` re-exports them). The
//! `ndn-namespace` crate produces them on any host; a host maps them to its
//! own surface.

use ndn_packet::Name;

/// The outcome of a successful `security/context-adopt`, returned to the
/// client as JSON in the ControlResponse status text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdoptedContextInfo {
    pub namespace: String,
    pub version: u64,
    /// Hex of the expected fingerprint the link carried (the signing anchor's).
    pub expected_fingerprint: String,
    pub anchors: usize,
    pub ca_endpoints: usize,
    /// Fetched from the network (else carried inline by the link).
    pub fetched: bool,
    /// Where the signed context was stored.
    pub stored: String,
    /// Whether this node now publishes it by name.
    pub published: bool,
}

/// Why a trust-admin verb (`security/context-adopt`, `security/enroll`)
/// changed nothing: a status code (`400` bad link or parameters, `403`
/// refused by a trust check or the CA, `409` conflicting state or another
/// such command running, `504` the network did not deliver, `500` local
/// failure) and a reason that says what to do instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRefusal {
    pub status_code: u64,
    pub reason: String,
}

/// A refused approval decision or listing, with the status code it is
/// answered with: `404` no such request, `409` already decided or an
/// ambiguous code, `403` the signer may not decide, `400` a malformed
/// decision, `500` the CA could not record it.
impl From<crate::approval::ApprovalRefusal> for TrustRefusal {
    fn from(refusal: crate::approval::ApprovalRefusal) -> Self {
        use crate::approval::RefusalKind;
        let status_code = match refusal.kind {
            RefusalKind::NotFound => 404,
            RefusalKind::Conflict => 409,
            RefusalKind::Unauthorized => 403,
            RefusalKind::BadRequest => 400,
            RefusalKind::Storage => 500,
        };
        Self {
            status_code,
            reason: refusal.reason,
        }
    }
}

/// What `security/enroll` asks: enroll `identity` (`/<ns>/<role>/<device>`)
/// with the CA the link names — an `ndn-trust://invite` link, or an
/// `ndn-trust://anchor` link for a role the namespace certifies on an
/// admin's approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollRequest {
    pub link_uri: String,
    pub identity: Name,
    /// Enroll a new key although this node already holds a certificate in
    /// the namespace (the old one stays valid until revoked).
    pub force: bool,
}

/// The answer to `security/enroll`, JSON in the ControlResponse status text,
/// tagged by `state`. A token enrollment completes in one exchange
/// (`enrolled`); enrollment by an admin's approval answers `pending`, and
/// the node finishes on its own once an admin approves.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum EnrollOutcome {
    Enrolled(EnrolledInfo),
    Pending(PendingEnrollInfo),
}

/// A `security/enroll` waiting for an admin's approval.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingEnrollInfo {
    /// The identity asked for, `/<ns>/<role>/<device>`.
    pub identity: String,
    /// The key generated for it in the node's PIB.
    pub key: String,
    pub namespace: String,
    /// The CA asked.
    pub ca: String,
    /// The request id at the CA.
    pub request: String,
    /// The verification code, computed from this node's own key: an admin's
    /// screen must show the same.
    pub code: String,
    /// When the request expires undecided, ISO 8601 (UTC); empty if the CA
    /// did not say.
    pub expires: String,
    /// The trust context adopted on the way; `None` when it was already held.
    pub adopted_context: Option<AdoptedContextInfo>,
}

/// A completed `security/enroll`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnrolledInfo {
    /// The enrolled identity, `/<ns>/<role>/<device>`.
    pub identity: String,
    /// The certified key, `<identity>/KEY/<id>`; generated in the node's PIB.
    pub key: String,
    /// The issued certificate's name.
    pub certificate: String,
    /// The key that signed the certificate (the CA's).
    pub issuer: String,
    /// Certificate validity end, ISO 8601 (UTC).
    pub valid_until: String,
    /// The issued certificate's lifetime in seconds, as the CA's policy
    /// (`[ca] cert_validity_days`) decided it.
    pub validity_secs: u64,
    /// The trust context adopted on the way; `None` when it was already held.
    pub adopted_context: Option<AdoptedContextInfo>,
    /// The PIB directory holding the key and certificate.
    pub pib: String,
    /// The node's identity before this enrollment, if any.
    pub previous_identity: Option<String>,
    /// Whether the running node signs as the new identity now: the Data it
    /// publishes under the namespace is signed with the new key (each
    /// trusted prefix with its own key; the device's other identities are
    /// unchanged). `false` when the host can only take it at its next start.
    pub signing_now: bool,
    /// Whether the new identity became the node identity (management
    /// responses, discovery records, links): only when the node had no
    /// persistent identity before. An enrollment never changes an existing
    /// node identity.
    #[serde(default)]
    pub node_identity: bool,
    /// What changes only at the next start, and why (empty: nothing).
    pub at_next_start: Vec<String>,
    /// Certificates in this namespace this node held before a `force`
    /// enrollment that still validate: each until its validity end (or a
    /// revocation), as `<key> (valid until <ISO 8601>)`. Judged against the
    /// trust context [`Self::context_check`] reports.
    pub still_valid: Vec<String>,
    /// Certificates this node holds in this namespace whose chain the held
    /// trust context revokes — the key itself or an issuer up its chain
    /// (e.g. the old root after a recovery): they validate nowhere, and
    /// their key needs enrolling anew. `<key> (revoked: <name>)`.
    #[serde(default)]
    pub unusable: Vec<String>,
    /// The check for a newer version of the namespace's trust context made
    /// before judging the certificates held (a `security/context-refresh` of
    /// that namespace). Unless its state is `updated`, `current` or
    /// `source`, `still_valid` and `unusable` reflect the version held
    /// (`version`), which may be stale. `None` when no certificate was held
    /// to judge and the context was not held before.
    #[serde(default)]
    pub context_check: Option<ContextRefreshInfo>,
}

/// What a `security/context-refresh` found for one namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefreshState {
    /// A newer version was adopted, stored and published.
    Updated,
    /// The namespace serves the version held.
    Current,
    /// What answered serves an older version than held; nothing changed.
    UpstreamOlder,
    /// What answered named a version older than one this node knows exists
    /// (its signed Data, served over the namespace's sync group, passed the
    /// continuity rule; an announced sequence number alone never counts) but
    /// does not hold: a cache may answer with the previous metadata for up
    /// to its FreshnessPeriod after a new version, or the upstream has not
    /// refreshed yet. Nothing changed; refresh again.
    Behind,
    /// This node holds the namespace root key: it is where new versions
    /// are made, so it does not fetch them.
    Source,
    /// Nothing answered for the namespace's newest version (no route, no
    /// reply): whether a newer one exists is unknown; the held version stays.
    Unreachable,
    /// The check failed or the update was refused; the held version stays.
    Failed,
}

/// One namespace's `security/context-refresh` result (the answer is a JSON
/// list of these).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContextRefreshInfo {
    pub namespace: String,
    pub state: RefreshState,
    /// The version held before the check.
    pub held_version: u64,
    /// The version held now.
    pub version: u64,
    /// Revocation entries the adopted version adds.
    pub revoked: Vec<String>,
    /// Why, for `failed`; what answered, otherwise.
    pub detail: String,
}

/// What a `security/renew` did for one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenewalState {
    /// A new certificate for the same key was issued, stored and served.
    Renewed,
    /// Not renewable as it stands — the CA refused (revoked key,
    /// non-renewable role, …) or the certificate expired; `detail` says what
    /// to do instead (usually: a new invite).
    Refused,
    /// The attempt failed (CA unreachable, local error); it can be retried.
    Failed,
}

/// One certificate's `security/renew` result (the answer is a JSON list of
/// these, one per certificate a namespace CA issued to this node).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RenewalInfo {
    /// The certified key, `/<ns>/<role>/<device>/KEY/<id>`.
    pub key: String,
    pub state: RenewalState,
    /// The certificate held before.
    pub previous: String,
    /// Its validity end, ISO 8601 (UTC).
    pub previous_valid_until: String,
    /// The new certificate, for `renewed`.
    pub certificate: Option<String>,
    /// Its validity end, ISO 8601 (UTC), for `renewed`.
    pub valid_until: Option<String>,
    /// Its lifetime in seconds, as the CA's policy for the role set it.
    pub validity_secs: Option<u64>,
    /// Why, for `refused` and `failed`.
    pub detail: String,
}

/// How a device takes part in a namespace (a trusted prefix) it holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MembershipRelation {
    /// The namespace's trust context is adopted: the device verifies its
    /// Data but holds no certificate in it, so it cannot publish under it.
    Following,
    /// The device holds a currently valid, unrevoked device certificate in
    /// the namespace: it publishes under it with that key.
    Member,
    /// The device holds the namespace's root key: the namespace's versions
    /// are made here.
    Owner,
}

impl MembershipRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Following => "following",
            Self::Member => "member",
            Self::Owner => "owner",
        }
    }
}

impl std::fmt::Display for MembershipRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One namespace a device holds and how it takes part in it
/// (`security/memberships` answers a JSON list of these, one per held
/// namespace).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipInfo {
    pub namespace: String,
    /// The version of the namespace's trust context held.
    pub version: u64,
    pub relation: MembershipRelation,
    /// The device's role in the namespace (`admin`, `member`, `node`,
    /// `guest`, …); empty when it holds no device certificate there.
    pub role: String,
    /// The device identity it signs the namespace's Data as,
    /// `/<ns>/<role>/<device>`; empty when it holds none.
    pub identity: String,
    /// That identity's key; empty when none.
    pub key: String,
    /// The key's certificate validity end, ISO 8601 (UTC); empty when none.
    pub valid_until: String,
    /// Whether `identity` is the node identity (management responses,
    /// discovery records, links).
    pub node_identity: bool,
    /// Hex of the SHA-256 fingerprint of the namespace's root (its first
    /// trust anchor's public key): what an anchor link names.
    pub root_fingerprint: String,
}

/// What changed a device's membership in a namespace
/// ([`MembershipEvent::change`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MembershipChange {
    /// The namespace's trust context was adopted: the device follows it.
    Adopted,
    /// The device enrolled: it holds a certificate in the namespace now.
    Enrolled,
    /// A certificate of the device in the namespace was renewed.
    Renewed,
    /// A version of the namespace revokes a certificate of the device (or an
    /// issuer on its chain).
    Revoked,
    /// The namespace's root changed (a recovery): a new root signs it.
    RootChanged,
}

/// A change of the device's membership in one namespace, published as it
/// happens (`/localhost/nfd/security/notifications`, JSON).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipEvent {
    pub namespace: String,
    /// The device's relation to the namespace after the change.
    pub relation: MembershipRelation,
    pub change: MembershipChange,
    /// What changed, in words (the key enrolled or renewed, the version
    /// adopted, what a revocation names).
    pub detail: String,
}
