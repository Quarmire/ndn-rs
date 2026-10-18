//! What the trust-admin operations of a device in a personal namespace
//! report: adopting a trust context, enrolling, refreshing held contexts,
//! taking a version made on the device, renewing certificates — and why one
//! changed nothing ([`TrustRefusal`]).
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
    /// Whether the running node signs with the new key now (management
    /// responses, discovery records). `false` when `[security] identity` in
    /// its config names another identity, which keeps precedence.
    pub signing_now: bool,
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
