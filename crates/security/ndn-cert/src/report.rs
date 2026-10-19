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

/// The parameters of a [`TrustRefusal`] or a [`Detail`]: named facts a
/// client words its own sentence from (names, versions, roles, times).
pub type Params = std::collections::BTreeMap<String, String>;

/// What the person at the device can do about a refusal, by class. A
/// client words the step itself (its own command, button or screen); the
/// code's parameters say what the step is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NextStep {
    /// Nothing to do: what was asked holds already, or the outcome is final.
    None,
    /// Ask again later, unchanged: something was busy, unreachable or slow.
    RetryLater,
    /// Correct what was given (a link, a name, a parameter) and ask again.
    FixRequest,
    /// Get a (new) invite from an admin of the namespace.
    GetInvite,
    /// Adopt the namespace on this device first (its anchor link).
    Adopt,
    /// Enroll this device (first, or again).
    Enroll,
    /// Have an admin decide: approve or deny on an admin or root device.
    AskAdmin,
    /// Check the namespace's trust context for a newer version.
    Refresh,
    /// Do it on another device: the namespace's root device or an admin
    /// device.
    UseOtherDevice,
    /// Fix this device's own setup: its key storage, configuration or
    /// permissions.
    FixLocal,
    /// Give the right secret (passphrase, PIN, recovery words).
    ProvideSecret,
    /// Wait for what is under way (a pending approval, a busy device).
    Wait,
    /// A step this client does not know (a newer peer): show the reason.
    #[serde(other)]
    Other,
}

/// One stable refusal code: its machine id, the status code it is answered
/// with, whether asking again unchanged can succeed, and the class of the
/// next step. The catalogue is [`code`]; `ndn-rs/docs/specs/mgmt-trust.md`
/// documents every entry and its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalCode {
    /// Stable, kebab-case: what a client keys its wording on.
    pub code: &'static str,
    /// `400` bad link or parameters, `403` refused by a trust check or the
    /// CA, `404` nothing of that kind here, `409` conflicting state or
    /// another such command running, `500` local failure, `504` the network
    /// did not deliver.
    pub status_code: u64,
    /// Whether the same request, unchanged, can succeed later.
    pub retry: bool,
    pub next: NextStep,
}

impl RefusalCode {
    pub const fn new(code: &'static str, status_code: u64, retry: bool, next: NextStep) -> Self {
        Self {
            code,
            status_code,
            retry,
            next,
        }
    }
}

/// The catalogue of refusal codes, grouped by the operations that answer
/// them. Every code here is documented in `ndn-rs/docs/specs/mgmt-trust.md`
/// with its parameters.
pub mod code {
    #[allow(unused_imports)]
    use super::{NextStep, RefusalCode};

    // --- adopt, enroll, enroll-status, context-refresh, context-update, renew
    //
    // A refusal wrapping another one names it in `cause` and carries its
    // params too. `error` is a failure's own text (neutral).

    /// No trust context of `namespace` is held: adopt it first. Params:
    /// `namespace`.
    pub const CONTEXT_NOT_HELD: RefusalCode =
        RefusalCode::new("context-not-held", 404, false, NextStep::Adopt);
    /// The anchor or enroll link is unreadable or incomplete. Params:
    /// `error`.
    pub const LINK_INVALID: RefusalCode =
        RefusalCode::new("link-invalid", 400, false, NextStep::FixRequest);
    /// The link given to enroll is neither an invite nor an anchor link.
    /// Params: `error`.
    pub const NOT_AN_ENROLL_LINK: RefusalCode =
        RefusalCode::new("not-an-enroll-link", 400, false, NextStep::FixRequest);
    /// The trust context could not be fetched. Params: `namespace`, `error`.
    pub const CONTEXT_UNREACHABLE: RefusalCode =
        RefusalCode::new("context-unreachable", 504, true, NextStep::RetryLater);
    /// Another adoption or update of the namespace runs on this device.
    /// Params: `error`.
    pub const TRUST_CHANGE_IN_PROGRESS: RefusalCode =
        RefusalCode::new("trust-change-in-progress", 409, true, NextStep::Wait);
    /// The trust context failed its checks (fingerprint, signature,
    /// version). Params: `namespace`, `error`.
    pub const CONTEXT_REFUSED: RefusalCode =
        RefusalCode::new("context-refused", 403, false, NextStep::FixRequest);
    /// The held context of `namespace` is signed by another root than the
    /// link expects; the held one stays. Params: `namespace`, `held`,
    /// `expected` (fingerprints, hex).
    pub const DIFFERENT_ROOT: RefusalCode =
        RefusalCode::new("different-root", 403, false, NextStep::FixRequest);
    /// Version `version` was adopted, but a newer one (`now`) was adopted
    /// meanwhile and is what the device keeps. Params: `namespace`,
    /// `version`, `now`.
    pub const CONTEXT_SUPERSEDED: RefusalCode =
        RefusalCode::new("context-superseded", 409, false, NextStep::None);
    /// Version `version` holds for this run, but storing it failed.
    /// Params: `namespace`, `version`, `error`, `location` (the store).
    pub const CONTEXT_NOT_STORED: RefusalCode =
        RefusalCode::new("context-not-stored", 500, false, NextStep::FixLocal);
    /// The update handed over is not a trust-context Data. Params: `error`.
    pub const UPDATE_INVALID: RefusalCode =
        RefusalCode::new("update-invalid", 400, false, NextStep::FixRequest);
    /// The update does not follow the held version (not signed by one of
    /// its anchors, not newer). Params: `namespace`, `held_version`,
    /// `error`.
    pub const UPDATE_REFUSED: RefusalCode =
        RefusalCode::new("update-refused", 403, false, NextStep::FixRequest);
    /// The held version changed while the update was checked: make the new
    /// version again from the one held now. Params: `namespace`, `now`.
    pub const CONTEXT_CHANGED_MEANWHILE: RefusalCode = RefusalCode::new(
        "context-changed-meanwhile",
        409,
        false,
        NextStep::FixRequest,
    );
    /// Another enrollment in the namespace runs on this device. Params:
    /// `namespace`.
    pub const ENROLL_BUSY: RefusalCode = RefusalCode::new("enroll-busy", 409, true, NextStep::Wait);
    /// The identity to enroll is not `/<namespace>/<role>/<device>` in the
    /// link's namespace. Params: `identity`, `namespace`.
    pub const IDENTITY_INVALID: RefusalCode =
        RefusalCode::new("identity-invalid", 400, false, NextStep::FixRequest);
    /// The identity to enroll is not `<device>` under the invite's identity
    /// namespace. Params: `identity`, `prefix`.
    pub const IDENTITY_OUTSIDE_INVITE: RefusalCode =
        RefusalCode::new("identity-outside-invite", 400, false, NextStep::FixRequest);
    /// The invite admits another role than the one asked, which the
    /// namespace certifies by invite. Params: `namespace`, `invite_role`,
    /// `role`.
    pub const INVITE_FOR_ANOTHER_ROLE: RefusalCode =
        RefusalCode::new("invite-for-another-role", 400, false, NextStep::GetInvite);
    /// An anchor link was given for a role the namespace certifies by
    /// invite. Params: `namespace`, `role`, `policy` (what it certifies on
    /// an admin's approval).
    pub const ROLE_BY_INVITE: RefusalCode =
        RefusalCode::new("role-by-invite", 400, false, NextStep::GetInvite);
    /// An anchor link was given for a role the namespace certifies only on
    /// an invite and an admin's approval. Params: `namespace`, `role`.
    pub const ROLE_NEEDS_INVITE_AND_APPROVAL: RefusalCode = RefusalCode::new(
        "role-needs-invite-and-approval",
        400,
        false,
        NextStep::GetInvite,
    );
    /// The device holds a valid certificate in the namespace already.
    /// Params: `namespace`, `still_valid` (`, `-separated `<key> (valid
    /// until <ISO 8601>)`), and when the newest version could not be
    /// confirmed `judged_version` with `cause` (the check's detail code)
    /// and its params and `judged_detail` (its text).
    pub const ALREADY_CERTIFIED: RefusalCode =
        RefusalCode::new("already-certified", 409, false, NextStep::FixRequest);
    /// The device's key storage could not be read. Params: `error`.
    pub const KEYS_UNREADABLE: RefusalCode =
        RefusalCode::new("keys-unreadable", 500, false, NextStep::FixLocal);
    /// The device's records of its requests for an admin's approval could
    /// not be read or updated. Params: `error`.
    pub const REQUESTS_UNREADABLE: RefusalCode =
        RefusalCode::new("requests-unreadable", 500, false, NextStep::FixLocal);
    /// The device key could not be generated. Params: `error`, `location`
    /// (absent: naming it failed, the system RNG).
    pub const KEY_NOT_GENERATED: RefusalCode =
        RefusalCode::new("key-not-generated", 500, false, NextStep::FixLocal);
    /// The invite is unusable as given (unreadable, altered, for another
    /// role, without a root fingerprint). Params: `error`.
    pub const INVITE_INVALID: RefusalCode =
        RefusalCode::new("invite-invalid", 400, false, NextStep::GetInvite);
    /// The CA refused the invite (spent, expired, unknown). Params:
    /// `error`, and `adopted_namespace` / `adopted_version` when a trust
    /// context was adopted on the way (it stays adopted).
    pub const INVITE_REFUSED: RefusalCode =
        RefusalCode::new("invite-refused", 403, false, NextStep::GetInvite);
    /// The device name is refused (malformed). Params: `error`.
    pub const DEVICE_NAME_INVALID: RefusalCode =
        RefusalCode::new("device-name-invalid", 400, false, NextStep::FixRequest);
    /// The CA certified that device name already: ask under another one,
    /// or revoke that certificate first. Params: `error`.
    pub const DEVICE_NAME_TAKEN: RefusalCode =
        RefusalCode::new("device-name-taken", 409, false, NextStep::FixRequest);
    /// The CA (or the trust context on the way) could not be reached.
    /// Params: `error`, and `adopted_namespace` / `adopted_version`.
    pub const CA_UNREACHABLE: RefusalCode =
        RefusalCode::new("ca-unreachable", 504, true, NextStep::RetryLater);
    /// The CA refused the request. Params: `error`, and
    /// `adopted_namespace` / `adopted_version`.
    pub const CA_REFUSED: RefusalCode =
        RefusalCode::new("ca-refused", 403, false, NextStep::FixRequest);
    /// The request ended unanswered or expired at the CA: ask again.
    /// Params: `error`.
    pub const REQUEST_EXPIRED: RefusalCode =
        RefusalCode::new("request-expired", 410, false, NextStep::Enroll);
    /// An admin denied the request. Params: `error` (the denial).
    pub const REQUEST_DENIED: RefusalCode =
        RefusalCode::new("request-denied", 403, false, NextStep::Enroll);
    /// The certificate the CA issued failed its checks: refresh the trust
    /// context, then ask again. Params: `error`.
    pub const ISSUED_CERTIFICATE_REFUSED: RefusalCode =
        RefusalCode::new("issued-certificate-refused", 403, false, NextStep::Refresh);
    /// Signing with a device or admin key failed. Params: `error`.
    pub const SIGNING_FAILED: RefusalCode =
        RefusalCode::new("signing-failed", 500, false, NextStep::FixLocal);
    /// The CA holds the request, but the device could not record it: its
    /// key was deleted. Params: `request`, `code` (the verification code),
    /// `error`, `location` (the key storage).
    pub const REQUEST_NOT_RECORDED: RefusalCode =
        RefusalCode::new("request-not-recorded", 500, false, NextStep::FixLocal);
    /// The CA issued a certificate that could not be kept: nothing was
    /// kept. Params: `certificate`, `location`, `error`, `spent` (`invite`:
    /// the token is spent; `approval`: the approval is used).
    pub const CERTIFICATE_NOT_KEPT: RefusalCode =
        RefusalCode::new("certificate-not-kept", 500, false, NextStep::FixLocal);
    /// The certificates to renew could not be read. Params: `error`.
    pub const RENEWAL_KEYS_UNREADABLE: RefusalCode =
        RefusalCode::new("renewal-keys-unreadable", 500, false, NextStep::FixLocal);
    /// The device holds no certificate a namespace CA issued to it.
    /// Params: `location` (the key storage).
    pub const NOTHING_TO_RENEW: RefusalCode =
        RefusalCode::new("nothing-to-renew", 404, false, NextStep::Enroll);

    // --- approvals (ca/list-approvals, ca/approve, ca/deny)
    //
    // A CA's own refusal of a decision or a listing (`ApprovalRefusal`) is
    // answered with one of these too; one from a CA that names no code is
    // the generic code of its kind (`approval-not-found`,
    // `approval-conflict`, `approval-unauthorized`, `approval-bad-decision`,
    // `approval-not-recorded`).

    /// This device neither runs a CA that takes approval requests nor holds
    /// a current admin certificate of a namespace whose CA runs elsewhere.
    pub const NOTHING_TO_APPROVE: RefusalCode =
        RefusalCode::new("nothing-to-approve", 404, false, NextStep::UseOtherDevice);
    /// No such pending request. Params: `target` when known.
    pub const APPROVAL_NOT_FOUND: RefusalCode =
        RefusalCode::new("approval-not-found", 404, false, NextStep::FixRequest);
    /// `target` is neither a request id nor a six-digit code. Params:
    /// `target`.
    pub const APPROVAL_UNKNOWN_TARGET: RefusalCode =
        RefusalCode::new("approval-unknown-target", 404, false, NextStep::FixRequest);
    /// No pending request shows the code. Params: `code`.
    pub const APPROVAL_NO_CODE_MATCH: RefusalCode =
        RefusalCode::new("approval-no-code-match", 404, false, NextStep::FixRequest);
    /// No pending request shows `target` at the CAs asked. Params:
    /// `target`, `scope` (`local-and-administered`: this device's CA and
    /// those of the namespaces it administers; `administered`: only the
    /// latter), and `unasked` (`; `-separated reasons) when not every CA
    /// could be asked — the status code is then the first such reason's.
    pub const APPROVAL_NOT_PENDING: RefusalCode =
        RefusalCode::new("approval-not-pending", 404, false, NextStep::FixRequest);
    /// Several pending requests show the code: decide by request id.
    /// Params: `code` (at one CA), or `target` and `matches` (`, `-separated
    /// `<request id> (<CA>)`) when they are at several CAs.
    pub const APPROVAL_AMBIGUOUS: RefusalCode =
        RefusalCode::new("approval-ambiguous", 409, false, NextStep::FixRequest);
    /// A conflicting decision (generic, from a CA naming no code).
    pub const APPROVAL_CONFLICT: RefusalCode =
        RefusalCode::new("approval-conflict", 409, false, NextStep::None);
    /// The request is decided already; a decision is final. Params:
    /// `request`, `state`.
    pub const APPROVAL_DECIDED: RefusalCode =
        RefusalCode::new("approval-decided", 409, false, NextStep::None);
    /// The request expired undecided: the device must ask again. Params:
    /// `request`, `expired` (ISO 8601).
    pub const APPROVAL_EXPIRED: RefusalCode =
        RefusalCode::new("approval-expired", 409, false, NextStep::None);
    /// The signer may not decide or list (signature, chain, schema,
    /// revocation, freshness). Params: `error`.
    pub const APPROVAL_UNAUTHORIZED: RefusalCode = RefusalCode::new(
        "approval-unauthorized",
        403,
        false,
        NextStep::UseOtherDevice,
    );
    /// The decision is malformed or names another request or key. Params:
    /// `error`.
    pub const APPROVAL_BAD_DECISION: RefusalCode =
        RefusalCode::new("approval-bad-decision", 400, false, NextStep::FixRequest);
    /// The CA could not record the decision durably; nothing changed.
    /// Params: `error`.
    pub const APPROVAL_NOT_RECORDED: RefusalCode =
        RefusalCode::new("approval-not-recorded", 500, true, NextStep::RetryLater);
    /// The namespace's CA refused this admin device's listing or decision.
    /// The status code, retry and next step are the CA's refusal's. Params:
    /// `ca`, `cause` (the CA's code) and its params, `error` (the CA's
    /// sentence).
    pub const APPROVAL_REFUSED_BY_CA: RefusalCode =
        RefusalCode::new("approval-refused-by-ca", 403, false, NextStep::Other);
    /// The namespace's CA could not be asked. Params: `ca`, `error`.
    pub const APPROVAL_CA_UNREACHABLE: RefusalCode =
        RefusalCode::new("approval-ca-unreachable", 504, true, NextStep::RetryLater);
    /// The namespace's CA answered something unreadable or untrusted.
    /// Params: `ca`, `error`.
    pub const APPROVAL_CA_BAD_ANSWER: RefusalCode =
        RefusalCode::new("approval-ca-bad-answer", 502, true, NextStep::RetryLater);
    /// Nothing at all could be listed: no administered namespace's CA
    /// answered. The status code is the first failure's. Params: `notes`
    /// (`; `-separated, the listing notes' texts).
    pub const APPROVALS_UNLISTED: RefusalCode =
        RefusalCode::new("approvals-unlisted", 504, true, NextStep::RetryLater);
    /// The approve / deny target is missing: give the request id or the
    /// six-digit code (a denial may add `:<reason>`).
    pub const APPROVAL_TARGET_MISSING: RefusalCode =
        RefusalCode::new("approval-target-missing", 400, false, NextStep::FixRequest);

    // --- invites (ca/invite-*)

    /// This node runs no CA, so it makes no invites. Params: none.
    pub const INVITE_NO_CA: RefusalCode =
        RefusalCode::new("invite-no-ca", 404, false, NextStep::UseOtherDevice);
    /// This node runs several CAs and the request names none: name the
    /// namespace (or CA prefix). Params: `namespaces` (`, `-separated, the
    /// namespaces of its CAs), `count`.
    pub const INVITE_SEVERAL_CAS: RefusalCode =
        RefusalCode::new("invite-several-cas", 400, false, NextStep::FixRequest);
    /// This node runs no CA of the namespace (or CA prefix) asked. Params:
    /// `requested`, `namespaces` (`, `-separated, those of its CAs).
    pub const INVITE_CA_UNKNOWN: RefusalCode =
        RefusalCode::new("invite-ca-unknown", 404, false, NextStep::FixRequest);
    /// The invite request is unreadable (not an invite request). Params:
    /// `error`.
    pub const INVITE_REQUEST_INVALID: RefusalCode =
        RefusalCode::new("invite-request-invalid", 400, false, NextStep::FixRequest);
    /// The role asked is not a role of the namespace layout. Params: `role`.
    pub const INVITE_ROLE_UNKNOWN: RefusalCode =
        RefusalCode::new("invite-role-unknown", 400, false, NextStep::FixRequest);
    /// The role is certified only on an admin's approval, never by an
    /// invite: invite a member or a guest, or have the device ask for the
    /// role with the namespace's anchor link. Params: `role`, `namespace`.
    pub const INVITE_ROLE_NEEDS_APPROVAL: RefusalCode = RefusalCode::new(
        "invite-role-needs-approval",
        400,
        false,
        NextStep::FixRequest,
    );
    /// The lifetime asked is zero or beyond what a time can hold. Params:
    /// `ttl_secs`.
    pub const INVITE_EXPIRY_INVALID: RefusalCode =
        RefusalCode::new("invite-expiry-invalid", 400, false, NextStep::FixRequest);
    /// The device-name hint is not a valid device name. Params: `device`,
    /// `error`.
    pub const INVITE_DEVICE_INVALID: RefusalCode =
        RefusalCode::new("invite-device-invalid", 400, false, NextStep::FixRequest);
    /// The CA holds no invite with this id. Params: `id`.
    pub const INVITE_UNKNOWN: RefusalCode =
        RefusalCode::new("invite-unknown", 404, false, NextStep::FixRequest);
    /// The invite was redeemed already: there is nothing to withdraw (revoke
    /// the device's certificate instead). Params: `id`, `ended_secs`, and
    /// `redeemed_for` (the name it certified) when known.
    pub const INVITE_ALREADY_REDEEMED: RefusalCode =
        RefusalCode::new("invite-already-redeemed", 409, false, NextStep::None);
    /// The invite was withdrawn already. Params: `id`, `ended_secs`.
    pub const INVITE_ALREADY_WITHDRAWN: RefusalCode =
        RefusalCode::new("invite-already-withdrawn", 409, false, NextStep::None);
    /// The CA could not record the change durably, so nothing changed (an
    /// invite is never made, withdrawn or redeemed unrecorded). Params:
    /// `error`.
    pub const INVITE_NOT_RECORDED: RefusalCode =
        RefusalCode::new("invite-not-recorded", 500, true, NextStep::FixLocal);
    /// The CA could not draw the invite's random token or id (the system
    /// RNG failed). Params: `error`.
    pub const INVITE_NOT_MADE: RefusalCode =
        RefusalCode::new("invite-not-made", 500, true, NextStep::FixLocal);

    // --- trust-admin gate and management parameters

    /// This node does not do `operation` at runtime (its host has no such
    /// backend). Params: `operation` (the verb, e.g. `enroll`).
    pub const NOT_AT_RUNTIME: RefusalCode =
        RefusalCode::new("not-at-runtime", 404, false, NextStep::UseOtherDevice);
    /// A required parameter of the verb is missing. Params: `operation`,
    /// `parameter` (the ControlParameters field: `Uri`, `Name`,
    /// `ContextData`), `expects` (what it carries).
    pub const MISSING_PARAMETER: RefusalCode =
        RefusalCode::new("missing-parameter", 400, false, NextStep::FixRequest);
    /// A trust change arrived over `/localhop`: trust changes are accepted
    /// only on the node's local management socket. Params: `operation`.
    pub const TRUST_CHANGE_OVER_LOCALHOP: RefusalCode = RefusalCode::new(
        "trust-change-over-localhop",
        403,
        false,
        NextStep::UseOtherDevice,
    );
    /// A trust change arrived on a face that carries no caller identity (not
    /// the local management socket). Params: `daemon_uid`, `groups`
    /// (`, `-separated trust-admin groups configured; empty: none).
    pub const TRUST_CHANGE_UNIDENTIFIED: RefusalCode =
        RefusalCode::new("trust-change-unidentified", 403, false, NextStep::FixLocal);
    /// A trust change from a local user who is no operator of this node.
    /// Params: `uid`, `daemon_uid`, `groups` (as above).
    pub const TRUST_CHANGE_NOT_OPERATOR: RefusalCode =
        RefusalCode::new("trust-change-not-operator", 403, false, NextStep::FixLocal);
    /// An unsigned (or digest-signed) command from a local user who is no
    /// operator of this node, where signed commands are required. Params:
    /// `uid`, `daemon_uid`, `groups` (as above), `anchor_configured`
    /// (`true`/`false`: whether a command trust anchor is configured to
    /// verify a signed one).
    pub const COMMAND_NOT_OPERATOR: RefusalCode =
        RefusalCode::new("command-not-operator", 403, false, NextStep::FixLocal);
    /// A local operator's command is signed by a key, but no command trust
    /// anchor is configured to verify it: send it unsigned.
    pub const COMMAND_SIGNER_UNVERIFIABLE: RefusalCode = RefusalCode::new(
        "command-signer-unverifiable",
        403,
        false,
        NextStep::FixRequest,
    );
    /// The command must be signed by a key a command trust anchor vouches
    /// for, and none is configured.
    pub const COMMAND_NO_ANCHOR: RefusalCode =
        RefusalCode::new("command-no-anchor", 403, false, NextStep::FixLocal);
    /// The command carries no key-backed signature (unsigned or
    /// DigestSha256) where one is required.
    pub const COMMAND_UNSIGNED: RefusalCode =
        RefusalCode::new("command-unsigned", 403, false, NextStep::FixRequest);
    /// The command's signature failed (invalid, its signing certificate
    /// not resolved yet, missing or stale signature time, a replay).
    /// Params: `error`.
    pub const COMMAND_SIGNATURE_REFUSED: RefusalCode = RefusalCode::new(
        "command-signature-refused",
        403,
        false,
        NextStep::FixRequest,
    );
    /// The command's signing certificate is not resolved yet: ask again
    /// shortly.
    pub const COMMAND_SIGNER_PENDING: RefusalCode =
        RefusalCode::new("command-signer-pending", 403, true, NextStep::RetryLater);
    /// Validation is disabled on this node, so it manages no trust schema.
    pub const VALIDATION_DISABLED: RefusalCode =
        RefusalCode::new("validation-disabled", 404, false, NextStep::FixLocal);

    // --- root-device operations (init, revoke, recovery kits, recover,
    //     root key, schema)
    //
    // Answered by the `ndn_namespace::root` library (in process, never over
    // the wire). A refusal wrapping another one names it in `cause` and
    // carries its params too. `secret` params are `root-passphrase`,
    // `root-pin`, `kit-passphrase`, `kit-pin` or `kit-words`.

    /// The PIB (key storage) could not be opened. Params: `pib`.
    pub const PIB_UNREADABLE: RefusalCode =
        RefusalCode::new("pib-unreadable", 500, false, NextStep::FixLocal);
    /// A local failure (storage, encoding, crypto) under a root operation.
    /// Params: `error`.
    pub const ROOT_LOCAL_FAILURE: RefusalCode =
        RefusalCode::new("root-local-failure", 500, false, NextStep::FixLocal);
    /// The PIB holds no namespace root: `operation` is done on the root
    /// device. Params: `pib`, `operation`.
    pub const NOT_ROOT_DEVICE: RefusalCode =
        RefusalCode::new("not-root-device", 409, false, NextStep::UseOtherDevice);
    /// The PIB's root is no anchor of the held version (the namespace was
    /// recovered elsewhere). Params: `key`, `namespace`, `version`.
    pub const NO_LONGER_ROOT: RefusalCode =
        RefusalCode::new("no-longer-root", 409, false, NextStep::UseOtherDevice);
    /// No trust context of `namespace` is held. Params: `namespace`, `pib`
    /// (when read from a PIB).
    pub const NAMESPACE_NOT_HELD: RefusalCode =
        RefusalCode::new("namespace-not-held", 404, false, NextStep::Adopt);
    /// No trust context is held at all. Params: `pib`.
    pub const NO_NAMESPACE_HELD: RefusalCode =
        RefusalCode::new("no-namespace-held", 404, false, NextStep::Adopt);
    /// Several trust contexts are held: name the namespace. Params: `pib`
    /// or `namespaces` (comma-separated) and `count`.
    pub const SEVERAL_NAMESPACES: RefusalCode =
        RefusalCode::new("several-namespaces", 400, false, NextStep::FixRequest);
    /// The PIB holds no root of the namespace asked, only of others.
    /// Params: `pib`, `namespace` (those held, comma-separated),
    /// `requested`, `operation` (when known).
    pub const OTHER_NAMESPACE_ROOT: RefusalCode =
        RefusalCode::new("other-namespace-root", 409, false, NextStep::FixRequest);
    /// A name in the request does not fit the namespace's role layout.
    /// Params: `error`.
    pub const ROOT_BAD_REQUEST: RefusalCode =
        RefusalCode::new("root-bad-request", 400, false, NextStep::FixRequest);
    /// The host could not give the secret asked for (none entered, two
    /// entries differ, no way to ask). Params: `secret`.
    pub const SECRET_UNAVAILABLE: RefusalCode =
        RefusalCode::new("secret-unavailable", 400, false, NextStep::ProvideSecret);
    /// The root store needs a secret that was not given. Params: `secret`,
    /// `key`, `store`, `location`.
    pub const SECRET_NEEDED: RefusalCode =
        RefusalCode::new("secret-needed", 400, false, NextStep::ProvideSecret);
    /// The secret does not open the sealed root or kit. Params: `secret`,
    /// `path`.
    pub const WRONG_SECRET: RefusalCode =
        RefusalCode::new("wrong-secret", 403, false, NextStep::ProvideSecret);
    /// The recovery words are refused (not text, unknown word, checksum).
    /// Params: `error`.
    pub const BAD_RECOVERY_WORDS: RefusalCode =
        RefusalCode::new("bad-recovery-words", 400, false, NextStep::ProvideSecret);
    /// No OS keychain is reachable. Params: `reason`.
    pub const KEYCHAIN_UNAVAILABLE: RefusalCode =
        RefusalCode::new("keychain-unavailable", 500, false, NextStep::FixLocal);
    /// No root store was chosen and the default (the OS keychain) is not
    /// reachable: choose one. Params: `reason`.
    pub const NO_DEFAULT_ROOT_STORE: RefusalCode =
        RefusalCode::new("no-default-root-store", 400, false, NextStep::FixRequest);
    /// The OS keychain lost the entry that seals the root. Params:
    /// `service`, `account`, `path`.
    pub const KEYCHAIN_ENTRY_MISSING: RefusalCode =
        RefusalCode::new("keychain-entry-missing", 500, false, NextStep::FixLocal);
    /// The token holds the other key a new one must not share it with.
    /// Params: `serial`, `holds`.
    pub const TOKEN_IN_USE: RefusalCode =
        RefusalCode::new("token-in-use", 409, false, NextStep::FixRequest);
    /// The token's slot holds (or may hold) a key a new one would destroy.
    /// Params: `serial`, `slot`, `state`.
    pub const SLOT_IN_USE: RefusalCode =
        RefusalCode::new("slot-in-use", 409, false, NextStep::FixRequest);
    /// This build has no support for the root store. Params: `store`,
    /// `feature`.
    pub const ROOT_STORE_NOT_BUILT: RefusalCode =
        RefusalCode::new("root-store-not-built", 500, false, NextStep::UseOtherDevice);
    /// The hardware token failed. Params: `error`.
    pub const TOKEN_FAILED: RefusalCode =
        RefusalCode::new("token-failed", 500, true, NextStep::FixLocal);
    /// The token's firmware cannot hold a recovery kit. Params: `firmware`.
    pub const KIT_TOKEN_TOO_OLD: RefusalCode =
        RefusalCode::new("kit-token-too-old", 400, false, NextStep::FixRequest);
    /// The root store is unusable (descriptor, wrong key, storage).
    /// Params: `error`.
    pub const ROOT_STORE_FAILED: RefusalCode =
        RefusalCode::new("root-store-failed", 500, false, NextStep::FixLocal);
    /// The root cannot be moved to that store. Params: `from`, `to`,
    /// `reason`.
    pub const ROOT_STORE_UNMOVABLE: RefusalCode =
        RefusalCode::new("root-store-unmovable", 400, false, NextStep::FixRequest);
    /// The root did not unlock; nothing was signed. Params: `cause` and its
    /// params.
    pub const ROOT_NOT_UNLOCKED: RefusalCode =
        RefusalCode::new("root-not-unlocked", 403, false, NextStep::ProvideSecret);
    /// The namespace is initialized in the PIB already. Params:
    /// `namespace`, `pib`, `what`.
    pub const ALREADY_INITIALIZED: RefusalCode =
        RefusalCode::new("already-initialized", 409, false, NextStep::FixRequest);
    /// The stated namespace policy (enrollment, links, relays) is refused.
    /// Params: `error`.
    pub const NAMESPACE_POLICY_REFUSED: RefusalCode =
        RefusalCode::new("namespace-policy-refused", 400, false, NextStep::FixLocal);
    /// The name (or recovery key) to revoke is outside every namespace
    /// whose root the device holds. Params: `name`, `namespace` (those
    /// held, comma-separated), `operation` (when not a revocation: what is
    /// done on the root device of the name's namespace).
    pub const REVOKE_OUTSIDE_NAMESPACE: RefusalCode =
        RefusalCode::new("revoke-outside-namespace", 400, false, NextStep::FixRequest);
    /// The name to revoke is in another namespace than the one named.
    /// Params: `name`, `namespace` (the one it is in), `requested`.
    pub const REVOKE_OTHER_NAMESPACE: RefusalCode =
        RefusalCode::new("revoke-other-namespace", 400, false, NextStep::FixRequest);
    /// The name to revoke is the namespace CA's. Params: `name`,
    /// `namespace`.
    pub const REVOKE_NAMESPACE_CA: RefusalCode =
        RefusalCode::new("revoke-namespace-ca", 403, false, NextStep::FixRequest);
    /// The CA issued no certificate under the device name. Params: `pib`,
    /// `name`.
    pub const REVOKE_NONE_ISSUED: RefusalCode =
        RefusalCode::new("revoke-none-issued", 404, false, NextStep::FixRequest);
    /// The key may not be revoked (not a key of the namespace, or it covers
    /// an anchor). Params: `name`, `error`.
    pub const REVOKE_REFUSED: RefusalCode =
        RefusalCode::new("revoke-refused", 403, false, NextStep::FixRequest);
    /// The held version has everything asked already. Params: `version`.
    pub const NOTHING_TO_SIGN: RefusalCode =
        RefusalCode::new("nothing-to-sign", 409, false, NextStep::None);
    /// The file is not a recovery kit. Params: `path`, `reason`.
    pub const NOT_A_KIT: RefusalCode =
        RefusalCode::new("not-a-kit", 400, false, NextStep::FixRequest);
    /// The kit recovers another namespace. Params: `kit`, `namespace`,
    /// `path` (a file kit).
    pub const KIT_OTHER_NAMESPACE: RefusalCode =
        RefusalCode::new("kit-other-namespace", 400, false, NextStep::FixRequest);
    /// The kit's key is no recovery anchor of the held version. Params:
    /// `key`, `namespace`, `version`.
    pub const KIT_NOT_AN_ANCHOR: RefusalCode =
        RefusalCode::new("kit-not-an-anchor", 403, false, NextStep::FixRequest);
    /// The key named is no recovery kit of the held version. Params: `key`,
    /// `namespace`, `version`.
    pub const NOT_A_RECOVERY_KIT: RefusalCode =
        RefusalCode::new("not-a-recovery-kit", 404, false, NextStep::FixRequest);
    /// A kit file exists where a new one would be written. Params: `path`.
    pub const KIT_FILE_EXISTS: RefusalCode =
        RefusalCode::new("kit-file-exists", 409, false, NextStep::FixRequest);
    /// The kit was made but no version listing it was signed or taken:
    /// nothing changed, and a kit file written for it was removed. Params:
    /// `cause` and its params, `removed` (the kit file removed, if any).
    pub const KIT_NOT_ADDED: RefusalCode =
        RefusalCode::new("kit-not-added", 409, false, NextStep::Other);
    /// The signing key is no anchor of the held version. Params: `key`,
    /// `namespace`, `version`.
    pub const SIGNER_NOT_AN_ANCHOR: RefusalCode =
        RefusalCode::new("signer-not-an-anchor", 403, false, NextStep::UseOtherDevice);
    /// A recovery on a device that holds a namespace root already. Params:
    /// `pib`, `namespace`, `store`.
    pub const ALREADY_ROOT_DEVICE: RefusalCode =
        RefusalCode::new("already-root-device", 409, false, NextStep::UseOtherDevice);
    /// A recovery into a PIB holding a CA identity. Params: `path`.
    pub const CA_PRESENT: RefusalCode =
        RefusalCode::new("ca-present", 409, false, NextStep::UseOtherDevice);
    /// Kits to keep are named only when the old root is compromised.
    pub const KEPT_KITS_NEED_COMPROMISED: RefusalCode = RefusalCode::new(
        "kept-kits-need-compromised",
        400,
        false,
        NextStep::FixRequest,
    );
    /// The running device holds `version` but its PIB stores another one (or
    /// none). Params: `namespace`, `version`, `pib`, `stored` (absent: none).
    pub const DEVICE_STORE_MISMATCH: RefusalCode =
        RefusalCode::new("device-store-mismatch", 409, false, NextStep::FixRequest);
    /// The stored version does not verify. Params: `namespace`, `version`.
    pub const HELD_CONTEXT_INVALID: RefusalCode =
        RefusalCode::new("held-context-invalid", 500, false, NextStep::FixLocal);
    /// A newer version exists than the one held: a recovery from it would
    /// fork. Params: `namespace`, `held_version`, `detail`.
    pub const NEWEST_BEHIND: RefusalCode =
        RefusalCode::new("newest-behind", 409, true, NextStep::Refresh);
    /// Nothing answered: whether the held version is the newest is unknown
    /// (a recovery may vouch for it). Params: `namespace`, `held_version`,
    /// `detail`.
    pub const NEWEST_UNCONFIRMED: RefusalCode =
        RefusalCode::new("newest-unconfirmed", 504, true, NextStep::RetryLater);
    /// The device holds the namespace root: nothing to recover. Params:
    /// `namespace`.
    pub const RECOVER_ON_ROOT_DEVICE: RefusalCode =
        RefusalCode::new("recover-on-root-device", 409, false, NextStep::None);
    /// The newest version could not be fetched. Params: `namespace`,
    /// `held_version`, `detail`.
    pub const NEWEST_FAILED: RefusalCode =
        RefusalCode::new("newest-failed", 504, true, NextStep::RetryLater);
    /// The device holds no version and there is no expected fingerprint to
    /// adopt one with. Params: `namespace`.
    pub const NEWEST_NOT_HELD: RefusalCode =
        RefusalCode::new("newest-not-held", 404, false, NextStep::Adopt);
    /// Adopting with the kit's expected fingerprint was refused. Params:
    /// `namespace`, `status_code`, `reason`.
    pub const NEWEST_NOT_ADOPTED: RefusalCode =
        RefusalCode::new("newest-not-adopted", 403, false, NextStep::Adopt);
    /// No device runs where the operation needs one. Params: `address`,
    /// `error`.
    pub const DEVICE_NOT_RUNNING: RefusalCode =
        RefusalCode::new("device-not-running", 409, true, NextStep::FixLocal);
    /// The running device could not be used (permissions). Params:
    /// `address`, `pib`, `error`.
    pub const DEVICE_UNREACHABLE: RefusalCode =
        RefusalCode::new("device-unreachable", 403, false, NextStep::FixLocal);
    /// The running device did not say which PIB it uses. Params: `address`,
    /// `error`.
    pub const DEVICE_PIB_UNKNOWN: RefusalCode =
        RefusalCode::new("device-pib-unknown", 500, true, NextStep::RetryLater);
    /// The running device uses another PIB than the one worked on. Params:
    /// `address`, `device_pib`, `pib`.
    pub const DEVICE_OTHER_PIB: RefusalCode =
        RefusalCode::new("device-other-pib", 409, false, NextStep::FixRequest);
    /// An exchange with the running device failed. Params: `address`,
    /// `error`.
    pub const DEVICE_FAILED: RefusalCode =
        RefusalCode::new("device-failed", 500, true, NextStep::RetryLater);
    /// The running device answered that it did not take the version.
    /// Params: `version`, `status_code`, `device_code`, `reason`.
    pub const HAND_OVER_REFUSED: RefusalCode =
        RefusalCode::new("hand-over-refused", 409, false, NextStep::Other);
    /// The running device's answer could not be read. Params: `version`,
    /// `error`, `answer`.
    pub const HAND_OVER_UNREADABLE: RefusalCode =
        RefusalCode::new("hand-over-unreadable", 500, false, NextStep::Wait);
    /// Handing the version over failed without an answer. Params:
    /// `version`, `failure`.
    pub const HAND_OVER_FAILED: RefusalCode =
        RefusalCode::new("hand-over-failed", 504, true, NextStep::Wait);
    /// The running device never answered. Params: `version`, `waits`.
    pub const HAND_OVER_UNANSWERED: RefusalCode =
        RefusalCode::new("hand-over-unanswered", 504, true, NextStep::Wait);
    /// No device runs and the version could not be stored for its next
    /// start. Params: `version`, `error`.
    pub const VERSION_NOT_STORED: RefusalCode =
        RefusalCode::new("version-not-stored", 500, false, NextStep::FixLocal);
    /// The signed version was not taken: nothing changed. Params:
    /// `version`, `held_version`, `cause` and its params.
    pub const VERSION_NOT_TAKEN: RefusalCode =
        RefusalCode::new("version-not-taken", 409, false, NextStep::Other);
    /// Whether the running device took the signed version is not known; it
    /// may still. Asking again once it is idle settles it. Params:
    /// `version`, `cause` and its params, and the operation's (`keys`,
    /// `key`, `namespace`).
    pub const HAND_OVER_UNKNOWN: RefusalCode =
        RefusalCode::new("hand-over-unknown", 504, true, NextStep::Wait);
    /// The namespace's schema could not be generated. Params: `namespace`,
    /// `error`.
    pub const SCHEMA_NOT_GENERATED: RefusalCode =
        RefusalCode::new("schema-not-generated", 500, false, NextStep::FixLocal);
    /// The update would narrow what devices may do, without consent.
    /// Params: `namespace`, `version`, `what` (`rules`, `link`, `relays`),
    /// `removed` (`; `-separated).
    pub const SCHEMA_NARROWING: RefusalCode =
        RefusalCode::new("schema-narrowing", 409, false, NextStep::FixRequest);
    /// A schema blob of the held context cannot be read. Params: `blob`
    /// (its index), `format` (`lvs` or `native`), `error`.
    pub const SCHEMA_UNREADABLE: RefusalCode =
        RefusalCode::new("schema-unreadable", 500, false, NextStep::FixLocal);
    /// No held trust context governs the name. Params: `name`.
    pub const NO_CONTEXT_GOVERNS: RefusalCode =
        RefusalCode::new("no-context-governs", 404, false, NextStep::Adopt);

    // --- links (links/connect, links/disconnect, links/mode, and the links
    //     module itself)

    /// The links module has no such verb. Params: `verb`.
    pub const LINKS_UNKNOWN_VERB: RefusalCode =
        RefusalCode::new("links-unknown-verb", 404, false, NextStep::FixRequest);
    /// This node runs no QUIC links: it has no key (security is disabled).
    pub const LINKS_NOT_RUNNING: RefusalCode =
        RefusalCode::new("links-not-running", 404, false, NextStep::FixLocal);
    /// The command names no link (its label in the link listing).
    pub const LINK_LABEL_MISSING: RefusalCode =
        RefusalCode::new("link-label-missing", 400, false, NextStep::FixRequest);
    /// The mode given is not a link mode. Params: `mode` (as given).
    pub const LINK_MODE_INVALID: RefusalCode =
        RefusalCode::new("link-mode-invalid", 400, false, NextStep::FixRequest);
    /// No link has this label. Params: `label`.
    pub const LINK_NOT_FOUND: RefusalCode =
        RefusalCode::new("link-not-found", 404, false, NextStep::FixRequest);
    /// The device linked in and has no peer entry: it has no mode and is
    /// not dialled. Params: `label`.
    pub const LINK_NOT_CONFIGURED: RefusalCode =
        RefusalCode::new("link-not-configured", 400, false, NextStep::FixLocal);
    /// `links/mode` names no mode.
    pub const LINK_MODE_MISSING: RefusalCode =
        RefusalCode::new("link-mode-missing", 400, false, NextStep::FixRequest);
    /// The idle close is out of bounds. Params: `idle_secs`, `min`, `max`.
    pub const LINK_IDLE_OUT_OF_RANGE: RefusalCode =
        RefusalCode::new("link-idle-out-of-range", 400, false, NextStep::FixRequest);
}

/// Why a trust-admin operation changed nothing, as structured data: a
/// stable [`code`](Self::code) with its [`params`](Self::params), the
/// status code, whether retrying can help and the class of the next step —
/// a client words its own message from these — plus a neutral default
/// sentence ([`reason`](Self::reason)) that names no host's commands.
///
/// Management verbs answer a refusal with this as JSON in the
/// ControlResponse status text (status code = [`status_code`](Self::status_code)).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustRefusal {
    pub code: String,
    pub status_code: u64,
    pub retry: bool,
    pub next: NextStep,
    #[serde(default)]
    pub params: Params,
    /// The neutral default sentence: what happened and what to do, in no
    /// host's terms.
    pub reason: String,
}

impl TrustRefusal {
    /// A refusal of `kind` with the neutral sentence `reason`.
    pub fn new(kind: RefusalCode, reason: impl Into<String>) -> Self {
        Self {
            code: kind.code.to_owned(),
            status_code: kind.status_code,
            retry: kind.retry,
            next: kind.next,
            params: Params::new(),
            reason: reason.into(),
        }
    }

    /// With the parameter `key` = `value`.
    pub fn with(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.params.insert(key.to_owned(), value.to_string());
        self
    }

    /// The parameter `key`, if set.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Whether this is a refusal of `kind`.
    pub fn is(&self, kind: RefusalCode) -> bool {
        self.code == kind.code
    }

    /// Wrapping `cause`: the param `cause` is its code, and its params are
    /// carried too (those this refusal sets already win).
    pub fn with_cause(mut self, code: &str, params: &Params) -> Self {
        for (k, v) in params {
            self.params.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self.params.insert("cause".to_owned(), code.to_owned());
        self
    }
}

impl std::fmt::Display for TrustRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// A fact an outcome reports in words (why a refresh failed, what changes
/// at the next start), as structured data: a stable code with parameters
/// and a neutral default sentence. Codes are documented with the refusal
/// codes in `ndn-rs/docs/specs/mgmt-trust.md`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Detail {
    pub code: String,
    #[serde(default)]
    pub params: Params,
    /// The neutral default sentence.
    pub text: String,
}

impl Detail {
    pub fn new(code: &str, text: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            params: Params::new(),
            text: text.into(),
        }
    }

    /// With the parameter `key` = `value`.
    pub fn with(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.params.insert(key.to_owned(), value.to_string());
        self
    }

    /// The parameter `key`, if set.
    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }

    /// Wrapping `cause`, as [`TrustRefusal::with_cause`].
    pub fn with_cause(mut self, code: &str, params: &Params) -> Self {
        for (k, v) in params {
            self.params.entry(k.clone()).or_insert_with(|| v.clone());
        }
        self.params.insert("cause".to_owned(), code.to_owned());
        self
    }
}

/// A refusal reported inside an outcome (a request record that ended, a
/// check that failed): its code, params and sentence.
impl From<TrustRefusal> for Detail {
    fn from(refusal: TrustRefusal) -> Self {
        Self {
            code: refusal.code,
            params: refusal.params,
            text: refusal.reason,
        }
    }
}

/// A CA's refused approval decision or listing, as the approval code it
/// names; a CA that names none (or one this build does not know) is
/// answered with the generic code of its kind: `approval-not-found` (404),
/// `approval-conflict` (409), `approval-unauthorized` (403),
/// `approval-bad-decision` (400), `approval-not-recorded` (500).
impl From<crate::approval::ApprovalRefusal> for TrustRefusal {
    fn from(refusal: crate::approval::ApprovalRefusal) -> Self {
        use crate::approval::RefusalKind as Kind;
        let known = [
            code::APPROVAL_UNKNOWN_TARGET,
            code::APPROVAL_NO_CODE_MATCH,
            code::APPROVAL_AMBIGUOUS,
            code::APPROVAL_DECIDED,
            code::APPROVAL_EXPIRED,
        ];
        let kind = known
            .into_iter()
            .find(|c| c.code == refusal.code)
            .unwrap_or(match refusal.kind {
                Kind::NotFound => code::APPROVAL_NOT_FOUND,
                Kind::Conflict => code::APPROVAL_CONFLICT,
                Kind::Unauthorized => code::APPROVAL_UNAUTHORIZED,
                Kind::BadRequest => code::APPROVAL_BAD_DECISION,
                Kind::Storage => code::APPROVAL_NOT_RECORDED,
            });
        let mut out = Self::new(kind, refusal.reason);
        out.params = refusal.params;
        out
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
#[allow(
    clippy::large_enum_variant,
    reason = "one answer per enrollment, moved once into its JSON"
)]
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
    /// What changes only at the next start, and why (empty: nothing). The
    /// host's details (a forwarder's: its routing keeps the startup key,
    /// its configuration names another identity).
    pub at_next_start: Vec<Detail>,
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
    pub detail: Detail,
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
    /// Why, for `refused` and `failed`; `None` for `renewed`.
    pub detail: Option<Detail>,
}

/// The answer to `ca/approve` and `ca/deny`: the request as decided, JSON
/// in the ControlResponse status text.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ApprovalDecision {
    pub request_id: String,
    /// The key certified on approval, `/<ns>/<role>/<device>/KEY/<id>`.
    pub key_name: String,
    /// The CA the request was made to (the namespace, for a namespace CA).
    pub namespace: String,
    /// Empty when the CA did not record it.
    pub role: String,
    pub device: String,
    /// The verification code both screens showed (`482 913`).
    pub code: String,
    /// `approved` or `denied`.
    pub state: String,
    /// Who decided: the local operator the kernel attested (`uid 1000
    /// (alice)`), or the admin key that signed the decision.
    pub approver: String,
    /// A denial's reason (empty for an approval).
    pub reason: String,
    /// Until when the CA keeps the decided record (Unix seconds).
    pub expires_secs: u64,
}

/// The answer to `security/identity-status`, JSON in the ControlResponse
/// status text: the node identity — the key of the node's own packets
/// (management responses, discovery records, links) — and why it is the
/// one, every identity the node signs Data as (each trusted prefix with its
/// own key), and where the root key of each namespace it is the root device
/// of lives.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IdentityStatus {
    /// The node identity; `None` when it has none (no configured identity
    /// and no trust anchor).
    pub identity: Option<String>,
    /// The node key is an in-memory key minted at startup.
    pub is_ephemeral: bool,
    /// The PIB directory the node uses.
    pub pib_path: String,
    /// The node key, when the node tracks it.
    pub key: Option<String>,
    /// When the node key's certificate expires, ISO 8601 basic UTC
    /// (`20270101T000000Z`); `None` when the node holds no certificate
    /// with an end for it.
    pub valid_until: Option<String>,
    /// Days until then (negative once expired), with `valid_until`.
    pub days_left: Option<f64>,
    /// Which rule chose the node identity, when the node tracks it.
    pub node_identity_source: Option<crate::NodeIdentitySource>,
    /// Every identity the node signs Data as, sorted by identity.
    pub signing_identities: Vec<SigningIdentityStatus>,
    /// Where the root key of each namespace this node is the root device
    /// of is kept, sorted by namespace; empty on every other node.
    pub root_stores: Vec<RootStoreStatus>,
}

/// An identity a node signs Data as ([`IdentityStatus::signing_identities`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SigningIdentityStatus {
    /// `/<ns>/<role>/<device>`.
    pub identity: String,
    /// The key it signs with, `<identity>/KEY/<id>`.
    pub key: String,
}

/// Where a root device keeps a namespace's root key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootStoreStatus {
    /// The namespace whose root it is.
    pub namespace: String,
    /// `os-keyring`, `sealed-file`, `yubikey-piv` or `file`.
    pub kind: String,
    /// The root key, `<ns>/KEY/root`.
    pub key: String,
}

/// The codes of the [`Detail`]s trust-admin and approval outcomes carry
/// (documented with their params in `ndn-rs/docs/specs/mgmt-trust.md`).
/// A detail may also carry a refusal code ([`code`]) when it reports a
/// refusal inside an outcome.
pub mod detail_code {
    // --- context-refresh, context-update (`ContextRefreshInfo::detail`)

    /// This device holds the namespace root key: new versions are made
    /// here.
    pub const REFRESH_SOURCE: &str = "refresh-source";
    /// The namespace serves the version held. Params: `version`.
    pub const REFRESH_CURRENT: &str = "refresh-current";
    /// The answer names an older version than held. Params: `offered`,
    /// `held`, `freshness_secs`.
    pub const REFRESH_UPSTREAM_OLDER: &str = "refresh-upstream-older";
    /// The answer names an older version than one known to exist. Params:
    /// `answered`, `verified`, `by`, `freshness_secs`.
    pub const REFRESH_BEHIND: &str = "refresh-behind";
    /// Nothing answered for the newest version. Params: `error`.
    pub const REFRESH_UNREACHABLE: &str = "refresh-unreachable";
    /// The check failed or the update was refused. Params: `error`.
    pub const REFRESH_FAILED: &str = "refresh-failed";
    /// A refresh adopted a newer version. Params: `version`, `signer`,
    /// `from`, `walked` (`,`-separated versions walked through, absent if
    /// none), `published` (`true`/`false`), `stored` (where) or else
    /// `cause` (why it is not kept: a refusal code) with its params,
    /// `ca_revoked` (`, `-separated), `ca_not_persisted` (error).
    pub const CONTEXT_UPDATED: &str = "context-updated";
    /// A version made on this device was adopted. Params: `version`,
    /// `signer`, `held`, and as [`CONTEXT_UPDATED`] `published`, `stored`
    /// or `cause`, `ca_revoked`, `ca_not_persisted`.
    pub const UPDATE_ADOPTED: &str = "update-adopted";
    /// The version handed over was taken before. Params: `version`,
    /// `held`, `stored`.
    pub const UPDATE_ALREADY_TAKEN: &str = "update-already-taken";
    /// Enrollment's check of the trust context ran out of its budget.
    /// Params: `budget_secs`, `namespace`.
    pub const CONTEXT_CHECK_TIMED_OUT: &str = "context-check-timed-out";

    // --- renew (`RenewalInfo::detail`)

    /// The held trust context revokes the key: never renewed. Params:
    /// `key`.
    pub const RENEWAL_REVOKED: &str = "renewal-revoked";
    /// The key cannot sign. Params: `key`, `error`.
    pub const RENEWAL_KEY_UNAVAILABLE: &str = "renewal-key-unavailable";
    /// The CA refused for good (expired, not renewable). Params: `error`.
    pub const RENEWAL_REFUSED: &str = "renewal-refused";
    /// The attempt failed; it can be retried. Params: `error`.
    pub const RENEWAL_FAILED: &str = "renewal-failed";
    /// The CA issued a new certificate that could not be stored. Params:
    /// `certificate`, `location`, `error`.
    pub const RENEWAL_NOT_STORED: &str = "renewal-not-stored";

    // --- enroll (`EnrolledInfo::at_next_start`, a host's activation)

    /// The device started without a signing key: it signs as the new
    /// identity after a restart. Params: `identity`.
    pub const NEXT_START_UNSIGNED: &str = "next-start-unsigned";
    /// The host's configuration names the node identity, so it stays; the
    /// new identity is recorded as the default, the node identity once the
    /// configuration names none. Params: `configured`, `identity`.
    pub const NEXT_START_CONFIGURED_IDENTITY: &str = "next-start-configured-identity";
    /// Routing keeps signing with the key the device started with until a
    /// restart; its neighbours must trust the new key first. Params: `key`.
    pub const NEXT_START_ROUTING_KEY: &str = "next-start-routing-key";
    /// The identity was kept but the running device could not take it into
    /// use; it does at the next start. Params: `identity`, `error`.
    pub const NEXT_START_NOT_ACTIVATED: &str = "next-start-not-activated";

    // --- enroll-status (`OutgoingState` reasons)

    /// The CA never answered before the request expired; it ended here.
    /// Params: `request`, `expired`.
    pub const REQUEST_UNANSWERED: &str = "request-unanswered";
    /// The CA's signed answer ended the request (denied or expired), or a
    /// final failure did. Params: `error` (the CA's reason or the
    /// failure), `key`, `deleted` (`true`/`false`), `delete_error` and
    /// `location` when the key could not be deleted, `cause` (the refusal
    /// code of a final failure) with its params.
    pub const REQUEST_ENDED: &str = "request-ended";
    /// The request record names no valid namespace or CA.
    pub const REQUEST_NAMES_NO_CA: &str = "request-names-no-ca";
    /// The request record names no valid namespace, CA, identity or key.
    pub const REQUEST_NAMES_NO_KEY: &str = "request-names-no-key";
    /// The request's key is gone. Params: `key`, `why`.
    pub const REQUEST_KEY_GONE: &str = "request-key-gone";

    // --- ca/list-approvals notes

    /// A namespace's CA could not be asked. Params: `namespace`, `error`.
    pub const APPROVALS_CA_UNREACHABLE: &str = "approvals-ca-unreachable";
    /// A namespace's requests could not be listed. Params: `namespace`,
    /// `cause` (the refusal code) with its params, `error` (its text).
    pub const APPROVALS_NOT_LISTED: &str = "approvals-not-listed";
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

/// A change of the device's membership in one namespace
/// ([`TrustEvent::MembershipChanged`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipEvent {
    pub namespace: String,
    /// The device's relation to the namespace after the change.
    pub relation: MembershipRelation,
    pub change: MembershipChange,
    /// The version of the namespace's trust context held after the change.
    pub version: u64,
    /// The device key the change is about: the key enrolled, renewed, or
    /// that no longer validates (`revoked`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// What the version revokes on the key's chain (`revoked`): the key or
    /// certificate name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,
    /// The version whose root the new one replaced (`root-changed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_version: Option<u64>,
    /// The new certificate's validity end, ISO 8601 UTC (`enrolled`,
    /// `renewed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// The request for an admin's approval the enrollment waited for
    /// (`enrolled`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
}

/// One change in a device's trust, as it happens: the events of the trust
/// notification stream (`/localhost/nfd/security/notifications`, one JSON
/// object per Data, tagged by `"kind"`; spec: `mgmt-trust.md`,
/// "Notifications").
///
/// Events carry identifiers and states only — never a verification code,
/// an invite token, a key's secret or a denial's free text: the details are
/// read through the gated verbs (`ca/list-approvals`,
/// `security/enroll-status`, `ca/invite-list`, `security/memberships`).
///
/// Evolution: a kind's fields are only ever added (clients ignore fields
/// they do not know); a change of meaning takes a new kind, and a client
/// skips kinds it does not know ([`TrustEvent::Unknown`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TrustEvent {
    /// A device asked a CA of this node for an admin's approval. Who and
    /// its verification code: `ca/list-approvals`.
    ApprovalRequested {
        /// The CA's prefix.
        ca: String,
        /// The request id.
        request: String,
        /// The role the key asks for, when it follows the namespace layout.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    /// A request at a CA of this node was approved or denied (here or by an
    /// admin device).
    ApprovalDecided {
        ca: String,
        request: String,
        decision: Decision,
    },
    /// A CA of this node made an invite. The token is never carried:
    /// `ca/invite-list`.
    InviteCreated {
        ca: String,
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    /// An invite of a CA of this node was withdrawn before it was used.
    InviteWithdrawn { ca: String, id: String },
    /// A device redeemed an invite of a CA of this node.
    InviteRedeemed {
        ca: String,
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    /// This node now holds `version` of the namespace's trust context.
    ContextUpdated {
        namespace: String,
        /// The version held before, when this node held one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        held_version: Option<u64>,
        version: u64,
        how: ContextChange,
        /// What the new version revokes that the one held before did not
        /// (key or certificate names; empty for a first adoption).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        revoked: Vec<String>,
    },
    /// This node's membership in a namespace changed: it adopted the
    /// namespace, enrolled or renewed a certificate in it, a version
    /// revokes its key there, or the namespace's root changed.
    MembershipChanged(MembershipEvent),
    /// This node's request for an admin's approval ended without a
    /// certificate. Why: `security/enroll-status`. (An approved one ends in
    /// [`MembershipChanged`](Self::MembershipChanged) `enrolled`.)
    EnrollmentEnded {
        namespace: String,
        /// The identity asked for.
        identity: String,
        request: String,
        state: EnrollmentEnd,
    },
    /// A renewal of this node's certificate failed; the current one stays
    /// in use until it expires.
    RenewalFailed {
        key: String,
        state: RenewalFailure,
        /// The detail code `security/renew` reports for it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    /// A kind this client does not know: skip it.
    #[serde(other)]
    Unknown,
}

/// How an admin decided a request ([`TrustEvent::ApprovalDecided`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Approved,
    Denied,
    #[serde(other)]
    Unknown,
}

/// How a request for an admin's approval ended without a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnrollmentEnd {
    /// An admin denied the request (the key was deleted).
    Denied,
    /// The request expired undecided (the key was deleted).
    Expired,
    /// Approved, but the certificate could not be kept, or the request
    /// could not go on.
    Failed,
    #[serde(other)]
    Unknown,
}

/// How a trust-context version reached this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContextChange {
    /// Adopted from a link (`security/context-adopt`, or on the way to an
    /// enrollment).
    Adopt,
    /// Fetched from upstream by a refresh.
    Refresh,
    /// Handed over by a tool that signed it on a root device
    /// (`security/context-update`: a revocation, recovery, schema update).
    Update,
    /// Pushed over the namespace's sync group.
    Sync,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenewalFailure {
    /// The CA refused: renewing again does not help.
    Refused,
    /// It may work later; it is retried.
    Failed,
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod catalogue_tests {
    use super::*;

    /// The codes of this file's catalogues: every refusal code and every
    /// detail code, as written.
    fn catalogued() -> (Vec<&'static str>, Vec<&'static str>) {
        const SOURCE: &str = include_str!("report.rs");
        // The string literal a segment starts with, if it starts with one
        // that reads like a code.
        let quoted = |rest: &'static str| {
            let literal = rest.trim_start().strip_prefix('"')?;
            literal
                .starts_with(|c: char| c.is_ascii_lowercase())
                .then(|| literal.split('"').next())
                .flatten()
        };
        let refusals = SOURCE
            .split("RefusalCode::new(")
            .skip(1)
            .filter_map(quoted)
            .collect();
        let details_mod = SOURCE
            .split("pub mod detail_code {")
            .nth(1)
            .and_then(|m| m.split("\n}\n").next())
            .unwrap_or_default();
        let details = details_mod
            .split(": &str = ")
            .skip(1)
            .filter_map(quoted)
            .collect();
        (refusals, details)
    }

    /// Every code is stable kebab-case, unique across refusals and details,
    /// and documented in `ndn-rs/docs/specs/mgmt-trust.md`.
    #[test]
    fn codes_are_unique_kebab_and_documented() {
        const SPEC: &str = include_str!("../../../../docs/specs/mgmt-trust.md");
        let (refusals, details) = catalogued();
        assert!(refusals.len() > 100 && details.len() > 20);
        let all: Vec<&str> = refusals.iter().chain(&details).copied().collect();
        let mut seen = std::collections::BTreeSet::new();
        for code in &all {
            assert!(
                !code.is_empty()
                    && code
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && !code.starts_with('-')
                    && !code.ends_with('-'),
                "{code:?} is not kebab-case"
            );
            assert!(seen.insert(*code), "{code:?} is catalogued twice");
            assert!(
                SPEC.contains(&format!("`{code}`")),
                "{code:?} is not documented in mgmt-trust.md"
            );
        }
    }

    /// A refusal reads back from its JSON wire form unchanged; a peer's
    /// unknown next step reads as `other`.
    #[test]
    fn a_refusal_round_trips_through_json() {
        let refusal = TrustRefusal::new(code::ALREADY_CERTIFIED, "neutral")
            .with("namespace", "/home/bob")
            .with_cause(
                detail_code::CONTEXT_CHECK_TIMED_OUT,
                &[("budget_secs".to_owned(), "8".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let json = serde_json::to_string(&refusal).unwrap();
        assert_eq!(
            serde_json::from_str::<TrustRefusal>(&json).unwrap(),
            refusal
        );
        let newer = json.replace("\"fix-request\"", "\"a-newer-step\"");
        assert_eq!(
            serde_json::from_str::<TrustRefusal>(&newer).unwrap().next,
            NextStep::Other
        );
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

    #[test]
    fn trust_events_are_tagged_by_kebab_kind() {
        let event = TrustEvent::ContextUpdated {
            namespace: "/alice".into(),
            held_version: Some(3),
            version: 4,
            how: ContextChange::Update,
            revoked: vec!["/alice/node/old/KEY/1".into()],
        };
        let json: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "context-updated");
        assert_eq!(json["how"], "update");
        let back: TrustEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);

        // A membership change is one flat object beside its kind.
        let event = TrustEvent::MembershipChanged(MembershipEvent {
            namespace: "/alice".into(),
            relation: MembershipRelation::Member,
            change: MembershipChange::Enrolled,
            version: 4,
            key: Some("/alice/member/phone/KEY/1".into()),
            revoked: None,
            replaced_version: None,
            valid_until: None,
            request: Some("r1".into()),
        });
        let json: serde_json::Value = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "membership-changed");
        assert_eq!(json["change"], "enrolled");
        assert_eq!(json["relation"], "member");
        assert!(json.get("revoked").is_none());
        let back: TrustEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn unknown_kinds_and_values_are_skippable() {
        let later: TrustEvent = serde_json::from_str(r#"{"kind":"something-new","x":1}"#).unwrap();
        assert_eq!(later, TrustEvent::Unknown);
        let grown: TrustEvent = serde_json::from_str(
            r#"{"kind":"approval-decided","ca":"/a/CA","request":"r1","decision":"withdrawn","extra":true}"#,
        )
        .unwrap();
        assert_eq!(
            grown,
            TrustEvent::ApprovalDecided {
                ca: "/a/CA".to_string(),
                request: "r1".to_string(),
                decision: Decision::Unknown,
            }
        );
    }
}
