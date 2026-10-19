//! Enrolling a device key in a namespace.
//!
//! The device owns every piece of state: it generates the device key
//! `/<ns>/<role>/<device>/KEY/<id>` in its [`KeyVault`] (the private key
//! never leaves it), adopts the namespace's trust context if it is not held
//! (the link names the expected fingerprint of its root), obtains a
//! certificate from the namespace's CA and keeps it beside the key (and the
//! issuer certificates of its chain, [`KeyVault::keep_issuers`]). The new
//! identity is **added** to the identities the device signs as: Data under
//! the namespace is signed with the new key, the device's identities in
//! other namespaces and its node identity stay as they were
//! ([`KeyVault::activate`]). Only a device's first identity becomes the
//! vault's default — its node identity.
//!
//! How the certificate is obtained is the namespace's policy, read from its
//! trust context ([`ndn_cert::ApprovalPolicy`]):
//!
//! - a role it certifies **by invite** (member, guest by default): an
//!   `ndn-trust://invite` link's token is redeemed in one exchange
//!   ([`ndn_identity::enroll_with_invite_via_engine`]);
//! - a role it certifies **on an admin's approval** (admin, node by
//!   default): the request opens a durable record at the CA
//!   ([`ndn_cert::approval`]) and answers `pending` with the request id and
//!   the verification code, computed from the device's own key. The device
//!   keeps an outgoing request record ([`KeyVault::request_store`]) and
//!   waits for the CA's decision ([`crate::approval_wait`]) until the record
//!   resolves: approved — the certificate is issued and installed with no
//!   further action; denied or expired — the record says why and what to
//!   do, and the key is deleted. With an invite link too when the namespace
//!   requires one beside the approval.
//!
//! A failed enrollment leaves the previous state: the new key (and anything
//! kept for it) is deleted, and nothing else changes. One enrollment runs at
//! a time per namespace; enrollments in different namespaces never wait on
//! each other.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::report::{
    AdoptedContextInfo, ContextRefreshInfo, Detail, EnrollOutcome, EnrollRequest, EnrolledInfo,
    PendingEnrollInfo, RefreshState, TrustRefusal, code, detail_code,
};
use ndn_cert::roles::{Role, parse_device_identity, parse_device_key};
use ndn_cert::{
    ApprovalEnrollError, ApprovalPolicy, ApprovalPoll, EnrollLink, InviteEnrollError, InviteLink,
    IssuedCertificate, OutgoingRequest, OutgoingState, RequestStore, anchor_fingerprint,
    new_device_key_name,
};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, SignedTrustContext, Signer};

use crate::words::refuse;
use crate::{KeyVault, Participant, hex, iso, now_secs};

/// The refusal of an invite enrollment that failed with `e`: its code by
/// what failed, `error` its text.
pub fn invite_refusal(e: &InviteEnrollError) -> TrustRefusal {
    use InviteEnrollError as E;
    let kind = match e {
        E::BadInvite(_)
        | E::NotInvite(_)
        | E::InviteField { .. }
        | E::InviteRole(_)
        | E::TokenRole { .. }
        | E::NoExpectedFingerprint { .. } => code::INVITE_INVALID,
        E::Device(_) => code::DEVICE_NAME_INVALID,
        E::KeyOutsideInvite { .. } => code::IDENTITY_OUTSIDE_INVITE,
        E::DifferentRoot { .. } => code::DIFFERENT_ROOT,
        E::ContextUnreachable { .. } => code::CONTEXT_UNREACHABLE,
        E::ContextFromDifferentRoot { .. } => code::CONTEXT_REFUSED,
        E::Adopt {
            source: ndn_cert::AdoptError::InProgress(_),
            ..
        } => code::TRUST_CHANGE_IN_PROGRESS,
        E::Adopt { .. } => code::CONTEXT_REFUSED,
        E::CaUnreachable { .. } => code::CA_UNREACHABLE,
        E::TokenRefused(_) | E::TokenExpired { .. } => code::INVITE_REFUSED,
        E::NameRefused(_) => code::DEVICE_NAME_TAKEN,
        E::CaRefused(_) | E::ChallengeIncomplete(_) => code::CA_REFUSED,
        E::Signing(_) => code::SIGNING_FAILED,
        E::IssuedCertificate(_) => code::ISSUED_CERTIFICATE_REFUSED,
    };
    TrustRefusal::new(kind, e.to_string()).with("error", e)
}

/// The refusal of a request for an admin's approval that failed with `e`:
/// its code by what failed, `error` its text.
pub fn approval_refusal(e: &ApprovalEnrollError) -> TrustRefusal {
    use ApprovalEnrollError as E;
    let kind = match e {
        E::Denied(_) => code::REQUEST_DENIED,
        E::Expired(_) => code::REQUEST_EXPIRED,
        E::CaUnreachable { .. } | E::UntrustedAnswer(_) => code::CA_UNREACHABLE,
        E::NameRefused(_) => code::DEVICE_NAME_TAKEN,
        E::CaRefused(_) => code::CA_REFUSED,
        E::Signing(_) => code::SIGNING_FAILED,
        E::IssuedCertificate(_) => code::ISSUED_CERTIFICATE_REFUSED,
    };
    TrustRefusal::new(kind, e.to_string()).with("error", e)
}

/// What an enrollment spent on a certificate it could not keep, for the
/// refusal (`spent` of `certificate-not-kept`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spent {
    /// An invite's token: ask for a new invite.
    Invite,
    /// An admin's approval: ask again, for a new approval.
    Approval,
}

impl Spent {
    fn as_str(self) -> &'static str {
        match self {
            Spent::Invite => "invite",
            Spent::Approval => "approval",
        }
    }
}

/// The device component of `identity` when it is `<identity_prefix>/<device>`.
fn device_of<'a>(invite: &InviteLink, identity: &'a Name) -> Result<&'a str, TrustRefusal> {
    let comps = identity.components();
    let device = (identity.has_prefix(&invite.identity_prefix)
        && comps.len() == invite.identity_prefix.len() + 1)
        .then(|| std::str::from_utf8(&comps[comps.len() - 1].value).ok())
        .flatten();
    device.ok_or_else(|| {
        TrustRefusal::new(
            code::IDENTITY_OUTSIDE_INVITE,
            format!(
                "the identity to enroll, {identity}, is not <device> under the invite's \
                 identity namespace {}",
                invite.identity_prefix
            ),
        )
        .with("identity", identity)
        .with("prefix", &invite.identity_prefix)
    })
}

/// A device key of a namespace the vault holds a currently valid
/// certificate for.
pub struct Certified {
    pub key: Name,
    pub valid_until: u64,
    /// What the held trust context revokes on the certificate's chain — the
    /// key itself, or an issuer up to the root: the certificate validates
    /// nowhere.
    pub revoked: Option<Name>,
}

impl Certified {
    /// `<key> (valid until <ISO 8601>)`.
    fn still_valid(&self) -> String {
        format!("{} (valid until {})", self.key, iso(self.valid_until))
    }

    /// `<key> (revoked: <name>)` when the trust context revokes its chain.
    fn unusable(&self) -> Option<String> {
        Some(format!(
            "{} (revoked: {})",
            self.key,
            self.revoked.as_ref()?
        ))
    }
}

/// Device keys in `namespace` the vault holds a currently valid certificate
/// for, each with what revokes its chain, if anything. Issuer certificates
/// come from those the vault keeps ([`KeyVault::issuers`]), else the
/// validation cache.
pub fn certified_in(p: &Participant, vault: &dyn KeyVault, namespace: &Name) -> Vec<Certified> {
    let kept: Vec<Certificate> = vault
        .issuers()
        .into_iter()
        .filter_map(|wire| Certificate::decode(&Data::decode(wire).ok()?).ok())
        .collect();
    let issuer_cert = |key: &Name| {
        kept.iter()
            .filter(|c| c.name.has_prefix(key))
            .max_by_key(|c| c.valid_from)
            .cloned()
            .or_else(|| p.engine().security()?.cert_cache().get_valid(key))
    };
    let mut held: Vec<Certified> = vault
        .keys()
        .unwrap_or_default()
        .into_iter()
        .filter(|k| parse_device_key(namespace, k).is_some())
        .filter_map(|key| {
            let cert = vault.certificate(&key)?;
            if !cert.is_valid_now() {
                return None;
            }
            let revoked = revoked_on_chain(&p.keyring().context_for(&key), &cert, issuer_cert);
            Some(Certified {
                key,
                valid_until: cert.valid_until,
                revoked,
            })
        })
        .collect();
    held.sort_by(|a, b| a.key.cmp(&b.key));
    held
}

/// [`certified_in`] without `key` (the key just enrolled).
fn held_besides(
    p: &Participant,
    vault: &dyn KeyVault,
    namespace: &Name,
    key: &Name,
) -> Vec<Certified> {
    let mut held = certified_in(p, vault, namespace);
    held.retain(|c| &c.key != key);
    held
}

/// How long enrollment waits for the check of its namespace's trust
/// context: the metadata fetch and the newest version's fetch. A longer
/// catch-up across several versions (after a recovery) is left to a
/// refresh, and the enrollment reports that it judged against the version
/// held.
pub fn context_check_budget() -> Duration {
    ndn_app::DEFAULT_TIMEOUT * 2
}

/// Check the held trust context of `namespace` for a newer version through
/// the refresh path ([`crate::refresh::refresh_contexts`]: adopted only
/// under the continuity rule, then kept), so certificates are judged
/// against the newest version reachable. `None` when the context is not
/// held. Best effort: whatever the outcome, the held version stays in
/// force, and the result says which version the judgement used.
async fn check_context(p: &Participant, namespace: &Name) -> Option<ContextRefreshInfo> {
    let held = p.keyring().version_of(namespace)?;
    let not_checked = |detail: Detail| ContextRefreshInfo {
        namespace: namespace.to_string(),
        state: RefreshState::Failed,
        held_version: held,
        version: held,
        revoked: Vec::new(),
        detail,
    };
    let budget = context_check_budget();
    // Dropping the refresh at the deadline is safe: it adopts, stores and
    // publishes only after its last fetch, with no await in between.
    match tokio::time::timeout(
        budget,
        crate::refresh::refresh_contexts(p, Some(namespace.clone())),
    )
    .await
    {
        Ok(Ok(mut results)) => results.pop(),
        Ok(Err(e)) => Some(not_checked(
            Detail::new(detail_code::REFRESH_FAILED, e.reason.clone()).with("error", &e.reason),
        )),
        Err(_) => Some(not_checked(crate::words::detail(
            detail_code::CONTEXT_CHECK_TIMED_OUT,
            [
                ("budget_secs", budget.as_secs().to_string()),
                ("namespace", namespace.to_string()),
            ],
        ))),
    }
}

/// Whether the check of the trust context confirmed the version held is
/// the newest; else certificates were judged against that version.
fn confirmed(check: &ContextRefreshInfo) -> bool {
    match check.state {
        RefreshState::Updated | RefreshState::Current | RefreshState::Source => true,
        RefreshState::UpstreamOlder
        | RefreshState::Behind
        | RefreshState::Unreachable
        | RefreshState::Failed => false,
    }
}

/// The first name on `cert`'s chain that `ctx` revokes: each certificate
/// (a revoked key or identity is a prefix of its certificates' names) and
/// each issuer key, walking issuer certificates `issuer_cert` resolves up to
/// a self-signed one or one it cannot resolve.
pub fn revoked_on_chain(
    ctx: &SignedTrustContext,
    cert: &Certificate,
    issuer_cert: impl Fn(&Name) -> Option<Certificate>,
) -> Option<Name> {
    const MAX_CHAIN: usize = 8;
    let mut current = cert.clone();
    for _ in 0..MAX_CHAIN {
        if ctx.is_revoked(&current.name) {
            return Some((*current.name).clone());
        }
        let issuer = current.issuer.clone()?;
        if ctx.is_revoked(&issuer) {
            return Some((*issuer).clone());
        }
        let next = issuer_cert(&issuer)?;
        if next.name == current.name {
            return None;
        }
        current = next;
    }
    None
}

/// Delete a key this enrollment generated (and whatever was kept for it).
pub(crate) fn discard(vault: &dyn KeyVault, key: &Name) {
    if let Err(e) = vault.discard(key) {
        tracing::error!(
            target: "security",
            key = %key,
            error = %e,
            "could not delete the key of a failed enrollment; it is not the default identity"
        );
    }
}

/// The device's request records ([`KeyVault::request_store`]).
pub fn request_store(vault: &dyn KeyVault) -> Result<RequestStore, TrustRefusal> {
    vault.request_store().map_err(|e| {
        TrustRefusal::new(
            code::REQUESTS_UNREADABLE,
            format!("cannot open this node's request records: {e}"),
        )
        .with("error", e)
    })
}

/// End the device's pending requests the CA never answered before they
/// expired ([`RequestStore::expire_overdue`]) and delete their keys, so a
/// new request may go out; the host is told of each
/// ([`Participant::events`]).
pub fn expire_overdue(
    p: &Participant,
    vault: &dyn KeyVault,
    store: &RequestStore,
) -> Result<(), TrustRefusal> {
    let ended = store.expire_overdue().map_err(|e| {
        TrustRefusal::new(
            code::REQUESTS_UNREADABLE,
            format!("cannot update this node's request records: {e}"),
        )
        .with("error", e)
    })?;
    for r in ended {
        if let Ok(key) = r.key_name.parse::<Name>() {
            discard(vault, &key);
        }
        tracing::warn!(target: "security", request = %r.request_id, key = %r.key_name, "{}", p.words().request_expired_unanswered());
        crate::events::request_ended(p, &r);
    }
    Ok(())
}

/// Parse the link an enrollment was given: an invite, or an anchor link.
pub fn parse_link(uri: &str) -> Result<EnrollLink, TrustRefusal> {
    EnrollLink::parse(uri).map_err(|e| refuse(code::NOT_AN_ENROLL_LINK, [("error", e.to_string())]))
}

/// Hold the trust context of the namespace `link` names: adopt it (and keep
/// it) when it is not held — the link must name its root's expected
/// fingerprint — else check the held one is signed by the root the link
/// expects. `Some`: the context adopted now.
pub async fn ensure_context(
    p: &Participant,
    link: &EnrollLink,
) -> Result<Option<AdoptedContextInfo>, TrustRefusal> {
    let namespace = link.namespace();
    if let Some(held) = p.held_context(namespace) {
        let Some(expected) = link.expected_fingerprint() else {
            return Ok(None);
        };
        let fingerprints: Vec<[u8; 32]> = held
            .anchors()
            .iter()
            .map(|a| anchor_fingerprint(a.value()))
            .collect();
        if fingerprints.contains(&expected) {
            return Ok(None);
        }
        let held = fingerprints.first().map(|f| hex(f)).unwrap_or_default();
        let expected = hex(&expected);
        return Err(TrustRefusal::new(
            code::DIFFERENT_ROOT,
            format!(
                "the trust context this node holds for {namespace} is signed by a different \
                 root (fingerprint {held}) than the link expects ({expected}): check where the \
                 link came from; this node keeps the context it holds"
            ),
        )
        .with("namespace", namespace)
        .with("held", held)
        .with("expected", expected));
    }
    let from_invite;
    let anchor = match link {
        EnrollLink::Anchor(anchor) => anchor,
        EnrollLink::Invite(invite) => {
            let Some(anchor) = invite.anchor_link() else {
                let e = InviteEnrollError::NoExpectedFingerprint {
                    namespace: namespace.to_string(),
                };
                return Err(invite_refusal(&e).with("namespace", namespace));
            };
            from_invite = anchor;
            &from_invite
        }
    };
    crate::keep::adopt_link(p, anchor).await.map(Some)
}

/// What enrollment in `namespace` needs an admin's approval for: what its
/// held trust context advertises (the default for a context made before
/// the hint carried it).
fn namespace_policy(p: &Participant, namespace: &Name) -> ApprovalPolicy {
    p.held_context(namespace)
        .map(|ctx| ApprovalPolicy::of_context(&ctx))
        .unwrap_or_default()
}

/// The prefix of the CA of `namespace` its held trust context names, else
/// the namespace itself.
fn ca_prefix_of(p: &Participant, namespace: &Name) -> Name {
    p.held_context(namespace)
        .map(|ctx| ndn_cert::approval::ca_prefix_of(&ctx))
        .unwrap_or_else(|| namespace.clone())
}

/// How a device certificate is obtained in a namespace, as its policy says.
pub enum Route {
    /// Redeem the invite's token in one exchange.
    Invite,
    /// Ask the CA at `ca_prefix` for an admin's approval, with the invite's
    /// `token` when the namespace requires one beside the approval.
    Approval {
        ca_prefix: Name,
        token: Option<String>,
    },
}

/// How `role` is certified in `link`'s namespace, as its held trust
/// context says, or why the link cannot certify it.
pub fn route(p: &Participant, link: &EnrollLink, role: Role) -> Result<Route, TrustRefusal> {
    let namespace = link.namespace();
    let policy = namespace_policy(p, namespace);
    let by_approval = policy.roles.contains(&role);
    match (link, by_approval) {
        (EnrollLink::Invite(invite), false) if invite.role == role => return Ok(Route::Invite),
        (_, true) => {}
        (EnrollLink::Invite(invite), false) => {
            return Err(refuse(
                code::INVITE_FOR_ANOTHER_ROLE,
                [
                    ("namespace", namespace.to_string()),
                    ("invite_role", invite.role.to_string()),
                    ("role", role.to_string()),
                ],
            ));
        }
        (EnrollLink::Anchor(_), false) => {
            return Err(refuse(
                code::ROLE_BY_INVITE,
                [
                    ("namespace", namespace.to_string()),
                    ("role", role.to_string()),
                    ("policy", policy.describe()),
                ],
            ));
        }
    }
    let token = match (link, policy.invite_also) {
        (EnrollLink::Invite(invite), true) => Some(invite.token.clone()),
        (EnrollLink::Anchor(_), true) => {
            return Err(refuse(
                code::ROLE_NEEDS_INVITE_AND_APPROVAL,
                [
                    ("namespace", namespace.to_string()),
                    ("role", role.to_string()),
                ],
            ));
        }
        _ => None,
    };
    let ca_prefix = match link {
        EnrollLink::Invite(invite) => invite.ca_prefix.clone(),
        EnrollLink::Anchor(_) => ca_prefix_of(p, namespace),
    };
    Ok(Route::Approval { ca_prefix, token })
}

/// Enroll `request.identity` (`/<ns>/<role>/<device>`) with the CA its link
/// names: by invite (enrolled at once) or on an admin's approval (pending,
/// finished by [`crate::approval_wait`]). One enrollment at a time per
/// namespace. Refused (`409`) when the vault holds a valid certificate in
/// the namespace already, unless `request.force`.
pub async fn enroll(
    p: &Participant,
    vault: &dyn KeyVault,
    request: EnrollRequest,
) -> Result<EnrollOutcome, TrustRefusal> {
    let link = parse_link(&request.link_uri)?;
    let namespace = link.namespace().clone();
    let lock = p.enroll_lock(&namespace);
    let Ok(_one_at_a_time) = lock.try_lock() else {
        return Err(TrustRefusal::new(
            code::ENROLL_BUSY,
            format!(
                "another enrollment in {namespace} is running on this node; wait for it to finish"
            ),
        )
        .with("namespace", &namespace));
    };
    let identity = request.identity.clone();
    let Some(device) = parse_device_identity(&namespace, &identity) else {
        return Err(TrustRefusal::new(
            code::IDENTITY_INVALID,
            format!(
                "the identity to enroll, {identity}, is not /<namespace>/<role>/<device> in the \
                 namespace {namespace} the link names (roles: admin, member, node, guest; a \
                 device name of letters, digits, '-', '_', '.')"
            ),
        )
        .with("identity", &identity)
        .with("namespace", &namespace));
    };
    // The device name the invite admits, before anything is fetched.
    if let EnrollLink::Invite(invite) = &link
        && device.role == invite.role
    {
        device_of(invite, &identity)?;
    }

    let adopted_context = ensure_context(p, &link).await?;
    let route = route(p, &link, device.role)?;

    let previous_identity = vault
        .default_identity()
        .map_err(|e| TrustRefusal::new(code::KEYS_UNREADABLE, e.clone()).with("error", e))?;
    // Judge the certificates held against the namespace's newest trust
    // context, not a possibly stale held one: a newer version may revoke one.
    let context_check = check_context(p, &namespace).await;
    let held: Vec<Certified> = certified_in(p, vault, &namespace)
        .into_iter()
        .filter(|c| c.revoked.is_none())
        .collect();
    if !held.is_empty() && !request.force {
        let still_valid: Vec<String> = held.iter().map(Certified::still_valid).collect();
        let mut params = vec![
            ("namespace", namespace.to_string()),
            ("still_valid", still_valid.join(", ")),
        ];
        if let Some(check) = context_check.as_ref().filter(|c| !confirmed(c)) {
            params.push(("judged_version", check.version.to_string()));
            params.push(("judged_detail", check.detail.text.clone()));
            params.push(("cause", check.detail.code.clone()));
            for (k, v) in &check.detail.params {
                if !matches!(k.as_str(), "namespace" | "still_valid" | "cause") {
                    params.push((k.as_str(), v.clone()));
                }
            }
        }
        return Err(refuse(code::ALREADY_CERTIFIED, params));
    }

    let enrolling = Enrolling {
        namespace,
        identity,
        previous_identity,
        adopted_context,
        context_check,
    };
    match (route, &link) {
        (Route::Invite, EnrollLink::Invite(invite)) => {
            enroll_by_invite(p, vault, invite, enrolling).await
        }
        (Route::Approval { ca_prefix, token }, _) => {
            enroll_by_approval(p, vault, &ca_prefix, device.role, token, enrolling).await
        }
        (Route::Invite, EnrollLink::Anchor(_)) => {
            unreachable!("an anchor link never routes by invite")
        }
    }
}

/// What an enrollment knows before it asks the CA.
pub struct Enrolling {
    pub namespace: Name,
    pub identity: Name,
    /// The vault's default identity before this enrollment.
    pub previous_identity: Option<Name>,
    /// The trust context adopted on the way; `None` when it was held.
    pub adopted_context: Option<AdoptedContextInfo>,
    /// The check for a newer version of the namespace's trust context made
    /// before judging the certificates held.
    pub context_check: Option<ContextRefreshInfo>,
}

/// Generate the device key for `identity` in the vault.
fn generate_key(
    vault: &dyn KeyVault,
    identity: &Name,
) -> Result<(Name, Arc<dyn Signer>), TrustRefusal> {
    let key = new_device_key_name(identity).map_err(|e| {
        TrustRefusal::new(
            code::KEY_NOT_GENERATED,
            format!("cannot name the device key (the system RNG failed): {e}"),
        )
        .with("error", e)
    })?;
    let signer = vault.generate(&key).map_err(|e| {
        let location = vault.location();
        TrustRefusal::new(
            code::KEY_NOT_GENERATED,
            format!("cannot generate the device key in {location}: {e}"),
        )
        .with("error", e)
        .with("location", location)
    })?;
    Ok((key, signer))
}

/// Redeem `invite` for a new key of `enrolling.identity` and install the
/// certificate.
pub async fn enroll_by_invite(
    p: &Participant,
    vault: &dyn KeyVault,
    invite: &InviteLink,
    enrolling: Enrolling,
) -> Result<EnrollOutcome, TrustRefusal> {
    let identity = &enrolling.identity;
    let (key, signer) = generate_key(vault, identity)?;
    tracing::info!(
        target: "security",
        key = %key,
        ca = %invite.ca_prefix,
        "enrolling with an invite"
    );
    let issued = match ndn_identity::enroll_with_invite_via_engine(
        p.engine(),
        p.keyring(),
        invite,
        Arc::clone(&signer),
    )
    .await
    {
        Ok(enrollment) => enrollment.issued,
        Err(failure) => {
            discard(vault, &key);
            let mut refusal = invite_refusal(&failure.error);
            if let Some(adopted) = &enrolling.adopted_context {
                refusal.reason.push_str(&format!(
                    ". The trust context {} v{} was adopted on the way and stays adopted",
                    adopted.namespace, adopted.version
                ));
                refusal = refusal
                    .with("adopted_namespace", &adopted.namespace)
                    .with("adopted_version", adopted.version);
            }
            tracing::warn!(
                target: "security",
                identity = %identity,
                error = %refusal.reason,
                "enrollment failed; nothing was kept for the new key"
            );
            return Err(refusal);
        }
    };
    install(
        p,
        vault,
        &key,
        signer,
        &issued,
        enrolling,
        Spent::Invite,
        None,
    )
    .await
    .map(EnrollOutcome::Enrolled)
}

/// The `pending` answer for `request`.
pub fn pending_info(
    request: &OutgoingRequest,
    adopted_context: Option<AdoptedContextInfo>,
) -> PendingEnrollInfo {
    PendingEnrollInfo {
        identity: request.identity.clone(),
        key: request.key_name.clone(),
        namespace: request.namespace.clone(),
        ca: request.ca_prefix.clone(),
        request: request.request_id.clone(),
        code: request.code.clone(),
        expires: match request.expires_secs {
            0 => String::new(),
            secs => ndn_cert::approval::iso_secs(secs),
        },
        adopted_context,
    }
}

/// Ask the CA at `ca_prefix` to certify a new key for the identity on an
/// admin's approval: answered `pending` (the request is recorded in the
/// vault's request store, the key kept first, and
/// [`crate::approval_wait`] finishes it), or `enrolled` if the CA issued at
/// once. A request for this identity still pending is answered as it
/// stands: no second key, no second request.
pub async fn enroll_by_approval(
    p: &Participant,
    vault: &dyn KeyVault,
    ca_prefix: &Name,
    role: Role,
    token: Option<String>,
    enrolling: Enrolling,
) -> Result<EnrollOutcome, TrustRefusal> {
    let requests = request_store(vault)?;
    let identity = enrolling.identity.to_string();
    let outstanding = expire_overdue(p, vault, &requests).and_then(|()| {
        requests.outstanding(&identity).map_err(|e| {
            TrustRefusal::new(
                code::REQUESTS_UNREADABLE,
                format!("cannot read this node's request records: {e}"),
            )
            .with("error", e)
        })
    })?;
    if let Some(outstanding) = outstanding {
        return Ok(EnrollOutcome::Pending(pending_info(
            &outstanding,
            enrolling.adopted_context,
        )));
    }
    let (key, signer) = generate_key(vault, &enrolling.identity)?;
    tracing::info!(
        target: "security",
        key = %key,
        ca = %ca_prefix,
        role = %role,
        "asking for an admin's approval"
    );
    let poll = ndn_identity::poll_approval_via_engine(
        p.engine(),
        p.keyring(),
        &enrolling.namespace,
        ca_prefix,
        Arc::clone(&signer),
        None,
        token.as_deref(),
    )
    .await;
    match poll {
        Ok(ApprovalPoll::Pending(pending)) => {
            let record = OutgoingRequest {
                namespace: enrolling.namespace.to_string(),
                ca_prefix: ca_prefix.to_string(),
                identity,
                key_name: key.to_string(),
                request_id: pending.request_id,
                code: pending.code,
                created_secs: now_secs(),
                expires_secs: pending.expires_secs,
                state: OutgoingState::Pending,
            };
            // The key first: a record whose key is missing could never
            // finish.
            if let Err(e) = vault
                .keep_pending(&key)
                .and_then(|()| requests.save(&record).map_err(|e| e.to_string()))
            {
                discard(vault, &key);
                return Err(refuse(
                    code::REQUEST_NOT_RECORDED,
                    [
                        ("request", record.request_id.clone()),
                        ("code", record.code.clone()),
                        ("error", e),
                        ("location", vault.location()),
                    ],
                ));
            }
            // Its status Interest goes out now.
            p.requests_changed.notify_one();
            tracing::info!(
                target: "security",
                key = %key,
                request = %record.request_id,
                code = %record.code,
                "waiting for an admin's approval; the daemon finishes the enrollment once approved"
            );
            Ok(EnrollOutcome::Pending(pending_info(
                &record,
                enrolling.adopted_context,
            )))
        }
        Ok(ApprovalPoll::Issued(issued)) => install(
            p,
            vault,
            &key,
            signer,
            &issued,
            enrolling,
            Spent::Approval,
            None,
        )
        .await
        .map(EnrollOutcome::Enrolled),
        Err(e) => {
            discard(vault, &key);
            tracing::warn!(
                target: "security",
                identity = %enrolling.identity,
                error = %e,
                "request for an admin's approval refused; nothing was kept for the new key"
            );
            Err(approval_refusal(&e))
        }
    }
}

/// Keep the certificate the CA issued for `key` (generated for
/// `enrolling.identity`) and add the identity to those the device signs as:
/// the vault, issuer chain, the engine's key store (the namespace's Data is
/// signed with `key` from now on) and validation cache, served by name, the
/// renewal timer told, the running device told as the host allows
/// ([`KeyVault::activate`]). The device's other identities stay as they
/// were; only a device without a default identity records this one as its
/// default — its node identity. The host is told
/// ([`Participant::events`]: `enrolled`, with `request`, the request for an
/// admin's approval it waited for). `spent`: what getting the certificate
/// used up, for the refusal when keeping it fails (the key is then
/// deleted).
#[allow(clippy::too_many_arguments)]
pub async fn install(
    p: &Participant,
    vault: &dyn KeyVault,
    key: &Name,
    signer: Arc<dyn Signer>,
    issued: &IssuedCertificate,
    enrolling: Enrolling,
    spent: Spent,
    request: Option<&str>,
) -> Result<EnrolledInfo, TrustRefusal> {
    let Enrolling {
        namespace,
        identity,
        previous_identity,
        adopted_context,
        mut context_check,
    } = enrolling;
    if let Err(e) = vault.store_certificate(key, &issued.data) {
        discard(vault, key);
        return Err(refuse(
            code::CERTIFICATE_NOT_KEPT,
            [
                ("certificate", issued.cert.name.to_string()),
                ("location", vault.location()),
                ("error", e),
                ("spent", spent.as_str().to_owned()),
            ],
        ));
    }

    // The certificate's issuer chain, kept beside the key: it is served with
    // the device's certificates and sent with a renewal, so a later CA of
    // the namespace can verify the chain once nobody else serves this CA's
    // certificate (`ndn_cert::issuers`).
    if let Err(e) = vault.keep_issuers(&issued.issuers) {
        tracing::warn!(
            target: "security",
            error = %e,
            "enrolled, but the issuer certificates of its chain were not kept"
        );
    }

    // The running engine's key store signs the identity's Data with the new
    // key from now on (`SecurityManager::signer_for`), beside the device's
    // other identities.
    if let Some(mgr) = p.engine().security() {
        mgr.register_identity_signer(key.clone(), Arc::clone(&signer));
        mgr.cert_cache().insert(issued.cert.clone());
    }
    // Peers validating the device's Data can fetch the certificate, and its
    // issuers, from it.
    if let Some(own) = p.own_certs() {
        own.serve(issued.data.raw().clone());
        for issuer in &issued.issuers {
            own.serve(issuer.raw().clone());
        }
    }
    // The renewal timer schedules the new certificate's renewal.
    p.certificates_changed.notify_one();
    let activation = {
        // Of two installs in different namespaces, only the first of a
        // device without an identity becomes its default.
        let _installing = p.installing.lock();
        let first_identity = match vault.default_identity() {
            Ok(default) => default.is_none(),
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    error = %e,
                    "cannot read the default identity; the enrolled identity does not become it"
                );
                false
            }
        };
        if first_identity && let Err(e) = vault.make_default(&identity) {
            tracing::warn!(
                target: "security",
                identity = %identity,
                error = %e,
                "the device's first identity was not recorded as its default identity; it is \
                 chosen again as the first enrolled at the next start"
            );
        }
        vault.activate(&identity, key, signer, first_identity)
    };
    crate::membership::enrolled(p, &namespace, key, issued.cert.valid_until, request);
    // The other certificates the device holds in the namespace, judged
    // against the context held now: the one checked before asking, or the
    // one adopted on the way (checked here when there is something to
    // judge).
    let mut others = held_besides(p, vault, &namespace, key);
    if context_check.is_none() && !others.is_empty() {
        context_check = check_context(p, &namespace).await;
        others = held_besides(p, vault, &namespace, key);
    }
    let (unusable, still_valid): (Vec<Certified>, Vec<Certified>) =
        others.into_iter().partition(|c| c.revoked.is_some());
    tracing::info!(
        target: "security",
        identity = %identity,
        certificate = %issued.cert.name,
        issuer = ?issued.issuer.as_ref().map(Name::to_string),
        signing_now = activation.signing_now,
        node_identity = activation.node_identity,
        "{}",
        p.words().enrolled(activation.node_identity)
    );
    Ok(EnrolledInfo {
        identity: identity.to_string(),
        key: key.to_string(),
        certificate: issued.cert.name.to_string(),
        issuer: issued
            .issuer
            .as_ref()
            .map(Name::to_string)
            .unwrap_or_default(),
        valid_until: iso(issued.cert.valid_until),
        validity_secs: issued
            .cert
            .valid_until
            .saturating_sub(issued.cert.valid_from)
            / 1_000_000_000,
        adopted_context,
        pib: vault.location(),
        previous_identity: previous_identity.map(|n| n.to_string()),
        signing_now: activation.signing_now,
        node_identity: activation.node_identity,
        at_next_start: activation.at_next_start,
        still_valid: still_valid.iter().map(Certified::still_valid).collect(),
        unusable: unusable.iter().filter_map(Certified::unusable).collect(),
        context_check,
    })
}

/// The device's requests for an admin's approval, oldest first (overdue
/// ones ended first, [`expire_overdue`]).
pub fn enroll_status(
    p: &Participant,
    vault: &dyn KeyVault,
) -> Result<Vec<OutgoingRequest>, TrustRefusal> {
    let store = request_store(vault)?;
    expire_overdue(p, vault, &store)?;
    store.list().map_err(|e| {
        TrustRefusal::new(
            code::REQUESTS_UNREADABLE,
            format!("cannot read this node's request records: {e}"),
        )
        .with("error", e)
    })
}
