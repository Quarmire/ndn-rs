//! What a namespace CA's configuration states about the namespace's
//! policies, reconciled with what the namespace's trust context advertises.
//!
//! Devices read the enrollment policy ([`ApprovalPolicy`], the context's
//! enrollment hint), the link policy ([`LinkPolicy`]) and the relays the
//! namespace advertises ([`AdvertisedRelay`]) from the trust context, so a
//! namespace CA enforces exactly what its context advertises. Its
//! configuration ([`PolicyInput`]: `[ca] approval_roles`,
//! `approval_requires_invite`, `link_roles`, `relay_roles`,
//! `enrollment_links`, `direct_paths`, `direct_pairs`, `[[ca.relay]]` in
//! `ndn-fwd`) only states it again; a CA whose configuration disagrees with
//! the held context does not start ([`PolicyInput::enforced_policy`]). The
//! configuration is what a new namespace starts with
//! ([`PolicyInput::new_namespace_policies`]) and what a schema update
//! writes into the next version ([`plan_schema_update`]).
//!
//! Also here: which challenges a namespace CA offers, in which order
//! ([`challenge_order`]).

use std::fmt;

use ndn_packet::Name;
use ndn_security::{AdvertisedRelay, EnrollmentHint, LinkPolicy, SchemaBlob, SignedTrustContext};

use crate::approval::DEVICE_APPROVAL;
use crate::context_update::{BumpError, SchemaChange, same_relays, schema_change};
use crate::policy::ApprovalPolicy;
use crate::roles::{Role, RoleError, namespace_schema};

/// What a CA's configuration states about the namespace's policies; each
/// unset key defers to the trust context (or, for a new namespace, the
/// default).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyInput {
    /// Roles certified only on an admin's approval.
    pub approval_roles: Option<Vec<String>>,
    /// Whether an approval role also redeems an invite.
    pub approval_requires_invite: Option<bool>,
    /// Roles whose devices may link (empty: every role).
    pub link_roles: Option<Vec<String>>,
    /// Roles whose devices may relay.
    pub relay_roles: Option<Vec<String>>,
    /// Whether relays admit enrollment links.
    pub enrollment_links: Option<bool>,
    /// Whether linked devices may try a direct path instead of the relay.
    pub direct_paths: Option<bool>,
    /// Unordered role pairs whose devices may make direct paths with each
    /// other, each `"<role>:<role>"` (empty: none).
    pub direct_pairs: Option<Vec<String>>,
    /// The relays the namespace advertises (empty: none).
    pub relays: Option<Vec<AdvertisedRelay>>,
}

/// What a new namespace's first trust context advertises
/// ([`PolicyInput::new_namespace_policies`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespacePolicies {
    /// Which roles enroll only on an admin's approval.
    pub approval: ApprovalPolicy,
    /// Which devices may link, relay and make direct paths.
    pub link: LinkPolicy,
    /// The relays every member learns.
    pub relays: Vec<AdvertisedRelay>,
}

/// Why a CA's stated policy was refused.
#[derive(Debug)]
pub enum PolicyError {
    /// `key` names a role that does not exist.
    UnknownRole {
        key: &'static str,
        reason: RoleError,
    },
    /// A relay role that may not link, so none could relay.
    RelayMayNotLink {
        role: String,
        link_roles: Vec<String>,
    },
    /// The stated link policy is not the one the context `version` states.
    LinkDisagrees { version: u64, held: LinkPolicy },
    /// A `direct_pairs` entry is not `<role>:<role>`.
    BadDirectPair { entry: String },
    /// A stated relay has no endpoint.
    RelayWithoutEndpoint { device: Name },
    /// A stated relay outside the namespace has no expected fingerprint.
    RelayNeedsKey { device: Name, namespace: Name },
    /// The stated relays are not the ones the context `version` advertises.
    RelaysDisagree {
        version: u64,
        held: Vec<AdvertisedRelay>,
    },
    /// The stated approval policy is not the one the context `version`
    /// advertises.
    ApprovalDisagrees {
        version: u64,
        advertised: ApprovalPolicy,
    },
    /// The context advertises approval roles that also redeem an invite,
    /// but the CA offers no token challenge to redeem it.
    InviteWithoutToken { advertised: ApprovalPolicy },
}

fn quoted(roles: &[String]) -> String {
    roles
        .iter()
        .map(|r| format!("{r:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Relays one per `; `, or `none`.
fn relay_list(relays: &[AdvertisedRelay]) -> String {
    if relays.is_empty() {
        return "none".to_string();
    }
    relays
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole { key, reason } => write!(f, "[ca] {key}: {reason}"),
            Self::RelayMayNotLink { role, link_roles } => write!(
                f,
                "[ca] relay_roles names {role:?}, but link_roles ({}) does not let {role} devices \
                 link, so none could relay: add {role:?} to link_roles, or remove it from \
                 relay_roles",
                link_roles.join(", ")
            ),
            Self::LinkDisagrees { version, held } => {
                let pairs: Vec<String> = held
                    .canonical_direct_pairs()
                    .iter()
                    .map(|(a, b)| format!("{a}:{b}"))
                    .collect();
                write!(
                    f,
                    "[ca] link_roles / relay_roles / enrollment_links / direct_paths / direct_pairs \
                     disagree with the namespace's trust context (v{}), which states: {}. Devices \
                     admit links by the context, so the CA does not start with another policy: to \
                     change it, run `ndn-fwd schema update -c <config>` on the root device (a \
                     narrowing needs --accept-narrowing); to keep it, set link_roles = [{}], \
                     relay_roles = [{}], enrollment_links = {}, direct_paths = {} and direct_pairs \
                     = [{}] in [ca], or remove the keys",
                    version,
                    held.describe(),
                    quoted(&held.roles),
                    quoted(&held.relay_roles),
                    held.enrollment_links,
                    held.direct_paths,
                    quoted(&pairs)
                )
            }
            Self::BadDirectPair { entry } => write!(
                f,
                "[ca] direct_pairs: {entry:?} is not a pair of roles: write \"<role>:<role>\" with \
                 roles admin, member, node or guest, such as \"member:member\""
            ),
            Self::RelayWithoutEndpoint { device } => write!(
                f,
                "[ca] relay {device} has no endpoint, so no device could reach it: give it \
                 endpoint = [\"host:port\"]"
            ),
            Self::RelayNeedsKey { device, namespace } => write!(
                f,
                "[ca] relay {device} is not a device of {namespace}, so devices admit it only by \
                 its expected fingerprint: set key = \"<64 hex digits>\" (the link key that \
                 relay's `ndn-fwd` prints)"
            ),
            Self::RelaysDisagree { version, held } => write!(
                f,
                "[ca] relay entries disagree with the namespace's trust context (v{version}), \
                 which advertises: {}. Devices learn the relays from the context, so the CA does \
                 not start with others: to change them, run `ndn-fwd schema update -c <config>` \
                 on the root device (dropping a relay needs --accept-narrowing); to keep them, \
                 list exactly these as [[ca.relay]] entries (relay = [] for none), or remove the \
                 entries",
                relay_list(held)
            ),
            Self::ApprovalDisagrees {
                version,
                advertised,
            } => {
                let roles: Vec<String> = advertised
                    .roles
                    .iter()
                    .map(|r| format!("{:?}", r.as_str()))
                    .collect();
                write!(
                    f,
                    "[ca] approval_roles / approval_requires_invite disagree with the namespace's trust \
                     context (v{version}), which advertises: {}. Devices read the policy from the \
                     context, so the CA enforces exactly that: set approval_roles = [{}] and \
                     approval_requires_invite = {} in [ca], or remove both keys",
                    advertised.describe(),
                    roles.join(", "),
                    advertised.invite_also
                )
            }
            Self::InviteWithoutToken { advertised } => write!(
                f,
                "[ca] the namespace's trust context advertises {}, but [ca] offers \
                 no token challenge to redeem the invites: add a [[ca.challenge]] \
                 entry with kind = \"token\" and the invite tokens",
                advertised.describe()
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl PolicyInput {
    /// The approval policy stated; `None` when neither approval key is set.
    /// Refuses an unknown role.
    pub fn approval_policy(&self) -> Result<Option<ApprovalPolicy>, PolicyError> {
        if self.approval_roles.is_none() && self.approval_requires_invite.is_none() {
            return Ok(None);
        }
        let defaults = ApprovalPolicy::default();
        let roles = match &self.approval_roles {
            Some(roles) => roles
                .iter()
                .map(|r| {
                    r.parse::<Role>()
                        .map_err(|reason| PolicyError::UnknownRole {
                            key: "approval_roles",
                            reason,
                        })
                })
                .collect::<Result<Vec<Role>, _>>()?,
            None => defaults.roles,
        };
        Ok(Some(ApprovalPolicy {
            roles,
            invite_also: self
                .approval_requires_invite
                .unwrap_or(defaults.invite_also),
        }))
    }

    /// The link policy stated, each unset key taken from `base` (the held
    /// context's policy, or the default for a new namespace); `None` when
    /// no link key is set. Refuses an unknown role, a direct pair that is
    /// not two roles, and a relay role that may not link.
    pub fn link_policy(&self, base: &LinkPolicy) -> Result<Option<LinkPolicy>, PolicyError> {
        if self.link_roles.is_none()
            && self.relay_roles.is_none()
            && self.enrollment_links.is_none()
            && self.direct_paths.is_none()
            && self.direct_pairs.is_none()
        {
            return Ok(None);
        }
        let role = |key: &'static str, r: &str| -> Result<String, PolicyError> {
            let role = r
                .parse::<Role>()
                .map_err(|reason| PolicyError::UnknownRole { key, reason })?;
            Ok(role.as_str().to_string())
        };
        let roles = |key: &'static str,
                     roles: &Option<Vec<String>>,
                     base: &[String]|
         -> Result<Vec<String>, PolicyError> {
            let Some(roles) = roles else {
                return Ok(base.to_vec());
            };
            let mut parsed = Vec::with_capacity(roles.len());
            for r in roles {
                let role = role(key, r)?;
                if !parsed.contains(&role) {
                    parsed.push(role);
                }
            }
            Ok(parsed)
        };
        let direct_pairs = match &self.direct_pairs {
            None => base.direct_pairs.clone(),
            Some(pairs) => pairs
                .iter()
                .map(|entry| {
                    let (a, b) =
                        entry
                            .split_once(':')
                            .ok_or_else(|| PolicyError::BadDirectPair {
                                entry: entry.clone(),
                            })?;
                    Ok((role("direct_pairs", a)?, role("direct_pairs", b)?))
                })
                .collect::<Result<Vec<_>, PolicyError>>()?,
        };
        let mut policy = LinkPolicy {
            roles: roles("link_roles", &self.link_roles, &base.roles)?,
            relay_roles: roles("relay_roles", &self.relay_roles, &base.relay_roles)?,
            enrollment_links: self.enrollment_links.unwrap_or(base.enrollment_links),
            direct_paths: self.direct_paths.unwrap_or(base.direct_paths),
            direct_pairs,
        };
        policy.direct_pairs = policy.canonical_direct_pairs();
        if let Some(role) = policy.relay_roles.iter().find(|r| !policy.allows_link(r)) {
            return Err(PolicyError::RelayMayNotLink {
                role: role.clone(),
                link_roles: policy.roles.clone(),
            });
        }
        Ok(Some(policy))
    }

    /// The relays stated for `namespace`; `None` when `[[ca.relay]]` is
    /// not set. Refuses a relay without an endpoint, and one outside the
    /// namespace without an expected fingerprint (devices could not admit
    /// it).
    pub fn advertised_relays(
        &self,
        namespace: &Name,
    ) -> Result<Option<Vec<AdvertisedRelay>>, PolicyError> {
        let Some(relays) = &self.relays else {
            return Ok(None);
        };
        for relay in relays {
            if relay.endpoints.is_empty() || relay.endpoints.iter().any(String::is_empty) {
                return Err(PolicyError::RelayWithoutEndpoint {
                    device: relay.device.clone(),
                });
            }
            if relay.key.is_none() && !relay.device.has_prefix(namespace) {
                return Err(PolicyError::RelayNeedsKey {
                    device: relay.device.clone(),
                    namespace: namespace.clone(),
                });
            }
        }
        Ok(Some(relays.clone()))
    }

    /// The policies a new namespace's first trust context advertises: the
    /// stated ones, the default for what is not stated (no relays).
    pub fn new_namespace_policies(
        &self,
        namespace: &Name,
    ) -> Result<NamespacePolicies, PolicyError> {
        Ok(NamespacePolicies {
            approval: self.approval_policy()?.unwrap_or_default(),
            link: self
                .link_policy(&LinkPolicy::default())?
                .unwrap_or_default(),
            relays: self.advertised_relays(namespace)?.unwrap_or_default(),
        })
    }

    /// Refuses a stated link policy that disagrees with the one the
    /// namespace's trust context `ctx` states: devices admit links by the
    /// context, so the configuration only states it again.
    pub fn check_link_policy(&self, ctx: &SignedTrustContext) -> Result<(), PolicyError> {
        let held = ctx.link_policy();
        match self.link_policy(&held)? {
            Some(stated) if !same_link_policy(&stated, &held) => Err(PolicyError::LinkDisagrees {
                version: ctx.version(),
                held,
            }),
            _ => Ok(()),
        }
    }

    /// Refuses stated relays other than the ones the namespace's trust
    /// context `ctx` advertises, as [`check_link_policy`](Self::check_link_policy)
    /// does for the link policy.
    pub fn check_relays(&self, ctx: &SignedTrustContext) -> Result<(), PolicyError> {
        match self.advertised_relays(ctx.namespace())? {
            Some(stated) if !same_relays(&stated, ctx.relays()) => {
                Err(PolicyError::RelaysDisagree {
                    version: ctx.version(),
                    held: ctx.relays().to_vec(),
                })
            }
            _ => Ok(()),
        }
    }

    /// The link policy the next version of a context holding `held`
    /// carries: the stated one when it differs from `held`; `None` carries
    /// `held` verbatim.
    pub fn link_change(&self, held: &LinkPolicy) -> Result<Option<LinkPolicy>, PolicyError> {
        Ok(self
            .link_policy(held)?
            .filter(|link| !same_link_policy(link, held)))
    }

    /// The relays the next version of `held` advertises: the stated ones
    /// when they differ from `held`'s; `None` carries `held`'s verbatim.
    pub fn relays_change(
        &self,
        held: &SignedTrustContext,
    ) -> Result<Option<Vec<AdvertisedRelay>>, PolicyError> {
        Ok(self
            .advertised_relays(held.namespace())?
            .filter(|relays| !same_relays(relays, held.relays())))
    }

    /// The approval policy a namespace CA enforces under `held`, the newest
    /// trust context of its namespace it holds (`None`: none held). Refuses
    /// a stated link policy, relays or approval policy that disagree with
    /// the context.
    pub fn enforced_policy(
        &self,
        held: Option<&SignedTrustContext>,
    ) -> Result<ApprovalPolicy, PolicyError> {
        if let Some(ctx) = held {
            self.check_link_policy(ctx)?;
            self.check_relays(ctx)?;
        }
        let advertised = held.and_then(|ctx| {
            let policy = ApprovalPolicy::from_hint(ctx.enrollment_hint()?)?;
            Some((ctx.version(), policy))
        });
        ApprovalPolicy::reconcile(self, advertised)
    }

    /// The enrollment policy the namespace's CA enforces under `held`, and
    /// the hint the next version carries for it: `held`'s own hint when it
    /// advertises a policy (refused when this states another, as the CA's
    /// start refuses it); else — a context made before the hint carried
    /// the policy — the policy the CA enforces for it
    /// ([`ApprovalPolicy::reconcile`]: the stated one, else the default).
    pub fn update_enrollment(
        &self,
        held: &SignedTrustContext,
    ) -> Result<(ApprovalPolicy, EnrollmentHint), PolicyError> {
        if let Some(hint) = held.enrollment_hint()
            && let Some(policy) = ApprovalPolicy::from_hint(hint)
        {
            let policy = ApprovalPolicy::reconcile(self, Some((held.version(), policy)))?;
            return Ok((policy, hint.clone()));
        }
        let policy = ApprovalPolicy::reconcile(self, None)?;
        let hint = policy.to_hint();
        Ok((policy, hint))
    }
}

impl ApprovalPolicy {
    /// The approval policy a namespace CA enforces: what its trust context
    /// advertises (`advertised`: its version and policy). `stated` only
    /// states it again, and is refused when a key it sets disagrees — the
    /// devices read the policy from the context. A context that advertises
    /// none (made before the hint carried it) takes the stated policy, else
    /// the default.
    pub fn reconcile(
        stated: &PolicyInput,
        advertised: Option<(u64, ApprovalPolicy)>,
    ) -> Result<ApprovalPolicy, PolicyError> {
        let configured = stated.approval_policy()?;
        let Some((version, advertised)) = advertised else {
            return Ok(configured.unwrap_or_default());
        };
        let sorted = |roles: &[Role]| {
            let mut roles = roles.to_vec();
            roles.sort_by_key(|r| r.as_str());
            roles.dedup();
            roles
        };
        let disagrees = configured.is_some_and(|c| {
            (stated.approval_roles.is_some() && sorted(&c.roles) != sorted(&advertised.roles))
                || (stated.approval_requires_invite.is_some()
                    && c.invite_also != advertised.invite_also)
        });
        if disagrees {
            return Err(PolicyError::ApprovalDisagrees {
                version,
                advertised,
            });
        }
        Ok(advertised)
    }

    /// Whether a request for an approval role must also redeem an invite
    /// (so the CA needs a token challenge next to `device-approval`).
    pub fn needs_invite(&self) -> bool {
        self.invite_also && !self.roles.is_empty()
    }
}

/// Whether two link policies admit the same (role lists and direct pairs
/// compared as sets).
pub fn same_link_policy(a: &LinkPolicy, b: &LinkPolicy) -> bool {
    let set = |roles: &[String]| {
        let mut roles = roles.to_vec();
        roles.sort();
        roles.dedup();
        roles
    };
    set(&a.roles) == set(&b.roles)
        && set(&a.relay_roles) == set(&b.relay_roles)
        && a.enrollment_links == b.enrollment_links
        && a.direct_paths == b.direct_paths
        && a.canonical_direct_pairs() == b.canonical_direct_pairs()
}

/// One challenge a CA offers, in offer order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeSlot {
    /// The one `token` challenge, over the tokens of every `token` entry.
    Token,
    /// The one `device-approval` challenge.
    DeviceApproval,
    /// Any other challenge: the configured entry at this index.
    Configured(usize),
}

/// The challenges a CA offers, in order ([`challenge_order`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeOrder {
    pub slots: Vec<ChallengeSlot>,
    /// `device-approval` is offered although no entry lists it: the
    /// namespace's trust context advertises approval roles.
    pub approval_unlisted: bool,
}

/// The challenges a CA offers for the configured challenge `kinds`, in
/// order: each `token` and `device-approval` entry joins one challenge,
/// offered where its kind is first listed; every other entry is its own.
/// A namespace CA (`approval`: the policy its trust context advertises)
/// whose policy names approval roles also offers `device-approval`, last,
/// when no entry lists it.
pub fn challenge_order<'a>(
    kinds: impl IntoIterator<Item = &'a str>,
    approval: Option<&ApprovalPolicy>,
) -> ChallengeOrder {
    let mut slots = Vec::new();
    for (i, kind) in kinds.into_iter().enumerate() {
        let slot = match kind {
            "token" => ChallengeSlot::Token,
            DEVICE_APPROVAL => ChallengeSlot::DeviceApproval,
            _ => ChallengeSlot::Configured(i),
        };
        if matches!(slot, ChallengeSlot::Configured(_)) || !slots.contains(&slot) {
            slots.push(slot);
        }
    }
    let approval_unlisted = approval.is_some_and(|p| !p.roles.is_empty())
        && !slots.contains(&ChallengeSlot::DeviceApproval);
    if approval_unlisted {
        slots.push(ChallengeSlot::DeviceApproval);
    }
    ChallengeOrder {
        slots,
        approval_unlisted,
    }
}

/// What a schema update signs as the next version of `held`, decided
/// before the root is unlocked ([`plan_schema_update`]).
#[derive(Clone, Debug)]
pub struct SchemaUpdatePlan {
    /// The current generated schema of the namespace.
    pub schema: Vec<SchemaBlob>,
    /// The enrollment policy the namespace's CA enforces, and the hint
    /// stating it that the new version carries.
    pub policy: ApprovalPolicy,
    pub hint: EnrollmentHint,
    /// The stated link policy when it differs from the held one; `None`:
    /// the held one is carried.
    pub link: Option<LinkPolicy>,
    /// The stated relays when they differ from the held ones; `None`: the
    /// held ones are carried.
    pub relays: Option<Vec<AdvertisedRelay>>,
    pub change: SchemaChange,
}

/// Why [`plan_schema_update`] signs nothing.
#[derive(Debug)]
pub enum SchemaPlanError {
    /// The namespace's schema could not be generated.
    Schema { namespace: Name, reason: RoleError },
    /// The stated policy was refused (the source says why).
    Policy(PolicyError),
    /// The update would narrow without consent, or the schema is unreadable.
    Change(BumpError),
}

impl fmt::Display for SchemaPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema { namespace, reason } => write!(
                f,
                "cannot generate the schema of {namespace}: {reason}. Nothing was signed"
            ),
            Self::Policy(_) => f.write_str("nothing was signed"),
            Self::Change(e) => write!(f, "{e}. Nothing was signed"),
        }
    }
}

impl std::error::Error for SchemaPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            _ => None,
        }
    }
}

/// Plan the schema update of the namespace whose newest held context is
/// `held` (on its root device): the current generated schema, the
/// enrollment policy and hint ([`PolicyInput::update_enrollment`]), the
/// link policy and relays `stated` changes ([`PolicyInput::link_change`],
/// [`PolicyInput::relays_change`]), and what that changes
/// ([`schema_change`]: refused when it narrows, unless `accept_narrowing`).
pub fn plan_schema_update(
    held: &SignedTrustContext,
    stated: &PolicyInput,
    accept_narrowing: bool,
) -> Result<SchemaUpdatePlan, SchemaPlanError> {
    let namespace = held.namespace();
    let schema = namespace_schema(namespace)
        .map_err(|reason| SchemaPlanError::Schema {
            namespace: namespace.clone(),
            reason,
        })?
        .blobs();
    let (policy, hint) = stated
        .update_enrollment(held)
        .map_err(SchemaPlanError::Policy)?;
    let link = stated
        .link_change(&held.link_policy())
        .map_err(SchemaPlanError::Policy)?;
    let relays = stated
        .relays_change(held)
        .map_err(SchemaPlanError::Policy)?;
    let change = schema_change(
        held,
        &schema,
        &hint,
        link.as_ref(),
        relays.as_deref(),
        accept_narrowing,
    )
    .map_err(SchemaPlanError::Change)?;
    Ok(SchemaUpdatePlan {
        schema,
        policy,
        hint,
        link,
        relays,
        change,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(r: &[&str]) -> Option<Vec<String>> {
        Some(r.iter().map(|r| r.to_string()).collect())
    }

    #[test]
    fn approval_policy_states_only_what_is_set() {
        assert_eq!(PolicyInput::default().approval_policy().unwrap(), None);
        let stated = PolicyInput {
            approval_requires_invite: Some(true),
            ..PolicyInput::default()
        };
        assert_eq!(
            stated.approval_policy().unwrap(),
            Some(ApprovalPolicy {
                invite_also: true,
                ..ApprovalPolicy::default()
            })
        );
        let unknown = PolicyInput {
            approval_roles: roles(&["robot"]),
            ..PolicyInput::default()
        };
        let err = unknown.approval_policy().unwrap_err();
        assert!(
            err.to_string()
                .starts_with("[ca] approval_roles: unknown role"),
            "{err}"
        );
    }

    #[test]
    fn the_advertised_approval_policy_wins_and_a_disagreeing_statement_is_refused() {
        let advertised = ApprovalPolicy::default();
        // Nothing advertised: the stated policy, else the default.
        assert_eq!(
            ApprovalPolicy::reconcile(&PolicyInput::default(), None).unwrap(),
            advertised
        );
        let admins_only = PolicyInput {
            approval_roles: roles(&["admin"]),
            ..PolicyInput::default()
        };
        assert_eq!(
            ApprovalPolicy::reconcile(&admins_only, None).unwrap().roles,
            vec![Role::Admin]
        );
        // Advertised: restating it in any order is accepted, nothing stated
        // takes it, another policy is refused.
        let restated = PolicyInput {
            approval_roles: roles(&["node", "admin"]),
            approval_requires_invite: Some(false),
            ..PolicyInput::default()
        };
        for stated in [&restated, &PolicyInput::default()] {
            assert_eq!(
                ApprovalPolicy::reconcile(stated, Some((3, advertised.clone()))).unwrap(),
                advertised
            );
        }
        let invite = PolicyInput {
            approval_requires_invite: Some(true),
            ..PolicyInput::default()
        };
        for stated in [&admins_only, &invite] {
            let err = ApprovalPolicy::reconcile(stated, Some((3, advertised.clone()))).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("disagree with the namespace's trust context (v3)"),
                "{msg}"
            );
            assert!(
                msg.contains("approval_roles = [\"admin\", \"node\"]"),
                "{msg}"
            );
        }
        assert!(advertised.clone().roles.len() == 2 && !advertised.needs_invite());
        assert!(
            ApprovalPolicy {
                invite_also: true,
                ..advertised
            }
            .needs_invite()
        );
        assert!(
            !ApprovalPolicy {
                roles: Vec::new(),
                invite_also: true
            }
            .needs_invite()
        );
    }

    #[test]
    fn the_stated_link_policy_takes_unset_keys_from_its_base() {
        assert_eq!(
            PolicyInput::default()
                .link_policy(&LinkPolicy::default())
                .unwrap(),
            None
        );
        let stated = PolicyInput {
            link_roles: roles(&["admin", "node", "admin"]),
            enrollment_links: Some(false),
            ..PolicyInput::default()
        };
        let link = stated.link_policy(&LinkPolicy::default()).unwrap().unwrap();
        assert_eq!(
            link,
            LinkPolicy {
                roles: vec!["admin".into(), "node".into()],
                relay_roles: vec!["node".into()],
                enrollment_links: false,
                direct_paths: true,
                direct_pairs: LinkPolicy::default_direct_pairs(),
            }
        );
        let ns: Name = "/home".parse().unwrap();
        let new = stated.new_namespace_policies(&ns).unwrap();
        assert_eq!(
            new,
            NamespacePolicies {
                approval: ApprovalPolicy::default(),
                link: link.clone(),
                relays: Vec::new(),
            }
        );

        let relay = PolicyInput {
            link_roles: roles(&["admin"]),
            relay_roles: roles(&["node"]),
            ..PolicyInput::default()
        };
        let err = relay.link_policy(&LinkPolicy::default()).unwrap_err();
        assert!(
            matches!(err, PolicyError::RelayMayNotLink { .. }),
            "a relay that may not link"
        );
        let unknown = PolicyInput {
            link_roles: roles(&["robot"]),
            ..PolicyInput::default()
        };
        let err = unknown.link_policy(&LinkPolicy::default()).unwrap_err();
        assert!(
            err.to_string().starts_with("[ca] link_roles: unknown role"),
            "{err}"
        );
    }

    #[test]
    fn link_policies_compare_role_lists_as_sets() {
        let a = LinkPolicy {
            roles: vec!["admin".into(), "node".into()],
            relay_roles: vec!["node".into()],
            enrollment_links: true,
            direct_paths: true,
            direct_pairs: LinkPolicy::default_direct_pairs(),
        };
        let b = LinkPolicy {
            roles: vec!["node".into(), "admin".into(), "node".into()],
            ..a.clone()
        };
        assert!(same_link_policy(&a, &b));
        let restated = PolicyInput {
            link_roles: roles(&["node", "admin"]),
            ..PolicyInput::default()
        };
        assert_eq!(
            restated.link_change(&a).unwrap(),
            None,
            "the same policy is no change"
        );
        let off = PolicyInput {
            enrollment_links: Some(false),
            ..PolicyInput::default()
        };
        assert!(!same_link_policy(
            &a,
            &LinkPolicy {
                enrollment_links: false,
                ..a.clone()
            }
        ));
        assert_eq!(
            off.link_change(&a).unwrap(),
            Some(LinkPolicy {
                enrollment_links: false,
                ..a.clone()
            })
        );
        let no_direct = PolicyInput {
            direct_paths: Some(false),
            ..PolicyInput::default()
        };
        assert!(!same_link_policy(
            &a,
            &LinkPolicy {
                direct_paths: false,
                ..a.clone()
            }
        ));
        assert_eq!(
            no_direct.link_change(&a).unwrap(),
            Some(LinkPolicy {
                direct_paths: false,
                ..a
            })
        );
    }

    #[test]
    fn direct_pairs_are_role_pairs_compared_as_sets() {
        let stated = PolicyInput {
            direct_pairs: roles(&["member:admin", "member:member", "admin:member"]),
            ..PolicyInput::default()
        };
        let link = stated.link_policy(&LinkPolicy::default()).unwrap().unwrap();
        assert_eq!(
            link.direct_pairs,
            [
                ("admin".into(), "member".into()),
                ("member".into(), "member".into())
            ]
        );
        assert!(!same_link_policy(&link, &LinkPolicy::default()));
        let restated = PolicyInput {
            direct_pairs: roles(&[
                "node:node",
                "member:node",
                "member:member",
                "admin:node",
                "admin:member",
                "admin:admin",
            ]),
            ..PolicyInput::default()
        };
        assert_eq!(restated.link_change(&LinkPolicy::default()).unwrap(), None);
        for (bad, start) in [
            (
                "member",
                "[ca] direct_pairs: \"member\" is not a pair of roles",
            ),
            ("member:robot", "[ca] direct_pairs: unknown role"),
        ] {
            let err = PolicyInput {
                direct_pairs: roles(&[bad]),
                ..PolicyInput::default()
            }
            .link_policy(&LinkPolicy::default())
            .unwrap_err();
            assert!(err.to_string().starts_with(start), "{err}");
        }
    }

    fn relay(
        device: &str,
        key: Option<[u8; 32]>,
        endpoint: &str,
        preference: u32,
    ) -> AdvertisedRelay {
        AdvertisedRelay {
            device: device.parse().unwrap(),
            key,
            endpoints: vec![endpoint.to_string()],
            preference,
        }
    }

    /// A relay needs an endpoint, and one outside the namespace its
    /// expected fingerprint; a CA whose relays disagree with the context
    /// does not start.
    #[test]
    fn stated_relays_are_checked_and_must_match_the_context() {
        let ns: Name = "/home".parse().unwrap();
        let own = relay("/home/node/r", None, "r.example.net:6367", 0);
        let mut no_endpoint = own.clone();
        no_endpoint.endpoints.clear();
        let foreign = relay("/club/node/r", None, "club.example.org:6367", 1);
        for (relays, start) in [
            (vec![no_endpoint], "[ca] relay /home/node/r has no endpoint"),
            (
                vec![foreign.clone()],
                "[ca] relay /club/node/r is not a device of /home",
            ),
        ] {
            let err = PolicyInput {
                relays: Some(relays),
                ..PolicyInput::default()
            }
            .new_namespace_policies(&ns)
            .unwrap_err();
            assert!(err.to_string().starts_with(start), "{err}");
        }
        let keyed = AdvertisedRelay {
            key: Some([9; 32]),
            ..foreign
        };
        let stated = PolicyInput {
            relays: Some(vec![keyed.clone(), own.clone()]),
            ..PolicyInput::default()
        };
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_relays(vec![own, keyed]);
        stated
            .check_relays(&ctx)
            .expect("the same relays, in another order");
        assert_eq!(stated.relays_change(&ctx).unwrap(), None);
        PolicyInput::default()
            .check_relays(&ctx)
            .expect("unset: the context's");
        let none = PolicyInput {
            relays: Some(Vec::new()),
            ..PolicyInput::default()
        };
        let err = none.enforced_policy(Some(&ctx)).unwrap_err();
        assert!(matches!(err, PolicyError::RelaysDisagree { .. }), "{err}");
        assert!(
            err.to_string()
                .contains("which advertises: /home/node/r at"),
            "{err}"
        );
    }

    /// Removing a direct pair or dropping an advertised relay narrows (a
    /// schema update needs consent); adding a relay, or moving one to other
    /// endpoints or another preference, does not.
    #[test]
    fn removing_a_direct_pair_or_a_relay_is_a_narrowing() {
        let ns: Name = "/home".parse().unwrap();
        let schema = namespace_schema(&ns).unwrap().blobs();
        let r = relay("/home/node/r", None, "r.example.net:6367", 0);
        let held = SignedTrustContext::hierarchical(ns.clone())
            .with_version(4)
            .with_schema_blobs(schema)
            .unwrap()
            .schema_authoritative()
            .with_enrollment_hint(ApprovalPolicy::default().to_hint())
            .with_relays(vec![r.clone()]);

        let fewer_pairs = PolicyInput {
            direct_pairs: roles(&["member:member", "admin:admin"]),
            ..PolicyInput::default()
        };
        match plan_schema_update(&held, &fewer_pairs, false) {
            Err(SchemaPlanError::Change(BumpError::LinkNarrowing { narrowed, .. })) => {
                assert!(
                    narrowed.contains(
                        &"admin and member devices may no longer make direct paths with each other"
                            .to_string()
                    ),
                    "{narrowed:?}"
                );
                assert_eq!(narrowed.len(), 4, "{narrowed:?}");
            }
            other => panic!("expected a link narrowing, got {other:?}"),
        }
        let plan = plan_schema_update(&held, &fewer_pairs, true).unwrap();
        assert_eq!(plan.change.link_narrowed.len(), 4);
        let more_pairs = PolicyInput {
            direct_pairs: roles(&[
                "node:node",
                "member:node",
                "member:member",
                "admin:node",
                "admin:member",
                "admin:admin",
                "guest:member",
            ]),
            ..PolicyInput::default()
        };
        let plan = plan_schema_update(&held, &more_pairs, false).expect("adding a pair widens");
        assert!(plan.change.changes_link() && plan.change.link_narrowed.is_empty());

        let dropped = PolicyInput {
            relays: Some(Vec::new()),
            ..PolicyInput::default()
        };
        match plan_schema_update(&held, &dropped, false) {
            Err(SchemaPlanError::Change(BumpError::RelayNarrowing { dropped, .. })) => {
                assert_eq!(dropped, ["/home/node/r is no longer advertised as a relay"]);
            }
            other => panic!("expected a relay narrowing, got {other:?}"),
        }
        let plan = plan_schema_update(&held, &dropped, true).unwrap();
        assert_eq!(plan.relays, Some(Vec::new()));
        assert_eq!(plan.change.relays_dropped.len(), 1);

        let moved = AdvertisedRelay {
            endpoints: vec!["r2.example.net:6367".into(), "r.example.net:6367".into()],
            preference: 3,
            ..r.clone()
        };
        let added = relay("/home/node/s", None, "s.example.net:6367", 1);
        let widened = PolicyInput {
            relays: Some(vec![moved, added]),
            ..PolicyInput::default()
        };
        let plan = plan_schema_update(&held, &widened, false).expect("no relay is dropped");
        assert!(plan.change.changes_relays() && plan.change.relays_dropped.is_empty());

        let pinned = PolicyInput {
            relays: Some(vec![AdvertisedRelay {
                key: Some([1; 32]),
                ..r
            }]),
            ..PolicyInput::default()
        };
        assert!(matches!(
            plan_schema_update(&held, &pinned, false),
            Err(SchemaPlanError::Change(BumpError::RelayNarrowing { .. }))
        ));
    }

    #[test]
    fn token_and_device_approval_are_one_challenge_each_where_first_listed() {
        use ChallengeSlot::*;
        let order = challenge_order(
            [
                "pin",
                "token",
                "device-approval",
                "token",
                "email",
                "device-approval",
            ],
            None,
        );
        assert_eq!(
            order.slots,
            [Configured(0), Token, DeviceApproval, Configured(4)]
        );
        assert!(!order.approval_unlisted);
    }

    #[test]
    fn a_namespace_ca_offers_device_approval_when_its_context_names_approval_roles() {
        use ChallengeSlot::*;
        let policy = ApprovalPolicy::default();
        let order = challenge_order(["token"], Some(&policy));
        assert_eq!(order.slots, [Token, DeviceApproval]);
        assert!(order.approval_unlisted);
        // Listed: where listed.
        let order = challenge_order(["device-approval", "token"], Some(&policy));
        assert_eq!(order.slots, [DeviceApproval, Token]);
        assert!(!order.approval_unlisted);
        // No approval roles, or not a namespace CA: not offered.
        let none = ApprovalPolicy {
            roles: Vec::new(),
            invite_also: false,
        };
        assert_eq!(challenge_order(["token"], Some(&none)).slots, [Token]);
        assert_eq!(challenge_order(["nop"], None).slots, [Configured(0)]);
    }
}
