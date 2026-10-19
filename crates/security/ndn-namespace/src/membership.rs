//! How the device takes part in each namespace (trusted prefix) it holds —
//! following, member (with a role) or owner — as data ([`memberships`]) and
//! as events when that changes ([`Participant::events`]).
//!
//! - **owner**: the device holds the namespace's root key
//!   ([`ContextStore::holds_root_key`](crate::ContextStore::holds_root_key));
//! - **member**: it holds a currently valid device certificate in it that no
//!   held version revokes (on its chain);
//! - **following**: it holds the namespace's trust context only — it
//!   verifies the namespace's Data and cannot publish under it.
//!
//! Events are published when a namespace is adopted, the device enrolls or
//! renews a certificate in one, a version revokes one of the device's
//! certificates, or a namespace's root changes (a recovery).

use std::collections::HashMap;

use ndn_cert::report::{
    ContextChange, MembershipChange, MembershipEvent, MembershipInfo, MembershipRelation,
};
use ndn_cert::roles::parse_device_key;
use ndn_packet::Name;
use ndn_security::cert_name::key_name_of;
use ndn_security::trust_context::{KeyRole, anchor_fingerprint};
use ndn_security::{Keyring, SignedTrustContext};

use crate::enroll::{certified_in, revoked_on_chain};
use crate::{KeyVault, Participant, hex, iso};

/// What the device last saw of one namespace: to tell an adoption, a
/// revocation of its own certificate and a root change apart, and what a
/// new version revokes.
pub(crate) struct Seen {
    version: u64,
    roots: Vec<[u8; 32]>,
    revocations: Vec<Name>,
}

impl Seen {
    fn of(ctx: &SignedTrustContext) -> Self {
        Self {
            version: ctx.version(),
            roots: root_fingerprints(ctx),
            revocations: ctx.revocations().to_vec(),
        }
    }
}

/// What the device sees of every namespace `keyring` holds now.
pub(crate) fn seen_now(keyring: &Keyring) -> HashMap<Name, Seen> {
    keyring
        .contexts()
        .iter()
        .map(|ctx| (ctx.namespace().clone(), Seen::of(ctx)))
        .collect()
}

/// The fingerprints of `ctx`'s root anchors (every trust anchor but a
/// recovery kit's: adding or removing a kit changes no root), sorted.
fn root_fingerprints(ctx: &SignedTrustContext) -> Vec<[u8; 32]> {
    let mut roots: Vec<[u8; 32]> = ctx
        .anchors()
        .iter()
        .filter(|a| !ctx.has_key_role(&key_name_of(a.key()), KeyRole::RECOVERY_ANCHOR))
        .map(|a| anchor_fingerprint(a.value()))
        .collect();
    roots.sort();
    roots
}

/// The device's membership in every namespace it holds, sorted by
/// namespace: its relation, and the device identity it signs the
/// namespace's Data as (`vault`'s keys, judged against the held context).
pub fn memberships(p: &Participant, vault: &dyn KeyVault) -> Vec<MembershipInfo> {
    let node = vault.node_identity();
    let mut contexts = p.keyring().contexts();
    contexts.sort_by(|a, b| a.namespace().cmp(b.namespace()));
    contexts
        .iter()
        .map(|ctx| {
            let namespace = ctx.namespace();
            let certified: Vec<_> = certified_in(p, vault, namespace)
                .into_iter()
                .filter(|c| c.revoked.is_none())
                .collect();
            // The key the running device signs the namespace's Data with,
            // when it is one of those; else the first certified.
            let signing = p
                .engine()
                .security()
                .and_then(|mgr| mgr.signing_identity_for(namespace).ok())
                .map(|s| s.key);
            let held = certified
                .iter()
                .find(|c| Some(&c.key) == signing.as_ref())
                .or_else(|| certified.first());
            let owner = p.store().holds_root_key(ctx);
            let relation = if owner {
                MembershipRelation::Owner
            } else if held.is_some() {
                MembershipRelation::Member
            } else {
                MembershipRelation::Following
            };
            let mut info = MembershipInfo {
                namespace: namespace.to_string(),
                version: ctx.version(),
                relation,
                role: String::new(),
                identity: String::new(),
                key: String::new(),
                valid_until: String::new(),
                node_identity: false,
                root_fingerprint: root_fingerprints(ctx)
                    .first()
                    .map(|fp| hex(fp))
                    .unwrap_or_default(),
            };
            if let Some(held) = held
                && let Some(device) = parse_device_key(namespace, &held.key)
            {
                let identity = key_identity(namespace, &held.key);
                info.role = device.role.to_string();
                info.node_identity = node.as_ref() == Some(&identity);
                info.identity = identity.to_string();
                info.key = held.key.to_string();
                info.valid_until = iso(held.valid_until);
            }
            info
        })
        .collect()
}

/// `/<ns>/<role>/<device>` of the device key `key` in `namespace`.
fn key_identity(namespace: &Name, key: &Name) -> Name {
    Name::from_components(key.components()[..namespace.len() + 2].iter().cloned())
}

/// The device's relation to `ctx`'s namespace as the running device signs:
/// owner when it holds the root key, member when the engine signs the
/// namespace's Data with a device key whose certificate is valid and not
/// revoked on its chain, else following.
pub(crate) fn relation_now(p: &Participant, ctx: &SignedTrustContext) -> MembershipRelation {
    if p.store().holds_root_key(ctx) {
        return MembershipRelation::Owner;
    }
    let member = p.engine().security().is_some_and(|mgr| {
        mgr.signing_identity_for(ctx.namespace())
            .ok()
            .filter(|s| parse_device_key(ctx.namespace(), &s.key).is_some())
            .and_then(|s| mgr.cert_cache().get_valid(&s.key))
            .is_some_and(|cert| {
                revoked_on_chain(ctx, &cert, |issuer| mgr.cert_cache().get_valid(issuer)).is_none()
            })
    });
    if member {
        MembershipRelation::Member
    } else {
        MembershipRelation::Following
    }
}

/// `ctx` was kept as its namespace's newest version
/// ([`keep::keep`](crate::keep::keep)), reached `how`: told as a
/// `context-updated` event, then what it changes about the device's
/// membership — an adoption when the namespace is new to the device, a root
/// change when other anchors sign it, and a revocation when it revokes the
/// chain of the key the device signs the namespace's Data with — each
/// published as a [`MembershipEvent`]. Nothing for a version no newer than
/// the one seen.
pub(crate) fn kept(p: &Participant, ctx: &SignedTrustContext, how: ContextChange) {
    let namespace = ctx.namespace();
    let before = {
        let mut seen = p.seen.lock();
        if seen
            .get(namespace)
            .is_some_and(|before| ctx.version() <= before.version)
        {
            return;
        }
        seen.insert(namespace.clone(), Seen::of(ctx))
    };
    let revoked = ctx
        .revocations()
        .iter()
        .filter(|r| before.as_ref().is_some_and(|b| !b.revocations.contains(r)))
        .map(Name::to_string)
        .collect();
    crate::events::context_kept(
        p,
        namespace,
        before.as_ref().map(|b| b.version),
        ctx.version(),
        how,
        revoked,
    );
    let event = |change| MembershipEvent {
        namespace: namespace.to_string(),
        relation: relation_now(p, ctx),
        change,
        version: ctx.version(),
        key: None,
        revoked: None,
        replaced_version: None,
        valid_until: None,
        request: None,
    };
    let Some(before) = before else {
        p.publish_membership(event(MembershipChange::Adopted));
        return;
    };
    if root_fingerprints(ctx) != before.roots {
        p.publish_membership(MembershipEvent {
            replaced_version: Some(before.version),
            ..event(MembershipChange::RootChanged)
        });
    }
    let revoked = p.engine().security().and_then(|mgr| {
        let signing = mgr.signing_identity_for(namespace).ok()?;
        let cert = mgr.cert_cache().get_valid(&signing.key)?;
        let name = revoked_on_chain(ctx, &cert, |issuer| mgr.cert_cache().get_valid(issuer))?;
        Some((signing.key, name))
    });
    if let Some((key, name)) = revoked {
        p.publish_membership(MembershipEvent {
            key: Some(key.to_string()),
            revoked: Some(name.to_string()),
            ..event(MembershipChange::Revoked)
        });
    }
}

/// The device enrolled `key` in `namespace` (now signing its Data with it),
/// certified until `valid_until`, after `request` when it waited for an
/// admin's approval.
pub(crate) fn enrolled(
    p: &Participant,
    namespace: &Name,
    key: &Name,
    valid_until: u64,
    request: Option<&str>,
) {
    let Some(ctx) = p.held_context(namespace) else {
        return;
    };
    p.publish_membership(MembershipEvent {
        namespace: namespace.to_string(),
        relation: relation_now(p, &ctx),
        change: MembershipChange::Enrolled,
        version: ctx.version(),
        key: Some(key.to_string()),
        revoked: None,
        replaced_version: None,
        valid_until: Some(iso(valid_until)),
        request: request.map(str::to_owned),
    });
}

/// A certificate of `key` in `namespace` was renewed; `valid_until` is the
/// new one's validity end.
pub(crate) fn renewed(p: &Participant, namespace: &Name, key: &Name, valid_until: u64) {
    let Some(ctx) = p.held_context(namespace) else {
        return;
    };
    p.publish_membership(MembershipEvent {
        namespace: namespace.to_string(),
        relation: relation_now(p, &ctx),
        change: MembershipChange::Renewed,
        version: ctx.version(),
        key: Some(key.to_string()),
        revoked: None,
        replaced_version: None,
        valid_until: Some(iso(valid_until)),
        request: None,
    });
}
