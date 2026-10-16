//! [`IdentityRef`] and its capability vocabulary — one identity a principal
//! holds, the custodian that signs for it, and the [`CapabilitySet`] scope it
//! may act within (the scope carried by [`Delegation`](crate::Delegation) and
//! [`SignedDelegation`](crate::SignedDelegation)).

use std::time::SystemTime;

use ndn_packet::Name;
use ndn_security::custodian::{CustodianRef, KeyId};
use ndn_security::{NamePattern, PatternComponent};

#[derive(Debug, Clone)]
pub struct IdentityRef {
    pub name: Name,
    pub key_id: KeyId,
    pub custodian: CustodianRef,
    pub lifetime: IdentityLifetime,
    pub derived_from: Option<KeyId>,
    pub capabilities: CapabilitySet,
}

impl IdentityRef {
    /// Derive a sub-identity authorized to sign under `scope`, with `lifetime`.
    /// The caller is responsible for then enrolling the resulting key under
    /// this (parent) identity (NDNCERT, or self-signed for ephemeral).
    pub fn derive_sub(
        &self,
        scope: Name,
        lifetime: IdentityLifetime,
        custodian: CustodianRef,
    ) -> IdentityRef {
        IdentityRef {
            key_id: KeyId::placeholder_for(&scope),
            capabilities: CapabilitySet {
                sign: vec![pattern_under(&scope)],
                ..Default::default()
            },
            name: scope,
            custodian,
            lifetime,
            derived_from: Some(self.key_id.clone()),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IdentityLifetime {
    Persistent,
    Ephemeral {
        expires_at: Option<SystemTime>,
        revoke_on_unbind: bool,
    },
    SessionScoped {
        custodian_session_id: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct CapabilitySet {
    pub sign: Vec<NamePattern>,
    pub unwrap_for: bool,
    pub enroll: bool,
    pub mgmt: bool,
}

impl CapabilitySet {
    /// Whether any `sign` pattern in this set authorizes signing `name`.
    pub fn may_sign(&self, name: &Name) -> bool {
        let mut bindings = std::collections::HashMap::new();
        self.sign.iter().any(|pattern| {
            bindings.clear();
            pattern.matches(name, &mut bindings)
        })
    }
}

/// The pattern covering `prefix` and everything beneath it
/// (`<prefix>/<**_>`).
pub(crate) fn pattern_under(prefix: &Name) -> NamePattern {
    let mut comps: Vec<PatternComponent> = prefix
        .components()
        .iter()
        .map(|c| PatternComponent::Literal(c.clone()))
        .collect();
    comps.push(PatternComponent::MultiCapture("_".into()));
    NamePattern(comps)
}
