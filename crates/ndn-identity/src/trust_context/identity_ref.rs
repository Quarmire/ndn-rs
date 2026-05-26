//! `IdentityRef` and supporting types — one identity I hold inside a
//! [`TrustContext`].

use std::time::SystemTime;

use ndn_packet::Name;
use ndn_security::NamePattern;

use crate::custodian::CustodianRef;

/// Opaque key locator. Today this is the canonical NDN key name
/// (`/<identity>/KEY/<key-id>`); the type stays separate so future
/// custodians can introduce private locators that don't round-trip through
/// the name codec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub Name);

impl KeyId {
    /// Placeholder key-id minted from an identity name — used in tests and
    /// for derived sub-identities whose key has not been generated yet.
    pub fn placeholder_for(identity: &Name) -> Self {
        let n = identity.clone().append(b"KEY").append(b"pending");
        Self(n)
    }

    pub fn as_name(&self) -> &Name {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct IdentityRef {
    pub name: Name,
    pub key_id: KeyId,
    pub custodian: CustodianRef,
    pub lifetime: IdentityLifetime,
    pub derived_from: Option<KeyId>,
    pub capabilities: CapabilitySet,
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
