//! `IdentityRef` and supporting types — one identity I hold inside a
//! [`TrustContext`].

use std::time::SystemTime;

use ndn_packet::Name;
use ndn_security::NamePattern;

use ndn_security::custodian::CustodianRef;
// `KeyId` now lives in `ndn-custodian` (the custodian signs by it). Re-export
// so `trust_context::KeyId` and every existing path keeps resolving.
pub use ndn_security::custodian::KeyId;

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
