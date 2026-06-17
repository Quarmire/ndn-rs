//! [`KeyId`] — an opaque key locator. Lives here (rather than in
//! `ndn-identity`) because the [`crate::custodian::Custodian`] trait signs *by* a `KeyId`,
//! so it is the more foundational of the two and breaks the custodian ↔
//! trust-context dependency cycle.

use ndn_packet::Name;

/// Opaque key locator. Today this is the canonical NDN key name
/// (`/<identity>/KEY/<key-id>`); the type stays separate so future custodians
/// can introduce private locators that don't round-trip through the name codec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(pub Name);

impl KeyId {
    /// Placeholder key-id minted from an identity name — used in tests and for
    /// derived sub-identities whose key has not been generated yet.
    pub fn placeholder_for(identity: &Name) -> Self {
        let n = identity.clone().append(b"KEY").append(b"pending");
        Self(n)
    }

    pub fn as_name(&self) -> &Name {
        &self.0
    }
}
