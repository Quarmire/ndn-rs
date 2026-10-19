//! `SigningInfo` — ndn-cxx-style composable signing policy.
//!
//! The caller describes what should sign a packet (an identity name, a
//! specific key, a cert, an HMAC key, plain `DigestSha256`, or an
//! LVS-suggested signer) plus any `SignatureInfo` overrides;
//! [`KeyChain::sign_packet`] resolves the selection against the local PIB,
//! cert cache, and LVS schema and applies the signature.
//!
//! [`KeyChain::sign_packet`]: crate::KeyChain::sign_packet

use ndn_packet::Name;

/// What should sign a packet, resolved at `sign_packet` time against
/// the keychain's PIB and cert cache.
#[derive(Debug, Clone)]
pub enum SignerSelection {
    /// Identity's default key; `Name` is the identity prefix
    /// (e.g. `/com/example/alice`). Any identity whose key the keychain's
    /// [`SecurityManager`] holds resolves; an unknown identity is an error.
    ///
    /// [`SecurityManager`]: crate::SecurityManager
    Identity(Name),
    /// Specific key by name; must already be in the [`SecurityManager`]'s
    /// key store.
    ///
    /// [`SecurityManager`]: crate::SecurityManager
    Key(Name),
    /// Key behind a specific certificate name; the cert pins the
    /// `KeyLocator` placed on the wire.
    Cert(Name),
    /// Named HMAC-SHA-256 symmetric key.
    HmacKey(Name),
    /// `DigestSha256` — integrity only, no key.
    Digest,
    /// Let the packet name choose the signer. Until full LVS-rule
    /// evaluation lands, the identity
    /// [`SecurityManager::signing_identity_for`] chooses signs: the device's
    /// identity in the trusted prefix governing `for_name`, else the held
    /// identity with the longest name covering it; none is an error that
    /// says why ([`TrustError::NoSigningIdentity`]).
    ///
    /// [`SecurityManager::signing_identity_for`]: crate::SecurityManager::signing_identity_for
    /// [`TrustError::NoSigningIdentity`]: crate::TrustError::NoSigningIdentity
    Suggested { for_name: Name },
}

/// Optional overrides applied to the `SignatureInfo` emitted on the wire.
#[derive(Debug, Default, Clone)]
pub struct SignatureInfoOverrides {
    /// Override the `KeyLocator` name placed on the wire. Useful when the
    /// application has a specific cert name to advertise even though the
    /// signer lives under a different key directory.
    pub key_locator: Option<Name>,
    /// `(not_before_ms, not_after_ms)` validity-period window in
    /// milliseconds since the Unix epoch. Encoder integration pending.
    pub validity_period_ms: Option<(u64, u64)>,
}

/// Composable signing policy passed to [`KeyChain::sign_packet`].
///
/// [`KeyChain::sign_packet`]: crate::KeyChain::sign_packet
#[derive(Debug, Clone)]
pub struct SigningInfo {
    pub selection: SignerSelection,
    pub overrides: Option<SignatureInfoOverrides>,
}

impl SigningInfo {
    pub fn identity(name: Name) -> Self {
        Self {
            selection: SignerSelection::Identity(name),
            overrides: None,
        }
    }

    pub fn key(name: Name) -> Self {
        Self {
            selection: SignerSelection::Key(name),
            overrides: None,
        }
    }

    pub fn cert(name: Name) -> Self {
        Self {
            selection: SignerSelection::Cert(name),
            overrides: None,
        }
    }

    pub fn hmac_key(name: Name) -> Self {
        Self {
            selection: SignerSelection::HmacKey(name),
            overrides: None,
        }
    }

    pub fn digest_sha256() -> Self {
        Self {
            selection: SignerSelection::Digest,
            overrides: None,
        }
    }

    pub fn suggested(for_name: Name) -> Self {
        Self {
            selection: SignerSelection::Suggested { for_name },
            overrides: None,
        }
    }

    pub fn with_overrides(mut self, overrides: SignatureInfoOverrides) -> Self {
        self.overrides = Some(overrides);
        self
    }
}
