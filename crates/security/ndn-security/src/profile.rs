use std::sync::Arc;

use crate::Validator;

/// Configures how the engine validates Data packet signatures.
///
/// Security is default-on in NDN. Use `Disabled` only for benchmarking
/// or isolated lab environments.
pub enum SecurityProfile {
    /// Full chain validation with cert fetching and hierarchical trust.
    ///
    /// This is the default. When a `SecurityManager` is set on the builder,
    /// the engine wires a `Validator` with:
    /// - `TrustSchema::hierarchical()` (data and key share first component)
    /// - Shared `CertCache` from the `SecurityManager`
    /// - Trust anchors from the `SecurityManager`
    /// - `CertFetcher` for missing certificates
    ///
    /// **When no `SecurityManager` is set**, the engine falls back to
    /// `AcceptSigned` behaviour: each Data packet's signature is verified
    /// cryptographically but namespace hierarchy is not enforced. This keeps
    /// security on by default even without a configured trust anchor.
    ///
    /// Use [`Disabled`](Self::Disabled) to explicitly turn off all validation.
    Default,

    /// Verify that signatures are present and cryptographically valid,
    /// but skip chain walking: each Data packet is verified against its
    /// signer's certificate — fetched when not cached, a self-signed one
    /// included — and accepted without that certificate reaching a trust
    /// anchor ([`Validator::accept_signed`]). On a forwarder the signer's
    /// certificate is itself Data validated this way before it is used.
    /// The ambient schema accepts any name relationship.
    ///
    /// Useful for testing or deployments where any valid signature
    /// is sufficient (e.g., all participants share a trust domain).
    AcceptSigned,

    /// No validation — all Data packets pass through unchecked.
    ///
    /// Must be explicitly set. Use only for benchmarking or isolated
    /// lab environments where security is irrelevant.
    Disabled,

    /// Custom validator provided by the caller.
    ///
    /// Full control over trust schema, cert cache, trust anchors,
    /// and chain depth. For advanced use cases.
    Custom(Arc<Validator>),
}
