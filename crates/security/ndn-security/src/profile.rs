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
    /// - `CertFetcher` for missing certificates (the engine fetches them
    ///   through its own faces)
    ///
    /// **When no `SecurityManager` is set** there are no trust anchors, and
    /// `Default` fails closed: every Data from a non-local face that names a
    /// signer is refused at once with the final local refusal
    /// `untrusted-root` ([`TrustError::NoTrustAnchors`](crate::TrustError::NoTrustAnchors),
    /// [`Validator::refuse_without_anchors`]). DigestSha256 Data still
    /// validates (integrity only, no signer); local faces are not validated,
    /// as under every profile. It never degrades to signature-only checking:
    /// choose [`AcceptSigned`](Self::AcceptSigned) or
    /// [`Disabled`](Self::Disabled) explicitly for that. Trust anchors added
    /// to the engine's validator later (or a trust context adopted into its
    /// keyring) are honoured for the names they govern.
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
