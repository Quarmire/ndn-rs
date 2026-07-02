//! `NdnIdentity` — the former name of `Identity`(crate::Identity).
//!
//! The keychain-wrapper and the principal/rotation facade were merged into one
//! `Identity` type (see `facade.rs`). This alias keeps existing
//! `ndn_identity::NdnIdentity` paths compiling for one release.

/// Deprecated alias for `Identity`(crate::Identity), the one managed identity
/// above `KeyChain`. Use `Identity` directly.
#[deprecated(since = "0.1.0", note = "renamed to `Identity`")]
pub type NdnIdentity = crate::facade::Identity;
