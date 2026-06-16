//! TLV constants for the context-sync wire shapes used by `ndn-identity`'s
//! [`SyncBundle`](../../../../ndn-identity/src/trust_context/sync.rs) and the
//! Phase-2 SVS delta payloads (`.claude/prompts/
//! trust-context-synthesis-implementation-2026-05-25.md` §Phase 2).
//!
//! Provisional block `0x0420..=0x042F`, the next free range after the
//! TrustContext block (`0x0410..=0x041F` in [`super::tlv`]). Allocation
//! verified against on-disk NFD / ndn-cxx / ndnd and the
//! `.claude/notes/ndn-rs-tlv-allocations-2026-05-20.md` doctrine — no
//! collisions.
//!
//! Same evolvability rule applies: `type <= 31 || (type & 0x01)` → odd =
//! must-understand, even = additive.

/// Outer container for a [`SyncBundle`] on the wire (the `Content` body of a
/// snapshot Data published into the context-sync namespace). Even — it *is*
/// the content body, so its own criticality is moot.
pub const TC_SYNC_BUNDLE: u64 = 0x0420;

/// Anchor add/remove delta. Additive: an old node skipping it still has the
/// schema and existing anchors. Even — non-critical.
pub const TC_SYNC_ANCHOR_DELTA: u64 = 0x0422;

/// Schema delta carrying a versioned LVS rule update. Critical (odd): a peer
/// that cannot parse the schema update would mis-authorize signatures.
pub const TC_SYNC_SCHEMA_DELTA: u64 = 0x0423;

/// CA endpoint list additions / removals. Additive, even.
pub const TC_SYNC_CA_ENDPOINT_DELTA: u64 = 0x0424;

/// Private key wrapped to a specific recipient device cert. Critical (odd):
/// recipients that can't decode it cannot bind the new identity, so they
/// must visibly reject the bundle.
pub const TC_SYNC_WRAPPED_KEY_FOR_DEVICE: u64 = 0x0425;

/// Device id (NameComponent / Name) producing the bundle. Additive.
pub const TC_SYNC_DEVICE_ID: u64 = 0x0426;

/// Monotonic schema version riding inside a [`TC_SYNC_SCHEMA_DELTA`].
/// Critical: missing it allows reorder-induced rollback. Odd.
pub const TC_SYNC_SCHEMA_VERSION: u64 = 0x0427;
