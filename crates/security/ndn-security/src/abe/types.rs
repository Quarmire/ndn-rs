//! TLV type-number registry for ndn-abe wire formats.
//!
//! Numbers live in a non-critical extension range (260–280) and are allocated
//! here in one place; never scatter literals. Per NDN Packet Format v0.3, odd
//! types are critical and even types are non-critical. These ABE types sit
//! inside the [`crate::abe::AbeCiphertext`] envelope and are all even (non-critical
//! extensions): an unaware decoder skips the whole envelope rather than any
//! single inner field.

/// Outer `AbeCiphertext` TLV envelope.
pub const ABE_CIPHERTEXT_TYPE: u64 = 260;
/// `AbeSchemeId` discriminant byte.
pub const ABE_SCHEME_ID_TYPE: u64 = 262;
/// `policy_source` UTF-8 string.
pub const ABE_POLICY_SOURCE_TYPE: u64 = 264;
/// `kgc_refs` list envelope.
pub const ABE_KGC_REFS_TYPE: u64 = 266;
/// Individual `KgcRef` envelope.
pub const ABE_KGC_REF_TYPE: u64 = 268;
/// `kgc_did` Name bytes (within KgcRef).
pub const ABE_KGC_DID_TYPE: u64 = 270;
/// `master_params_hash` 32-byte SHA-256 (within KgcRef).
pub const ABE_MASTER_PARAMS_HASH_TYPE: u64 = 272;
/// `rabe_ciphertext_bytes` — bincode-serialized rabe CT (BSW or AW11).
pub const ABE_CIPHERTEXT_BLOB_TYPE: u64 = 274;
/// Outer `PolicyBlockPayload` TLV envelope.
pub const ABE_POLICY_BLOCK_TYPE: u64 = 276;
/// `Aw11GlobalKey` bytes inside a multi-authority context.
pub const ABE_AW11_GLOBAL_KEY_TYPE: u64 = 278;
/// `Aw11PublicKey` bytes for one authority.
pub const ABE_AW11_PUB_KEY_TYPE: u64 = 280;
