//! TLV constants for the [`TrustContext`](super::TrustContext) wire object.
//!
//! Provisional block `0x0410–0x041F` in the app-defined range (`>= 0x0400`),
//! above `ndn-packet`'s `REFLEXIVE_NAME = 0x0402` with `0x0403–0x040F` as
//! headroom. Not LP (`0x500`), not management (`0xD0`), not NDNCERT
//! (`0x81–0xAF`). Flagged for a future NDN TLV-registry submission note; see
//! `.claude/notes/ndn-rs-tlv-allocations-2026-05-20.md`.
//!
//! # Criticality parity
//!
//! ndn-cxx's evolvability rule (`tlv.hpp::isCriticalType`) is
//! `type <= 31 || (type & 0x01)` — for our range, **odd = critical**
//! (must-understand) and **even = non-critical** (an old node may skip it).
//! Numbers are assigned so a node on an older build degrades correctly when it
//! meets a newer context:
//!
//! - Must-understand → **odd**: [`ANCHOR_SET`], [`TRUST_SCHEMA_BLOB`],
//!   [`SCHEMA_FORMAT`], [`SCHEMA_BODY`]. Without the anchors or schema a
//!   context is meaningless, so a node that can't parse them must reject it.
//! - Additive → **even**: [`CA_ENDPOINT`], [`ENROLLMENT_HINT`],
//!   [`REVOCATION`]. An old node skips an unknown one and still validates with
//!   the anchors + schema it does understand.
//!
//! (The design note's draft had the parity inverted for the must-understand
//! fields; renumbered here per the note's own "verify criticality parity"
//! directive.)

/// Outer container; the `Content` of the context Data. Even — it *is* the
/// content body, so its own criticality is moot.
pub const TRUST_CONTEXT: u64 = 0x0410;

/// One-or-more anchor certificates (each a `Data`, `0x06`). Critical.
pub const ANCHOR_SET: u64 = 0x0411;

/// Trust schema, carrying [`SCHEMA_FORMAT`] + [`SCHEMA_BODY`]. Critical.
pub const TRUST_SCHEMA_BLOB: u64 = 0x0413;

/// CA enrollment endpoint, a `Name` (`0x07`), repeatable. Non-critical
/// connectivity/future-join hint.
pub const CA_ENDPOINT: u64 = 0x0414;

/// `{1 = native-text, 2 = lvs-binary}` schema encoding. Critical.
pub const SCHEMA_FORMAT: u64 = 0x0415;

/// Schema bytes interpreted per [`SCHEMA_FORMAT`]. Critical.
pub const SCHEMA_BODY: u64 = 0x0417;

/// Enrollment challenge hint. Non-critical.
pub const ENROLLMENT_HINT: u64 = 0x0416;

/// Revoked cert name / key digest, repeatable. Non-critical.
pub const REVOCATION: u64 = 0x0418;

/// `SchemaFormat` value: native ndn-rs text grammar (local authoring).
pub const SCHEMA_FORMAT_NATIVE: u8 = 1;
/// `SchemaFormat` value: stock LightVerSec binary (portable / published form).
pub const SCHEMA_FORMAT_LVS: u8 = 2;
