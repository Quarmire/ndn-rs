//! TLV constants for the [`SignedTrustContext`](super::SignedTrustContext) wire object.
//!
//! Provisional block `0x0410–0x041F` in the app-defined range (`>= 0x0400`),
//! above `ndn-packet`'s `REFLEXIVE_NAME = 0x0402` with `0x0403–0x040F` as
//! headroom, continued in `0x0420–0x042F` once every even number of the
//! first block was taken ([`ADVERTISED_RELAY`] and its sub-TLVs). Not LP
//! (`0x500`), not management (`0xD0`), not NDNCERT (`0x81–0xAF`). Flagged
//! for a future NDN TLV-registry submission.
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
//!   [`REVOCATION`], [`KEY_ROLE`], [`LINK_POLICY`], [`ADVERTISED_RELAY`]. An
//!   old node skips an unknown one and still validates with the anchors +
//!   schema it does understand.
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
/// Repeatable: the runtime schema is the OR of every blob (at most one LVS
/// binary plus native-text rules for what LVS cannot express). An older node
/// that keeps only one blob authorizes less, never more.
pub const TRUST_SCHEMA_BLOB: u64 = 0x0413;

/// CA enrollment endpoint, a `Name` (`0x07`), repeatable. Non-critical
/// connectivity/future-join hint.
pub const CA_ENDPOINT: u64 = 0x0414;

/// `{1 = native-text, 2 = lvs-binary}` schema encoding, exactly one octet.
/// Critical. Another code makes its blob not understood: it authorizes
/// nothing and is re-emitted verbatim ([`SchemaFormat::Unknown`](super::SchemaFormat::Unknown));
/// a context with no understood blob is refused.
pub const SCHEMA_FORMAT: u64 = 0x0415;

/// Schema bytes interpreted per [`SCHEMA_FORMAT`]. Critical.
pub const SCHEMA_BODY: u64 = 0x0417;

/// Enrollment challenge hint. Non-critical.
pub const ENROLLMENT_HINT: u64 = 0x0416;

/// Revoked cert name / key digest, repeatable. Non-critical.
pub const REVOCATION: u64 = 0x0418;

/// Provenance hint: the SHA-256 implicit digest (32 bytes) of the source trust
/// **bundle** this context was projected/compiled from, so a wire object is
/// traceable back to the authoritative Block root of authority. Non-critical
/// (even): a hint, not a rule — an old node skips it and still validates with
/// the anchors + schema it understands. Filed as NDF feature request F9.
pub const SOURCE_BUNDLE_HASH: u64 = 0x041A;

/// Empty flag: the schema is **authoritative** — no hierarchy floor
/// (`keyLocator.isPrefixOf(name)`) on top of it, and every certificate hop of
/// a chain walk is checked against it (as LVS validation does). Set by
/// contexts whose schema binds every signer to the names it may sign,
/// certificates included (the generated namespace schema), and
/// deliberately grants cross-identity signing (admins approving enrollments,
/// members writing `/<ns>/shared`). Non-critical (even): an old node skips it
/// and keeps the floor.
pub const SCHEMA_AUTHORITATIVE: u64 = 0x041C;

/// What a key the context names is for, repeatable: one role code byte
/// followed by the key's `Name` (`0x07`) — see
/// [`KeyRole`](super::KeyRole). Recovery anchors are anchors kept offline to
/// sign the next version when the root device is lost; root-device keys are
/// the CA and admin keys that live on the root device beside the root (what a
/// recovery after a compromise revokes). Non-critical (even): an old node
/// skips it and treats every anchor alike, which is what a recovery anchor is.
/// Unknown role codes are kept and re-emitted.
pub const KEY_ROLE: u64 = 0x041E;

/// Which devices of the namespace may link to its devices, which may be
/// relays, whether relays admit enrollment links, whether direct paths are
/// allowed and between which roles — see [`LinkPolicy`](super::LinkPolicy):
/// UTF-8 `<roles>;<relay roles>;<enrollment|no-enrollment>[;<direct|no-direct>
/// [;<direct pairs>]]`, comma-separated role names, an empty role list
/// meaning every device role (a missing third field means `enrollment`, a
/// missing fourth means direct paths on, a missing fifth the default role
/// pairs). Non-critical (even): an old node skips it and links by the
/// default (any enrolled device; relays are `node` devices).
pub const LINK_POLICY: u64 = 0x0412;

/// A relay the namespace advertises, repeatable — see
/// [`AdvertisedRelay`](super::AdvertisedRelay). Non-critical (even): an old
/// node skips it, and a device that does not use namespace relays ignores
/// it. Its value is the sub-TLVs below plus the relay's device `Name`
/// (`0x07`); a malformed entry is skipped, not the context.
pub const ADVERTISED_RELAY: u64 = 0x0420;

/// In [`ADVERTISED_RELAY`]: the relay's expected fingerprint, 32 octets
/// (SHA-256 of its public key as its certificate carries it). Optional
/// for a device of the namespace, required otherwise.
pub const RELAY_KEY: u64 = 0x0422;

/// In [`ADVERTISED_RELAY`]: one endpoint, UTF-8 `host:port`, repeatable, in
/// the order a device tries them (at least one).
pub const RELAY_ENDPOINT: u64 = 0x0424;

/// In [`ADVERTISED_RELAY`]: preference, a NonNegativeInteger (lower is
/// preferred).
pub const RELAY_PREFERENCE: u64 = 0x0426;

/// `SchemaFormat` value: native ndn-rs text grammar (local authoring).
pub const SCHEMA_FORMAT_NATIVE: u8 = 1;
/// `SchemaFormat` value: stock LightVerSec binary (portable / published form).
pub const SCHEMA_FORMAT_LVS: u8 = 2;
