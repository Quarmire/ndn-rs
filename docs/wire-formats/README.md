# Wire-format mappings

One file per type, keyed by NDN-TLV tag ID. These are the cross-stack
consumer documentation per the dashboard security-design kickoff
(`docs/notes/dashboard-security-v1-implementation-kickoff-2026-05-13.md`
§4 — "Cross-stack consumer documentation: publish a
`field-tag-mapping.toml` per type for non-Rust consumers").

Each file pairs with a Rust type that implements `ChainEntry` (or, in
the policy case, a non-chained serializable forwarder-internal
struct). Tag IDs are **wire identifiers** — once shipped, never
reused.

| File | Type | Defined in |
|------|------|------------|
| [`audit-log-entry.toml`](audit-log-entry.toml)       | `AuditLogEntry`       | `crates/tooling/ndn-dashboard/src/security_chains.rs` |
| [`schema-journal-entry.toml`](schema-journal-entry.toml) | `SchemaJournalEntry` | `crates/tooling/ndn-dashboard/src/security_chains.rs` |

## Reserved chain-primitive tags

Every chain entry's Content starts with three reserved tags before
the type-defined payload (per `signed_data_chain.rs::tag`):

| Tag | Field             | Type                   | Notes                                                              |
|-----|-------------------|------------------------|--------------------------------------------------------------------|
| 0   | `schema_version`  | NonNegativeInteger u16 | Per-type version pin; bumped only on backward-incompatible breaks. |
| 1   | `authored_under`  | optional 32-byte hash  | v1: always zero-length (None). Reserved for v2 SemanticManifest.   |
| 2   | `prev_entry_hash` | 32 bytes               | SHA-256 of prior entry's Data wire (NDN ImplicitSha256Digest).     |
| 3+  | type-defined      | (see per-type file)    | First type-defined tag is `tag::PAYLOAD_START` = 3.                |
