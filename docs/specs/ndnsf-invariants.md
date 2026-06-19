# NDNSF Security-Invariant Witness Catalog (O4 gate)

**Status:** Draft (living document)
**Editor:** ndn-rs contributors
**Source:** `NDN_Service_Framework/SECURITY_INVARIANTS.md` + `FINAL_SECURITY_AUDIT.md`
**Relationship:** O4 gate from `service-layer.md` §9.

---

## Purpose — the gate

A reimplementation in a new language is the classic way an audited system silently
loses its audited properties: the invariants do not travel with the code unless we
make them. This catalogue extracts every NDNSF security invariant, assigns it a
stable ID, maps it to the ndn-rs layer that must enforce it, and names the witness
that proves it.

**The gate:** `ndn-nacabe` (the NAC protocol) and `ndn-ndnsf` (the faithful compat
layer) **MUST NOT land** until every invariant mapped to them has a passing
witness. Invariants that already map to shipped primitives (CK, capability) have
runnable witnesses today (`ndn-security/tests/ndnsf_invariants_witness.rs`); the
rest are the acceptance criteria for the layers that will enforce them.

## Threat model (carried over)

Attackers may publish forged, unsigned, malformed, stale, or replayed NDN Data and
SVS messages; fetch encrypted permission Data addressed to another identity; race
selection against cleanup; replay observed tokens; or inject random tokens. The
system relies on configured trust validation, NAC-ABE attributes, encrypted
(content-key-wrapped) permission payloads, and one-time tokens to **fail closed**.

## Invariants

Status: ✅ runnable witness today · ⛔ gates a future layer (acceptance criterion).

### Authentication

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-A1 | `PermissionResponse` Data is validated by the trust validator **before** it is decrypted or installed. | `ndn-nacabe::service`: the `ParamFetcher` validates the authority's response before use, and the authority validates the signed `DKEY` request before issuing. | ✅ `aa_paramfetcher_witness` (over-NDN) |
| NSF-A2 | The signer identity of `PermissionResponse` matches the Permission-Controller identity encoded in the permission Interest path. | `ndn-nacabe::service`: the authority issues to the **validated signer's** identity (the request's `KeyLocator`), so a requester can only obtain its own key. | ✅ `aa_paramfetcher_witness` / `serve_cp` |
| NSF-A3 | `ACK`/`COORDINATION`/`RESPONSE` pass trust validation **and** NAC-ABE authorization before their payloads affect runtime state. | `ndn-ndnsf` four-phase handlers. | ⛔ gates `ndn-ndnsf` |
| NSF-A4 | Permission-discovery Interests may be unsigned; the returned **Data** is the authenticated object. | `ndn-discovery`/`ndn-ndnsf` — matches NDN's data-centric trust. | ⛔ gates `ndn-ndnsf` |

### Token properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-T1 | `ProviderToken` is one-time use. | compat: `ndn-ndnsf` token consumption. v2: `ReplayGuard` on the signed request Interest. | ⛔ gates `ndn-ndnsf` (ReplayGuard precedent exists) |
| NSF-T2 | `ProviderToken` expires after its pending-state TTL. | v2: capability `not_after`. compat: `ndn-ndnsf` TTL. | ✅ `nsf_t2_capability_expires_after_window` |
| NSF-T3 | Replaying a token after successful coordination fails. | `ReplayGuard` + `ndn-ndnsf`. | ⛔ gates `ndn-ndnsf` |
| NSF-T4 | Using an expired token fails. | capability validity window. | ✅ `nsf_t4_expired_capability_rejected` |
| NSF-T5 | An unknown/random token fails. | capability: wrong grantee / bad signature (signature is the `Validator`'s job). | ✅ `nsf_t5_unknown_grantee_rejected` (binding); ⛔ signature path gates `ndn-ndnsf` |
| NSF-T6 | A provider restart before coordination does not preserve pending token state unless an explicit, audited persistence mechanism exists. | `ndn-ndnsf` runtime (memory-local by default). | ⛔ gates `ndn-ndnsf` |

### State properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-S1 | `pendingRequests`/`pendingProviderTokens` are eventually cleaned. | `ndn-ndnsf` runtime (bounded-state, TTL cleanup). | ⛔ gates `ndn-ndnsf` |
| NSF-S2 | Successful coordination removes provider pending state immediately. | `ndn-ndnsf`. | ⛔ gates `ndn-ndnsf` |
| NSF-S3 | Timeout cleanup does not remove an active request before normal coordination can arrive. | `ndn-ndnsf`. | ⛔ gates `ndn-ndnsf` |
| NSF-S4 | Cleanup firing after successful completion is a no-op. | `ndn-ndnsf`. | ⛔ gates `ndn-ndnsf` |
| NSF-S5 | Repeated cleanup cycles do not grow pending state without bound. | `ndn-ndnsf` (engine has bounded-state precedents: PIT, `ReplayGuard` LRU). | ⛔ gates `ndn-ndnsf` |

### Failure properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-F1 | Validator failures invoke an explicit failure callback exactly once. | `ndn-nacabe` consumer. | ⛔ gates `ndn-nacabe` |
| NSF-F2 | Validator failures log the failed name and reason. | `tracing` in the consumer path. | ⛔ gates `ndn-nacabe` |
| NSF-F3 | Decryption failures do not mutate request/permission/token/completion state and reveal no plaintext. | `ndn-security::confidentiality`: `ContentKey::open` returns `Err` and yields nothing on wrong key / AAD / tamper. | ✅ `nsf_f3_decryption_failure_yields_no_plaintext` |
| NSF-F4 | Malformed payloads do not mutate state. | primitives reject at decode: `Capability::decode` / `Sealed::from_bytes` return `Err` (no partial state). | ✅ `nsf_f4_malformed_payload_rejected_at_decode` |
| NSF-F5 | Negative paths fail closed: no permission install, no token consumption, no request execution, no final-response publication. | doctrine; primitive level proven (CK/capability fail closed), protocol level in `ndn-nacabe`/`ndn-ndnsf`. | ✅ primitive part `nsf_f5_primitives_fail_closed`; ⛔ protocol part gates layers |

## Porting assumptions (must be re-stated where the compat layer enforces them)

- Trust schemas encode acceptable controller and runtime signing authorities (NSF-A2/A3).
- The Permission-Controller identity is the name prefix before `/NDNSF` in discovery Interests (NSF-A2).
- Provider pending state is memory-local; restart discards unselected pending tokens (NSF-T6).
- The default pending-token TTL is long enough for normal ACK collection/selection (NSF-T2/S3).
- The ABE library reports validation/decryption failures **without mutating** NDNSF state (NSF-F3) — in ndn-rs, `ndn-security::abe`/`confidentiality` are pure transforms, so this holds by construction.

## Known limitations (carried over)

- Test-only instrumentation counters are not production metrics.
- Cleanup TTL is fixed at the runtime default unless configuration is added.
- Stress coverage is deterministic, local-unit; not a substitute for multi-process/soak testing — a gap to close with a testbed multi-node witness for `ndn-ndnsf`.
