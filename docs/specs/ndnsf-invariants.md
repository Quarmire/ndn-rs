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
| NSF-A3 | `ACK`/`COORDINATION`/`RESPONSE` pass trust validation **and** NAC-ABE authorization before their payloads affect runtime state. | **Authorization:** `ndn-ndnsf::access` NAC-seals payloads under the service's KP-ABE attributes; only a satisfying `ServiceController`-issued key decrypts (unauthorized fails closed). **Trust validation:** `ndn-ndnsf::trust::TrustCtx` (a node's outbound `Signer` + inbound `Validator`) is threaded through every leg of `ndn-ndnsf::driver` — each REQUEST/ACK/SELECTION/RESPONSE is published as a signed Data (`seal`) and verified on receipt (`unseal` → `verify_message`: signature valid against the anchors **and** signer under the phase's expected sender); a message that fails either check never affects state (fail closed). The default empty `TrustCtx` is the unsigned fast path. | ✅ authorization (`secure_four_phase_over_svs`); ✅ trust wired end-to-end (`trust_validated_four_phase`: signed exchange between trusting peers round-trips; a REQUEST from a requester the provider does not trust fails closed — no ACK/RESPONSE) + `trust` unit tests (valid-accepted, wrong-sender/untrusted-signer/tampered rejected). *Substrate note: `SvsPubSub::join_secured` + the `IngestValidator` seam (bridged by `trust::publisher_signer`/`ingest_validator`) is the orthogonal durable-**store** trust path — it gates ingest/repo persistence, not pub/sub delivery, so message trust lives in the flow per above.* |
| NSF-A4 | Permission-discovery Interests may be unsigned; the returned **Data** is the authenticated object. | `ndn-nacabe::ParamFetcher` — discovery (`fetch_public_params`) expresses an *unsigned* Interest and trusts only the validated response (`verified_content` against the AA anchor); matches NDN's data-centric trust. | ✅ `unsigned_discovery_returns_authenticated_params` |

### Token properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-T1 | `ProviderToken` is one-time use. | `ndn-ndnsf::tokens` — `consume` removes the token. | ✅ `nsf_t1_t3_token_is_single_use` |
| NSF-T2 | `ProviderToken` expires after its pending-state TTL. | `ndn-ndnsf::tokens` TTL; v2 capability `not_after`. | ✅ `nsf_t4_expired_token_rejected` + `nsf_t2_capability_expires_after_window` |
| NSF-T3 | Replaying a token after successful coordination fails. | `ndn-ndnsf::tokens` — consumed tokens are gone. | ✅ `nsf_t1_t3_token_is_single_use` |
| NSF-T4 | Using an expired token fails. | `ndn-ndnsf::tokens` TTL; capability window. | ✅ `nsf_t4_expired_token_rejected` |
| NSF-T5 | An unknown/random token fails. | `ndn-ndnsf::tokens`; capability grantee binding. | ✅ `nsf_t5_unknown_token_rejected` (+ `nsf_t5_unknown_grantee_rejected`) |
| NSF-T6 | A provider restart before coordination does not preserve pending token state unless an explicit, audited persistence mechanism exists. | `ndn-ndnsf::tokens` is memory-local. | ✅ `nsf_t6_restart_drops_pending_state` |

### State properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-S1 | `pendingRequests`/`pendingProviderTokens` are eventually cleaned. | `ndn-ndnsf::tokens` `cleanup_expired`. | ✅ `nsf_s1_cleanup_reaps_expired` |
| NSF-S2 | Successful coordination removes provider pending state immediately. | `ndn-ndnsf::tokens` `consume` removes. | ✅ `nsf_s2_success_removes_pending_immediately` |
| NSF-S3 | Timeout cleanup does not remove an active request before normal coordination can arrive. | `ndn-ndnsf::tokens` only reaps past-TTL entries. | ✅ `nsf_s3_cleanup_spares_active_tokens` |
| NSF-S4 | Cleanup firing after successful completion is a no-op. | `ndn-ndnsf::tokens` cleanup is idempotent. | ✅ `nsf_s4_s5_cleanup_idempotent_and_bounded` |
| NSF-S5 | Repeated cleanup cycles do not grow pending state without bound. | `ndn-ndnsf::tokens` cleanup is idempotent. | ✅ `nsf_s4_s5_cleanup_idempotent_and_bounded` |

### Failure properties

| ID | Invariant | Enforced in (ndn-rs) | Witness / status |
|---|---|---|---|
| NSF-F1 | Validator failures invoke an explicit failure callback exactly once. | `ndn-nacabe::ParamFetcher::with_failure_callback` — `verified_content`'s failure branch invokes the registered `ValidationFailureHook` once per failed response, then fails closed. | ✅ `validation_failure_fires_callback_once_with_name_and_reason` |
| NSF-F2 | Validator failures log the failed name and reason. | `ndn-nacabe::ParamFetcher` — `verified_content` emits `tracing::warn!(name, reason)` on every failure (reason from the `ValidationResult::Invalid` `TrustError` / `Pending`); the same `(name, reason)` is passed to the F1 callback. | ✅ `validation_failure_fires_callback_once_with_name_and_reason` (asserts the failed name + non-empty reason reach the hook) |
| NSF-F3 | Decryption failures do not mutate request/permission/token/completion state and reveal no plaintext. | `ndn-security::confidentiality`: `ContentKey::open` returns `Err` and yields nothing on wrong key / AAD / tamper. | ✅ `nsf_f3_decryption_failure_yields_no_plaintext` |
| NSF-F4 | Malformed payloads do not mutate state. | primitives reject at decode: `Capability::decode` / `Sealed::from_bytes` return `Err` (no partial state). | ✅ `nsf_f4_malformed_payload_rejected_at_decode` |
| NSF-F5 | Negative paths fail closed: no permission install, no token consumption, no request execution, no final-response publication. | doctrine; primitive level (CK/capability fail closed) + protocol level across `ndn-nacabe`/`ndn-ndnsf`: unauthorized ABE key installs no plaintext permission; an untrusted message yields no ACK/RESPONSE; a bogus/spent token consumes nothing and runs no request. | ✅ primitive part `nsf_f5_primitives_fail_closed`; ✅ protocol part — no permission install (`secure_four_phase_over_svs`: unauthorized key fails closed), no request execution / no final response (`trust_validated_four_phase`: untrusted requester → no ACK/RESPONSE), no token consumption (`targeted_over_svs`: bogus token → no response) |

## Porting assumptions (must be re-stated where the compat layer enforces them)

- Trust schemas encode acceptable controller and runtime signing authorities (NSF-A2/A3).
- The Permission-Controller identity is the name prefix before `/NDNSF` in discovery Interests (NSF-A2).
- Provider pending state is memory-local; restart discards unselected pending tokens (NSF-T6).
- The default pending-token TTL is long enough for normal ACK collection/selection (NSF-T2/S3).
- The ABE library reports validation/decryption failures **without mutating** NDNSF state (NSF-F3) — in ndn-rs, `ndn-security::abe`/`confidentiality` are pure transforms, so this holds by construction.

## 2026-08 wire refresh (compact SELECTION) — invariant notes

The compact (unified V2) SELECTION replaces the plaintext token in the shared
selection payload with a provider-bound **token-proof hash**
(`messages::selection_token_proof_hash`). The T/S invariants carry over
unchanged to the proof-hash consume path (`PendingProviderTokens::consume_where`
/ `ProviderEngine::consume_selection_compact`), witnessed by:

| Invariant | Compact-path witness |
|---|---|
| NSF-T1/T3 single-use, replay fails | ✅ `flow::tests::compact_selection_happy_path_and_replay` |
| NSF-T5 unknown (forged/empty hash) fails closed, nothing consumed | ✅ `flow::tests::compact_selection_empty_or_forged_hash_fails_closed` |
| SEC-03 requester binding (a hash cannot be redeemed by another verified identity, and the failed attempt does not burn the token) | ✅ `flow::tests::compact_selection_wrong_requester_cannot_redeem` |
| Inbound legacy shape still served (upstream accept-old-emit-new posture) | ✅ `tests/compact_selection_compat.rs::legacy_selection_shape_still_accepted` |
| Spec-044 negative ACK: no token issued, nothing pending, user early-stops | ✅ `tests/compact_selection_compat.rs::negative_ack_early_stops_call` |

Strengthening over the audited baseline: the plaintext provider token no longer
crosses the shared medium at selection time — it travels only in the issuing
ACK (whose payload the full-security configuration NAC-seals) and is thereafter
proven by hash. This narrows the read-the-token exposure that SEC-03 previously
only made unredeemable; it does not remove the ACK leg.

## Known limitations (carried over)

- Test-only instrumentation counters are not production metrics.
- Cleanup TTL is fixed at the runtime default unless configuration is added.
- Stress coverage is deterministic, local-unit; not a substitute for multi-process/soak testing — a gap to close with a testbed multi-node witness for `ndn-ndnsf`.
