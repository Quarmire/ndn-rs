# Expected Failures

Tests in `testbed/tests/audit/` are tagged here with their current
expected outcome. Any PR that changes a row — especially flipping
a test from `EXPECTED-FAIL` to `RESOLVED` — must attach the
before/after transcripts to the PR description.

## Status legend

- **EXPECTED-FAIL** — the test is currently expected to fail; this
  matches an unresolved BLOCKER or MAJOR finding from the audit.
- **RESOLVED** — the fix has landed, the test passes.
- **BLOCKED-BY-INTEROP** — the test cannot be run yet because an
  upstream peer is not yet available in the container (NLSR,
  ACME, etc.).
- **NOT-WITNESSABLE** — a feature-absence finding that has no
  corresponding observable packet event (e.g. "NLSR missing"
  cannot produce a failing test — it's the absence of a
  protocol).

Last reviewed: 2026-05-01 (cross-reference pass; see
`docs/notes/spec-compliance-cross-reference-2026-05-01.md` for the
ndn-cxx / NFD / ndnd / ndn-svs source-line citations and the
reverification recipe per finding). No interop run has been executed
against these scripts yet — the statuses below remain predictions, not
measurements. When the harness is first run, update the "Last seen"
column with the date and container digest.

The 2026-05-01 cross-reference also retracted four findings (A.17,
C.04, B.03, B.04) and added thirteen new entries (N.01–N.14); the
new rows appear below under the appropriate severity tiers.

## BLOCKER

| Finding | Witness test | Status | Predicted failure | Last seen |
|---------|------|--------|----|-|
| A.01 | `a01_blake3_name_component.sh` | RESOLVED 2026-05-01 | BLAKE3_DIGEST 0x03 surface removed: tlv constant, NameComponent helpers, Name helpers, Display alt-form, ZoneKey + zone-bound DID surface all extracted. Witness flipped to GREP-PROOF; before/after transcripts at `testbed/tests/audit/transcripts/a01_{before,after}.txt`. | 2026-05-01 (grep witness) |
| A.09 | `a09_signed_interest_verify.sh` | RESOLVED (code-level; interop witness pending helper binary) | Fix landed 2026-05-01; unit regression test `interest_builder_sign_sync_signed_region_matches_extractor` in ndn-packet asserts sign/extract agreement. Interop helper (`ndn-rs-emit-signed-interest`) still needs to be added to unblock the testclient-side witness. | code test added 2026-05-01 |
| B.01 | `b01_reliability_txsequence.sh` | RESOLVED 2026-05-01 | encoder writes `TxSequence` (0x0348), decoder + ack-extractor read `0x0348`, reliability layer keys `unacked` on TxSequence; witness flipped to RUST-UNIT (`b01_b09_reliable_wire_uses_tx_sequence` + `b01_b09_fragmented_reliable_carries_both_sequences`). Before/after transcripts at `testbed/tests/audit/transcripts/b01_{before,after}.txt`. | 2026-05-01 (rust-unit witness) |
| B.09 | rolled into `b01_reliability_txsequence.sh` | RESOLVED 2026-05-01 | fragmented frames now carry both `Sequence` (0x51) shared across fragments and per-LP `TxSequence` (0x0348); `LpReliability` splits `next_seq` (network-packet) from `next_tx_seq` (per-LP). | 2026-05-01 |
| C.01 | `c01_ecdsa_verify.sh` | RESOLVED 2026-05-01 (architecture; RSA/ECDSA crypto deferred) | Validator now dispatches via `verify_by_sig_type` per `SignatureType`. DigestSha256, Ed25519, HmacSha256, Blake3-plain, Blake3-keyed all wired. RSA / ECDSA surface as `UnsupportedSignatureType` (explicit, not `Invalid`) per the audit's recommendation 3 — concrete crypto is deferred to a follow-up. Witness rewritten as RUST-UNIT covering c01_/c02_/c03_ dispatch tests. Before/after transcripts at `testbed/tests/audit/transcripts/c01_ecdsa_verify_{before,after}.txt`. | 2026-05-01 |
| C.07 | `c07_cert_naming.sh` | RESOLVED 2026-05-01 | KeyChain ephemeral now produces cert names ending `/KEY/<keyid>/<issuer>/<version>` per ndn-cxx Certificate::isValidName. Witness: RUST-UNIT in `ndn-security` integration tests/cert_format.rs. Before/after transcripts at `testbed/tests/audit/transcripts/c07_{before,after}.txt`. | 2026-05-01 |
| C.08 | `c08_cert_content.sh` | RESOLVED 2026-05-01 | cert Content body is DER SubjectPublicKeyInfo (44-byte Ed25519 envelope per RFC 8410); `encode_cert_data` wraps via `ndn_security::spki::wrap_ed25519`; `Certificate::decode` unwraps. Before/after transcripts at `testbed/tests/audit/transcripts/c08_{before,after}.txt`. | 2026-05-01 |
| C.13 | `c13_ndncert_challenge_tlv.sh` | RESOLVED 2026-05-01 (encoder side, RUST-UNIT) | CHALLENGE plaintext is now TLV-encoded ParameterKey (0x85) / ParameterValue (0x87) pairs per NDNCERT 0.3 §2.4.3. Both `EnrollmentSession::challenge_request_body` and `CertAuthority::handle_challenge` use the new `encode_challenge_parameters` / `decode_challenge_parameters` codec in `tlv.rs`. The interop leg of this finding (running against `ndncert-ca-server`) is still BLOCKED-BY-INTEROP until that image lands in the testclient container. Before/after transcripts at `testbed/tests/audit/transcripts/c13_ndncert_challenge_tlv_{before,after}.txt`. | 2026-05-01 (encoder rust-unit) |
| C.18 | `c18_validity_period_iso8601.sh` | RESOLVED 2026-05-01 | NotBefore/NotAfter are 15-byte ASCII `YYYYMMDDTHHMMSS` strings per ndn-cxx ISO_DATETIME_SIZE=15; ValidityPeriod relocated from Content to SignatureInfo. New `ndn_security::iso8601` helper. Before/after transcripts at `testbed/tests/audit/transcripts/c18_{before,after}.txt`. | 2026-05-01 |
| D.01 | `d01_hoplimit_decrement.sh` | RESOLVED 2026-05-01 (RUST-UNIT; tcpdump verification still BLOCKED-BY-INTEROP) | New `ndn_packet::interest::decrement_hop_limit` rewrites the HopLimit byte in-place; `TlvDecodeStage::decode_interest` now decrements after the zero-check per NFD `daemon/fw/forwarder.cpp:104-111`. Witness covers helper-level + decode-stage tests. Before/after transcripts at `testbed/tests/audit/transcripts/d01_hoplimit_decrement_{before,after}.txt`. | 2026-05-01 |
| E.04 | `e04_dataset_segmentation.sh` | RESOLVED 2026-05-01 (RUST-UNIT; `nfdc` interop still BLOCKED-BY-INTEROP) | `send_dataset` now wraps the response into versioned segments via `build_segmented_dataset` per ndn-cxx `mgmt/status-dataset-context.cpp` (`<base>/v=<v>/seg=<n>`, `MAX_DATASET_PAYLOAD_LEN = 8000`, FinalBlockId on the last segment). Witness runs `cargo test -p ndn-fwd --bin ndn-fwd e04_`. Before/after transcripts at `testbed/tests/audit/transcripts/e04_dataset_segmentation_{before,after}.txt`. | 2026-05-01 |
| N.01 | `n01_fragcount_dos.sh` | RESOLVED 2026-05-01 | New `MAX_FRAGMENTS = 400` cap in `ReassemblyBuffer::process` rejects oversized FragCount before any allocation, matching NFD `daemon/face/lp-reassembler.hpp:52-56` (`nMaxFragments = 400`). Two RUST-UNIT tests cover the cap and the at-limit case. Before/after transcripts at `testbed/tests/audit/transcripts/n01_fragcount_dos_{before,after}.txt`. | 2026-05-01 |
| E.01 | `e01_mgmt_unauth.sh` | RESOLVED 2026-05-01 (architecture; default-on flip + trust anchors deferred) | New `authorize_command` gate in `mgmt_ndn.rs` rejects unsigned commands when `MgmtHandles::require_signed_commands=true`; the gate uses `Validator::validate_interest` (audit C.11). Architecture wired; default is still off so existing deployments keep dispatching unsigned commands until operators populate trust anchors and flip the flag. Witness rolled with C.11. Before/after transcripts at `testbed/tests/audit/transcripts/e01_mgmt_unauth_{before,after}.txt`. | 2026-05-01 |
| G.03 | `g03_psync_interop.sh` | RESOLVED 2026-05-01 (architecture; live PSync interop still BLOCKED-BY-INTEROP) | IBF cell-selection and `keyCheck` now use `MurmurHash3_x86_32` per PSync `detail/util.cpp::murmurHash3` with `N_HASH=3` and `N_HASHCHECK=11`. Witness rewritten as RUST-UNIT (Murmur3 canonical vectors + IBF dispatch). The remaining wire-format gap (PSync uses `uint32_t` keys; ndn-rs IBF stores `u64`) plus the IBF TLV envelope and segmented Sync Data flow still block live interop with the PSync C++ peer. Before/after transcripts at `testbed/tests/audit/transcripts/g03_psync_interop_{before,after}.txt`. | 2026-05-01 (architecture) |

## MAJOR

| Finding | Witness test | Status | Predicted failure | Last seen |
|---------|------|--------|----|-|
| A.02 / A.21 | `a02_psdc_structural.sh` | RESOLVED 2026-05-02 | `Interest::decode` now calls a new `validate_psdc_structure` after `Name::decode` and a forked-reader `body_has_app_params` scan; rejects (i) AppParams without PSDC, (ii) PSDC not at the last position, (iii) more than one PSDC. Mirrors ndn-cxx `interest.cpp:171-173,303,692-710` and ndnd `spec_2022/spec.go:513-518`. Witness: RUST-UNIT covering all three shapes. Before/after transcripts at `testbed/tests/audit/transcripts/a02_psdc_structural_{before,after}.txt`. | 2026-05-01 (rust-unit witness) |
| A.03 / A.04 / N.04 | `a03_unknown_critical_tlv.sh` | RESOLVED 2026-05-02 | New body-level structural pass at `Interest::decode` (`validate_interest_body_structure`) and `Data::decode` (`validate_data_body_structure`) tracks a `last_element` cursor (rejects out-of-order or duplicate spec elements per `interest.html` / `data.html`) and rejects unknown critical TLV-TYPEs via the new `is_critical_tlv_type` helper. `MetaInfo::decode` and `SignatureInfo::decode` got the same critical-bit gate. Mirrors ndn-cxx `interest.cpp:171-173,183-300`, `data.cpp:182`, `signature-info.cpp:158`. Witness: 10 RUST-UNIT tests covering A.03 / A.04 in Interest+Data, N.04 in MetaInfo/SignatureInfo, plus non-critical-unknown sanity checks. Before/after transcripts at `testbed/tests/audit/transcripts/a03_unknown_critical_tlv_{before,after}.txt`. | 2026-05-02 (rust-unit witness) |
| A.10 | `a10_databuilder_build_sig.sh` | RESOLVED 2026-05-01 | `DataBuilder::build()` now routes through the existing `sign_digest_sha256()` fast path so `SignatureValue` is the real `SHA-256(signed region)` per NDN Packet Format §6.3.2. Witness: RUST-UNIT `a10_databuilder_build_emits_real_sha256` in ndn-packet. Before/after transcripts at `testbed/tests/audit/transcripts/a10_databuilder_build_sig_{before,after}.txt`. | 2026-05-01 (rust-unit witness) |
| A.15 | `a15_keylocator_rules.sh` | EXPECTED-FAIL | Ed25519 Data without KeyLocator accepted by ndn-rs, rejected by ndn-cxx | not yet run |
| C.02 | rolled into `c01_ecdsa_verify.sh` | RESOLVED 2026-05-01 | `HmacSha256Verifier` added; reachable via `verify_by_sig_type` for SignatureType code 4. | 2026-05-01 |
| C.03 | rolled into `c01_ecdsa_verify.sh` | RESOLVED 2026-05-01 | `DigestSha256Verifier` added; reachable on the basic `Validator::validate` path (no KeyLocator required). | 2026-05-01 |
| C.06 | `c06_keychain_sigtype_label.sh` | RESOLVED 2026-05-02 | `KeyChain::sign_data` / `sign_interest` now pass `signer.sig_type()` (rather than the hardcoded `SignatureEd25519`) into `DataBuilder::sign_sync` / `InterestBuilder::sign_sync`. New `SecurityManager::install_signer` opens the path for non-Ed25519 signers (HMAC, BLAKE3, YubiKey). Witness: RUST-UNIT pair in `ndn-security` (`c06_sign_data_uses_signer_sigtype_hmac`, `c06_sign_interest_uses_signer_sigtype_hmac`). Sub-fix in the same pass: `SignatureInfo::decode` recognises `ValidityPeriod` (TLV 0xFD, critical) so cert wires don't fail the N.04 strict-criticality gate. Before/after transcripts at `testbed/tests/audit/transcripts/c06_keychain_sigtype_label_{before,after}.txt`. | 2026-05-02 (rust-unit witness) |
| C.11 | rolled into `e01_mgmt_unauth.sh` | RESOLVED 2026-05-01 | New `Validator::validate_interest` returns the new `InterestValidationOutcome` (Valid / Invalid / Pending) using `verify_by_sig_type`. Two cargo tests in `ndn-security` cover signed-Valid + unsigned-Invalid. | 2026-05-01 |
| C.14 | `c14_ndncert_error_names.sh` | EXPECTED-FAIL | NDNCERT ErrorCode names (`BadInterest`/`InvalidSignature`) diverge from spec (`BadInterestFormat`/`BadSignature`) — numbers OK | not yet run |
| D.02 | `d02_localhop_scope.sh` | RESOLVED 2026-05-01 (RUST-UNIT + GREP-PROOF; live interop still BLOCKED-BY-INTEROP) | New `is_localhop_name` helper in `decode.rs`; `check_scope` drops `/localhop` Interests received on a non-local face. The drop is conservatively wider than NFD's outbound-only `wouldViolateScope` check (refinement to "permit if a local consumer exists" tracked as follow-up). Before/after transcripts at `testbed/tests/audit/transcripts/d02_localhop_scope_{before,after}.txt`. | 2026-05-01 |
| D.03 | `d03_nexthop_faceid.sh` | EXPECTED-FAIL | Interest with `NextHopFaceId` LP header goes through strategy LPM instead of to the named face | not yet run |
| D.04 | `d04_pit_aggregation_selectors.sh` | EXPECTED-FAIL | Two Interests for the same Name with different selectors produce two PIT entries, leading to double upstream forward | not yet run |
| D.07 | `d07_pit_token_echo.sh` | EXPECTED-FAIL | Data response to a PitToken-tagged Interest lacks the echoed token | not yet run |
| D.09 | `d09_bestroute_nack_retry.sh` | EXPECTED-FAIL | On nexthop-1 Nack, ndn-rs does not retry nexthop-2; propagates Nack immediately | not yet run |
| D.10 | `d10_strategy_name_version.sh` | EXPECTED-FAIL | BestRouteStrategy::strategy_name() last component is not a Version (TLV 0x36); NFD `nfdc` rejects | not yet run |
| D.13 | `d13_localhost_unvalidated.sh` | RESOLVED 2026-05-01 (RUST-UNIT + GREP-PROOF; live forgery interop still BLOCKED-BY-INTEROP) | The blanket `/localhost` skip is removed from `validation.rs`; /localhost Data goes through the same chain walk as any other Data. Mgmt responses use DigestSha256 today (covered by the C.01/C.03 verifier dispatch). Before/after transcripts at `testbed/tests/audit/transcripts/d13_localhost_unvalidated_{before,after}.txt`. | 2026-05-01 |
| E.03 | `e03_extended_modules_unsigned.sh` | EXPECTED-FAIL | `/localhost/nfd/security/*` and other ndn-rs-extended modules accept commands without auth | not yet run |
| F.01 | `f01_ipv6_faceuri.sh` | EXPECTED-FAIL | IPv6 peer Face reports `udp4://[…]`, rejected by NFD FaceUri parser | not yet run |
| F.03 | `f03_faceuri_schemes.sh` | EXPECTED-FAIL | TCP face emits `tcp://`, should be `tcp4://`/`tcp6://` | not yet run |
| F.06 | `f06_websocket_uri.sh` | EXPECTED-FAIL | WS face emits `ws://` regardless of direction; spec uses `wsclient`/`wsserver`/`wss` | not yet run |
| G.02 | `g02_svs_typed_components.sh` | EXPECTED-FAIL | Two NodeIDs with identical wire bytes but different URI strings produce 2 state-map entries | not yet run |
| G.06 | `g06_swim_vs_autoconfig.sh` | BLOCKED-BY-INTEROP | needs ndn-autoconfig-server peer; ndn-rs hello/gossip is SWIM, not AutoConfig PROBE | not yet run |
| G.09 | `g09_prefix_announcement_consume.sh` | EXPECTED-FAIL | LP `PrefixAnnouncement` decoded into LpPacket but no strategy reads it (no self-learning) | not yet run |
| N.02 | `n02_lp_reassembly_collision.sh` | EXPECTED-FAIL | Two peers with same Sequence on a multi-access face overwrite each other's partials | not yet run |
| N.03 | `n03_lp_header_order.sh` | EXPECTED-FAIL | LpPacket with duplicate IncomingFaceId or unsorted headers accepted; ndn-cxx rejects | not yet run |
| N.04 | rolled into `a03_unknown_critical_tlv.sh` | RESOLVED 2026-05-02 | Unknown critical TLV inside MetaInfo / SignatureInfo body now triggers `MalformedPacket` via the shared `is_critical_tlv_type` gate added in the same A.03/A.04 pass. See A.03 / A.04 / N.04 row above for detail. | 2026-05-02 (rust-unit witness) |
| N.05 | `n05_nack_no_reason.sh` | EXPECTED-FAIL | Nack header without NackReason decodes as `Other(0)` instead of `None` | not yet run |
| N.06 | `n06_dead_nonce_list.sh` | EXPECTED-FAIL | Re-entered Interest with recently-used nonce after PIT erasure not detected as loop (no DNL) | not yet run |
| N.07 | rolled into `d13_localhost_unvalidated.sh` | RESOLVED 2026-05-01 | The decode-stage `check_scope` already covered Data (it keys on `ctx.name`, not packet kind); the audit's "ingress check missing for Data" claim was outdated. RUST-UNIT `n07_is_localhost_name_recognises_prefix` confirms the helper. | 2026-05-01 |
| N.10 | `n10_command_replay.sh` | EXPECTED-FAIL (depends on E.01 fix) | Captured signed command replays accepted indefinitely; no SignatureTime window | not yet run |
| N.11 | `n11_control_param_binding.sh` | EXPECTED-FAIL (depends on E.01) | ControlParameters in AppParams without matching PSDC dispatched | not yet run |
| N.12 | `n12_mgmt_response_signing.sh` | EXPECTED-FAIL (depends on C.07/C.08 fix) | All control responses use DigestSha256; ndn-cxx `nfd::Controller` with trust schema rejects | not yet run |
| N.13 | `n13_cert_serialize_tlv.sh` | RESOLVED 2026-05-01 | `serialize_cert` reconstitutes the cert as a real NDN Data TLV from `signed_region`+`sig_value`; `deserialize_cert` parses Data and calls `Certificate::decode`. `SecurityManager::issue_self_signed` and `certify` now populate the wire bytes. Before/after transcripts at `testbed/tests/audit/transcripts/n13_{before,after}.txt`. | 2026-05-01 |

## NOT-WITNESSABLE

| Finding | Severity | Reason | Reference |
|---------|-|-|-|
| G.04 | MAJOR | NLSR absence cannot be exercised via a packet exchange — the feature simply isn't there. Track as a roadmap item, not a test. | audit §G.04 |
| C.16 | MAJOR | LVS user functions fail silently open — the failure is semantic, not observable as a wire event. Needs a dedicated LVS unit test. | audit §C.16 |
| E.05 | MAJOR | Notification streams missing; witness must show absence (no `/localhost/nfd/<module>/notifications` producer). Use a GREP-PROOF instead of a wire test. | cross-ref §E.05 |
| N.08 | MINOR | No unsolicited-Data policy hook; absence test, not wire-observable. | cross-ref §N.08 |
| N.09 | MINOR | Ad-hoc/multi-access link-type Nack handling missing; semantic gap. | cross-ref §N.09 |
| N.14 | MINOR | `add_trust_anchor` skips validity-period check; RUST-UNIT only (no wire path). | cross-ref §N.14 |

## RETRACTED 2026-05-01

The following findings from the 2026-04-20 audit were **withdrawn**
during the cross-reference pass against the on-disk reference
implementations. Do not author witness tests for these. The audit
document should be updated to mark them retracted (with the citation
below as the reason). Removed rows are kept here for traceability.

| Finding | Original severity | Reason for retraction | Citation |
|---------|-------------------|-----------------------|----------|
| A.17 | MAJOR | BLAKE3 SignatureType codes 6 and 7 are now officially registered on the NDN TLV registry (yoursunny). ndn-rs wire is fine; only stale comments remain. | `redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType` |
| C.04 | MAJOR | Same as A.17. | same |
| B.03 | MINOR | ndn-cxx `lp/packet.cpp:107-110` also accepts a top-level Interest/Data inside an LpPacket as the implicit fragment. Standard tolerance, not an ndn-rs deviation. | ndn-cxx `lp/packet.cpp` |
| B.04 | MINOR | PitToken 1-32 byte bound IS the spec; ndn-cxx `lp/pit-token.cpp:28-37` defines `LENGTH_MIN=1`, `LENGTH_MAX=32`. ndn-rs matches. | ndn-cxx `lp/pit-token.cpp` |

## When to add a row here

Every new test added under `tests/audit/` must appear in this
file with its expected status. Removing a row means either:

- the finding was resolved (move to "RESOLVED" and note the
  commit and date of the last-seen pass); or
- the finding was retracted after further spec reading (document
  the retraction in the audit document too).
