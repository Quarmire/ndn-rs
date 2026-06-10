# Spec compliance

ndn-rs's compliance with the NDN Packet Specification and the
NDNCERT specification is tracked by live witness scripts under
`testbed/tests/audit/` that exit non-zero when a compliance claim
regresses. This page summarises which areas are covered.

The live source of truth is `testbed/EXPECTED_FAILURES.md`. This page
is a reader-facing map to the witnesses, not a substitute for the
tracker. A feature is release-ready only when the corresponding
witness passes or the tracker explains why the remaining work is out
of scope.

## Coverage areas

| Area | Spec source | Audit section | Witness prefix |
|---|---|---|---|
| Name and component types | Packet spec §2 (Name) | A.01 – A.04 | `a*_blake3_*`, `a19_a20_uri_*` |
| Interest TLV | Packet spec §3 | A.05 – A.08 | `a05_a18_tlv_strictness` |
| Data TLV | Packet spec §4 | A.09 – A.16 | `a10_databuilder_build_sig` |
| Signature types | Packet spec §5 | A.16, A.17, BLAKE3 | `a16_signature_value_length`, `a17_blake3_registered` |
| KeyLocator rules | Packet spec §5.5 | A.15 | `a15_keylocator_rules` |
| LP TLV (NDNLPv2) | LP spec | A.11, A.12 | `a11_nack_reason_documented`, `a12_nack_lp_only` |
| LP IncomingFaceId / LocalFields | NDNLPv2 §local fields | X.02 | `x02_incoming_face_id_local_fields` |
| Nonce length | Packet spec §3 | A.13 | `a13_nonce_length_rejected` |
| FinalBlockId / UriComponent | Naming convention | A.19, A.20 | `a19_a20_uri_finalblockid` |
| Signed Interests | Packet spec §3 (signed) | A.09 | `a09_signed_interest_verify` |
| Persistent-state Interest | Persistent Interest design | (interop) | `persistent_interest_*` |
| NDNCERT issued cert | NDNCERT spec | C.07, C.08, C.18, N.13 | `acme_dns01.sh`, `cert_*` |
| Architectural cleanup | Phase 2 ARCH-1..20 | (ARCH-N) | `arch*` (per-item witnesses) |
| Tiered API surface | Phase 3 §3 | tier docs | `phase3_*` |

The `testbed/tests/audit/*.sh` scripts are the runnable witnesses;
each exits non-zero when the claim it tracks regresses.

As of the 2026-05-28 release-readiness pass, the tracker-driven audit
harness runs every script named by `testbed/EXPECTED_FAILURES.md` and
reports 54 PASS / 0 FAIL / 0 SKIP. The report for that local pass was
captured in
`testbed/tests/audit/transcripts/release_audit_run_all_after.txt`; the
important release signal is zero divergences from the tracker.

Grep-only checks are not release-quality proof for protocol behavior. They
may guard documentation wording, removed APIs, or source inventory, but packet,
security, forwarding, and management claims need a `RUST-UNIT`, `RUST-INTEG`,
`INTEROP-SCRIPT`, or `WIRE-CAPTURE` witness before this page should describe
them as complete.

## Reading the witnesses

Each witness is a shell script with exit-code semantics:

- `0` — finding passes / claim holds.
- `1` — finding fails / claim regressed; the script prints the
  exact diagnostic.
- `2` — live interop precondition is missing; Rust/local witnesses
  may have passed, but the Docker leg did not run.

```sh
# Run a single witness:
bash testbed/tests/audit/a17_blake3_registered.sh ; echo exit=$?

# Run every release-tracked audit witness:
RESULTS_DIR=/tmp/ndn-audit-results bash testbed/tests/audit/run_all.sh
```

The audit harness scaffold is `testbed/tests/audit/_template.sh`;
new findings follow the same shape (project memory
`feedback_witness_first_compliance`).

## Cross-impl on-disk references

Per project memory `feedback_cross_reference_standard`, every
audit finding cites the source implementation it tracks against
the upstream NDN reference implementations cloned on disk. The
references live alongside each witness script's `# Finding:`
header comment.

## Recently closed blockers

These audit rows were release blockers in the pre-v0.1 tracker and now
have passing behavioral or live witnesses:

| Finding | Witness | Resolution |
|---|---|---|
| A.09 | `a09_signed_interest_verify.sh` | Signed Interest signer bytes are checked against the decoded final-wire `Interest::signed_region()`, and KeyChain-signed Interests verify against that region. |
| A.15 | `a15_keylocator_rules.sh` | KeyLocator presence/absence is enforced by SignatureType and surfaced by outer packet decoders. |
| C.01 | `c01_rsa_ecdsa_verifiers.sh` | RSA-SHA256 and ECDSA-SHA256 now have behavioral verifier witnesses for valid signature, wrong signature, malformed key, and validator dispatch. |
| C.09 | `c09_safebag_ndnsec_interop.sh` | SafeBag portability is now witnessed through reference `ndnsec`: ndn-rs exports an ECDSA-P256 SafeBag, ndnsec imports/re-exports it, and ndn-rs decrypts and verifies the returned SafeBag. SafeBag encryption now uses the ndn-cxx-compatible PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC profile. |
| C.12 | `c12_mgmt_sign_digest.sh`, `c12_mgmt_sign_key.sh`, `c12_mgmt_dataset_fresh.sh` | MgmtClient command Interests are decoded and checked for DigestSha256 over the spec signed region; the key-backed script now registers a signed route against Docker NFD and verifies it with `nfdc route list`. Dataset queries now set CanBePrefix+MustBeFresh, and the follow-up witness proves `ndn-ctl route rib-list` sees a freshly registered NFD route instead of stale cached dataset Data. |
| C.13 | `c13_ndncert_challenge_tlv.sh`, `c13_ndncert_live_interop.sh` | NDNCERT CHALLENGE parameters use TLV `ParameterKey`/`ParameterValue`, and the live witness enrolls against upstream `ndncert-ca-server`, completes the PIN challenge, fetches the issued Certificate v2 Data, decodes it with ndn-rs, and checks the issuer chain prefix. |
| Validator config | `validator_config_behavior.sh` | The configuration-validator release claim is now behavioral: ordered first-match rules, no-match denial, exact KeyLocator-prefix checking, and hierarchical checking all have Rust witnesses. Full ndn-cxx `validator.conf` parsing is not advertised. |
| C.16 | `c16_lvs_user_fn_failsafe.sh` | LVS binary schemas with unsupported user functions fail closed: the parser flags the function call, trust-schema import rejects enforcement, and direct policy evaluation denies a fixture that would match if the constraint were ignored open. |
| D.01 | `d01_hoplimit_decrement.sh` | HopLimit is decremented on the incoming pipeline; the Docker witness proves HopLimit=2 still reaches an NFD producer while HopLimit=1 is dropped after decrementing to zero. |
| D.04 | `d04_pit_aggregation_selectors.sh` | PIT entries aggregate by Name/ForwardingHint with per-in-record selectors, and CS lookup rejects stale cached Data for `MustBeFresh` Interests at both store and engine stage level. |
| D.02 / I.11 | `d02_localhop_scope.sh` | `/localhop` scope is covered by Rust unit behavior and live interop: remote TCP drops, local Unix face passes. |
| E.04 | `e04_dataset_segmentation.sh` | Management datasets are returned as versioned segmented Data with FinalBlockId; the Docker witness verifies this for `/localhost/nfd/faces/list`. |
| E.05 | `e05_notification_streams.sh` | `NotificationStream<T>` has unit coverage for publisher/subscriber delivery and semantic face events; the Docker live witness mutates `strategy-choice` and fetches the resulting `/localhost/nfd/strategy-choice/notifications/seq=<n>` event Data with `ndn-mgmt-notification-fetch`. |
| Management FaceStatus | `nfdc_interop_face_list.sh` | The Docker interop image ships reference NFD `nfdc`; `nfdc face list` decodes ndn-fwd FaceStatus Data, including required `Flags`, without tripping NFD's strict dataset decoder. |
| N.12 | `n12_mgmt_response_signing.sh` | ndn-fwd testbed boots with a persistent ECDSA-P256 identity; reference `nfdc status` decodes live management Data, and `ndn-mgmt-response-verify` verifies `/localhost/nfd/cs/config` ControlResponse Data against the shared PIB trust anchor. |
| G.03 | `g03_psync_interop.sh` | The Docker interop image builds upstream C++ PSync plus a deterministic FullProducer fixture; the witness runs it against ndn-rs `ndn-psync-consumer` through NFD and requires five distinct expected Sync update prefixes. |
| G.04 | `g04_nlsr_interop.sh` | ndn-rs NLSR now has a live C++ NLSR sidecar witness. The Docker test requires bidirectional route convergence: ndn-fwd-nlsr installs `/test/r1/data`, and C++ NLSR/NFD installs `/test/r2/data` with `origin=nlsr`; a pcap is saved with the transcript. |
| G.06 | `g06_swim_vs_autoconfig.sh` | SWIM artifacts are absent, Rust AutoConfig hub-discovery witnesses pass, and upstream `ndn-autoconfig` succeeds through an NDN-FCH fixture by creating a hub face and registering `/` plus `/localhop/nfd` routes on ndn-fwd. |
| G.09 | `g09_prefix_announcement_consume.sh` | PrefixAnnouncement is now covered through decode, validation, route installation, and live forwarding-path use: a validated announcement installs `/learned`, and a later `/learned/item` Interest reaches the announcing face. Tampered or untrusted announcements install no route. |
| Management status | `testbed/tests/compliance/mgmt_protocol.sh` | `ndn-ctl status` renders the NFD-compatible status/version/startTime/uptime signal expected by the live compliance suite. |
| N.05 | `n05_nack_no_reason.sh` | A Nack header without `NackReason` decodes as `None`, not `Other(0)`. |
| N.06 | `n06_dead_nonce_list.sh` | The engine inserts retiring PIT nonces into `DeadNonceList` on satisfaction/expiry and consults it before PIT aggregation, so repeated `(Name, Nonce)` after PIT erasure drops as a loop. |
| N.08 | `n08_unsolicited_data_policy.sh` | `UnsolicitedDataPolicy` is now engine-witnessed for all four NFD-compatible modes: drop-all, admit-all, admit-local, and admit-network. Admitted unsolicited Data is cache-only and still must pass the verified-Data CS gate. |
| N.09 | `n09_multiaccess_nack_policy.sh` | Nacks are treated as point-to-point feedback: generated Nacks are suppressed on shared-medium ingress, incoming shared-medium Nacks are ignored, and propagation skips multi-access/ad-hoc downstream faces. A live UDP fixture now injects a real socket-originated Nack on the shared-medium face and proves it is not propagated. |
| N.10 | `n10_command_replay.sh` | Signed management commands enforce the SignatureTime window and per-signer strictly-increasing replay rule, and `ndn-fwd` mounts management with the replay cache wired by default. |
| N.14 | `n14_trust_anchor_validity.sh` | Expired and not-yet-valid trust anchors are rejected before entering the anchor set or cert cache; valid anchors still insert. |
| N.02 | `n02_lp_reassembly_collision.sh` | LP reassembly is keyed by sender endpoint as well as fragment sequence: packet-level tests cover overlapping sequences, engine tests prove `FaceAddr`-derived UDP/MAC endpoint IDs reach `TlvDecodeStage`, and a live UDP fixture reassembles colliding fragment sequences from two real socket source addresses. |

The remaining shared-medium depth work is now optional transport breadth:
Ethernet/BLE captures can extend the same invariants beyond the live UDP socket
fixtures when those environments are available.

## Intentional extensions (downstream-relied-upon divergences)

A few ndn-rs behaviors deliberately extend or diverge from stock NFD/ndn-cxx.
They are **intentional**, not findings, and downstream stacks (notably NDF)
build on them, so each is pinned by a passing regression-guard witness in
`testbed/tests/audit/` and tracked in `testbed/EXPECTED_FAILURES.md` under
"NDF-relied-upon extensions". They are listed here so the divergence is part of
the documented compliance surface rather than an untracked delta.

| Extension | What diverges | Witness |
|---|---|---|
| Persistent Interest / SubscriptionRequest (TLV `0x230`) | A subscription Interest creates a persistent PIT entry with per-InRecord persistence state and a data-count budget, distinct from a classical one-shot entry at the same name. Stock NFD has no such TLV. | `f16i_subscription_persistence.sh` |
| ReplayGuard `monotonic=false` shared-key mode | Signed-Interest replay protection uses AND-semantics (a replay only when *every* shared anti-replay field agrees), and supports a non-monotonic mode for a key shared across devices, where an out-of-order seq is legitimate but an exact in-window repeat is still rejected. | `f16ii_replay_guard_shared_key.sh` |
| `ContentHashTarget::InnerTlvType` delegated hashing | A face may be configured to hash a specific inner TLV type (e.g. `364`) rather than the whole Content, so a delegating consumer can name/verify by that inner digest. | `f16iii_inner_tlv_hashing.sh` |
| Implicit-digest fetch (`<auth>/blocks/<hash>`) | Content-Store lookup and CanBePrefix resolution by `ImplicitSha256DigestComponent`, supporting content-hash-addressed retrieval. (Standard NDN component, but pinned here as a relied-upon retrieval path.) | `f14_implicit_digest_fetch.sh` |

The `SignedTrustContext` wire object also carries an optional non-critical
provenance hint (`SOURCE_BUNDLE_HASH`, TLV `0x041A`) recording the SHA-256
digest of the source trust bundle a context was projected from; old nodes skip
it per the NDN evolvability rule.

## TLV codepoint allocations

ndn-rs's TLV allocations split into three classes:

- IANA / registry codes ndn-rs implements (forwarding).
- ndn-rs-internal codes used only on in-process or shared-memory
  faces (no wire reach).
- Codes reserved for v0.1.x.

## Releasing under v0.1.0

Release-readiness is gated on every critical-severity audit finding
being closed, the cross-implementation interop suite running in the
`interop` image, and the release notes matching the live tracker.
The 2026-05-28 Docker baseline for `testbed/tests/interop/run_all.sh`
passes all eight ndn-cxx and NDNts packet-exchange scenarios. The same pass now
also includes live G.03 PSync, G.04 NLSR, G.06 AutoConfig, C.09 SafeBag, N.12
management-response signing, and E.05 notification-stream witnesses. Remaining
work is mostly deeper optional fixture coverage and smaller semantic policy
rows, not a blocked generic interop harness. For heavy AutoConfig/testbed
rebuilds on Docker Desktop, prefer
`NDN_TESTBED_BUILD_JOBS=2 testbed/tools/up-g06-low-memory.sh` so the reference
C++ and Rust tool images build sequentially.

## See also

- `testbed/tests/audit/` — runnable witness scripts.
- [v0.1.0 release boundary](../releases/v0.1.0.md) — what is in
  scope once the release is tagged.
