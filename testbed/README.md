# NDN Protocol Compliance Testbed

Docker-based harness for running `ndn-rs` alongside the reference NDN
forwarders (NFD, ndnd/yanfd) and NDN client libraries (ndn-cxx,
NDNts) so every protocol-compliance claim can be witnessed at the
packet level.

## Why this exists

`ndn-rs` had a reputation problem: the library made broad wire-
compatibility claims that did not survive the audit under
[`docs/notes/spec-compliance-audit-2026-04-20.md`](../docs/notes/spec-compliance-audit-2026-04-20.md).
The audit identified 12 BLOCKER-tier findings, roughly 35 MAJOR
findings, and a wiki page that contradicted the code in over a
dozen places.

Going forward, **no compliance claim lands in the wiki or an
issue comment without a corresponding test in this testbed that
produces a packet capture or transcript as evidence**. This
directory is where that evidence lives.

## Quick start

```bash
# From the repo root:
docker compose -f testbed/docker-compose.yml up -d --build

# Interop tests (ndn-rs ↔ ndn-cxx ↔ NDNts through NFD/yanfd/ndn-fwd):
docker compose -f testbed/docker-compose.yml exec testclient \
    bash /testbed/tests/interop/run_all.sh

# Compliance tests (same suites against all three forwarders):
docker compose -f testbed/docker-compose.yml exec testclient \
    bash /testbed/tests/compliance/run_all.sh

# Benchmarks:
docker compose -f testbed/docker-compose.yml exec testclient \
    bash /testbed/bench/run_all.sh
```

Results are written into the `results/` named volume (timestamped
`.txt` and `.json` files). Use `docker compose cp` to pull them
out.

## Topology

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
│  ndn-fwd    │  │     NFD     │  │    yanfd    │  │  testclient  │
│  (ndn-rs)   │  │  (C++ ref)  │  │  (Go ref)   │  │  ndn-cxx     │
│ 172.30.0.10 │  │ 172.30.0.11 │  │ 172.30.0.12 │  │  NDNts       │
│ UDP/TCP/WS  │  │  UDP/TCP    │  │  UDP/TCP    │  │  ndn-rs tools│
└─────────────┘  └─────────────┘  └─────────────┘  │ 172.30.0.20  │
      ▲                ▲                ▲           └──────────────┘
      │                │                │                  │
      └────────────────┴────────────────┴──────────────────┘
                    ndn-net (172.30.0.0/24)
```

Each forwarder's Unix socket is shared with `testclient` via a
named Docker volume, so `ndn-peek --face-socket` / `nfdc` / `ndn-ctl`
can drive any forwarder from the testclient.

## Suites

| Path | What it does |
|------|--------------|
| `tests/interop/` | ndn-rs ↔ ndn-cxx ↔ NDNts through each forwarder. 8 scenarios. |
| `tests/compliance/` | 4 black-box compliance suites (basic forwarding, PIT aggregation, CS behaviour, mgmt protocol) run against all three forwarders. |
| `tests/browser/` | Playwright tests for WebSocket / WASM / Web Bluetooth transports. |
| `tests/audit/` | **New.** Per-audit-finding witness scripts. See the audit-to-test map below. |
| `bench/` | Throughput, latency, internal throughput benchmarks. |

## Audit findings → witness tests

Every BLOCKER and MAJOR finding from the audit eventually needs a
witness test here. The table below tracks the current state. `*`
marks tests that are **expected to fail** today because the audit
finding is unresolved — they'll flip to PASS when the
corresponding fix lands.

| Finding | Severity | Witness test | Status |
|---------|----------|-----|-------|
| A.01 `BLAKE3_DIGEST` 0x03 component rejected by spec-compliant peers | BLOCKER | `tests/audit/a01_blake3_name_component.sh` | FAIL (to be fixed) |
| A.02 Missing `ParametersSha256DigestComponent` structural validation | MAJOR | `tests/audit/a02_psdc_structural.sh` | pending |
| A.03 Unknown critical TLVs silently ignored in bodies | MAJOR | `tests/audit/a03_unknown_critical_tlv.sh` | pending |
| A.09 Signed Interest signs placeholder, not real digest | ~~BLOCKER~~ **RESOLVED** 2026-05-01 | `tests/audit/a09_signed_interest_verify.sh` + ndn-packet unit test `interest_builder_sign_sync_signed_region_matches_extractor` | unit PASS; interop witness pending helper binary |
| A.10 `DataBuilder::build()` emits forged DigestSha256 | MAJOR | `tests/audit/a10_databuilder_build_sig.sh` | pending |
| A.12 Invented "bare Nack TLV" form | MAJOR | already exercised by interop tests (no separate witness) | — |
| A.15 KeyLocator required/forbidden rules unenforced | MAJOR | `tests/audit/a15_keylocator_rules.sh` | pending |
| A.17 BLAKE3 SignatureType codes 6/7 in reserved range | MAJOR | `tests/audit/a17_blake3_sigtype_rejected.sh` | pending |
| B.01 NDNLPv2 reliability uses `Sequence` instead of `TxSequence` | BLOCKER | `tests/audit/b01_reliability_txsequence.sh` | FAIL (to be fixed) |
| B.11 BLE face uses NDNLPv2 with no private framing | POSITIVE | `tests/browser/ws-transport.spec.ts` neighbour (manual BLE check outside harness) | PASS |
| C.01 RSA/ECDSA sigtypes declared, unimplemented | BLOCKER | `tests/audit/c01_ecdsa_verify.sh` | FAIL |
| C.02 No `HmacSha256Verifier` | MAJOR | `tests/audit/c02_hmac_roundtrip.sh` | FAIL |
| C.03 No `DigestSha256Verifier` | MAJOR | `tests/audit/c03_digest_sha256_verify.sh` | FAIL |
| C.07 Certificate naming malformed | MAJOR | `tests/audit/c07_cert_naming.sh` | FAIL |
| C.08 Cert Content is raw pubkey, not DER SPKI | MAJOR | `tests/audit/c08_cert_content.sh` | FAIL |
| C.11 No Interest-signature validation path | MAJOR | `tests/audit/c11_signed_interest_validate.sh` | FAIL |
| C.13 NDNCERT CHALLENGE still JSON | MAJOR | `tests/audit/c13_ndncert_challenge_tlv.sh` | FAIL |
| D.01 HopLimit never decremented on forward | BLOCKER | `tests/audit/d01_hoplimit_decrement.sh` | FAIL |
| D.02 `/localhop` scope not enforced | MAJOR | `tests/audit/d02_localhop_scope.sh` | FAIL |
| D.03 `NextHopFaceId` LP header ignored | MAJOR | `tests/audit/d03_nexthop_faceid.sh` | FAIL |
| D.04 PIT keyed on selectors (aggregation broken) | MAJOR | `tests/audit/d04_pit_aggregation_selectors.sh` | FAIL |
| D.07 PitToken not echoed on return path | MAJOR | `tests/audit/d07_pit_token_echo.sh` | FAIL |
| D.09 BestRoute no Nack retry | MAJOR | `tests/audit/d09_bestroute_nack_retry.sh` | FAIL |
| D.13 `/localhost` Data bypasses validation | MAJOR | `tests/audit/d13_localhost_unvalidated.sh` | FAIL |
| E.01 Command Interests unauthenticated | BLOCKER | `tests/audit/e01_mgmt_unauth.sh` | FAIL |
| E.04 Status datasets not segmented | MAJOR | `tests/audit/e04_dataset_segmentation.sh` | FAIL |
| E.05 Notification streams absent | MAJOR | `tests/audit/e05_notifications.sh` | FAIL |
| F.01 `udp4://` forced for IPv6 peers | MAJOR | `tests/audit/f01_ipv6_faceuri.sh` | FAIL |
| F.03 FaceUri schemes incomplete | MAJOR | `tests/audit/f03_faceuri_schemes.sh` | FAIL |
| G.03 PSync IBF not wire-compatible | BLOCKER | `tests/audit/g03_psync_interop.sh` | FAIL |
| G.04 NLSR missing | MAJOR | n/a (feature absence, not witnessable as a wire test) | — |

**Not an exhaustive list** — add new rows whenever the audit is
updated or a new finding surfaces. A finding without a witness
test is not considered "tracked."

## How to use this when fixing a finding

1. Before writing any code, run the finding's witness test and
   capture the output showing the current failure.
2. Open the PR with that failure transcript in the description.
3. Write the fix.
4. Re-run the witness test. Capture the output showing PASS.
5. Attach both transcripts to the PR. Reviewer compares.
6. Update [`EXPECTED_FAILURES.md`](EXPECTED_FAILURES.md) to flip
   the finding from `expected-fail` to `resolved`.

The `tests/audit/` directory exists to make this lifecycle
trivial — one script per finding, one transcript pair per PR.
Fixes without both transcripts should be rejected in review.

## Configuration files

- `configs/ndn-fwd.toml` — ndn-rs forwarder config (ephemeral
  identity, LRU CS, UDP:6363 / TCP:6364 / management socket).
- `configs/nfd.conf` — NFD reference config.
- `configs/yanfd.yml` — yanfd (ndnd) reference config.

## Related docs

- Full audit: [`docs/notes/spec-compliance-audit-2026-04-20.md`](../docs/notes/spec-compliance-audit-2026-04-20.md)
- Wiki summary: [`docs/wiki/src/reference/spec-compliance.md`](../docs/wiki/src/reference/spec-compliance.md)
- Expected failures tracker: [`EXPECTED_FAILURES.md`](EXPECTED_FAILURES.md)
