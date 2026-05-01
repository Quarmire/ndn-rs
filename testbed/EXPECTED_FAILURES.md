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

Last reviewed: 2026-04-20 (initial, immediately after the audit;
no interop run has been executed against these scripts yet — the
statuses below are predictions from the audit, not measurements).
When the harness is first run, update the "Last seen" column with
the date and container digest.

## BLOCKER

| Finding | Witness test | Status | Predicted failure | Last seen |
|---------|------|--------|----|-|
| A.01 | `a01_blake3_name_component.sh` | EXPECTED-FAIL | ndn-cxx / NFD reject Name containing `BLAKE3_DIGEST` (TLV 0x03) | not yet run |
| A.09 | `a09_signed_interest_verify.sh` | EXPECTED-FAIL | ndn-cxx signature verify fails on a signed Interest produced by ndn-rs | not yet run |
| B.01 | `b01_reliability_txsequence.sh` | EXPECTED-FAIL | NFD sees `Sequence` (0x51) where reliability reads `TxSequence` (0x0348); retransmits never cleared | not yet run |
| C.01 | `c01_ecdsa_verify.sh` | EXPECTED-FAIL | ndn-rs validator returns `Invalid` on an ECDSA-signed Data from ndn-cxx | not yet run |
| D.01 | `d01_hoplimit_decrement.sh` | EXPECTED-FAIL | tcpdump on ndn-fwd's egress interface shows HopLimit unchanged from ingress | not yet run |
| E.01 | `e01_mgmt_unauth.sh` | EXPECTED-FAIL | unsigned `rib/register` command is accepted by ndn-fwd (NFD rejects — control) | not yet run |
| G.03 | `g03_psync_interop.sh` | EXPECTED-FAIL | ndn-rs PSync and C++ PSync produce different IBF decoding; no sync progress | not yet run |

## MAJOR

| Finding | Witness test | Status | Predicted failure | Last seen |
|---------|------|--------|----|-|
| A.02 | `a02_psdc_structural.sh` | EXPECTED-FAIL | Interest with `ApplicationParameters` but no PSDC accepted by ndn-rs, rejected by ndn-cxx | not yet run |
| A.03 | `a03_unknown_critical_tlv.sh` | EXPECTED-FAIL | Interest carrying unknown critical TLV type inside body accepted by ndn-rs, rejected by ndn-cxx | not yet run |
| A.10 | `a10_databuilder_build_sig.sh` | EXPECTED-FAIL | Data emitted by `DataBuilder::build()` has zero-bytes signature; ndn-cxx DigestSha256 verify fails | not yet run |
| A.15 | `a15_keylocator_rules.sh` | EXPECTED-FAIL | Ed25519 Data without KeyLocator accepted by ndn-rs, rejected by ndn-cxx | not yet run |
| A.17 | `a17_blake3_sigtype_rejected.sh` | EXPECTED-FAIL | Data signed with SignatureType=6 (BLAKE3) rejected by ndn-cxx (unknown type) | not yet run |
| C.02 | `c02_hmac_roundtrip.sh` | EXPECTED-FAIL | Self-signed HMAC Data round-trips through ndn-rs validator as `Invalid` | not yet run |
| C.03 | `c03_digest_sha256_verify.sh` | EXPECTED-FAIL | DigestSha256 Data from ndn-cxx rejected by ndn-rs validator | not yet run |
| C.07 | `c07_cert_naming.sh` | EXPECTED-FAIL | ndn-cxx `ndnsec-cert-dump` rejects ndn-rs-issued cert as "not a certificate name" | not yet run |
| C.08 | `c08_cert_content.sh` | EXPECTED-FAIL | ndn-cxx cert-content decode fails on ndn-rs Content (raw pubkey, not DER SPKI) | not yet run |
| C.11 | `c11_signed_interest_validate.sh` | EXPECTED-FAIL | Signed management Interest's `InterestSignatureInfo` not parsed by ndn-rs validator path | not yet run |
| C.13 | `c13_ndncert_challenge_tlv.sh` | BLOCKED-BY-INTEROP | ndncert-ca-server not yet in the testclient image; once added, expect CHALLENGE parameter parse failure | not yet run |
| D.02 | `d02_localhop_scope.sh` | EXPECTED-FAIL | `/localhop/nfd/*` Interest received on a non-local face is forwarded further | not yet run |
| D.03 | `d03_nexthop_faceid.sh` | EXPECTED-FAIL | Interest with `NextHopFaceId` LP header goes through strategy LPM instead of to the named face | not yet run |
| D.04 | `d04_pit_aggregation_selectors.sh` | EXPECTED-FAIL | Two Interests for the same Name with different selectors produce two PIT entries, leading to double upstream forward | not yet run |
| D.07 | `d07_pit_token_echo.sh` | EXPECTED-FAIL | Data response to a PitToken-tagged Interest lacks the echoed token | not yet run |
| D.09 | `d09_bestroute_nack_retry.sh` | EXPECTED-FAIL | On nexthop-1 Nack, ndn-rs does not retry nexthop-2; propagates Nack immediately | not yet run |
| D.13 | `d13_localhost_unvalidated.sh` | EXPECTED-FAIL | Forged `/localhost/...` Data (zeroed signature) accepted by ndn-rs, rejected by ndn-cxx | not yet run |
| E.04 | `e04_dataset_segmentation.sh` | EXPECTED-FAIL | `faces/list` dataset does not use SegmentName convention; `nfdc` parse fails | not yet run |
| E.05 | `e05_notifications.sh` | BLOCKED-BY-INTEROP | ndn-fwd does not publish `/localhost/nfd/<module>/notifications` streams | not yet run |
| F.01 | `f01_ipv6_faceuri.sh` | EXPECTED-FAIL | IPv6 peer Face reports `udp4://[…]`, rejected by NFD FaceUri parser | not yet run |
| F.03 | `f03_faceuri_schemes.sh` | EXPECTED-FAIL | TCP face emits `tcp://`, should be `tcp4://`/`tcp6://` | not yet run |

## NOT-WITNESSABLE

| Finding | Severity | Reason | Reference |
|---------|-|-|-|
| G.04 | MAJOR | NLSR absence cannot be exercised via a packet exchange — the feature simply isn't there. Track as a roadmap item, not a test. | audit §G.04 |
| C.16 | MAJOR | LVS user functions fail silently open — the failure is semantic, not observable as a wire event. Needs a dedicated LVS unit test. | audit §C.16 |

## When to add a row here

Every new test added under `tests/audit/` must appear in this
file with its expected status. Removing a row means either:

- the finding was resolved (move to "RESOLVED" and note the
  commit and date of the last-seen pass); or
- the finding was retracted after further spec reading (document
  the retraction in the audit document too).
