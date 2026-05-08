#!/usr/bin/env bash
# Witness test for audit finding C.13 — live NDNCERT CA interop leg.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.13
# Severity:    BLOCKED (8 wire-format gaps — see
#              docs/notes/c13-live-interop-gaps-2026-05-08.md)
# Spec ref:    NDNCERT 0.3 wiki — NEW / CHALLENGE / ISSUE round-trip
#
# This script exits 1 today because the following structural gaps have
# not yet been fixed in ndn-rs's EnrollmentSession / ChallengeRequestTlv:
#
#   L1  cert_request in NEW must be a self-signed NDN Certificate
#       (ndn-rs sends a custom binary blob)
#       ref: ndncert/src/detail/request-encoder.cpp:63-68
#
#   L2  CHALLENGE Interest name must carry request-id as a name component
#       (ndn-rs puts it in ApplicationParameters)
#       ref: ndncert/src/requester-request.cpp:217
#
#   L3  CHALLENGE ApplicationParameters outer TLV structure must be
#       {IV, AuthTag, EncryptedPayload} — ndn-rs sends
#       {RequestId, SelectedChallenge, IV, EncryptedPayload, AuthTag}
#       ref: ndncert/src/detail/crypto-helpers.cpp:388-413
#
#   L4  SelectedChallenge (0xA1) must be first element inside the
#       AES-GCM plaintext, not a cleartext TLV in the outer wrapper
#       ref: ndncert/src/challenge/challenge-pin.cpp:117-118
#
#   L5  CHALLENGE response is AES-GCM encrypted; ndn-rs parses it as
#       cleartext TLV
#       ref: ndncert/src/detail/challenge-encoder.cpp:48-51
#
#   L6  Issued cert is returned by name only; client must fetch it with
#       a separate Interest — ndn-rs expects cert bytes in the response
#       ref: ndncert/src/requester-request.cpp:242-248
#
#   L7  Both NEW and CHALLENGE Interests must be signed with the
#       requester's key; ndn-rs produces unsigned bodies
#       ref: ndncert/src/requester-request.cpp:148, 227
#
#   L8  IV must use the {random-8 || counter-4} structured layout
#       (minor, only matters for multi-round challenges)
#       ref: ndncert/src/detail/crypto-helpers.cpp:374-385
#
# Prerequisites for when these gaps are fixed:
#   - docker compose with ndncert-ca + nfd-ndncert services running
#   - The CA configured with ca-prefix /test/ndncert/CA, pin challenge,
#     a self-signed trust anchor, and a preconfigured static PIN so the
#     round-trip is fully automated (no human at the terminal)
#   - An ndn-rs enrollment binary (example or ndn-ctl subcommand) that
#     drives NEW → CHALLENGE(pin) → cert-fetch
#   - tshark for the wire capture to
#     testbed/tests/audit/transcripts/c13_ndncert_live_interop_after.{pcap,txt}
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "=== C.13 live NDNCERT interop — BLOCKED ===" >&2
echo "" >&2
echo "8 structural wire-format gaps remain in EnrollmentSession." >&2
echo "See: docs/notes/c13-live-interop-gaps-2026-05-08.md" >&2
echo "" >&2
echo "Gaps by category:" >&2
echo "  L1 cert_request not a proper NDN Certificate" >&2
echo "  L2 request-id must be in CHALLENGE Interest name, not AppParams" >&2
echo "  L3 CHALLENGE AppParams outer TLV layout wrong" >&2
echo "  L4 SelectedChallenge must be inside encrypted plaintext" >&2
echo "  L5 CHALLENGE response is AES-GCM encrypted; ndn-rs treats as plaintext" >&2
echo "  L6 issued cert returned by name only; cert-fetch step missing" >&2
echo "  L7 NEW and CHALLENGE Interests must be signed" >&2
echo "  L8 IV must use structured {random-8 || counter-4} layout (minor)" >&2
exit 1
