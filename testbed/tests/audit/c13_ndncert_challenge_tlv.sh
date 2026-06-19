#!/usr/bin/env bash
# Witness test for audit finding C.13 — NDNCERT 0.3 CHALLENGE
# parameters carried as JSON instead of TLV-encoded
# ParameterKey/ParameterValue pairs.
#
# Finding:     testbed/EXPECTED_FAILURES.md § C.13
# Severity:    BLOCKER
# Spec ref:    NDNCERT 0.3 wiki §2.4.3 — CHALLENGE plaintext is a
#              sequence of ParameterKey (0x85) / ParameterValue (0x87)
#              TLVs, not JSON.
# Witnesses:   `EnrollmentSession::challenge_request_body` produces an
#              encrypted_payload whose AES-GCM-decrypted plaintext
#              starts with TLV-TYPE 0x85. Today the plaintext starts
#              with `{` (0x7B) — JSON.
#
# Note: the spec also calls for an interop test against
# `ndncert-ca-server` once that image lands in the testclient
# container. This RUST-UNIT witness is the encoder-side proof.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-cert --lib --quiet \
        c13_challenge_request_plaintext_is_tlv_not_json \
        >/tmp/c13_witness.log 2>&1; then
    echo "=== C.13 RESOLVED — CHALLENGE plaintext is TLV ParameterKey/ParameterValue ==="
    exit 0
else
    echo "=== C.13 EXPECTED-FAIL — CHALLENGE plaintext is JSON, not TLV ==="
    cat /tmp/c13_witness.log
    exit 1
fi
