#!/usr/bin/env bash
# Witness test for audit finding N.05 — a Nack header without a NackReason
# must not be decoded as reason code 0.
#
# Finding:     testbed/EXPECTED_FAILURES.md § N.05
# Severity:    MAJOR
# Spec ref:    NDNLPv2 §3.5 — NackReason is optional inside the Nack header.
# Witnesses:   RUST-UNIT in ndn-packet:
#                n05_nack_header_without_reason_decodes_none
#                n05_decode_nack_without_reason_as_none
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-packet --features std --lib --quiet n05_ \
        >/tmp/n05_witness.log 2>&1; then
    echo "ok: Nack header without NackReason decodes as None"
    echo
    echo "=== N.05 RESOLVED — absent NackReason is not Other(0) ==="
    exit 0
else
    echo "FAIL: n05_* tests did not pass"
    cat /tmp/n05_witness.log
    echo
    echo "=== N.05 EXPECTED-FAIL — absent NackReason still misdecoded ==="
    exit 1
fi
