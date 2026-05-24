#!/usr/bin/env bash
# Witness — NC.09: in-flight linear-fingerprint pollution filter (doctrine §6).
#
# A producer-committed homomorphic fingerprint (random projection r + per-row
# projections h) lets any node reject a polluted coded packet *before* decode:
# genuine systematic packets and genuine linear combinations pass; a packet
# whose payload doesn't match its claimed coding vector fails and never enters
# the rank basis. This is a resilience filter, not authenticity (verify-on-
# decode remains the backstop).
#
# Witnesses (RUST-UNIT, feature `f2-recode`):
#   - recode::tests::fingerprint_filters_pollution_in_flight
#   - recode::tests::buffer_fingerprint_rejects_before_decode
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode --quiet -- \
        fingerprint_filters_pollution_in_flight \
        buffer_fingerprint_rejects_before_decode \
        >/tmp/nc09_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc09_witness.log; then
    echo "=== NC.09 PASS — fingerprint rejects pollution in flight, passes genuine combos ==="
    grep -E "test result|running" /tmp/nc09_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.09 FAIL — fingerprint-filter witness failed ==="
    cat /tmp/nc09_witness.log
    exit 1
fi
