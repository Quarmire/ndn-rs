#!/usr/bin/env bash
# Witness — NC.11: token-required recode capability (doctrine §3.2, wire spec).
#
# A producer-signed RecodeToken authorizes a recoder identity for a generation:
# the token round-trips on the wire and its namespace predicate is correct
# (core); end-to-end, a recoder under the token's namespace produces Data that
# `verify_token_recoder` accepts, while a token for a different namespace or a
# forged token is rejected (native, two-key: producer signs token, recoder
# signs Data).
#
# Witnesses:
#   - recode::tests::recode_token_round_trips_and_authorizes (f2-recode)
#   - recode_face::tests::token_required_capability_authorizes (f2-recode-face)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        recode_token_round_trips_and_authorizes \
        token_required_capability_authorizes \
        >/tmp/nc11_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc11_witness.log; then
    echo "=== NC.11 PASS — recode token authorizes by producer signature + namespace ==="
    grep -E "test result|running" /tmp/nc11_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.11 FAIL — recode-token witness failed ==="
    cat /tmp/nc11_witness.log
    exit 1
fi
