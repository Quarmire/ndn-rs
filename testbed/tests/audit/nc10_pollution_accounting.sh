#!/usr/bin/env bash
# Witness — NC.10: pollution accounting — decode budget + quarantine
# (doctrine §6 resilience floor).
#
# A per-generation absorb budget caps total attempts (DoS guard); a quarantine
# threshold refuses a generation after too many rejected packets — even clean
# ones — bounding the work a polluter can induce.
#
# Witness (RUST-UNIT, feature `f2-recode`):
#   - recode::tests::budget_and_quarantine_bound_pollution
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
        budget_and_quarantine_bound_pollution \
        >/tmp/nc10_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc10_witness.log; then
    echo "=== NC.10 PASS — budget + quarantine bound induced work ==="
    grep -E "test result|running" /tmp/nc10_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.10 FAIL — pollution-accounting witness failed ==="
    cat /tmp/nc10_witness.log
    exit 1
fi
