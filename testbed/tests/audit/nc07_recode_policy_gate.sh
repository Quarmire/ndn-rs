#!/usr/bin/env bash
# Witness — NC.07: F2 recode policy gate + runtime kill switch (doctrine §5).
#
# A generation with RecodePolicy=none never mints. With RecodePolicy=open the
# recoder mints, but flipping the runtime kill switch (operator control)
# stops it immediately — modelling "install no recoder where policy forbids"
# and "disable recoding at runtime".
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - recode_face::tests::kill_switch_and_policy_gate_stop_minting
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
        kill_switch_and_policy_gate_stop_minting \
        >/tmp/nc07_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc07_witness.log; then
    echo "=== NC.07 PASS — policy=none and kill switch suppress recoding ==="
    grep -E "test result|running" /tmp/nc07_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.07 FAIL — policy-gate witness failed ==="
    cat /tmp/nc07_witness.log
    exit 1
fi
