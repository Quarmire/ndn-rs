#!/usr/bin/env bash
# Witness — TCS.03: custodian unlock is idempotent.
#
# Unlocking an already-unlocked custodian must succeed without error and the
# custodian must remain available. Witness (RUST-UNIT, ndn-identity,
# tests/synthesis_phase1.rs):
#   - tcs03_custodian_unlock_idempotent
#
# Expected before Phase 1: FAIL. After Phase 1: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase1 --quiet -- \
        tcs03_custodian_unlock_idempotent \
        >/tmp/tcs03_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs03_witness.log; then
    echo "=== TCS.03 PASS — custodian unlock idempotent ==="
    grep -E "test result|running" /tmp/tcs03_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.03 FAIL — custodian unlock not idempotent ==="
    cat /tmp/tcs03_witness.log
    exit 1
fi
