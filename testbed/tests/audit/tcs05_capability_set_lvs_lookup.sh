#!/usr/bin/env bash
# Witness — TCS.05: `CapabilitySet.sign` patterns gate `TrustContext::can_sign`.
#
# A held identity scoped to `/home/bob/alice` may sign names under that
# subtree but not under `/home/bob/charlie` nor `/work/acme`. Witness
# (RUST-UNIT, ndn-identity, tests/synthesis_phase1.rs):
#   - tcs05_capability_set_lvs_lookup
#
# Expected before Phase 1: FAIL. After Phase 1: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase1 --quiet -- \
        tcs05_capability_set_lvs_lookup \
        >/tmp/tcs05_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs05_witness.log; then
    echo "=== TCS.05 PASS — can_sign honors CapabilitySet patterns ==="
    grep -E "test result|running" /tmp/tcs05_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.05 FAIL — capability-set lookup broken ==="
    cat /tmp/tcs05_witness.log
    exit 1
fi
