#!/usr/bin/env bash
# Witness — TCS.01: TrustContext sync-bundle round-trip.
#
# Constructing a TrustContext, exporting its sync bundle, and re-reading the
# bundle preserves the equality-critical subset (context name, anchors,
# CA endpoints). Witness (RUST-UNIT, ndn-identity, tests/synthesis_phase1.rs):
#   - tcs01_trust_context_roundtrip
#
# Expected before Phase 1: FAIL (target missing). After Phase 1: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase1 --quiet -- \
        tcs01_trust_context_roundtrip \
        >/tmp/tcs01_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs01_witness.log; then
    echo "=== TCS.01 PASS — TrustContext bundle round-trip ==="
    grep -E "test result|running" /tmp/tcs01_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.01 FAIL — bundle round-trip broken ==="
    cat /tmp/tcs01_witness.log
    exit 1
fi
