#!/usr/bin/env bash
# Witness — TCS.07: the base SyncBundle wire payload carries no private keys.
#
# Even at the wire level, a base SyncBundle must not embed any TLV with type
# code `TC_SYNC_WRAPPED_KEY_FOR_DEVICE` (0x0425). Wrapped-key delivery is
# Phase-4 work; until then `carries_private_keys()` is required to return
# false and the wire scan must find no such payload.
# Witness (RUST-UNIT, ndn-identity, tests/synthesis_phase2.rs):
#   - tcs07_context_sync_no_private_keys
#
# Expected before Phase 2: FAIL. After Phase 2: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase2 --quiet -- \
        tcs07_context_sync_no_private_keys \
        >/tmp/tcs07_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs07_witness.log; then
    echo "=== TCS.07 PASS — base bundle wire carries no private keys ==="
    grep -E "test result|running" /tmp/tcs07_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.07 FAIL — bundle wire may carry private-key material ==="
    cat /tmp/tcs07_witness.log
    exit 1
fi
