#!/usr/bin/env bash
# Witness — TCS.04: legacy flat anchors migrate into the implicit `/` root
# TrustContext at first run.
#
# `TrustContext::legacy_root(anchors)` produces a verify-only context whose
# `name == /`, whose `anchors` carries every supplied cert, and whose
# `provenance` is `Replicated` (signaling the migration source). Witness
# (RUST-UNIT, ndn-identity, tests/synthesis_phase1.rs):
#   - tcs04_legacy_anchors_in_root_tc
#
# Expected before Phase 1: FAIL. After Phase 1: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase1 --quiet -- \
        tcs04_legacy_anchors_in_root_tc \
        >/tmp/tcs04_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs04_witness.log; then
    echo "=== TCS.04 PASS — legacy anchors land in / context ==="
    grep -E "test result|running" /tmp/tcs04_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.04 FAIL — legacy anchor migration broken ==="
    cat /tmp/tcs04_witness.log
    exit 1
fi
