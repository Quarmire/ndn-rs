#!/usr/bin/env bash
# Witness — CTX.03: enrollment token is single-use.
#
# A redeemed token re-presented at challenge time is rejected, so a scanned QR
# is inert after first use. See trust-context-model-2026-05-25.md §6 gate 1.
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase3_tokens.rs):
#   - ctx03_redeemed_token_reuse_rejected
#
# Expected before Phase 3: FAIL. After Phase 3: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase3_tokens --quiet -- \
        ctx03_redeemed_token_reuse_rejected \
        >/tmp/ctx03_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx03_witness.log; then
    echo "=== CTX.03 PASS — redeemed token rejected on reuse ==="
    grep -E "test result|running" /tmp/ctx03_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.03 FAIL — token reuse not rejected ==="
    cat /tmp/ctx03_witness.log
    exit 1
fi
