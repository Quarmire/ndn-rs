#!/usr/bin/env bash
# Witness — CTX.04: enrollment token TTL.
#
# A token past its TTL is rejected (and reaped) at challenge time — the gap the
# design note flags as the one real security hole. See §6 gate 2.
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase3_tokens.rs):
#   - ctx04_expired_token_rejected
#
# Expected before Phase 3: FAIL (tokens had no expiry). After Phase 3: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase3_tokens --quiet -- \
        ctx04_expired_token_rejected \
        >/tmp/ctx04_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx04_witness.log; then
    echo "=== CTX.04 PASS — expired token rejected ==="
    grep -E "test result|running" /tmp/ctx04_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.04 FAIL — expired token accepted ==="
    cat /tmp/ctx04_witness.log
    exit 1
fi
