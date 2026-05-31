#!/usr/bin/env bash
# Witness — CTX.05: enrollment token name-scope.
#
# A scoped token authorizes a cert only under its name prefix; a request for a
# name outside the scope is rejected (and the token is not consumed), while an
# in-scope request succeeds. See §6 gate 3.
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase3_tokens.rs):
#   - ctx05_scoped_token_enforced
#
# Expected before Phase 3: FAIL (tokens had no scope). After Phase 3: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase3_tokens --quiet -- \
        ctx05_scoped_token_enforced \
        >/tmp/ctx05_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx05_witness.log; then
    echo "=== CTX.05 PASS — scoped token can't mint outside its scope ==="
    grep -E "test result|running" /tmp/ctx05_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.05 FAIL — token scope not enforced ==="
    cat /tmp/ctx05_witness.log
    exit 1
fi
