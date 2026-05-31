#!/usr/bin/env bash
# Witness — CTX.11: revoke issuing CA + roll intermediate recovers via pull
#
# See .claude/notes/trust-context/trust-context-model-2026-05-25.md §8.
# Witness (RUST-UNIT, ndn-security, tests/trust_context_phase7.rs):
#   - ctx11_intermediate_compromise_recovery
#
# Expected before Phase 7: FAIL. After Phase 7: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-security --test trust_context_phase7 --quiet -- \
        ctx11_intermediate_compromise_recovery >/tmp/ctx11_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx11_witness.log; then
    echo "=== ctx11 PASS ==="
    grep -E "test result|running" /tmp/ctx11_witness.log | tail -n 2
    exit 0
else
    echo "=== ctx11 FAIL ==="
    cat /tmp/ctx11_witness.log
    exit 1
fi
