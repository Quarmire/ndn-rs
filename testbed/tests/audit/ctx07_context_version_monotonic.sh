#!/usr/bin/env bash
# Witness — CTX.07: TrustContext anti-rollback.
#
# A node refuses a strictly older context version for a namespace it already
# holds, so an attacker cannot serve a stale context to re-introduce a weakened
# schema or a revoked anchor. Version lives in the RDR name; the keyring
# enforces monotonicity at adopt time.
#
# See .claude/notes/trust-context/trust-context-model-2026-05-25.md §8, §15.
# Witness (RUST-UNIT, ndn-security, tests/trust_context_phase1.rs):
#   - ctx07_context_version_monotonic
#
# Expected before Phase 2: FAIL (exit 1) — no versioned keyring exists.
# After Phase 2: exit 0 without script changes.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-security --test trust_context_phase1 --quiet -- \
        ctx07_context_version_monotonic \
        >/tmp/ctx07_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx07_witness.log; then
    echo "=== CTX.07 PASS — older context version refused (anti-rollback) ==="
    grep -E "test result|running" /tmp/ctx07_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.07 FAIL — stale context version accepted ==="
    cat /tmp/ctx07_witness.log
    exit 1
fi
