#!/usr/bin/env bash
# Witness — CTX.09: tighten reports orphaned certs before applying
#
# See .claude/notes/trust-context/trust-context-model-2026-05-25.md §8.
# Witness (RUST-UNIT, ndn-security, tests/trust_context_phase7.rs):
#   - ctx09_schema_tighten_dryrun_reports_orphans
#
# Expected before Phase 7: FAIL. After Phase 7: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-security --test trust_context_phase7 --quiet -- \
        ctx09_schema_tighten_dryrun_reports_orphans >/tmp/ctx09_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx09_witness.log; then
    echo "=== ctx09 PASS ==="
    grep -E "test result|running" /tmp/ctx09_witness.log | tail -n 2
    exit 0
else
    echo "=== ctx09 FAIL ==="
    cat /tmp/ctx09_witness.log
    exit 1
fi
