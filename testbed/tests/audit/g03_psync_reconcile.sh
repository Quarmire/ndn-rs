#!/usr/bin/env bash
# Witness test for audit finding G.03 — PSync reconciliation correctness.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.03
# Severity:    BLOCKER
# Spec ref:    PSync/detail/iblt.cpp operator- (Eppstein peeling)
# Witnesses:   Rust-only two-node reconciliation with N=5, N=20, and one
#              decode-failure case (IBF too full → fallback needed).
#
# Expected today: PASS (exit 0).  The fix landed in the same commit.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
#   2 — SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo not found" >&2
    exit 2
fi

cd "$REPO_ROOT"

echo "=== G.03 PSync reconciliation witness ==="

# N=5: A has 5 extras, B has none
echo "--- reconcile N=5 ---"
cargo test -p ndn-sync psync::tests::g03_reconcile_n5 -- --nocapture 2>&1

# N=20: A and B each have 20 non-overlapping elements
echo "--- reconcile N=20 ---"
cargo test -p ndn-sync psync::tests::g03_reconcile_n20 -- --nocapture 2>&1

# Decode failure: IBF too full → returns None (expected; caller must fall back
# to full-state download per PSync FullProducer threshold logic)
echo "--- decode failure (IBF oversaturated) ---"
cargo test -p ndn-sync psync::tests::g03_reconcile_decode_failure_returns_none -- --nocapture 2>&1

echo "=== All G.03 reconciliation witnesses passed ==="
