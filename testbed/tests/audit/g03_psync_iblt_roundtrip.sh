#!/usr/bin/env bash
# Witness test for audit finding G.03 — PSync IBLT wire-format round-trip.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.03
# Severity:    BLOCKER (BLOCKED-BY-INTEROP before this fix)
# Spec ref:    PSync/detail/iblt.{hpp,cpp} — cell layout, hash seeds,
#              sectioned table, zlib compression
# Witnesses:   Rust IBLT unit tests pass all C++ test-vector checks:
#              correct cell types (u32/i32), sectioned table (i*section+h%section),
#              12-byte big-endian wire cells, zlib compression, murmur3 seeds.
#
# Expected today: PASS (exit 0).  The fix landed in the same commit as
#                 this script.  The test is a RUST-UNIT proof.
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
echo "Running: cargo test -p ndn-sync psync -- --nocapture"
exec cargo test -p ndn-sync psync -- --nocapture
