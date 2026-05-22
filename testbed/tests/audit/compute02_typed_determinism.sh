#!/usr/bin/env bash
# Witness — C-COMPUTE-02..04: ComputeService::attach + FIB wiring, typed Tier-1
# functions, and the transparent/opaque determinism contract.
#
# Finding:   docs/notes/compute-design-2026-05-21.md § 12 (C-COMPUTE-02..04)
# Severity:  MAJOR (feature contract)
# Witnesses: RUST-UNIT (tests/end_to_end.rs against an embedded engine):
#              - transparent_function_round_trip_and_cs_memoization
#                  attach + FIB + typed (i64,i64)->i64 + CS hit on repeat
#              - transparent_concurrent_calls_coalesce
#                  two identical concurrent calls -> one handler execution
#              - opaque_calls_do_not_coalesce
#                  per-call nonce -> two executions, results never alias
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-compute --test end_to_end --quiet -- \
        transparent_function_round_trip_and_cs_memoization \
        transparent_concurrent_calls_coalesce \
        opaque_calls_do_not_coalesce \
        >/tmp/compute02_witness.log 2>&1; then
    echo "=== C-COMPUTE-02..04 PASS — typed API + determinism contract hold ==="
    exit 0
fi
echo "=== C-COMPUTE-02..04 FAIL ==="
cat /tmp/compute02_witness.log
exit 1
