#!/usr/bin/env bash
# Witness — C-COMPUTE-05: ComputeExecutor seam + WasmExecutor (wasm-exec).
#
# Finding:   docs/notes/compute-design-2026-05-21.md § 12 (C-COMPUTE-05)
# Severity:  MAJOR (feature contract)
# Witnesses: RUST-UNIT (requires --features wasm-exec):
#              - wasm_executor_echoes_input        (memory ABI round-trip)
#              - wasm_executor_traps_on_fuel_exhaustion (fuel guard)
#              - wasm_executor_function_round_trip  (executor through engine)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if ! cargo test -p ndn-compute --features wasm-exec --test wasm_exec --quiet \
        >/tmp/compute05_witness.log 2>&1; then
    fail=1
fi
if ! cargo test -p ndn-compute --features wasm-exec --test end_to_end --quiet \
        wasm_executor_function_round_trip \
        >>/tmp/compute05_witness.log 2>&1; then
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== C-COMPUTE-05 PASS — WasmExecutor sandbox + fuel + engine round-trip ==="
    exit 0
fi
echo "=== C-COMPUTE-05 FAIL ==="
cat /tmp/compute05_witness.log
exit 1
