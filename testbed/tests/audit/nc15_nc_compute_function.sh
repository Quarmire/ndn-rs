#!/usr/bin/env bash
# Witness — NC.15: `_nc/<vector>` registered as an ndn-compute function.
#
# The deterministic named-combination mode is registered as a Tier-0
# ComputeHandler: it appears in the compute/list dataset (transparent), and a
# consumer naming the K unit vectors recovers the generation through the
# compute face. The face still serves `_nc` natively; this is the compute-
# framed realization (doctrine §8).
#
# Witness (RUST-UNIT, feature `f2-recode-compute`):
#   - tests/recode_compute.rs::nc_registered_as_compute_function
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-compute --test recode_compute --quiet \
        >/tmp/nc15_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc15_witness.log; then
    echo "=== NC.15 PASS — _nc registered as a compute function, served + listed ==="
    grep -E "test result|running" /tmp/nc15_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.15 FAIL — compute-registration witness failed ==="
    cat /tmp/nc15_witness.log
    exit 1
fi
