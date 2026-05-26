#!/usr/bin/env bash
# Witness — TCS.06: SyncBundle anchor-add wire payload round-trips.
#
# The wire shape SVS delivers between siblings carries a context name, anchor
# set, schema blob, and CA endpoint deltas through encode_wire/decode_wire
# unchanged. Sibling-device propagation over an actual SVS group is wired in a
# follow-up; the wire-shape witness here pins the payload contract.
# Witness (RUST-UNIT, ndn-identity, tests/synthesis_phase2.rs):
#   - tcs06_context_sync_anchor_propagation
#
# Expected before Phase 2: FAIL. After Phase 2: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-identity --test synthesis_phase2 --quiet -- \
        tcs06_context_sync_anchor_propagation \
        >/tmp/tcs06_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/tcs06_witness.log; then
    echo "=== TCS.06 PASS — anchor delta survives wire round-trip ==="
    grep -E "test result|running" /tmp/tcs06_witness.log | tail -n 2
    exit 0
else
    echo "=== TCS.06 FAIL — anchor delta wire round-trip broken ==="
    cat /tmp/tcs06_witness.log
    exit 1
fi
