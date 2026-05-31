#!/usr/bin/env bash
# Witness — CTX.16: clockless degradation.
#
# A node with no reliable wall-clock still enforces validity: it refuses an
# older context version (monotonic version compare) and rejects a reused token
# (single-use set membership) — neither check consults a clock. Hub init also
# round-trips through TOFU. See trust-context-model-2026-05-25.md §16 (N4).
# Witnesses (RUST-UNIT, ndn-cert, tests/ctx_phase5_hub.rs):
#   - ctx16_clockless_monotonic_version_and_single_use
#   - ctx16_hub_init_roundtrips_through_tofu
#
# Expected before Phase 5: FAIL. After Phase 5: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase5_hub --quiet -- \
        ctx16_clockless_monotonic_version_and_single_use \
        ctx16_hub_init_roundtrips_through_tofu \
        >/tmp/ctx16_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx16_witness.log; then
    echo "=== CTX.16 PASS — clockless monotonic version + single-use enforced ==="
    grep -E "test result|running" /tmp/ctx16_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.16 FAIL — clockless degradation broken ==="
    cat /tmp/ctx16_witness.log
    exit 1
fi
