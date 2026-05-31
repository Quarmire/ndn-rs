#!/usr/bin/env bash
# Witness — CTX.14: advert privacy + off-by-default.
#
# A cold-discovery advert exposes only an opaque anchor fingerprint, never the
# namespace in cleartext, on the link-local /localhop/trust-context prefix; and
# advertising is off by default. A passive listener learns nothing. See N3.
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase4_onboarding.rs):
#   - ctx14_advert_hides_namespace_off_by_default
#
# Expected before Phase 4: FAIL. After Phase 4: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase4_onboarding --quiet -- \
        ctx14_advert_hides_namespace_off_by_default \
        >/tmp/ctx14_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx14_witness.log; then
    echo "=== CTX.14 PASS — advert hides namespace; advertising off by default ==="
    grep -E "test result|running" /tmp/ctx14_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.14 FAIL — advert leaks namespace or advertises by default ==="
    cat /tmp/ctx14_witness.log
    exit 1
fi
