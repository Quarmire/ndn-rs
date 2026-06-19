#!/usr/bin/env bash
# Witness test for audit finding D.09 — `BestRouteStrategy` provides no
# Nack-retry hook, so an Interest whose first upstream Nacks is dropped
# instead of retried on another FIB nexthop.
#
# Finding:     testbed/EXPECTED_FAILURES.md § D.09
# Severity:    MAJOR
# Spec ref:    NFD `daemon/fw/best-route-strategy.cpp` `afterReceiveNack`
#              → `processNack` switches upstreams when one returns Nack.
# Witnesses:   RUST-UNIT trio in `ndn-strategy::best_route::tests`:
#                - d09_on_nack_retries_another_nexthop
#                - d09_on_nack_propagates_when_exhausted
#                - d09_on_nack_propagates_when_no_fib
#
# Deferred:    Per-PIT-entry out-record tracking of which upstreams have
#              already been tried (NFD's `pit::OutRecord` / `lastNonce`).
#              Without it, two nexthops that both Nack each other can
#              ping-pong this strategy; HopLimit + PIT lifetime + nonce
#              loop detection bound the practical impact.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-strategy --lib --quiet d09_ \
        >/tmp/d09_witness.log 2>&1; then
    echo "ok: BestRouteStrategy::on_nack retries another nexthop"
else
    echo "FAIL: BestRouteStrategy uses default `Suppress` on Nack"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.09 RESOLVED — BestRouteStrategy retries another nexthop on Nack ==="
    exit 0
else
    echo
    echo "=== D.09 EXPECTED-FAIL — BestRouteStrategy has no on_nack override ==="
    [ -f /tmp/d09_witness.log ] && cat /tmp/d09_witness.log
    exit 1
fi
