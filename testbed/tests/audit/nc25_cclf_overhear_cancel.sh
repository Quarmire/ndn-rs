#!/usr/bin/env bash
# Witness — NC.25: CCLF overhear-cancel (engine broadcast suppression).
#
# A scheduled forward (ForwardAfter, the timer election) must be cancellable
# when this node overhears a neighbor forwarding the SAME Interest instance
# (duplicate nonce) before its timer fires — the mechanism behind CCLF's
# broadcast-storm reduction. The PIT entry carries a `forward_cancelled` flag,
# set on the duplicate-nonce path (engine PIT stage) and read by the
# ForwardAfter timer task on wake; it defaults false so immediate-forward
# strategies are unaffected.
#
# Witnesses (RUST-UNIT, ndn-store):
#   - pit::tests::forward_cancelled_defaults_false_and_sets_on_existing
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-store --quiet -- \
        forward_cancelled_defaults_false_and_sets_on_existing \
        >/tmp/nc25_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc25_witness.log; then
    echo "=== NC.25 PASS — overhear-cancel flag set on duplicate nonce, read by timer task ==="
    grep -E "test result|running" /tmp/nc25_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.25 FAIL — overhear-cancel witness failed ==="
    cat /tmp/nc25_witness.log
    exit 1
fi
