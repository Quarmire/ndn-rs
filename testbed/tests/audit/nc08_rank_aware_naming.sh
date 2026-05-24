#!/usr/bin/env bash
# Witness — NC.08: F2 rank-aware admission + coded-request naming (§4a, §5).
#
# Under fork (B), distinct `_req=<j>` components are distinct names, so K
# coded requests are distinct (not aggregated) by construction — the naming
# round-trip pins this. Rank-aware admission drops a linearly-dependent coded
# packet (no new rank) — the cheapest pollution dampener and a cache-occupancy
# guard. (The engine-path NC.05 separately shows K distinct requests each
# answered by a distinct innovative combination.)
#
# Witnesses (RUST-UNIT, feature `f2-recode`):
#   - recode::tests::rank_basis_drops_dependent_vectors
#   - recode::tests::request_name_round_trips
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode --quiet -- \
        rank_basis_drops_dependent_vectors \
        request_name_round_trips \
        >/tmp/nc08_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc08_witness.log; then
    echo "=== NC.08 PASS — rank-aware drop + distinct coded-request names ==="
    grep -E "test result|running" /tmp/nc08_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.08 FAIL — rank-aware/naming witness failed ==="
    cat /tmp/nc08_witness.log
    exit 1
fi
