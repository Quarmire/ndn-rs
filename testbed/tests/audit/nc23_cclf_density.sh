#!/usr/bin/env bash
# Witness — NC.23: CCLF density-aware suppression p = min(K·n, 1).
#
# An isolated node (n = 0) always forwards; suppression probability rises
# monotonically with the network-layer named-neighbor count and a dense
# neighborhood suppresses most forwards — the broadcast-storm defense. The
# embedded adapter exhibits the same behavior per egress radio.
#
# Witnesses (RUST-UNIT, ndn-strategy-cclf):
#   - election::tests::isolated_node_never_suppresses
#   - election::tests::dense_neighborhood_suppresses_often
#   - election::tests::density_scales_suppression_monotonically
#   - tests::cclf_embedded_dense_neighborhood_suppresses
#   - neighbors::tests::counts_distinct_names_per_face
#   - neighbors::tests::stale_neighbors_age_out
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-strategy-cclf --quiet -- \
        isolated_node_never_suppresses \
        dense_neighborhood_suppresses_often \
        density_scales_suppression_monotonically \
        cclf_embedded_dense_neighborhood_suppresses \
        counts_distinct_names_per_face \
        stale_neighbors_age_out \
        >/tmp/nc23_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc23_witness.log; then
    echo "=== NC.23 PASS — density suppression scales with named-neighbor count ==="
    grep -E "test result|running" /tmp/nc23_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.23 FAIL — CCLF density witness failed ==="
    cat /tmp/nc23_witness.log
    exit 1
fi
