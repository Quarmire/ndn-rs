#!/usr/bin/env bash
# Witness — NC.22: CCLF content-aware election (Chowdhury/Khan/Wang ICN '20).
#
# The forwarding timer t = T/w with w = β·CCS + (1-β)·LS — higher content
# connectivity (CCS) forwards sooner; the Location Score feeds the weight when
# a position fix is present; a zero-weight node waits the full upper bound.
# CCS rolls up the C-L tree across descendant prefixes and respects NDN
# component boundaries.
#
# Witnesses (RUST-UNIT, ndn-strategy-cclf):
#   - election::tests::higher_ccs_forwards_sooner
#   - election::tests::zero_weight_uses_upper_bound
#   - election::tests::location_changes_weight_when_present
#   - cltree::tests::ccs_rolls_up_descendants
#   - cltree::tests::component_boundary_respected
#   - geo::tests::ls_rewards_progress
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
        higher_ccs_forwards_sooner \
        zero_weight_uses_upper_bound \
        location_changes_weight_when_present \
        ccs_rolls_up_descendants \
        component_boundary_respected \
        ls_rewards_progress \
        >/tmp/nc22_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc22_witness.log; then
    echo "=== NC.22 PASS — CCS/LS timer election behaves per paper ==="
    grep -E "test result|running" /tmp/nc22_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.22 FAIL — CCLF election witness failed ==="
    cat /tmp/nc22_witness.log
    exit 1
fi
