#!/usr/bin/env bash
# Witness — reflexive forwarding §5: end-to-end RICE I1->I2->D2->D1 and the
# ndn-compute §8 layer (ComputeService::function_reflexive).
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §5;
#            docs/notes/compute-wire-spec-2026-05-21.md §8
# Witness:   RUST-UNIT in ndn-compute (tests/end_to_end.rs):
#              - reflexive_function_end_to_end: a consumer sends an Interest with
#                a reflexive name and no params in the name; the node pulls the
#                params back over the reverse path (I2/D2), computes, and answers
#                (D1). Asserts the node returns the sum of the pulled params.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-compute --test end_to_end --quiet \
        reflexive_function_end_to_end \
        >/tmp/rf_compute_witness.log 2>&1; then
    echo "=== RF §5 PASS — I1->I2->D2->D1 reflexive compute end-to-end ==="
    exit 0
fi
echo "=== RF §5 FAIL ==="
cat /tmp/rf_compute_witness.log
exit 1
