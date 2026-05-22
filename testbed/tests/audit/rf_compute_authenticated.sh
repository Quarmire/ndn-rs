#!/usr/bin/env bash
# Witness — reflexive forwarding: the authenticated leg (RICE §8 authorization).
# The node validates the consumer's signed params Data (D2) before computing.
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §6;
#            docs/notes/compute-wire-spec-2026-05-21.md §8/§9
# Witness:   RUST-UNIT in ndn-compute (tests/end_to_end.rs):
#              - reflexive_authenticated_validates_and_computes (signed D2 passes
#                the validator → computation runs)
#              - reflexive_authenticated_rejects_unsigned (unsigned D2 fails the
#                validation gate → no result computed)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-compute --test end_to_end --quiet -- \
        reflexive_authenticated_validates_and_computes \
        reflexive_authenticated_rejects_unsigned \
        >/tmp/rf_auth_witness.log 2>&1; then
    echo "=== RF auth PASS — signed-D2 validation gates reflexive compute ==="
    exit 0
fi
echo "=== RF auth FAIL ==="
cat /tmp/rf_auth_witness.log
exit 1
