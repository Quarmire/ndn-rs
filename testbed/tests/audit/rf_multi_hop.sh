#!/usr/bin/env bash
# Witness — reflexive forwarding multi-hop (the all-hops property). A reverse
# Interest traverses an intermediate reflexive-aware forwarder back to the
# consumer, not just the first hop.
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §2 (deployment
#            contract: every on-path forwarder must support reflexive forwarding)
# Witness:   RUST-UNIT in ndn-compute (tests/end_to_end.rs):
#              - reflexive_multi_hop_traverses_intermediate_forwarder: two
#                ndn-rs engines joined by a link; consumer on forwarder A, compute
#                node on forwarder B. I1 installs a reverse route at each hop as
#                it travels A→B; the node's reverse Interest routes back B→A→
#                consumer. Asserts the node computes the pulled params.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-compute --test end_to_end --quiet \
        reflexive_multi_hop_traverses_intermediate_forwarder \
        >/tmp/rf_multihop_witness.log 2>&1; then
    echo "=== RF multi-hop PASS — reverse Interest crosses an intermediate forwarder ==="
    exit 0
fi
echo "=== RF multi-hop FAIL ==="
cat /tmp/rf_multihop_witness.log
exit 1
