#!/usr/bin/env bash
# Witness — NC.12: F3 link-layer inter-flow (COPE-style) coding core.
#
# A relay XORs native frames destined for different next-hops into one
# broadcast frame; each recipient, having overheard the others, XORs them out
# to recover its own (the canonical Alice↔Bob-via-relay saving). Without
# overhearing the relay cannot safely combine; a node missing >1 member can't
# decode. Pure XOR core (feature `f3-link`); face-driver wiring is the seam.
#
# Witnesses (RUST-UNIT, feature `f3-link`):
#   - cope::tests::alice_bob_relay_xor
#   - cope::tests::not_codeable_without_overhearing
#   - cope::tests::three_way_coding_and_partial_failure
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f3-link --quiet cope:: \
        >/tmp/nc12_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc12_witness.log; then
    echo "=== NC.12 PASS — COPE inter-flow XOR codes and decodes via overhearing ==="
    grep -E "test result|running" /tmp/nc12_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.12 FAIL — COPE inter-flow witness failed ==="
    cat /tmp/nc12_witness.log
    exit 1
fi
