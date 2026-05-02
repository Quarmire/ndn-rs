#!/usr/bin/env bash
# Witness test for audit finding N.02 — `ReassemblyBuffer` keys pending
# fragments by `Sequence` only, so two peers on a multi-access face
# (UDP multicast / Ethernet / BLE) using the same first-fragment
# Sequence value collide.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.02
# Severity:    MAJOR (correctness on multi-access links)
# Spec ref:    NFD `daemon/face/lp-reassembler.hpp:134-137` keys by
#              `(EndpointId, Sequence)`.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - n02_per_endpoint_keying_isolates_overlapping_sequences
#              Two simulated peers feed `seq=42` first fragments with
#              distinct endpoint identifiers; post-fix they produce two
#              pending entries and reassemble independently.
#
# Deferred:    The face → engine wire-up that derives a stable per-source
#              `endpoint_id` from `FaceAddr` for multi-access faces is a
#              follow-up; today the engine passes `0` (unicast assumption)
#              from `TlvDecodeStage::process_lp`. The data-structure-side
#              collision fix is in place so the wire-up is the only
#              remaining step.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet n02_ \
        >/tmp/n02_witness.log 2>&1; then
    echo "ok: per-endpoint reassembly key isolates overlapping sequences"
else
    echo "FAIL: ReassemblyBuffer collides on shared Sequence value"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.02 RESOLVED 2026-05-02 (data-structure; multi-access wire-up follow-up) ==="
    exit 0
else
    echo
    echo "=== N.02 EXPECTED-FAIL — ReassemblyBuffer keyed by Sequence only ==="
    [ -f /tmp/n02_witness.log ] && cat /tmp/n02_witness.log
    exit 1
fi
