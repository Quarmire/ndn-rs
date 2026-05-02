#!/usr/bin/env bash
# Witness test for audit finding N.03 — `LpPacket::decode` accepts
# duplicates of non-repeatable headers and arbitrary header order.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.03
# Severity:    MAJOR (decoder strictness)
# Spec ref:    NDNLPv2 §"Element Order" — LP headers MUST be in ascending
#              TLV-TYPE order, with `Fragment` last; repeated occurrences
#              MUST be consecutive and only `Ack` (0x0344) is repeatable.
#              ndn-cxx `lp/packet.cpp:128-135` enforces the same rule.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - n03_lp_decode_rejects_duplicate_incoming_face_id
#                - n03_lp_decode_rejects_out_of_order_headers
#                - n03_lp_decode_accepts_repeated_acks (sanity)
#                - n03_lp_decode_rejects_header_after_fragment
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet n03_ \
        >/tmp/n03_witness.log 2>&1; then
    echo "ok: LpPacket::decode enforces sort-order + repeatability"
else
    echo "FAIL: LpPacket::decode accepts malformed LP header layouts"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.03 RESOLVED — LP header sort-order + repeatability enforced ==="
    exit 0
else
    echo
    echo "=== N.03 EXPECTED-FAIL — LP header order / repeatability not enforced ==="
    [ -f /tmp/n03_witness.log ] && cat /tmp/n03_witness.log
    exit 1
fi
