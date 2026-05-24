#!/usr/bin/env bash
# Witness — NC.14: F3 broadcast-link wiring (CopeBroadcastLink over a face).
#
# The cope core is driven over a real broadcast Transport: the relay frames
# natives, XOR-codes those bound for different next-hops (given reception
# reports), and broadcasts; receivers decode via overheard side-info. Canonical
# Alice↔Bob-via-relay over an in-memory broadcast bus, plus the uncoded
# fallback without reports. Next-hop is supplied by the caller (the forwarding-
# plane layering constraint); engine-egress + report-protocol are seams.
#
# Seam A (next-hop feed): per-neighbor CopeMemberFace.send_bytes feeds the
# link with its neighbor id = the out-FaceId the engine chose (no PIT change).
# Seam B (reception reports): announce() broadcasts held ids; recv_event()
# applies a neighbor's report to the coder automatically.
#
# Witnesses (RUST-UNIT, feature `f3-link-face`):
#   - cope::tests::wire_framing_round_trips
#   - cope_face::tests::alice_bob_relay_over_broadcast_faces
#   - cope_face::tests::falls_back_to_native_without_reports
#   - cope_face::tests::member_faces_feed_next_hop_into_coding   (seam A)
#   - cope_face::tests::reception_report_announce_and_apply       (seam B)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f3-link-face --quiet -- \
        wire_framing_round_trips \
        alice_bob_relay_over_broadcast_faces \
        falls_back_to_native_without_reports \
        member_faces_feed_next_hop_into_coding \
        reception_report_announce_and_apply \
        >/tmp/nc14_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc14_witness.log; then
    echo "=== NC.14 PASS — COPE codes/decodes over real broadcast faces ==="
    grep -E "test result|running" /tmp/nc14_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.14 FAIL — broadcast-link witness failed ==="
    cat /tmp/nc14_witness.log
    exit 1
fi
