#!/usr/bin/env bash
# Audit witness — F.04.
#
# Finding:     `StrategyStage` forwarded `ctx.raw_bytes` and the
#              `satisfy` path emitted bare TLV when no `PitToken`
#              was attached.  NFD's GenericLinkService always
#              wraps in LpPacket on network faces; bare TLV is
#              wire-legal but loses per-hop headers
#              (CongestionMark, NextHopFaceId, IncomingFaceId,
#              PitToken on Data) on net→net forwards.
# Witness:     GREP-PROOF — egress branches in
#              `crates/spec/ndn-engine/src/dispatcher/outbound.rs`
#              now wrap non-local egress in LpPacket via
#              `encode_lp_packet`, the same wrapper NFD's link
#              service uses.  Local-scope faces keep bare TLV.
# Spec ref:    NDNLPv2 GenericLinkService (NFD
#              `daemon/face/generic-link-service.cpp`).
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

OUT="crates/spec/ndn-engine/src/dispatcher/outbound.rs"
if ! grep -q 'encode_lp_packet(&ctx.raw_bytes)' "$OUT"; then
    echo "FAIL: Send branch does not LP-wrap non-local Interest egress"
    exit 1
fi
if ! grep -q 'None if is_nonlocal => ndn_packet::lp::encode_lp_packet(&data_bytes)' "$OUT"; then
    echo "FAIL: satisfy() does not LP-wrap non-local Data egress"
    exit 1
fi

if ! cargo build -p ndn-engine --quiet 2>&1 | tail -3; then
    echo "FAIL: build broken"
    exit 1
fi

echo "=== F.04 RESOLVED — non-local egress wrapped in LpPacket ==="
