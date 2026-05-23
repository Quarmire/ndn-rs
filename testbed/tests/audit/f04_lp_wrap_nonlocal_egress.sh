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
# Witness:     GREP-PROOF — since the egress-framing unification, LP framing
#              for non-local (uses_lp) faces happens in ONE place,
#              `crate::engine::frame_with_intent` (the dispatcher enqueues bare
#              payload + EgressIntent; the send loop frames once). Assert that
#              single framer LP-wraps uses_lp egress, and that the dispatcher no
#              longer frames inline.
# Spec ref:    NDNLPv2 GenericLinkService (NFD
#              `daemon/face/generic-link-service.cpp`).
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

OUT="crates/ndn-engine/src/dispatcher/outbound.rs"
ENGINE="crates/ndn-engine/src/engine.rs"

# The single egress framer exists and LP-wraps uses_lp faces (with headers).
grep -q 'fn frame_with_intent' "$ENGINE" \
    || { echo "FAIL: frame_with_intent (single egress framer) missing"; exit 1; }
if ! grep -A20 'fn frame_with_intent' "$ENGINE" | grep -q 'encode_lp_with_headers(payload'; then
    echo "FAIL: frame_with_intent does not LP-wrap uses_lp egress"
    exit 1
fi
# Framing is unified: the dispatcher must NOT encode LP inline anymore.
if grep -qE 'encode_lp_packet\(&ctx\.raw_bytes\)|encode_lp_packet\(&data_bytes\)' "$OUT"; then
    echo "FAIL: dispatcher still frames inline — framing must be unified in frame_with_intent"
    exit 1
fi

if ! cargo build -p ndn-engine --quiet 2>&1 | tail -3; then
    echo "FAIL: build broken"
    exit 1
fi

echo "=== F.04 RESOLVED — non-local egress wrapped in LpPacket ==="
