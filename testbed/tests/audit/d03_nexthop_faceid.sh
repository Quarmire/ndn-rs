#!/usr/bin/env bash
# Witness test for audit finding D.03 — `NextHopFaceId` LP header
# (NDNLPv2 0x0330) decoded into `ctx.tags` but never consulted by the
# strategy stage.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.03
# Severity:    MAJOR
# Spec ref:    NFD `daemon/fw/forwarder.cpp:205-218` — when the
#              `NextHopFaceIdTag` is present, `Forwarder::onContentStoreMiss`
#              bypasses the strategy and goes directly to
#              `onOutgoingInterest(interest, *nextHopFace, pitEntry)`.
#              ndnd performs the same override in its forwarder thread.
# Witnesses:   RUST-UNIT quartet for the pure decision helper:
#                - d03_next_hop_override_absent_falls_through
#                - d03_next_hop_override_forwards_when_face_exists
#                - d03_next_hop_override_drops_when_face_unknown
#                - d03_next_hop_override_drops_when_face_id_overflows_u32
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --lib --quiet d03_next_hop_override_ \
        >/tmp/d03_witness.log 2>&1; then
    echo "ok: d03_next_hop_override_* helper tests pass"
else
    echo "FAIL: helper decision tests"
    cat /tmp/d03_witness.log
    exit 1
fi

echo
echo "=== D.03 RESOLVED — strategy stage honours NextHopFaceId override ==="
