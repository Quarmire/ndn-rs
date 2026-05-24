#!/usr/bin/env bash
# Witness for finding F.15 — `[[route]] face = N` is a zero-based index into
# `[[face]]` (as documented), not a literal FaceId.
#
# Finding:    ndn-fwd installed static routes with
#             `add_nexthop(name, FaceId(route.face as u64), cost)` — treating
#             the config `face` field as a literal FaceId. But RouteConfig
#             documents it as "zero-based index into faces", and configured
#             dial faces get dynamically-allocated FaceIds (e.g. the first
#             [[face]] becomes FaceId 1, not 0), so `face = 0` pointed at the
#             wrong/nonexistent face → the route silently black-holed.
# Severity:   MINOR (operability — static routes unusable as documented).
# Type:       GREP-PROOF (+ INTEROP: 2-forwarder UDP iperf with face = 0)
#
# What this pins:
#   1. The literal `FaceId(route.face as u64)` cast is gone from route install.
#   2. Routes resolve through `face_ids_by_index` (config index -> FaceId).
#   3. RouteConfig still documents `face` as a zero-based index.
#
# Reverify recipe:
#   bash testbed/tests/audit/f15_route_face_index.sh
#   # Behavioural (manual, needs two forwarders):
#   #   fwd-A: [[face]] udp bind 127.0.0.1:7001
#   #   fwd-B: [[face]] udp remote 127.0.0.1:7001 ; [[route]] prefix=/x face=0
#   #   ndn-iperf across them — face=0 now routes (was 100% loss pre-fix).
#   Pre-fix:  exit 1 (literal cast present).
#   Post-fix: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

MAIN="binaries/ndn-fwd/src/main.rs"
CFG="crates/ndn-config/src/config.rs"
fail=0

# (1) No literal FaceId-from-index cast in route install.
if grep -qE 'FaceId\(route\.face as u64\)' "$MAIN"; then
    echo "FAIL: route install still casts the config index to a literal FaceId"
    fail=1
else
    echo "ok: no literal FaceId(route.face as u64) cast"
fi
# (2) Routes resolve via the per-config-index FaceId map.
if grep -qE 'face_ids_by_index' "$MAIN"; then
    echo "ok: route install resolves through face_ids_by_index"
else
    echo "FAIL: face_ids_by_index map not used in ndn-fwd"
    fail=1
fi
# (3) Doc still says index.
if grep -qE 'index into .?faces' "$CFG"; then
    echo "ok: RouteConfig documents face as a zero-based index"
else
    echo "FAIL: RouteConfig no longer documents face as an index"
    fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.15 PASS — [[route]] face resolves as a config index ==="
    exit 0
else
    echo "=== F.15 FAIL ==="
    exit 1
fi
