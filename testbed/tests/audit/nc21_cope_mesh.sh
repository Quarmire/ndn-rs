#!/usr/bin/env bash
# Witness — NC.21: CopeMesh auto-installation from a neighbor table.
#
# From a neighbor set, CopeMesh installs one egress CopeMemberFace per neighbor
# (FaceId = neighbor id, for FIB next-hops) + a single ingress face on a live
# engine, and runs a report/flush ticker. The shared medium sees a reception
# report (announce) and a coded frame (flush) for two natives to two neighbors.
#
# Witness (RUST-UNIT, feature `f3-link-mesh`):
#   - tests/cope_mesh.rs::mesh_installs_member_faces_and_codes_over_engine
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f3-link-mesh --test cope_mesh --quiet \
        >/tmp/nc21_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc21_witness.log; then
    echo "=== NC.21 PASS — CopeMesh installs member+ingress faces, codes over engine ==="
    grep -E "test result|running" /tmp/nc21_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.21 FAIL ==="; cat /tmp/nc21_witness.log; exit 1
fi
