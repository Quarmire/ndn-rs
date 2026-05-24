#!/usr/bin/env bash
# Witness — NC.23: CopeMesh fed from a live routing protocol.
#
# As routing gains/loses adjacencies, sync_neighbors reconciles the installed
# member faces: a dropped neighbor's egress face is evicted from the engine
# (its child cancel token fires), a new neighbor's face is installed, and
# add_neighbor is idempotent. Neighbor ids are engine-allocated.
#
# Witness (RUST-UNIT, feature `f3-link-mesh`):
#   - tests/cope_mesh.rs::mesh_tracks_routing_neighbor_changes
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f3-link-mesh --test cope_mesh --quiet -- \
        mesh_tracks_routing_neighbor_changes \
        >/tmp/nc23_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc23_witness.log; then
    echo "=== NC.23 PASS — CopeMesh tracks routing neighbor changes ==="
    grep -E "test result|running" /tmp/nc23_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.23 FAIL ==="; cat /tmp/nc23_witness.log; exit 1
fi
