#!/usr/bin/env bash
# Witness — NC.25: CopeMesh neighbor-sync driver fed by a routing stream.
#
# CopeMesh::spawn_neighbor_sync reconciles the installed member faces from a
# watch<Vec<NeighborId>> a routing protocol feeds (e.g. NLSR adjacency_watch
# mapped to neighbor ids). A reported set installs faces; a later set evicts
# dropped neighbors and installs new ones — through the real engine. ndn-coding
# stays decoupled from the routing crate; the adapter is integration-layer glue.
#
# Witness (RUST-UNIT, feature `f3-link-mesh`):
#   - tests/cope_mesh.rs::neighbor_sync_driver_tracks_routing_stream
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f3-link-mesh --test cope_mesh --quiet -- \
        neighbor_sync_driver_tracks_routing_stream \
        >/tmp/nc25_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc25_witness.log; then
    echo "=== NC.25 PASS — mesh tracks routing neighbor stream ==="
    grep -E "test result|running" /tmp/nc25_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.25 FAIL ==="; cat /tmp/nc25_witness.log; exit 1
fi
