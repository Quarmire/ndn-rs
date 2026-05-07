#!/usr/bin/env bash
# Witness: G.04 partial — NLSR Hello protocol and adjacency state machine.
#
# Finding:    G.04 — NLSR Hello / adjacency lifecycle absent
# Severity:   BLOCKER (testbed-join gate)
# Spec ref:   NLSR/src/hello-protocol.{hpp,cpp}, NLSR/src/adjacent.hpp
# Witnesses:  Unit tests confirm Hello Interest/Data exchange drives
#             NeighborState Active/Inactive transitions and installs the
#             own AdjacencyLsa in the LSDB.
#
# Live interop with C++ NLSR is deferred to phase 6.  This script witnesses
# the Rust unit tests only.
#
# Exit codes:
#   0 — PASS (tests pass)
#   1 — FAIL (tests fail)
#   2 — SKIP (build toolchain missing)
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo not found" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

echo "=== G.04 Hello protocol witness ==="
echo "Running: cargo test -p ndn-routing nlsr::hello"
cd "$REPO_ROOT"
cargo test -p ndn-routing nlsr::hello 2>&1
echo "=== G.04 PASS ==="
