#!/usr/bin/env bash
# Witness: G.04 partial — NLSR Dijkstra link-state routing calculator.
#
# Finding:    G.04 — NLSR routing calculation absent
# Severity:   BLOCKER (testbed-join gate)
# Spec ref:   NLSR/src/route/routing-calculator-link-state.cpp
# Witnesses:  Unit tests confirm:
#             1. Basic triangle topology (A-B-C) produces multi-path routes
#                matching C++ NLSR test-routing-calculator-link-state.cpp::Basic.
#             2. Asymmetric link costs are corrected to the higher value.
#             3. A broken link (NON_ADJACENT_COST) removes paths through it.
#             4. Source router absent yields an empty routing table.
#             5. The watch channel fires when recompute() is called.
#
# Expected routes for A in the triangle A──5──B──17──C──10──A:
#   to B: via B-face (cost 5)  and via C-face (cost 10+17=27)
#   to C: via C-face (cost 10) and via B-face (cost 5+17=22)
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

echo "=== G.04 Dijkstra routing calculator witness ==="
echo "Running: cargo test -p ndn-routing nlsr::routing_table"
cd "$REPO_ROOT"
cargo test -p ndn-routing nlsr::routing_table 2>&1
echo "=== G.04 Dijkstra PASS ==="
