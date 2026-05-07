#!/usr/bin/env bash
# Witness: G.04 partial — NLSR sync wiring + three-node LSDB convergence.
#
# Finding:    G.04 — NLSR sync / routing absent
# Severity:   BLOCKER (testbed-join gate)
# Spec ref:   NLSR/src/communication/sync-logic-handler.{hpp,cpp}
#             NLSR/src/lsdb.{hpp,cpp}
# Witnesses:  Unit tests confirm:
#             1. NlsrSync::user_prefix_for builds the correct LSA user prefix.
#             2. NlsrSync::parse_update_name extracts origin_router, lsa_type,
#                and seq_no from a PSync update name.
#             3. Three-node convergence: after one simulated sync round each
#                node's LSDB holds all three NameLSAs.
#
# Live PSync interop with C++ NLSR is deferred to phase 6.
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

echo "=== G.04 sync wiring + three-node convergence witness ==="
echo "Running: cargo test -p ndn-routing nlsr::sync"
cd "$REPO_ROOT"
cargo test -p ndn-routing nlsr::sync 2>&1
echo "=== G.04 sync PASS ==="
