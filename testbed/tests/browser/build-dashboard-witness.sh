#!/usr/bin/env bash
# Build the wasm-bindgen witness bundle for `wsmgmt_wire.spec.ts`.
#
# Output: fixture-page/dashboard-witness-pkg/{dashboard_witness.js,
#         dashboard_witness_bg.wasm, ...} (gitignored).
#
# The bundle exposes `ndn-dashboard`'s `WsMgmtClient` to JS via
# wasm-bindgen so Playwright can drive `/localhost/nfd/...` against a
# real `ndn-fwd` over a real browser WebSocket. Mirrors the shape of
# `build-shared-engine.sh`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/testbed/tests/browser/fixture-page/dashboard-witness-pkg"

cd "$REPO_ROOT"
exec wasm-pack build crates/tooling/ndn-dashboard \
  --target no-modules \
  --out-dir "$OUT_DIR" \
  --out-name dashboard_witness \
  -- --no-default-features --features witness-export
