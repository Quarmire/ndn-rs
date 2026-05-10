#!/usr/bin/env bash
# Phase 6: build the SharedWorker wasm bundle that the
# `sharedworker_*.spec.ts` witnesses load.
#
# Output: fixture-page/sw-pkg/{shared_engine.js, shared_engine_bg.wasm, ...}
# (gitignored — wasm-pack writes its own `.gitignore` containing `*`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/testbed/tests/browser/fixture-page/sw-pkg"

cd "$REPO_ROOT"
exec wasm-pack build crates/research/dioxus-demo \
  --target no-modules \
  --out-dir "$OUT_DIR" \
  --out-name shared_engine \
  -- --no-default-features --features shared-engine
