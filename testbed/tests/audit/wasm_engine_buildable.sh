#!/usr/bin/env bash
# Witness for Phase 1.5 — ndn-engine builds for wasm32-unknown-unknown.
#
# Finding:     see docs/notes/wasm-readiness-audit-2026-05-07.md § 4
# Severity:    BLOCKER for Phase 4 (Dioxus browser demo)
# Witnesses:   `cargo build --target wasm32-unknown-unknown -p ndn-engine`
#              succeeds (exit 0). Today this fails because ndn-engine
#              hard-deps ndn-discovery, ndn-security, and ndn-face-native, all
#              of which pull in tokio::net / ring / std::fs.
#
# Expected today: FAIL (exit 1). After Phase 1.5 deps refactor, this
# script should exit 0 without changes.
#
# Exit codes:
#   0 — PASS (ndn-engine compiles for wasm32)
#   1 — FAIL (compile fails — expected pre-fix)
#   2 — SKIP (rustup wasm32 target missing)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    echo "SKIP: wasm32-unknown-unknown target not installed (rustup target add wasm32-unknown-unknown)" >&2
    exit 2
fi

if cargo build --target wasm32-unknown-unknown -p ndn-engine 2>&1; then
    echo "PASS: ndn-engine builds for wasm32-unknown-unknown"
    exit 0
else
    echo "FAIL: ndn-engine does not build for wasm32-unknown-unknown" >&2
    exit 1
fi
