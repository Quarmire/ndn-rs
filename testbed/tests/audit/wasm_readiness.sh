#!/usr/bin/env bash
# Witness test for WASM Phase 1 — foundation + runtime crates build for wasm32-unknown-unknown.
#
# Finding:     see docs/notes/wasm-readiness-audit-2026-05-07.md
# Severity:    MAJOR
# Witnesses:   cargo check --target wasm32-unknown-unknown for all in-scope crates exits 0.
#
# Expected today: FAIL (exit 1). After Phase 1 fixes land, this script
# should exit 0 without any script body changes.
#
# Exit codes:
#   0 — PASS (all in-scope crates compile for wasm32-unknown-unknown)
#   1 — FAIL (one or more crates fail wasm32 check)
#   2 — SKIP (wasm32-unknown-unknown target not installed)
set -euo pipefail

if ! rustup target list --installed 2>/dev/null | grep -q "wasm32-unknown-unknown"; then
    echo "SKIP: wasm32-unknown-unknown target not installed (run: rustup target add wasm32-unknown-unknown)" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
FAILED=0

wasm_check() {
    local crate="$1"
    shift
    local extra_args=("$@")
    echo -n "  checking $crate ... "
    if cargo check -p "$crate" --target wasm32-unknown-unknown "${extra_args[@]}" \
            --manifest-path "$REPO_ROOT/Cargo.toml" \
            2>/dev/null; then
        echo "PASS"
    else
        echo "FAIL"
        FAILED=1
    fi
}

echo "=== WASM Phase 1 — in-scope crates ==="

# Foundation layer (no native deps; should already be clean)
wasm_check ndn-foundation-types
wasm_check ndn-tlv

# ndn-packet: use std-wasm to avoid ring (ring doesn't build for wasm32-unknown-unknown)
wasm_check ndn-packet --no-default-features --features std-wasm

# Transport: depends on ndn-packet; std-wasm feature path
wasm_check ndn-transport

# Store: dashmap/ring/lru are cfg-gated to non-wasm already; ndn-packet must use std-wasm
wasm_check ndn-store

# Strategy: no tokio in non-dev deps; depends on ndn-store
wasm_check ndn-strategy

# Runtime trait crate (new in Phase 1)
wasm_check ndn-runtime

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "PASS: all in-scope crates compile for wasm32-unknown-unknown"
    exit 0
else
    echo "FAIL: one or more in-scope crates do not compile for wasm32-unknown-unknown"
    exit 1
fi
