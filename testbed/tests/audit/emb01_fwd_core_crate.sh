#!/usr/bin/env bash
# Witness for EMB-01 — shared sans-IO forwarding core crate exists.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — crate `ndn-fwd-core` exists with a Cargo.toml.
#   (b) GREP-PROOF — it is `#![no_std]` (never gains a `std` feature).
#   (c) GREP-PROOF — `alloc` is an *optional* feature, not unconditional.
#
# Reverify recipe: GREP-PROOF. Runs in any checkout; no Docker.
#
# Expected today: FAIL (exit 1) — the crate does not exist yet.
# After the pure-fn extraction lands, exits 0 without script changes.
#
# Exit codes: 0 PASS · 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)

if [ -z "$CRATE_DIR" ] || [ ! -f "$CRATE_DIR/Cargo.toml" ]; then
    echo "FAIL: ndn-fwd-core crate not found (expected crates/**/ndn-fwd-core/Cargo.toml)" >&2
    exit 1
fi

LIB="$CRATE_DIR/src/lib.rs"
if ! grep -qE '^\s*#!\[no_std\]' "$LIB" 2>/dev/null; then
    echo "FAIL: $LIB is not #![no_std]" >&2
    fail=1
fi

# `alloc` must be a declared feature (optional), and there must be no `std` feature.
if ! grep -qE '^\s*alloc\s*=' "$CRATE_DIR/Cargo.toml"; then
    echo "FAIL: $CRATE_DIR/Cargo.toml declares no optional \`alloc\` feature" >&2
    fail=1
fi
if grep -qE '^\s*std\s*=' "$CRATE_DIR/Cargo.toml"; then
    echo "FAIL: ndn-fwd-core must never gain a \`std\` feature" >&2
    fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-01 — ndn-fwd-core exists, no_std, alloc-optional ($CRATE_DIR)."
exit "$fail"
