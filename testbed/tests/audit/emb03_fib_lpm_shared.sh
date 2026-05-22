#!/usr/bin/env bash
# Witness for EMB-03 — FIB longest-prefix-match lives once, in ndn-fwd-core.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2 (step 2)
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core exposes a longest-prefix-match (LPM) routine.
#   (b) GREP-PROOF — ndn-embedded/src/fib.rs no longer hand-rolls its own LPM
#       scan; it delegates to ndn-fwd-core. FIB LPM is a pure, already-sync
#       function on both sides — the cheapest piece to de-duplicate first.
#
# Reverify recipe: GREP-PROOF. Runs in any checkout; no Docker.
#
# Expected today: FAIL (exit 1) — fib.rs:67 hand-rolls LPM; core absent.
#
# Exit codes: 0 PASS · 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)
EMB_FIB=crates/extension/ndn-embedded/src/fib.rs

if [ -z "$CRATE_DIR" ]; then
    echo "FAIL: ndn-fwd-core not found (EMB-01 must pass first)" >&2
    fail=1
elif ! grep -rqiE 'longest.?prefix|fn[[:space:]]+lpm|lpm_lookup' "$CRATE_DIR/src" 2>/dev/null; then
    echo "FAIL: ndn-fwd-core exposes no longest-prefix-match routine" >&2
    fail=1
fi

# The embedded FIB must delegate, not hand-roll. Today fib.rs contains the scan.
if [ -f "$EMB_FIB" ]; then
    if ! grep -qE 'ndn_fwd_core' "$EMB_FIB"; then
        echo "FAIL: $EMB_FIB does not reference ndn_fwd_core (still hand-rolls LPM)" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-03 — FIB LPM shared via ndn-fwd-core; ndn-embedded delegates."
exit "$fail"
