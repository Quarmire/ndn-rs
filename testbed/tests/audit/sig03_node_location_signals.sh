#!/usr/bin/env bash
# Witness for SIG-03 — node-level (GPS/position) signals flow end to end.
#
# Severity:    cross-layer / geographic-strategy foundation (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md
# Witnesses:
#   (a) GREP-PROOF — the taxonomy carries node position (NodeSignals.position
#       as integer-only GeoPos), and concrete location backends exist: a
#       stationary FixedLocationBackend and a browser-geolocation-friendly
#       SharedLocationBackend fed via a Send+Sync LocationHandle.
#   (b) RUST-UNIT  — a position pushed through a backend reaches the store via
#       SignalView::node().position (both fixed and shared/async paths).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
CORE=crates/ndn-signals-core/src/lib.rs
SRC=crates/ndn-signal-sources/src/lib.rs

grep -qE 'pub struct GeoPos' "$CORE" 2>/dev/null || { echo "FAIL: no GeoPos in taxonomy" >&2; fail=1; }
grep -qE 'pub position: Option<GeoPos>' "$CORE" 2>/dev/null || { echo "FAIL: NodeSignals has no position" >&2; fail=1; }
grep -qE 'pub struct FixedLocationBackend' "$SRC" 2>/dev/null || { echo "FAIL: no FixedLocationBackend (gps-fixed)" >&2; fail=1; }
grep -qE 'pub struct SharedLocationBackend' "$SRC" 2>/dev/null || { echo "FAIL: no SharedLocationBackend (browser path)" >&2; fail=1; }
grep -qE 'pub struct LocationHandle' "$SRC" 2>/dev/null || { echo "FAIL: no LocationHandle (push handle)" >&2; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-signal-sources (fixed + shared location)"
    if ! cargo test --quiet -p ndn-signal-sources >/dev/null 2>&1; then
        echo "FAIL: location backend tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-03 — node position (GeoPos) flows backend->source->store; fixed + browser-push location backends."
exit "$fail"
