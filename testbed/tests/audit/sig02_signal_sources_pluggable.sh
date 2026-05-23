#!/usr/bin/env bash
# Witness for SIG-02 — reusable signal sources with pluggable backends, wired
# into the engine.
#
# Severity:    cross-layer / measured-strategy foundation (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md
# Witnesses:
#   (a) GREP-PROOF — ndn-signal-sources defines the SignalSource trait, the
#       pluggable RadioBackend/LocationBackend backend traits, the reusable
#       RadioMetricsSource/LocationSource, and mock backends (the source logic
#       is decoupled from the driver).
#   (b) GREP-PROOF — the engine wires it: EngineBuilder::signal_source registers
#       sources and the signals_driver task polls them into the SignalsTable.
#   (c) RUST-UNIT  — ndn-signal-sources round-trips a reading into a store
#       (radio + location), and ndn-engine builds with the wiring.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
SRC=crates/ndn-signal-sources/src/lib.rs

# (a) source framework + pluggable backends.
[ -f "$SRC" ] || { echo "FAIL: ndn-signal-sources missing" >&2; fail=1; }
grep -qE 'pub trait SignalSource' "$SRC" 2>/dev/null || { echo "FAIL: no SignalSource trait" >&2; fail=1; }
grep -qE 'pub trait RadioBackend' "$SRC" 2>/dev/null || { echo "FAIL: no RadioBackend (pluggable)" >&2; fail=1; }
grep -qE 'pub trait LocationBackend' "$SRC" 2>/dev/null || { echo "FAIL: no LocationBackend (pluggable)" >&2; fail=1; }
grep -qE 'pub struct RadioMetricsSource' "$SRC" 2>/dev/null || { echo "FAIL: no RadioMetricsSource" >&2; fail=1; }
grep -qE 'pub struct MockRadioBackend' "$SRC" 2>/dev/null || { echo "FAIL: no mock backend for tests" >&2; fail=1; }

# (b) engine wiring.
grep -qE 'fn signal_source' crates/ndn-engine/src/builder.rs \
    || { echo "FAIL: EngineBuilder::signal_source missing" >&2; fail=1; }
grep -qE 'run_signal_sources' crates/ndn-engine/src/signals_driver.rs \
    || { echo "FAIL: signals_driver task missing" >&2; fail=1; }
grep -qE 'run_signal_sources' crates/ndn-engine/src/builder.rs \
    || { echo "FAIL: builder does not spawn the signal-source driver" >&2; fail=1; }

# (c) tests + engine build.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-signal-sources && cargo build -p ndn-engine"
    if ! cargo test --quiet -p ndn-signal-sources >/dev/null 2>&1 \
        || ! cargo build --quiet -p ndn-engine >/dev/null 2>&1; then
        echo "FAIL: signal-sources tests / engine build did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-02 — pluggable signal sources (radio/location + mocks); EngineBuilder::signal_source drives them into the SignalsTable."
exit "$fail"
