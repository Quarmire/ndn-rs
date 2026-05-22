#!/usr/bin/env bash
# Witness for EMB-08 — FIB/PIT storage traits abstract the sans-IO queries.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2, § 5e
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core defines FibStore + PitStore traits and the
#       store-driven `decide_interest_with` orchestration.
#   (b) GREP-PROOF — the constrained tables implement them, and the embedded
#       forwarder drives the decision through `decide_interest_with` (so the
#       core, not the shell, performs the FIB/PIT queries).
#   (c) RUST-UNIT  — ndn-fwd-core + ndn-embedded tests pass.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)
FIB=crates/extension/ndn-embedded/src/fib.rs
PIT=crates/extension/ndn-embedded/src/pit.rs
FWD=crates/extension/ndn-embedded/src/forwarder.rs

# (a) core defines the traits + the store-driven orchestration.
if [ -z "$CRATE_DIR" ] \
    || ! grep -rqE 'trait[[:space:]]+FibStore' "$CRATE_DIR/src" 2>/dev/null \
    || ! grep -rqE 'trait[[:space:]]+PitStore' "$CRATE_DIR/src" 2>/dev/null \
    || ! grep -rqE 'fn[[:space:]]+decide_interest_with' "$CRATE_DIR/src" 2>/dev/null; then
    echo "FAIL: ndn-fwd-core lacks FibStore/PitStore/decide_interest_with" >&2
    fail=1
fi

# (b) constrained tables implement the traits; forwarder drives the decision.
grep -qE 'impl.*FibStore[[:space:]]+for' "$FIB" || { echo "FAIL: $FIB does not impl FibStore" >&2; fail=1; }
grep -qE 'impl.*PitStore[[:space:]]+for' "$PIT" || { echo "FAIL: $PIT does not impl PitStore" >&2; fail=1; }
grep -qE 'decide_interest_with' "$FWD" || { echo "FAIL: $FWD does not use decide_interest_with" >&2; fail=1; }

# (c) tests pass.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core -p ndn-embedded"
    if ! cargo test --quiet -p ndn-fwd-core -p ndn-embedded >/dev/null 2>&1; then
        echo "FAIL: ndn-fwd-core / ndn-embedded tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-08 — FIB/PIT storage traits drive the sans-IO Interest decision."
exit "$fail"
