#!/usr/bin/env bash
# Witness for EMB-10 — Data decision single-sourced (decide_data).
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 5e
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core exposes the sans-IO Data decision
#       (`decide_data` + `DataDecision`).
#   (b) GREP-PROOF — the embedded forwarder's Data path drives decide_data
#       rather than calling PitStore::satisfy directly in the shell.
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
FWD=crates/extension/ndn-embedded/src/forwarder.rs

# (a) core exposes the Data decision.
if [ -z "$CRATE_DIR" ] \
    || ! grep -rqE 'fn[[:space:]]+decide_data' "$CRATE_DIR/src" 2>/dev/null \
    || ! grep -rqE 'enum[[:space:]]+DataDecision' "$CRATE_DIR/src" 2>/dev/null; then
    echo "FAIL: ndn-fwd-core lacks decide_data / DataDecision" >&2
    fail=1
fi

# (b) embedded Data path drives decide_data.
if ! grep -qE 'decide_data' "$FWD"; then
    echo "FAIL: $FWD does not drive ndn_fwd_core::pipeline::decide_data" >&2
    fail=1
fi

# (c) tests pass.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core -p ndn-embedded"
    if ! cargo test --quiet -p ndn-fwd-core -p ndn-embedded >/dev/null 2>&1; then
        echo "FAIL: ndn-fwd-core / ndn-embedded tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-10 — Data decision single-sourced in ndn-fwd-core (decide_data)."
exit "$fail"
