#!/usr/bin/env bash
# Witness for EMB-07 — Interest decision tree single-sourced (sans-IO pipeline).
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2, § 5d
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core exposes the sans-IO Interest decision
#       (`decide_interest` + `InterestDecision` + `DropReason`).
#   (b) GREP-PROOF — the embedded forwarder drives that decision rather than
#       hand-rolling the loop/hop-limit/route/split-horizon checks inline.
#   (c) RUST-UNIT  — ndn-fwd-core + ndn-embedded tests pass (the decision is
#       behaviour-preserving on the embedded path).
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
FWD=crates/ndn-embedded/src/forwarder.rs

# (a) core exposes the decision surface.
if [ -z "$CRATE_DIR" ] \
    || ! grep -rqE 'fn[[:space:]]+decide_interest' "$CRATE_DIR/src" 2>/dev/null \
    || ! grep -rqE 'enum[[:space:]]+InterestDecision' "$CRATE_DIR/src" 2>/dev/null \
    || ! grep -rqE 'enum[[:space:]]+DropReason' "$CRATE_DIR/src" 2>/dev/null; then
    echo "FAIL: ndn-fwd-core lacks decide_interest / InterestDecision / DropReason" >&2
    fail=1
fi

# (b) embedded drives the shared decision.
if ! grep -qE 'decide_interest' "$FWD"; then
    echo "FAIL: $FWD does not use ndn_fwd_core::pipeline::decide_interest" >&2
    fail=1
fi

# (c) behaviour-preserving: tests pass.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core -p ndn-embedded"
    if ! cargo test --quiet -p ndn-fwd-core -p ndn-embedded >/dev/null 2>&1; then
        echo "FAIL: ndn-fwd-core / ndn-embedded tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-07 — Interest decision tree single-sourced in ndn-fwd-core."
exit "$fail"
