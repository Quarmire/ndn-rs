#!/usr/bin/env bash
# Witness for EMB-09 — PIT write surface keyed by component slices.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 5e (PIT-key resolution)
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — PitStore exposes the write surface (record_pending,
#       satisfy, discard_pending), all keyed by `&[&[u8]]` component slices.
#   (b) GREP-PROOF — the embedded forwarder drives the PIT write surface
#       instead of hand-rolling name hashing in the shell: record_pending and
#       discard_pending directly, and satisfy via pipeline::decide_data (the
#       obsolete name_hash_from_components helper is gone).
#   (c) RUST-UNIT  — ndn-fwd-core + ndn-embedded tests pass, including the
#       strengthened data_satisfies_pit assertion (Data reaches the recorded
#       downstream face and the entry is consumed).
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
STORE=$(find "$CRATE_DIR/src" -name store.rs 2>/dev/null | head -1)
FWD=crates/extension/ndn-embedded/src/forwarder.rs

# (a) PitStore write surface, slice-keyed.
for m in record_pending satisfy discard_pending; do
    grep -qE "fn[[:space:]]+$m" "$STORE" 2>/dev/null \
        || { echo "FAIL: PitStore lacks $m" >&2; fail=1; }
done
grep -qE 'components:[[:space:]]*&\[&\[u8\]\]' "$STORE" 2>/dev/null \
    || { echo "FAIL: PitStore write surface is not keyed by &[&[u8]] slices" >&2; fail=1; }

# (b) forwarder drives the trait; the old shell-side hasher is gone.
#     record_pending + discard_pending are called directly; satisfy is driven
#     through the core's decide_data orchestrator (the Data path).
for m in record_pending discard_pending; do
    grep -qE "\.$m\(" "$FWD" 2>/dev/null \
        || { echo "FAIL: $FWD does not use PitStore::$m" >&2; fail=1; }
done
grep -qE 'decide_data' "$FWD" 2>/dev/null \
    || { echo "FAIL: $FWD does not drive PitStore::satisfy via decide_data" >&2; fail=1; }
if grep -qE 'fn[[:space:]]+name_hash_from_components' "$FWD" 2>/dev/null; then
    echo "FAIL: $FWD still hand-rolls name_hash_from_components" >&2
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

[ "$fail" -eq 0 ] && echo "PASS: EMB-09 — PIT write surface keyed by component slices; insert/satisfy agree."
exit "$fail"
