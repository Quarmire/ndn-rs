#!/usr/bin/env bash
# Witness for EMB-14 — embedded forwarder enacts an action LIST (multi-face /
# ForwardAfter / suppress), the prerequisite for shared strategies.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md (strategy seam, step 3)
# Severity:    embedded forwarder generalization (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core defines the shared ForwardAction vocabulary
#       (Now / After) that strategies emit.
#   (b) GREP-PROOF — the embedded forwarder enacts a list (`fn enact`), drains
#       scheduled forwards in run_one_tick(faces), and supports overhear
#       suppression (feature `sched`: PendingForward + overhear).
#   (c) RUST-UNIT — default tests pass (incl. the multicast enact test) and the
#       `sched` tests pass (After fires on the tick; overhearing suppresses).
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

# (a) shared action vocabulary.
grep -rqE 'enum ForwardAction' "$CRATE_DIR/src" 2>/dev/null || { echo "FAIL: no ForwardAction in ndn-fwd-core" >&2; fail=1; }
grep -rqE 'Now\(F\)|Now\(' "$CRATE_DIR/src/pipeline.rs" 2>/dev/null || { echo "FAIL: ForwardAction lacks Now" >&2; fail=1; }
grep -rqE 'After\(F, u32\)|After\(' "$CRATE_DIR/src/pipeline.rs" 2>/dev/null || { echo "FAIL: ForwardAction lacks After" >&2; fail=1; }

# (b) embedded enacts a list + schedules + suppresses.
grep -qE 'fn enact' "$FWD" || { echo "FAIL: forwarder has no enact()" >&2; fail=1; }
grep -qE 'fn run_one_tick\(&mut self, faces' "$FWD" || { echo "FAIL: run_one_tick does not take faces (can't fire scheduled forwards)" >&2; fail=1; }
grep -qE 'PendingForward' "$FWD" || { echo "FAIL: no scheduled-forward queue" >&2; fail=1; }
grep -qE 'fn overhear' "$FWD" || { echo "FAIL: no overhear suppression" >&2; fail=1; }

# (c) tests pass, default and with sched.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-embedded (default) && (--features sched)"
    if ! cargo test --quiet -p ndn-embedded >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-embedded --features sched >/dev/null 2>&1; then
        echo "FAIL: ndn-embedded action-list tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-14 — embedded forwarder enacts action lists (multicast / After / suppress)."
exit "$fail"
