#!/usr/bin/env bash
# Witness for SIG-04 — the sans-IO Strategy reads the same SignalView on the
# embedded floor as native, and NoSignals keeps signal-agnostic forwarders
# byte-identical.
#
# Severity:    cross-platform parity / anti-divergence (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core::Strategy::decide takes a `&dyn SignalView<F>`
#       (the input surface is widened, generic over the face type).
#   (b) GREP-PROOF — ndn-embedded provides a heapless SignalTable implementing
#       SignalStore, and its built-in forwarder passes a view into decide
#       (NoSignals — signal-agnostic, unchanged behavior).
#   (c) RUST-UNIT  — ndn-fwd-core + ndn-embedded tests pass AND ndn-embedded
#       still builds for thumbv7em-none-eabihf (the breaking trait change did
#       not pull alloc onto the no-alloc floor, and BestRoute/Multicast still
#       work with NoSignals).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
FWD=crates/ndn-fwd-core/src/strategy.rs
EMB=crates/ndn-embedded/src/signals.rs

# (a) widened sans-IO input surface.
grep -qE 'signals: &dyn SignalView<F>' "$FWD" 2>/dev/null \
    || { echo "FAIL: sans-IO Strategy::decide does not take a SignalView" >&2; fail=1; }

# (b) heapless embedded store + signal-agnostic built-in forwarder.
grep -qE 'impl<const N: usize> SignalStore<FaceId> for SignalTable' "$EMB" 2>/dev/null \
    || { echo "FAIL: no heapless embedded SignalStore (SignalTable)" >&2; fail=1; }
grep -qE 'decide\(&\[nexthop\], incoming_face, &NoSignals' crates/ndn-embedded/src/forwarder.rs 2>/dev/null \
    || { echo "FAIL: embedded forwarder does not pass a SignalView into decide" >&2; fail=1; }

# (c) tests + no_std floor.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core -p ndn-embedded"
    if ! cargo test --quiet -p ndn-fwd-core >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-embedded >/dev/null 2>&1; then
        echo "FAIL: fwd-core / embedded tests did not pass" >&2
        fail=1
    fi
    TARGET=thumbv7em-none-eabihf
    if rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
        echo "→ cargo build -p ndn-embedded --target $TARGET (no-alloc floor)"
        cargo build --quiet -p ndn-embedded --target "$TARGET" >/dev/null 2>&1 \
            || { echo "FAIL: ndn-embedded no longer builds for $TARGET" >&2; fail=1; }
    else
        echo "note: $TARGET not installed; skipping bare-metal leg (CI covers it)"
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-04 — sans-IO Strategy widened with SignalView; heapless embedded store; no-alloc floor intact."
exit "$fail"
