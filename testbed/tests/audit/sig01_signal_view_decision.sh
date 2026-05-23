#!/usr/bin/env bash
# Witness for SIG-01 — cross-layer signals are a first-class strategy input.
#
# Severity:    cross-layer / measured-strategy foundation (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md
# Witnesses:
#   (a) GREP-PROOF — ndn-signals-core (no_std) owns the taxonomy + the
#       SignalView/SignalStore traits + the NoSignals ZST (defined ONCE).
#   (b) GREP-PROOF — StrategyContext exposes a `signals` SignalView slot, and
#       the native SignalsTable implements SignalStore (the engine-owned store).
#   (c) GREP-PROOF — RssiFilter reads ctx.signals (the canonical path), not only
#       the legacy LinkQualitySnapshot extension DTO.
#   (d) RUST-UNIT  — ndn-signals-core + ndn-strategy tests pass (incl. the
#       SignalView-driven RSSI decision), and the no_std floor still builds.
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

# (a) the core owns the taxonomy + traits, once.
[ -f "$CORE" ] || { echo "FAIL: ndn-signals-core missing" >&2; fail=1; }
grep -qE 'pub trait SignalView' "$CORE" 2>/dev/null || { echo "FAIL: no SignalView trait" >&2; fail=1; }
grep -qE 'pub trait SignalStore' "$CORE" 2>/dev/null || { echo "FAIL: no SignalStore trait" >&2; fail=1; }
grep -qE 'pub struct (LinkSignals|NodeSignals)' "$CORE" 2>/dev/null || { echo "FAIL: no signal taxonomy" >&2; fail=1; }
grep -qE 'pub struct NoSignals' "$CORE" 2>/dev/null || { echo "FAIL: no NoSignals ZST" >&2; fail=1; }
grep -qE '#!\[no_std\]' "$CORE" 2>/dev/null || { echo "FAIL: signals-core is not no_std" >&2; fail=1; }

# (b) StrategyContext exposes the view; native SignalsTable is the store.
grep -qE 'pub signals: &.*dyn SignalView' crates/ndn-strategy/src/context.rs \
    || { echo "FAIL: StrategyContext lacks a signals SignalView slot" >&2; fail=1; }
grep -qE 'impl SignalStore<FaceId> for SignalsTable' crates/ndn-strategy/src/signals.rs \
    || { echo "FAIL: native SignalsTable does not implement SignalStore" >&2; fail=1; }

# (c) RssiFilter reads the canonical signal view.
grep -qE 'ctx\.signals' crates/ndn-strategy/src/filters/rssi.rs \
    || { echo "FAIL: RssiFilter does not read ctx.signals (canonical path)" >&2; fail=1; }

# (d) tests + no_std floor build.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-signals-core -p ndn-strategy"
    if ! cargo test --quiet -p ndn-signals-core >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-strategy >/dev/null 2>&1; then
        echo "FAIL: signals-core / strategy tests did not pass" >&2
        fail=1
    fi
    TARGET=thumbv7em-none-eabihf
    if rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
        echo "→ cargo build -p ndn-signals-core --target $TARGET (no-alloc floor)"
        cargo build --quiet -p ndn-signals-core --target "$TARGET" >/dev/null 2>&1 \
            || { echo "FAIL: ndn-signals-core no longer builds for $TARGET" >&2; fail=1; }
    else
        echo "note: $TARGET not installed; skipping bare-metal leg (CI covers it)"
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-01 — signals taxonomy/traits in no_std core; StrategyContext.signals + native SignalsTable; RssiFilter reads the view."
exit "$fail"
