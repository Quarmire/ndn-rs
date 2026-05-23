#!/usr/bin/env bash
# Witness for SIG-06 — the signal hot path does not build a per-packet AnyMap.
#
# Severity:    forwarding hot-path perf (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md (step 7)
# Context:     Known cross-layer inputs (RSSI/GPS) now come from `signals`
#              (the typed SignalView), not the AnyMap enricher path. So when no
#              open-ended ContextEnricher is registered — the signals-only
#              common case — the strategy stage must NOT construct a per-packet
#              AnyMap; it shares a single empty map instead.
# Witnesses:
#   (a) GREP-PROOF — both strategy dispatch paths (StrategyStage::process and
#       the dispatcher pipeline) branch on `enrichers.is_empty()` and reference
#       a shared `static EMPTY` AnyMap rather than building one per packet.
#   (b) RUST-UNIT  — ndn-engine builds and ndn-strategy tests pass (the
#       enricher path is preserved when enrichers ARE registered).
#
# Note: this pins the construction-elision, not a benchmarked allocation count
#       (a true alloc-count needs a custom global allocator + full-pipeline
#       integration). The shared-empty branch removes the AnyMap build from the
#       no-enricher path by construction.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
for f in crates/ndn-engine/src/stages/strategy.rs crates/ndn-engine/src/dispatcher/pipeline.rs; do
    grep -qE 'enrichers\.is_empty\(\)' "$f" 2>/dev/null \
        || { echo "FAIL: $f does not skip AnyMap on the no-enricher path" >&2; fail=1; }
    grep -qE 'static EMPTY' "$f" 2>/dev/null \
        || { echo "FAIL: $f does not share an empty AnyMap" >&2; fail=1; }
done

if [ "$fail" -eq 0 ]; then
    echo "→ cargo build -p ndn-engine && cargo test -p ndn-strategy"
    cargo build --quiet -p ndn-engine >/dev/null 2>&1 \
        || { echo "FAIL: engine build broke" >&2; fail=1; }
    cargo test --quiet -p ndn-strategy >/dev/null 2>&1 \
        || { echo "FAIL: strategy tests broke (enricher path regressed?)" >&2; fail=1; }
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-06 — no per-packet AnyMap on the signals-only hot path; enricher path preserved."
exit "$fail"
