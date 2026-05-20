#!/usr/bin/env bash
# Witness recipe for ARCH-14 / S7 — `StrategyFilter` scope decision
# (DOCS-only).
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-14
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Decision:    Keep `StrategyFilter` as an ndn-rs-only engine-builder
#              extension over NFD's one-strategy-per-prefix mgmt model.
#              No API change in v0.1 — document the scope.
#
# Witnesses:
#   (a) GREP-PROOF — `crates/spec/ndn-strategy/src/filter.rs`
#       documents the builder-only scope on both the module-level
#       docstring and the trait itself.
#   (b) GREP-PROOF — the strategy-composition wiki page covers the
#       scope decision under a dedicated heading.
#   (c) GREP-PROOF — no `MgmtModule` impl under
#       `crates/spec/ndn-mgmt/src/modules/strategy.rs` references
#       `StrategyFilter` (the mgmt surface stays single-strategy).
#
# Reverify recipe: GREP-PROOF only. Runs in any checkout of ndn-rs.
#
# Exit codes:
#   0 — PASS (scope documented in both code and wiki; mgmt module
#       does not touch StrategyFilter)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

check_absent_in_file() {
    local pattern="$1" path="$2" label="$3"
    if grep -nE "$pattern" "$path" >/dev/null 2>&1; then
        echo "FAIL: $label" >&2
        grep -nE "$pattern" "$path" >&2
        fail=1
    fi
}

FILTER=crates/spec/ndn-strategy/src/filter.rs
WIKI=docs/wiki/src/design/strategy-composition.md
MGMT_STRATEGY=crates/spec/ndn-mgmt/src/modules/strategy.rs

# (1) Module-level + trait-level docs explain the builder-only scope.
check_grep 'advanced engine-builder use only' "$FILTER" 'module-level scope doc'
check_grep 'never wired into the mgmt surface' "$FILTER" 'trait-level scope warning'

# (2) Wiki page documents the scope decision.
check_grep 'engine-builder only, never wired into the mgmt surface' \
    "$WIKI" 'wiki page scope section'
check_grep 'ARCH-14' "$WIKI" 'wiki page references ARCH-14'

# (3) The mgmt strategy module does not reference StrategyFilter
#     (matches NFD's one-strategy-per-prefix wire surface).
check_absent_in_file 'StrategyFilter' "$MGMT_STRATEGY" 'mgmt strategy module references StrategyFilter'

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-14 — StrategyFilter documented as builder-only; mgmt strategy module stays NFD-parity."
fi
exit "$fail"
