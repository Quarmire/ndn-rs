#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.5 — Tier 2 (Extend) reference example
# registers a third-party strategy via `register_strategy!` and the
# strategy appears in the cross-crate registry.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §7
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `examples/tier2-extend-strategy/src/main.rs`
#       calls `register_strategy!` with name `b"random-nexthop"`.
#   (b) RUST-BUILD — the example builds.
#   (c) RUST-RUN   — `cargo run -p example-tier2-extend-strategy`
#       exits 0 and the stdout contains the marker line
#       `registered strategies:` followed by `random-nexthop`.
#       This is the off-line analogue of "the strategy appears in
#       `/localhost/nfd/strategy-choice/list`" — the mgmt verb walks
#       the same `ndn_strategy::registry::registered()` slice this
#       check pins.
#
# Reverify recipe: GREP-PROOF + RUST-BUILD + RUST-RUN.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
MAIN=examples/tier2-extend-strategy/src/main.rs

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
        fail=1
    fi
}

check_grep 'register_strategy!' "$MAIN" 'register_strategy! invocation'
check_grep 'b"random-nexthop"'  "$MAIN" 'strategy registered as "random-nexthop"'

echo "→ cargo build -p example-tier2-extend-strategy"
if ! cargo build --quiet -p example-tier2-extend-strategy >/dev/null 2>&1; then
    echo "FAIL: tier2 example failed to build" >&2
    fail=1
fi

echo "→ cargo run -p example-tier2-extend-strategy (≤30 s)"
out=$(mktemp)
if ! timeout 30 cargo run --quiet -p example-tier2-extend-strategy >"$out" 2>&1; then
    echo "FAIL: tier2 example exited non-zero or timed out" >&2
    cat "$out" >&2
    fail=1
fi
if ! grep -q 'registered strategies' "$out"; then
    echo "FAIL: tier2 stdout missing 'registered strategies' marker" >&2
    cat "$out" >&2
    fail=1
fi
if ! grep -q 'random-nexthop' "$out"; then
    echo "FAIL: tier2 stdout missing 'random-nexthop' — registration not visible" >&2
    cat "$out" >&2
    fail=1
fi
rm -f "$out"

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.5 — Tier 2 (Extend) example registers a third-party strategy."
fi
exit "$fail"
