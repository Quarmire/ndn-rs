#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.5 — Tier 3 (Instrument) reference
# example uses `TapFace` (gated behind `experimental-instrument`) to
# record wire packets crossing an in-process engine.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §7
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `examples/tier3-instrument-tap/Cargo.toml`
#       enables the `experimental-instrument` feature on `ndn-engine`
#       and `ndn-face-native`.
#   (b) GREP-PROOF — `examples/tier3-instrument-tap/src/main.rs` uses
#       `TapFace` and calls `tap.captured()`.
#   (c) RUST-BUILD — the example builds.
#   (d) RUST-RUN   — `cargo run -p example-tier3-instrument-tap`
#       exits 0 and stdout reports a non-zero captured-packet count.
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
CARGO=examples/tier3-instrument-tap/Cargo.toml
MAIN=examples/tier3-instrument-tap/src/main.rs

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
        fail=1
    fi
}

# (a) Features.
check_grep 'features = \[.*"experimental-instrument".*\]' "$CARGO" 'experimental-instrument feature pulled by Cargo.toml'

# (b) Source uses TapFace.
check_grep 'TapFace::new'   "$MAIN" 'TapFace::new used'
check_grep 'tap\.captured'  "$MAIN" 'tap.captured() called'

# (c) Build.
echo "→ cargo build -p example-tier3-instrument-tap"
if ! cargo build --quiet -p example-tier3-instrument-tap >/dev/null 2>&1; then
    echo "FAIL: tier3 example failed to build" >&2
    fail=1
fi

# (d) Run + capture count.
echo "→ cargo run -p example-tier3-instrument-tap (≤30 s)"
out=$(mktemp)
if ! timeout 30 cargo run --quiet -p example-tier3-instrument-tap >"$out" 2>&1; then
    echo "FAIL: tier3 example exited non-zero or timed out" >&2
    cat "$out" >&2
    fail=1
fi
# Expect line of the form "tap captured N packet(s)" with N≥1.
if ! grep -qE 'tap captured [1-9][0-9]* packet' "$out"; then
    echo "FAIL: tier3 stdout missing 'tap captured N packet(s)' with N≥1" >&2
    cat "$out" >&2
    fail=1
fi
rm -f "$out"

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.5 — Tier 3 (Instrument) example captures wire packets via TapFace."
fi
exit "$fail"
