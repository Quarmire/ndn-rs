#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.5 — Tier 1 (Develop) reference example
# runs end-to-end via the `ndn` umbrella crate.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §7
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `examples/tier1-develop-5min/Cargo.toml` depends
#       only on `ndn-rs-prelude`, `tokio`, and `anyhow` (no
#       direct dep on `ndn-engine`, `ndn-face-native`, `ndn-strategy`, etc).
#   (b) GREP-PROOF — `examples/tier1-develop-5min/src/main.rs` does
#       not `use ndn_engine::`, `use ndn_face_native::`, `use ndn_strategy::`,
#       `use ndn_mgmt::`, or any other Extend / Instrument crate.
#   (c) RUST-BUILD — `cargo build -p example-tier1-develop-5min`
#       succeeds.
#   (d) RUST-RUN   — `cargo run -p example-tier1-develop-5min` exits 0
#       within 30 seconds.
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

CARGO=examples/tier1-develop-5min/Cargo.toml
MAIN=examples/tier1-develop-5min/src/main.rs

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
        fail=1
    fi
}

# (a) Cargo.toml only references ndn-rs-prelude (no Extend/Instrument crates).
check_grep '^ndn-rs-prelude' "$CARGO" 'tier1 depends on ndn-rs-prelude'
for forbidden in ndn-engine ndn-face-native ndn-strategy ndn-mgmt ndn-transport ndn-routing ndn-discovery ndn-runtime ndn-store ndn-face-local; do
    if grep -nE "^${forbidden}[[:space:]]*=" "$CARGO" >/dev/null 2>&1; then
        echo "FAIL: tier1 Cargo.toml lists $forbidden (must depend only on ndn-rs-prelude)" >&2
        grep -nE "^${forbidden}[[:space:]]*=" "$CARGO" >&2
        fail=1
    fi
done

# (b) main.rs doesn't reach below the umbrella.
for forbidden in ndn_engine ndn_face_native ndn_strategy ndn_mgmt ndn_transport ndn_routing ndn_discovery; do
    if grep -nE "use ${forbidden}::" "$MAIN" >/dev/null 2>&1; then
        echo "FAIL: tier1 main.rs imports $forbidden (Develop tier should use only the umbrella)" >&2
        grep -nE "use ${forbidden}::" "$MAIN" >&2
        fail=1
    fi
done

# (c) Build.
echo "→ cargo build -p example-tier1-develop-5min"
if ! cargo build --quiet -p example-tier1-develop-5min >/dev/null 2>&1; then
    echo "FAIL: tier1 example failed to build" >&2
    fail=1
fi

# (d) Run.
echo "→ cargo run -p example-tier1-develop-5min (≤30 s)"
out=$(mktemp)
if ! timeout 30 cargo run --quiet -p example-tier1-develop-5min >"$out" 2>&1; then
    echo "FAIL: tier1 example exited non-zero or timed out" >&2
    cat "$out" >&2
    fail=1
fi
rm -f "$out"

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.5 — Tier 1 (Develop) example builds and runs via the ndn umbrella."
fi
exit "$fail"
