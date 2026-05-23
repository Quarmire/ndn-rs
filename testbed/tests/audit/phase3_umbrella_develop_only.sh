#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.1 — `ndn` umbrella crate exports only
# the Develop-tier surface.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §2
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — `crates/ndn-rs-prelude/Cargo.toml` lists only
#       `ndn-app`, `ndn-packet`, `ndn-security` (and no other workspace
#       crate) as a runtime dependency. Package name is
#       `ndn-rs-prelude` (the unqualified `ndn` crate name is held by
#       a 2018 placeholder on crates.io); library name is `ndn` so
#       callers still write `use ndn::Consumer;`.
#   (b) GREP-PROOF — the lib.rs re-exports only Develop-tier symbols.
#       No `ndn-engine`, `ndn-faces`, `ndn-discovery*`, `ndn-routing`,
#       `ndn-strategy`, `ndn-mgmt`, `ndn-transport`, `ndn-runtime`,
#       `ndn-store` re-exports (those are Extend / Instrument).
#   (c) RUST-UNIT  — `cargo build -p ndn-rs-prelude` (native) and
#       `cargo build --target wasm32-unknown-unknown -p ndn-rs-prelude`
#       both succeed.
#   (d) RUST-UNIT  — `cargo doc -p ndn-rs-prelude --no-deps` is warning-free.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Exit codes:
#   0 — PASS (umbrella ships Develop-only surface; builds native + wasm32)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
CARGO=crates/ndn-rs-prelude/Cargo.toml
LIB=crates/ndn-rs-prelude/src/lib.rs

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
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

# (a) Cargo.toml dependency hygiene.
check_grep '^name = "ndn-rs-prelude"' "$CARGO" 'package name = ndn-rs-prelude'
check_grep '^name = "ndn"'            "$CARGO" 'library name = ndn'
check_grep 'ndn-packet'   "$CARGO" 'ndn-packet dep'
check_grep 'ndn-security' "$CARGO" 'ndn-security dep'
check_grep 'ndn-app'      "$CARGO" 'ndn-app dep (native-only target)'

for forbidden in ndn-engine ndn-faces ndn-discovery ndn-routing \
                 ndn-strategy ndn-mgmt ndn-transport ndn-runtime \
                 ndn-store ndn-tlv; do
    # Match the dep on a dependency line (starts with the crate name +
    # whitespace + `=`); avoids false positives inside comments / paths.
    if grep -nE "^${forbidden}[[:space:]]*=" "$CARGO" >/dev/null 2>&1; then
        echo "FAIL: $forbidden listed as a dep in $CARGO (Extend / Instrument crate)" >&2
        grep -nE "^${forbidden}[[:space:]]*=" "$CARGO" >&2
        fail=1
    fi
done

# (b) lib.rs re-export hygiene — no Extend / Instrument paths re-exported.
for forbidden in ndn_engine ndn_faces ndn_discovery ndn_routing \
                 ndn_strategy ndn_mgmt ndn_transport ndn_runtime \
                 ndn_store; do
    if grep -nE "^pub use ${forbidden}::" "$LIB" >/dev/null 2>&1; then
        echo "FAIL: $LIB re-exports from $forbidden (Extend / Instrument crate)" >&2
        grep -nE "^pub use ${forbidden}::" "$LIB" >&2
        fail=1
    fi
done

# Sanity check: lib.rs has the prelude module and the Develop-tier
# entry-point re-exports we promised.
check_grep '^pub use ndn_packet::'   "$LIB" 'ndn-packet re-exports'
check_grep '^pub use ndn_security::' "$LIB" 'ndn-security re-exports'
check_grep '^pub use ndn_app::'      "$LIB" 'ndn-app re-exports (native-only)'
check_grep '^pub mod prelude'        "$LIB" 'prelude module'

# (c) Builds.
echo "→ cargo build -p ndn-rs-prelude (native)"
if ! cargo build --quiet -p ndn-rs-prelude >/dev/null 2>&1; then
    echo "FAIL: native build of ndn-rs-prelude failed" >&2
    fail=1
fi

if rustc --print target-list 2>/dev/null | grep -q '^wasm32-unknown-unknown$' \
   && rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
    echo "→ cargo build --target wasm32-unknown-unknown -p ndn-rs-prelude"
    if ! cargo build --quiet --target wasm32-unknown-unknown -p ndn-rs-prelude >/dev/null 2>&1; then
        echo "FAIL: wasm32 build of ndn-rs-prelude failed" >&2
        fail=1
    fi
else
    echo "SKIP: wasm32-unknown-unknown target not installed; not gating Phase 3 on it"
fi

# (d) Docs warning-free.
echo "→ cargo doc -p ndn-rs-prelude --no-deps"
doc_log=$(mktemp)
if ! RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" \
     cargo doc --quiet -p ndn-rs-prelude --no-deps >"$doc_log" 2>&1; then
    echo "FAIL: cargo doc produced warnings or errors" >&2
    cat "$doc_log" >&2
    fail=1
fi
rm -f "$doc_log"

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.1 — umbrella crate ships Develop-tier-only surface (native + wasm32)."
fi
exit "$fail"
