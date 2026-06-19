#!/usr/bin/env bash
# Witness recipe for Phase 3 §3.4 — `experimental-instrument` feature
# gates the researcher-tier surface from default `cargo doc` output.
#
# Finding:     docs/notes/tiered-api-design-2026-05-20.md §4
# Severity:    Phase 3 deliverable (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — the `experimental-instrument` feature exists in
#       `ndn-engine`, `ndn-face`, and `ndn-face-local`.
#   (b) GREP-PROOF — each Instrument-tier item carries
#       `#[cfg_attr(not(feature = "experimental-instrument"),
#       doc(hidden))]`.
#       Items audited:
#         ndn-engine — `ForwarderEngine::{fib, rib, pit, cs,
#                       strategy_table, measurements, routing,
#                       discovery_ctx}`, `ContextEnricher`,
#                       `observability::targets`.
#         ndn-face  — `CallbackFace`, `TapFace`.
#         ndn-face-local — `InProcFace::new_kind`.
#   (c) RUST-DOC   — `cargo doc -p ndn-engine --no-deps` (no feature)
#       generates a `struct.ForwarderEngine.html` page with **zero**
#       `method.fib` / `method.pit` / `method.cs` / `method.rib`
#       anchors.
#   (d) RUST-DOC   — `cargo doc -p ndn-engine --no-deps --features
#       experimental-instrument` generates the same page with at least
#       4 such anchors.
#   (e) RUST-BUILD — `cargo build -p ndn-engine -p ndn-face -p
#       ndn-face-local` succeeds *without* the feature (proving the
#       items are still `pub` and in-tree code keeps compiling).
#
# Reverify recipe: GREP-PROOF + RUST-DOC + RUST-BUILD.  Runs in any
# checkout of ndn-rs; no Docker required.
#
# Exit codes:
#   0 — PASS (Instrument-tier items are doc-gated; with-feature docs surface them)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -qE "$pattern" "$path"; then
        echo "FAIL: $label — \"$pattern\" not found in $path" >&2
        fail=1
    fi
}

# (a) Features.
check_grep '^experimental-instrument =' crates/ndn-engine/Cargo.toml      'ndn-engine experimental-instrument feature'
check_grep '^experimental-instrument =' crates/faces/ndn-face/Cargo.toml       'ndn-face experimental-instrument feature'
check_grep '^experimental-instrument =' crates/ndn-face-local/Cargo.toml  'ndn-face-local experimental-instrument feature'

# (b) Engine table accessors carry the doc-hidden attr.
ENGINE_SRC=crates/ndn-engine/src/engine.rs
for method in fib rib pit cs strategy_table measurements routing discovery_ctx; do
    # Each gated method must have a doc(hidden) cfg_attr on a line
    # before its `pub fn <method>(` declaration.
    line=$(grep -n "pub fn ${method}(" "$ENGINE_SRC" | head -1 | cut -d: -f1)
    if [ -z "$line" ]; then
        echo "FAIL: pub fn $method not found in $ENGINE_SRC" >&2
        fail=1
        continue
    fi
    prev=$((line - 1))
    if ! sed -n "${prev}p" "$ENGINE_SRC" | grep -qE 'doc\(hidden\)'; then
        echo "FAIL: ForwarderEngine::${method} missing doc(hidden) gate at $ENGINE_SRC:$prev" >&2
        fail=1
    fi
done

# ContextEnricher trait + observability::targets — multi-line check:
# the cfg_attr line must precede the trait/mod declaration.
check_preceding_attr() {
    local file="$1" target="$2" label="$3"
    local line
    line=$(grep -nE "$target" "$file" | head -1 | cut -d: -f1 || true)
    if [ -z "$line" ]; then
        echo "FAIL: $label — '$target' not found in $file" >&2
        fail=1
        return
    fi
    # Scan up to 5 preceding lines for the doc(hidden) cfg_attr.
    local start=$((line > 5 ? line - 5 : 1))
    local window
    window=$(sed -n "${start},${line}p" "$file")
    if ! grep -qE 'cfg_attr\(not\(feature = "experimental-instrument"\), doc\(hidden\)\)' <<<"$window"; then
        echo "FAIL: $label — doc(hidden) gate missing above $file:$line" >&2
        fail=1
    fi
}

check_preceding_attr crates/ndn-engine/src/enricher.rs \
    '^pub trait ContextEnricher' 'ContextEnricher doc-hidden gate'
check_preceding_attr crates/ndn-engine/src/observability/mod.rs \
    '^pub mod targets' 'observability::targets doc-hidden gate'

# CallbackFace + TapFace + InProcFace::new_kind.
check_grep 'doc\(hidden\)' crates/faces/ndn-face/src/callback.rs     'callback.rs doc-hidden gate (CallbackFace/TapFace)'
check_grep 'pub struct TapFace'         crates/faces/ndn-face/src/callback.rs  'TapFace struct exists'
check_grep 'pub use callback::\{CallbackFace, TapFace\}' \
    crates/faces/ndn-face/src/lib.rs 'TapFace re-exported'
check_grep 'doc\(hidden\)' crates/ndn-face-local/src/lib.rs     'InProcFace::new_kind doc-hidden gate'

# (e) Build without the feature.
echo "→ cargo build (default features) — Instrument items stay pub"
if ! cargo build --quiet -p ndn-engine -p ndn-face -p ndn-face-local >/dev/null 2>&1; then
    echo "FAIL: build broke without experimental-instrument feature" >&2
    fail=1
fi

# (c) cargo doc without the feature — no Instrument method anchors.
echo "→ cargo doc -p ndn-engine --no-deps (no feature)"
if ! cargo doc --quiet -p ndn-engine --no-deps >/dev/null 2>&1; then
    echo "FAIL: cargo doc -p ndn-engine failed without feature" >&2
    fail=1
fi
DOC_HTML=target/doc/ndn_engine/engine/struct.ForwarderEngine.html
if [ ! -f "$DOC_HTML" ]; then
    echo "FAIL: expected doc page not generated: $DOC_HTML" >&2
    fail=1
else
    hits=$(grep -c 'method\.fib\|method\.pit\|method\.cs\|method\.rib' "$DOC_HTML" || true)
    if [ "$hits" -ne 0 ]; then
        echo "FAIL: $DOC_HTML lists $hits Instrument-tier methods without feature (expected 0)" >&2
        fail=1
    fi
fi

# (d) cargo doc with the feature — Instrument methods present.
echo "→ cargo doc -p ndn-engine --no-deps --features experimental-instrument"
if ! cargo doc --quiet -p ndn-engine --no-deps --features experimental-instrument >/dev/null 2>&1; then
    echo "FAIL: cargo doc with experimental-instrument feature failed" >&2
    fail=1
elif [ -f "$DOC_HTML" ]; then
    hits=$(grep -c 'method\.fib\|method\.pit\|method\.cs\|method\.rib' "$DOC_HTML" || true)
    if [ "$hits" -lt 4 ]; then
        echo "FAIL: $DOC_HTML lists only $hits Instrument-tier methods with feature (expected ≥4)" >&2
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: Phase 3 §3.4 — experimental-instrument feature gates the researcher-tier surface."
fi
exit "$fail"
