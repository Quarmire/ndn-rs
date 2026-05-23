#!/usr/bin/env bash
# Witness recipe for Face-system Tier 1 — `TraceContext` LP TLV codec
# + Nonce-derived fallback ship in ndn-packet.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §9.2 / §9.7
# Decision:    LP TLV-TYPE 0x520 carries W3C trace-context binary form
#              (16+8+1 byte fields + timestamp).  Codec is pure no_std-
#              friendly bytes ↔ struct, no OTel SDK dep.  Nonce
#              fallback synthesises a TraceId via blake3(Nonce ‖
#              Name ‖ router-id)[..16].
#
# Witnesses:
#   (a) GREP-PROOF — `crates/ndn-packet/src/lp/trace_context.rs`
#       exists; defines `TraceContext`, `TraceId`, `SpanId`,
#       `TraceFlags`; `TLV_TRACE_CONTEXT` pinned to 0x520.
#   (b) RUST-UNIT — `cargo test -p ndn-packet trace_context`
#       round-trips the W3C binary form.
#   (c) RUST-UNIT — same `cargo test` invocation runs
#       `from_nonce_and_name` and asserts: same (nonce, name, router)
#       returns the same TraceId; differing nonce produces a
#       different TraceId.
#   (d) GREP-PROOF — codec compiles on wasm32 (no `tokio::*` or other
#       native-only imports in the file).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT.
#
# Exit codes:
#   0 — PASS (codec + fallback land)
#   1 — FAIL
#   2 — SKIP (cargo not available)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo not in PATH" >&2
    exit 2
fi

check_grep() {
    local pattern="$1" path="$2" label="$3"
    if ! grep -rqnE "$pattern" "$path"; then
        echo "FAIL: $label — pattern \"$pattern\" not found under $path" >&2
        fail=1
    fi
}

check_absent_in_paths() {
    local pattern="$1" label="$2"; shift 2
    local hits
    hits="$(grep -rnE "$pattern" "$@" 2>/dev/null || true)"
    if [ -n "$hits" ]; then
        echo "FAIL: $label" >&2
        echo "$hits" >&2
        fail=1
    fi
}

TC_FILE=crates/ndn-packet/src/lp/trace_context.rs

# (a) File + types + TLV constant.
check_grep 'pub struct TraceContext'  "$TC_FILE" 'TraceContext struct'
check_grep 'pub struct TraceId'       "$TC_FILE" 'TraceId struct'
check_grep 'pub struct SpanId'        "$TC_FILE" 'SpanId struct'
check_grep 'TLV_TRACE_CONTEXT.*0x520' "$TC_FILE" 'TLV constant pinned to 0x520'
check_grep 'fn from_nonce_and_name'   "$TC_FILE" 'Nonce-derived fallback constructor'

# (d) No native-only imports in the codec file.
check_absent_in_paths '^use tokio' \
    'codec file imports tokio (must stay wasm32-compatible)' \
    "$TC_FILE"
check_absent_in_paths '^use std::net' \
    'codec file imports std::net (must stay wasm32-compatible)' \
    "$TC_FILE"

# (b) + (c) RUST-UNIT.
if [ "$fail" -eq 0 ]; then
    if ! cargo test -p ndn-packet --features std --lib trace_context -- --nocapture 2>&1 | tail -40; then
        echo "FAIL: cargo test -p ndn-packet trace_context failed" >&2
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 1 — TraceContext LP TLV codec + Nonce fallback land."
fi
exit "$fail"
