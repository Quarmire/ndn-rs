#!/usr/bin/env bash
# Witness recipe for Face-system Tier 1 — PIT in-record carries an
# additive `trace_ids: SmallVec<[TraceId; 1]>` for the aggregation
# fan-out shape from §9.6.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §9.6
# Decision:    Tier 1 ships the field + the additive append on
#              aggregation; Phase-3 OTel reads the list on Data
#              receive to emit one span per aggregated consumer.
#
# Witnesses:
#   (a) GREP-PROOF — InRecord has `trace_ids:` of a SmallVec backing.
#   (b) GREP-PROOF — `add_in_record` (or aggregating sibling) accepts
#       a `Vec<TraceId>` / `SmallVec<[TraceId; 1]>` parameter (or
#       there's a sibling that appends without resetting prior IDs).
#   (c) RUST-UNIT — `cargo test -p ndn-store trace_ids_aggregate`
#       passes: two adds with different trace IDs leave both present;
#       single add stores exactly one.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
#   2 — SKIP (cargo missing)
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

PIT=crates/ndn-store/src/pit.rs

# (a) Field on InRecord.
check_grep 'trace_ids:' "$PIT" 'InRecord.trace_ids field'
check_grep 'SmallVec<\[.*TraceId.*; 1\]>' "$PIT" 'SmallVec<[TraceId; 1]> backing'

# (b) Aggregation API surfaces trace ids.
check_grep 'fn add_in_record_with_trace_ids' "$PIT" 'aggregating add API'

# (c) RUST-UNIT.
if [ "$fail" -eq 0 ]; then
    if ! cargo test -p ndn-store --lib trace_ids -- --nocapture 2>&1 | tail -40; then
        echo "FAIL: cargo test -p ndn-store trace_ids failed" >&2
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: face-system Tier 1 — PIT in-record carries SmallVec<[TraceId; 1]>; aggregation appends."
fi
exit "$fail"
