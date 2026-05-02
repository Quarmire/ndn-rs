#!/usr/bin/env bash
# Witness test for audit finding D.04 — PIT keyed on
# (Name, Selectors, ForwardingHint), so two Interests with the same Name
# but different selectors land in distinct PIT entries instead of
# aggregating.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.04
# Severity:    MAJOR (correctness — aggregation, freshness checks)
# Spec ref:    NFD `daemon/table/pit-entry.cpp` `canMatch` — entry holds
#              in-records (each with its own selectors); the key is the
#              Name. NFD Developer Guide §4.1.
# Witnesses:   RUST-UNIT in `ndn-store`:
#                - d04_pit_token_does_not_factor_selector
#                - d04_in_record_carries_originator_selector
#                - d04_aggregation_same_name_different_selectors
#              Today: tests fail to compile (the API hashes selectors into
#              `PitToken` and `InRecord` has no `selector` field). After
#              fix: PitToken keyed on (Name, ForwardingHint), `InRecord`
#              carries the originator's selector; aggregation produces a
#              single PIT entry with two in-records.
#
# Deferred:    `MustBeFresh` re-check at match time (depends on cache-side
#              first-seen / age tracking). Each in-record now carries its
#              originator's `Selector`, so a future `PitMatchStage` filter
#              can apply per-downstream `MustBeFresh` without further PIT
#              changes.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-store --lib --quiet d04_ \
        >/tmp/d04_witness.log 2>&1; then
    echo "ok: PIT key drops selectors; in-record carries originator selector"
else
    echo "FAIL: PIT keyed on selectors / in-record missing selector"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.04 RESOLVED — PIT key is Name(+ForwardingHint) only; selectors per in-record ==="
    exit 0
else
    echo
    echo "=== D.04 EXPECTED-FAIL — PIT key includes selectors ==="
    [ -f /tmp/d04_witness.log ] && cat /tmp/d04_witness.log
    exit 1
fi
