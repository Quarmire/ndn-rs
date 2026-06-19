#!/usr/bin/env bash
# Witness test for audit finding D.04 — PIT keyed on
# (Name, Selectors, ForwardingHint), so two Interests with the same Name
# but different selectors land in distinct PIT entries instead of
# aggregating.
#
# Finding:     testbed/EXPECTED_FAILURES.md § D.04
# Severity:    MAJOR (correctness — aggregation, freshness checks)
# Spec ref:    NFD `daemon/table/pit-entry.cpp` `canMatch` — entry holds
#              in-records (each with its own selectors); the key is the
#              Name. NFD Developer Guide §4.1.
# Witnesses:   RUST-UNIT in `ndn-store`:
#                - d04_pit_token_does_not_factor_selector
#                - d04_in_record_carries_originator_selector
#                - d04_aggregation_same_name_different_selectors
#              Additional CS witnesses prove stale cached Data does not satisfy
#              MustBeFresh Interests at both the store and engine lookup stage.
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

if cargo test -p ndn-engine --lib --quiet d04_cs_lookup_ \
        >>/tmp/d04_witness.log 2>&1; then
    echo "ok: CS lookup applies MustBeFresh before satisfying from cache"
else
    echo "FAIL: CS lookup satisfies stale Data for MustBeFresh Interest"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.04 RESOLVED — PIT selectors aggregate; MustBeFresh rejects stale CS hits ==="
    exit 0
else
    echo
    echo "=== D.04 EXPECTED-FAIL — PIT key includes selectors ==="
    [ -f /tmp/d04_witness.log ] && cat /tmp/d04_witness.log
    exit 1
fi
