#!/usr/bin/env bash
# Witness — reflexive forwarding management module
# (/localhost/nfd/reflexive/{enable,disable,config,flush,info}).
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md (mgmt surface)
# Witnesses:
#   RUST-UNIT (ndn-engine reflexive::tests): runtime knobs + counters —
#     disabled_refuses_new_but_serves_existing, flush_clears_all_routes_immediately,
#     runtime_cap_change_takes_effect, status_reports_counters.
#   RUST-UNIT (ndn-mgmt): the module dispatch round-trip —
#     modules::reflexive::tests::enable_disable_flush_info_round_trip.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if ! cargo test -p ndn-engine --lib --quiet -- \
        reflexive::tests::disabled_refuses_new_but_serves_existing \
        reflexive::tests::flush_clears_all_routes_immediately \
        reflexive::tests::runtime_cap_change_takes_effect \
        reflexive::tests::status_reports_counters \
        >/tmp/rf_mgmt_witness.log 2>&1; then
    fail=1
fi
if ! cargo test -p ndn-mgmt --lib --quiet \
        modules::reflexive::tests::enable_disable_flush_info_round_trip \
        >>/tmp/rf_mgmt_witness.log 2>&1; then
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== RF mgmt PASS — runtime toggle/caps/flush/status + module dispatch ==="
    exit 0
fi
echo "=== RF mgmt FAIL ==="
cat /tmp/rf_mgmt_witness.log
exit 1
