#!/usr/bin/env bash
# Witness test for audit findings D.10 / E.06 — strategy names lack the
# `VersionNameComponent` (TLV 0x36) suffix that NFD requires for
# `nfdc strategy-choice set`.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.10 / E.06
# Severity:    MAJOR (D.10) / MINOR (E.06 alias)
# Spec ref:    NFD `daemon/fw/best-route-strategy.cpp:56`
#              `Name("/localhost/nfd/strategy/best-route").appendVersion(5)`;
#              `daemon/fw/multicast-strategy.cpp:56` similarly with v=5.
# Witnesses:   RUST-UNIT pair in `ndn-strategy`:
#                - best_route::tests::d10_strategy_name_ends_with_version_v5
#                - multicast::tests::d10_strategy_name_ends_with_version_v5
#              Plus updated `strategy_name` test asserting last component is
#              `tlv_type::VERSION` (0x36).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-strategy --lib --quiet d10_ \
        >/tmp/d10_witness.log 2>&1; then
    echo "ok: BestRoute and Multicast strategy names end with VersionNameComponent v=5"
else
    echo "FAIL: strategy names lack VersionNameComponent"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.10 / E.06 RESOLVED — strategy names end with /v=5 ==="
    exit 0
else
    echo
    echo "=== D.10 / E.06 EXPECTED-FAIL — strategy names lack VersionNameComponent ==="
    [ -f /tmp/d10_witness.log ] && cat /tmp/d10_witness.log
    exit 1
fi
