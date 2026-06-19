#!/usr/bin/env bash
# Witness test for audit finding C.16 — LVS from_lvs_binary rejects
# schemas that use user functions ($eq, $regex) instead of loading
# them silently.
#
# Finding:     testbed/EXPECTED_FAILURES.md § C.16
# Severity:    MAJOR (fail-unsafe by default)
# Spec ref:    LightVerSec binary format (python-ndn docs);
#              ndnd/std/security/trust_schema/lvs.go — user functions
#              are core matching primitives in real deployments.
# Witnesses:   RUST-UNIT — parser flags user-function schemas, direct
#              evaluator/policy use denies them, and from_lvs_binary refuses
#              to load them for enforcement.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-security --lib --quiet c16_ \
        >/tmp/c16_witness.log 2>&1 \
        && grep -Eq "test result: ok\. ([3-9]|[1-9][0-9]+) passed;" /tmp/c16_witness.log; then
    cat /tmp/c16_witness.log
    echo
    echo "=== C.16 RESOLVED — LVS user functions fail closed in parser, loader, and policy ==="
    exit 0
else
    echo "FAIL: C.16 LVS user-function fail-closed witness"
    cat /tmp/c16_witness.log
    echo
    echo "=== C.16 EXPECTED-FAIL — from_lvs_binary loads user-fn schemas silently ==="
    exit 1
fi
