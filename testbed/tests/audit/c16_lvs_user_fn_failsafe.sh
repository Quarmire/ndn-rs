#!/usr/bin/env bash
# Witness test for audit finding C.16 — LVS from_lvs_binary rejects
# schemas that use user functions ($eq, $regex) instead of loading
# them silently.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.16
# Severity:    MAJOR (fail-unsafe by default)
# Spec ref:    LightVerSec binary format (python-ndn docs);
#              ndnd/std/security/trust_schema/lvs.go — user functions
#              are core matching primitives in real deployments.
# Witnesses:   GREP-PROOF — LvsError::UserFunctionsNotSupported exists
#              in lvs.rs; from_lvs_binary checks uses_user_functions()
#              and returns that error.
#              RUST-UNIT — c16_from_lvs_binary_rejects_user_functions
#              (new test) verifies the error path.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0

# LvsError must contain UserFunctionsNotSupported
if grep -q "UserFunctionsNotSupported" \
    "$REPO_ROOT/crates/ndn-security/src/lvs.rs"; then
    echo "ok: LvsError::UserFunctionsNotSupported exists"
else
    echo "FAIL: LvsError::UserFunctionsNotSupported not found"
    fail=1
fi

# from_lvs_binary must check uses_user_functions and return error
if grep -A 5 "uses_user_functions" \
    "$REPO_ROOT/crates/ndn-security/src/trust_schema.rs" \
    | grep -q "UserFunctionsNotSupported"; then
    echo "ok: from_lvs_binary returns UserFunctionsNotSupported"
else
    echo "FAIL: from_lvs_binary does not return UserFunctionsNotSupported"
    fail=1
fi

# RUST-UNIT
if cargo test -p ndn-security --lib --quiet \
        "c16_from_lvs_binary_rejects_user_functions" \
        >>/tmp/c16_witness.log 2>&1; then
    echo "ok: c16_from_lvs_binary_rejects_user_functions"
else
    echo "FAIL: c16_from_lvs_binary_rejects_user_functions"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.16 RESOLVED — from_lvs_binary fail-safe; user-fn schemas rejected ==="
    exit 0
else
    echo
    echo "=== C.16 EXPECTED-FAIL — from_lvs_binary loads user-fn schemas silently ==="
    cat /tmp/c16_witness.log
    exit 1
fi
