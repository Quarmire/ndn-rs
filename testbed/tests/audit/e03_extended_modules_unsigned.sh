#!/usr/bin/env bash
# Witness test for audit finding E.03 — extended ndn-rs management
# modules (`security`, `routing`, `discovery`, `neighbors`, `service`,
# `measurements`, `config`, `log`) accept unsigned commands when the
# operator-level `require_signed_commands` flag is `false`.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.03
# Severity:    MAJOR (privilege escalation surface)
# Spec ref:    NFD's canonical management surface only includes
#              `faces`, `fib`, `rib`, `cs`, `strategy-choice`, `status`
#              (`daemon/mgmt/*-manager.cpp`). Anything beyond that is an
#              ndn-rs extension. Audit text cites
#              `security/identity-generate`, `security/key-delete`,
#              `security/schema-rule-add` as concrete privilege paths.
# Witnesses:   RUST-UNIT in `ndn-fwd::mgmt_ndn::tests`:
#                - e03_is_extended_module_classifies_correctly
#                - e03_effective_require_signed_forces_extended_modules
#                - e03_unsigned_security_command_rejected_by_default
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-fwd --bin ndn-fwd --quiet e03_ \
        >/tmp/e03_witness.log 2>&1; then
    echo "ok: extended modules unconditionally require signed commands"
else
    echo "FAIL: extended modules accept unsigned commands"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== E.03 RESOLVED — extended mgmt modules require signed commands ==="
    exit 0
else
    echo
    echo "=== E.03 EXPECTED-FAIL — extended mgmt modules accept unsigned commands ==="
    [ -f /tmp/e03_witness.log ] && cat /tmp/e03_witness.log
    exit 1
fi
