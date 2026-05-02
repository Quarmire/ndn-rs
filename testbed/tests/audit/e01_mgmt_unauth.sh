#!/usr/bin/env bash
# Witness test for audit findings E.01 / I.07 / C.11 — Command Interests
# dispatched without signature verification, and the missing
# Validator::validate_interest path.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.01 + § C.11
# Severity:    BLOCKER (E.01) / MAJOR (C.11)
# Spec ref:    NFD daemon/mgmt/command-authenticator.cpp:127,194,244;
#              ndn-cxx mgmt/dispatcher.cpp:166-185;
#              ndn-cxx security/validator.cpp::validate(const Interest&, ...).
# Witnesses:
#   - C.11 : Validator::validate_interest verifies signed Interests
#            (cargo tests c11_validate_signed_interest_returns_valid +
#            c11_unsigned_interest_returns_invalid in ndn-security).
#   - E.01 : authorize_command() in ndn-fwd's mgmt_ndn rejects
#            unsigned commands when require_signed_commands=true and
#            accepts properly-signed ones (4 cargo tests in
#            mgmt_ndn::e01_tests).
#
# This is the architecture-side witness. Live `ndn-ctl rib register`
# against a hardened ndn-fwd is BLOCKED-BY-INTEROP until the
# trust-anchor population path is wired and `require_signed_commands`
# is flipped on by default.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-security --lib --quiet c11_ \
        >/tmp/e01_witness.log 2>&1; then
    echo "ok: C.11 (validate_interest)"
else
    echo "FAIL: C.11"
    fail=1
fi

if cargo test -p ndn-fwd --bin ndn-fwd --quiet e01_ \
        >>/tmp/e01_witness.log 2>&1; then
    echo "ok: E.01 (authorize_command)"
else
    echo "FAIL: E.01"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== E.01 / C.11 RESOLVED — command auth + validate_interest in place ==="
    exit 0
else
    echo
    echo "=== E.01 / C.11 EXPECTED-FAIL — auth gate or validate_interest missing ==="
    cat /tmp/e01_witness.log
    exit 1
fi
