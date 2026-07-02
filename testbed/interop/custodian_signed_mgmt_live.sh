#!/usr/bin/env bash
# Witness — a mgmt command signed through a CustodianRegistry is authorized by
# a LIVE ndn-fwd that requires signed commands; an unsigned one is rejected.
#
# This closes the "route mgmt signing through a custodian" loop end-to-end
# against a running forwarder. The integration test (binaries/ndn-fwd/tests/
# custodian_signed_mgmt.rs) spawns a real ndn-fwd with require_signed_commands
# and a FilePib anchor, signs a strategy-choice/set through a CustodianSigner
# over an InPageCustodian holding the operator key, and asserts:
#   - the custodian-signed command is accepted (StatusCode 200, executed), and
#   - the same command unsigned (DigestSha256) is rejected by the validator.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

# The test boots ndn-fwd itself (via CARGO_BIN_EXE) — no external daemon needed.
if cargo test -p ndn-fwd --test custodian_signed_mgmt \
    custodian_signed_command_authorized_by_strict_ndn_fwd \
    >/tmp/custodian_live.log 2>&1; then
    grep -E 'test result|strategy-choice/set' /tmp/custodian_live.log || true
    echo "ok: custodian-signed mgmt command authorized by live strict ndn-fwd; unsigned rejected"
else
    echo "FAIL: live custodian-signed mgmt authorization test failed" >&2
    tail -30 /tmp/custodian_live.log >&2
    exit 1
fi
