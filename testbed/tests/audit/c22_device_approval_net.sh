#!/usr/bin/env bash
# Witness test for C.22 — cross-process NDNCERT device-approval transport.
#
# Follow-up:   .claude/notes/ndncert-device-approval-transport-2026-05-22.md
# Claim:       An approver device with no inbound route can approve an
#              enrollment: it advertises to the CA's APPROVE-FEED with a
#              reflexive name, the CA pulls the signed approval back along the
#              reverse path, verifies the approver's signature over the
#              approval statement, and records it in the PendingApprovalStore
#              the DeviceApprovalChallenge reads. An untrusted approver (no
#              resolvable key) does not flip the request.
# Witnesses:   ndn-identity device_approval_net integration tests, over an
#              embedded engine with reflexive forwarding.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-identity --test device_approval_net --quiet \
        >/tmp/c22_witness.log 2>&1; then
    echo "=== C.22 RESOLVED — cross-process device-approval over reflexive forwarding ==="
    exit 0
else
    echo "=== C.22 EXPECTED-FAIL — cross-process device-approval transport broken ==="
    cat /tmp/c22_witness.log
    exit 1
fi
