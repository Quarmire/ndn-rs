#!/usr/bin/env bash
# Witness for N.08 — unsolicited-Data policy is behavioral, not a grep proof.
#
# Proves all four policy shapes through a real ForwarderEngine:
#   - DropAll rejects unsolicited cache admission.
#   - AdmitAll admits unsolicited cache admission.
#   - AdmitLocal admits local faces only.
#   - AdmitNetwork admits non-local/broadcast faces only.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if cargo test -p ndn-engine --test broadcast_data_parity --quiet n08_ \
        >/tmp/n08_unsolicited_data_policy.log 2>&1; then
    cat /tmp/n08_unsolicited_data_policy.log
    echo
    echo "=== N.08 RESOLVED — unsolicited-Data policy covers drop/all/local/network ==="
    exit 0
else
    echo "FAIL: N.08 unsolicited-Data policy witness"
    cat /tmp/n08_unsolicited_data_policy.log
    exit 1
fi
