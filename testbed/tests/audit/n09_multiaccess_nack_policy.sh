#!/usr/bin/env bash
# Witness for N.09 — Nacks are suppressed on multi-access/ad-hoc faces.
#
# Proves:
#   - locally generated NoRoute Nacks are not emitted on a multi-access ingress;
#   - incoming Nacks from a multi-access face are ignored and not propagated to
#     downstream PIT in-records;
#   - live UDP source-address fixture: an LP Nack from a real socket sender on
#     a shared-medium face is ignored rather than propagated.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if cargo test -p ndn-engine --test broadcast_data_parity --quiet n09_ \
        >/tmp/n09_multiaccess_nack_policy.log 2>&1 \
        && cargo test -p ndn-face-native --test shared_medium_live --quiet \
            n09_live_udp_shared_medium_nack_is_ignored \
            >>/tmp/n09_multiaccess_nack_policy.log 2>&1; then
    cat /tmp/n09_multiaccess_nack_policy.log
    echo
    echo "=== N.09 RESOLVED — multi-access Nacks are suppressed/ignored, including live UDP source fixture ==="
    exit 0
else
    echo "FAIL: N.09 multi-access Nack policy witness"
    cat /tmp/n09_multiaccess_nack_policy.log
    exit 1
fi
