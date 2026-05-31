#!/usr/bin/env bash
# Witness for N.14 — trust anchors must be valid at insertion time.
#
# Proves the flat validator and SecurityManager add_trust_anchor paths reject
# expired and not-yet-valid certificates and do not insert them into either the
# anchor set or cert cache. Valid anchors are still accepted.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if cargo test -p ndn-security --lib --quiet n14_ \
        >/tmp/n14_trust_anchor_validity.log 2>&1; then
    cat /tmp/n14_trust_anchor_validity.log
    echo
    echo "=== N.14 RESOLVED — invalid trust-anchor validity windows are rejected ==="
    exit 0
else
    echo "FAIL: N.14 trust-anchor validity witness"
    cat /tmp/n14_trust_anchor_validity.log
    exit 1
fi
