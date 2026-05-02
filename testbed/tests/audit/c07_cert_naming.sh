#!/usr/bin/env bash
# Witness test for audit finding C.07 — cert naming.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.07
# Severity:    BLOCKER
# Spec ref:    ndn-cxx security/certificate.hpp:152-158
#              MIN_CERT_NAME_LENGTH = 4; KEY_COMPONENT_OFFSET = -4.
# Witnesses:   ndn-security `KeyChain::ephemeral` produces a cert/key
#              name whose -4-th component is literally "KEY". Today the
#              ephemeral path emits `/<id>/KEY/v=0` (only 2 trailing
#              components after `<id>`), so the assertion trips.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-security --test cert_format --quiet \
        c07_keychain_ephemeral_cert_name_has_four_trailing_components \
        >/tmp/c07_witness.log 2>&1; then
    echo "=== C.07 RESOLVED — cert name has KEY/<keyid>/<issuer>/<version> trailing ==="
    exit 0
else
    echo "=== C.07 EXPECTED-FAIL — cert name shorter than spec requires ==="
    cat /tmp/c07_witness.log
    exit 1
fi
