#!/usr/bin/env bash
# Witness test for audit finding C.18 — ValidityPeriod ISO-8601 form.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.18
# Severity:    BLOCKER
# Spec ref:    ndn-cxx security/validity-period.cpp:29 (ISO_DATETIME_SIZE
#              = 15) + util/time.cpp::toIsoString.
# Witnesses:   ValidityPeriod NotBefore / NotAfter inside the cert's
#              SignatureInfo are 15-byte ASCII YYYYMMDDTHHMMSS strings.
#              Today the encoder writes 8-byte big-endian u64 ns AND
#              places ValidityPeriod inside Content (wrong location).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-security --test cert_format --quiet \
        c18_cert_validity_period_is_iso8601_inside_signature_info \
        >/tmp/c18_witness.log 2>&1; then
    echo "=== C.18 RESOLVED — ValidityPeriod is 15-byte ISO-8601, in SignatureInfo ==="
    exit 0
else
    echo "=== C.18 EXPECTED-FAIL — ValidityPeriod is u64 ns and in Content ==="
    cat /tmp/c18_witness.log
    exit 1
fi
