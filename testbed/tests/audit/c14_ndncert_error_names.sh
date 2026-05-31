#!/usr/bin/env bash
# Witness test for audit finding C.14 — NDNCERT 0.3 `ErrorCode` variant
# names diverge from the canonical wiki spec.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.14
# Severity:    MAJOR (numeric codes correct; symbolic names wrong)
# Spec ref:    NDNCERT 0.3 protocol wiki
#              `github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3`.
#              Canonical names: `BadInterestFormat`, `BadParameterFormat`,
#              `BadSignature`, `InvalidParameters`, `NameNotAllowed`,
#              `BadValidityPeriod`, `RunOutOfTries`, `RunOutOfTime`,
#              `NoAvailableNames`.
# Witnesses:   RUST-UNIT round-trip
#              (`c14_error_code_canonical_names_and_numbers` in
#              `ndn-cert::protocol::tests`) that asserts each variant has the
#              canonical Debug name and the spec-defined numeric code.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-cert --lib --quiet c14_ \
        >/tmp/c14_witness.log 2>&1; then
    echo "ok: c14_error_code_canonical_names_and_numbers"
else
    echo "FAIL: c14 round-trip test"
    cat /tmp/c14_witness.log
    exit 1
fi

echo
echo "=== C.14 RESOLVED — NDNCERT ErrorCode names match the canonical spec ==="
