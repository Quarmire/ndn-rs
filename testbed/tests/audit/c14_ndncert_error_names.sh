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
# Witnesses:   GREP-PROOF (the old names must be absent in the protocol
#              module) plus a RUST-UNIT round-trip
#              (`c14_error_code_canonical_names_and_numbers` in
#              `ndn-cert::protocol::tests`) that asserts each variant has the
#              canonical Debug name and the spec-defined numeric code.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0

# 1. GREP-PROOF: the diverged old names must not appear in protocol.rs.
old_names_re='\b(BadInterest|BadApplicationParameters|InvalidSignature|OutOfTries|OutOfTime)\b'
hits=$(grep -nE "$old_names_re" crates/spec/ndn-cert/src/protocol.rs 2>/dev/null || true)
if [ -n "$hits" ]; then
    echo "FAIL: diverged ErrorCode names still present in protocol.rs:"
    echo "$hits"
    fail=1
else
    echo "ok: diverged ErrorCode names absent from protocol.rs"
fi

# 2. GREP-PROOF: every canonical name must appear at least once.
for canonical in BadInterestFormat BadParameterFormat BadSignature \
                 InvalidParameters NameNotAllowed BadValidityPeriod \
                 RunOutOfTries RunOutOfTime NoAvailableNames; do
    if grep -qE "\b${canonical}\b" crates/spec/ndn-cert/src/protocol.rs; then
        echo "ok: canonical ${canonical} present"
    else
        echo "FAIL: canonical ${canonical} missing from protocol.rs"
        fail=1
    fi
done

# 3. RUST-UNIT: round-trip the canonical names through `From<u8>` / `Into<u8>`.
if cargo test -p ndn-cert --lib --quiet c14_ \
        >/tmp/c14_witness.log 2>&1; then
    echo "ok: c14_error_code_canonical_names_and_numbers"
else
    echo "FAIL: c14 round-trip test"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.14 RESOLVED — NDNCERT ErrorCode names match the canonical spec ==="
    exit 0
else
    echo
    echo "=== C.14 EXPECTED-FAIL — NDNCERT ErrorCode names diverge from spec ==="
    [ -f /tmp/c14_witness.log ] && cat /tmp/c14_witness.log
    exit 1
fi
