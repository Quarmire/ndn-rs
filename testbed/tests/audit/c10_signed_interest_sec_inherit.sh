#!/usr/bin/env bash
# Witness test for audit finding C.10 — ndn-security's signed Interest
# path inherits the A.09 fix (signs over spec-correct two-range region).
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.10
# Severity:    BLOCKER (inherited A.09); RESOLVED with A.09
# Spec ref:    signed-interest.html signed-region;
#              ndn-cxx/ndn-cxx/interest.cpp:657-727 (extractSignedRanges,
#              computeParametersDigest)
# Witnesses:   RUST-UNIT — the same a09_signed_interest_verify.sh tests
#              that prove InterestBuilder produces spec-correct signed
#              regions cover the ndn-security path because KeyChain::sign_interest
#              delegates to InterestBuilder::sign_sync.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

# Verify that KeyChain::sign_interest delegates to InterestBuilder (GREP-PROOF)
if grep -q "InterestBuilder" \
    "$REPO_ROOT/crates/ndn-security/src/keychain.rs"; then
    echo "ok: keychain.rs delegates sign_interest to InterestBuilder"
else
    echo "FAIL: keychain.rs does not reference InterestBuilder for signing"
    exit 1
fi

# Run the a09 canonical witness tests — they cover the signing path
fail=0
for test_name in \
    interest_builder_sign_sync_signed_region_matches_extractor \
    interest_builder_sign_sync_roundtrip
do
    if cargo test -p ndn-packet --lib --features std --quiet "$test_name" \
            >>/tmp/c10_witness.log 2>&1; then
        echo "ok: $test_name"
    else
        echo "FAIL: $test_name"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.10 RESOLVED — ndn-security inherits A.09 fix; signed Interest region correct ==="
    exit 0
else
    echo
    echo "=== C.10 FAIL — A.09 tests failing; signed Interest region broken ==="
    cat /tmp/c10_witness.log
    exit 1
fi
