#!/usr/bin/env bash
# Witness test for audit findings C.01 / C.02 / C.03 / C.05 / I.04 —
# the Validator must dispatch on SignatureType, not hardwire one
# verifier.
#
# Finding:     testbed/EXPECTED_FAILURES.md § C.01
# Severity:    BLOCKER
# Spec ref:    NDN Packet Format v0.3 signature.html;
#              ndn-cxx security/verification-helpers.cpp:222-246
#              dispatches via DigestAlgorithm derived from
#              SignatureType.
# Witnesses:   RUST-UNIT tests in `ndn-security`:
#                - c01_rsa_and_ecdsa_verifiers_are_wired
#                  (RSA/ECDSA verifier dispatch reaches concrete crypto)
#                - c02_hmac_signed_data_validates_through_dispatch
#                  (HMAC-SHA-256 path; was hardwired to Ed25519)
#                - c03_digest_sha256_data_validates_through_dispatch
#                  (DigestSha256 reachable on basic validate path)
#
# The previous interop variant of this script (using ndnsec / ndnpeek)
# is still useful for end-to-end verification with ndn-cxx-issued
# certs and remains BLOCKED-BY-INTEROP until those tools land in the
# testclient image. Today's RUST-UNIT witness covers the dispatch
# architecture itself.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
for test_name in \
    c01_rsa_and_ecdsa_verifiers_are_wired \
    c02_hmac_signed_data_validates_through_dispatch \
    c03_digest_sha256_data_validates_through_dispatch
do
    if cargo test -p ndn-security --lib --quiet "$test_name" \
            >>/tmp/c01_witness.log 2>&1; then
        echo "ok: $test_name"
    else
        echo "FAIL: $test_name"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.01 / C.02 / C.03 / C.05 / I.04 RESOLVED — Validator dispatches on SignatureType ==="
    exit 0
else
    echo
    echo "=== C.01 / C.05 / I.04 EXPECTED-FAIL — Validator hardwired or dispatch missing ==="
    cat /tmp/c01_witness.log
    exit 1
fi
