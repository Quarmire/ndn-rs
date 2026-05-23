#!/usr/bin/env bash
# Witness test for audit finding C.01 — RSA-SHA256 and ECDSA-SHA256
# verifiers are implemented and wired into verify_by_sig_type.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.01
# Severity:    MAJOR; RESOLVED 2026-05-07
# Spec ref:    NDN Packet Format Spec §3 (SignatureType); ndn-cxx
#              security/verification-helpers.cpp:222-246
# Witnesses:   GREP-PROOF — RsaSha256Verifier / EcdsaSha256Verifier
#              structs exist and are dispatched in verify_by_sig_type.
#              RUST-UNIT — six unit tests in verifier::tests and one
#              validator integration test cover happy-path, wrong-sig,
#              and bad-key branches for both algorithms.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0

# GREP-PROOF: struct declarations exist
for sym in RsaSha256Verifier EcdsaSha256Verifier; do
    if grep -q "pub struct $sym" \
        "$REPO_ROOT/crates/ndn-security/src/verifier.rs"; then
        echo "ok: $sym declared"
    else
        echo "FAIL: $sym not found"
        fail=1
    fi
done

# GREP-PROOF: both arms wired in verify_by_sig_type (no longer UnsupportedSignatureType)
if ! grep -A2 "SignatureSha256WithRsa" \
        "$REPO_ROOT/crates/ndn-security/src/verifier.rs" \
        | grep -q "UnsupportedSignatureType"; then
    echo "ok: SignatureSha256WithRsa arm no longer returns UnsupportedSignatureType"
else
    echo "FAIL: SignatureSha256WithRsa still returns UnsupportedSignatureType"
    fail=1
fi

if ! grep -A2 "SignatureSha256WithEcdsa" \
        "$REPO_ROOT/crates/ndn-security/src/verifier.rs" \
        | grep -q "UnsupportedSignatureType"; then
    echo "ok: SignatureSha256WithEcdsa arm no longer returns UnsupportedSignatureType"
else
    echo "FAIL: SignatureSha256WithEcdsa still returns UnsupportedSignatureType"
    fail=1
fi

# RUST-UNIT: verifier unit tests + validator integration test
for test_name in \
    verifier::tests::rsa_valid_signature_returns_valid \
    verifier::tests::rsa_wrong_signature_returns_invalid \
    verifier::tests::rsa_bad_key_returns_err \
    verifier::tests::ecdsa_valid_signature_returns_valid \
    verifier::tests::ecdsa_wrong_signature_returns_invalid \
    verifier::tests::ecdsa_bad_key_returns_err \
    validator::tests::c01_rsa_and_ecdsa_verifiers_are_wired
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
    echo "=== C.01 RESOLVED — RsaSha256Verifier and EcdsaSha256Verifier wired ==="
    exit 0
else
    echo
    echo "=== C.01 FAIL — RSA/ECDSA verifiers missing or broken ==="
    cat /tmp/c01_witness.log
    exit 1
fi
