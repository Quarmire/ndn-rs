#!/usr/bin/env bash
# Witness test for audit finding C.01 — RSA-SHA256 and ECDSA-SHA256
# verifiers are implemented and wired into verify_by_sig_type.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.01
# Severity:    MAJOR; RESOLVED 2026-05-07
# Spec ref:    NDN Packet Format Spec §3 (SignatureType); ndn-cxx
#              security/verification-helpers.cpp:222-246
# Witnesses:   RUST-UNIT — six verifier tests plus one validator
#              integration test cover happy-path, wrong-sig, bad-key,
#              and dispatch branches for both algorithms.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

LOG="${TMPDIR:-/tmp}/c01_rsa_ecdsa_witness.log"
: > "$LOG"

if cargo test -p ndn-security --lib --quiet c01_ >>"$LOG" 2>&1; then
    echo "ok: c01_ behavioral verifier tests"
else
    echo "FAIL: c01_ behavioral verifier tests"
    cat "$LOG"
    exit 1
fi

TEST_LIST=$(cargo test -p ndn-security --lib -- --list 2>>"$LOG")
for test_name in \
    c01_rsa_valid_signature_returns_valid \
    c01_rsa_wrong_signature_returns_invalid \
    c01_rsa_bad_key_returns_err \
    c01_ecdsa_valid_signature_returns_valid \
    c01_ecdsa_wrong_signature_returns_invalid \
    c01_ecdsa_bad_key_returns_err \
    c01_rsa_and_ecdsa_verifiers_are_wired
do
    if [[ "$TEST_LIST" == *"::${test_name}: test"* ]]; then
        echo "ok: listed $test_name"
    else
        echo "FAIL: $test_name missing from ndn-security test list"
        cat "$LOG"
        exit 1
    fi
done

echo
echo "=== C.01 RESOLVED — RSA/ECDSA verifier behavior is witnessed by Rust tests ==="
