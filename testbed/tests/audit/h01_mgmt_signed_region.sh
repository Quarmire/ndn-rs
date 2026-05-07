#!/usr/bin/env bash
# Witness test for audit finding H.01 — MgmtClient command Interests inherit
# the A.09 signed-region fix: the DigestSha256 sig_value must equal
# SHA-256(signed_region) as reconstructed by Interest::signed_region().
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § H.01
# Severity:    BLOCKER (inherited from A.09)
# Spec ref:    NDN Packet Format v0.3 signed-interest.html §5.3 — signed
#              region = Name component TLVs (excl. PSDC) +
#              ApplicationParameters + InterestSignatureInfo.
#              DigestSha256 sig_value must equal SHA-256(signed_region).
#              ndn-cxx command-interest-signer.cpp:sendCommandInterest
# Witnesses:   RUST-UNIT in `ndn-ipc`:
#                - h01_digest_sha256_signed_region_verifies
#              Builds a rib/register command Interest with DigestSha256 policy,
#              extracts the signed_region, recomputes SHA-256, and asserts it
#              equals sig_value. Also verifies InterestSignatureInfo carries
#              SigNonce and SigTime (anti-replay per A.09 fix).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-ipc --lib h01_ \
        >/tmp/h01_witness.log 2>&1; then
    if grep -q "^running 0 tests" /tmp/h01_witness.log; then
        echo "FAIL: no h01_ tests found — witness test not yet written"
        fail=1
    else
        echo "ok: DigestSha256 sig_value equals SHA-256(signed_region)"
    fi
else
    echo "FAIL: signed_region mismatch or missing — A.09 not fully inherited"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== H.01 RESOLVED — MgmtClient signed Interest verifies with fresh DigestSha256 ==="
    exit 0
else
    echo
    echo "=== H.01 EXPECTED-FAIL — MgmtClient signed-region bug not fixed ==="
    cat /tmp/h01_witness.log
    exit 1
fi
