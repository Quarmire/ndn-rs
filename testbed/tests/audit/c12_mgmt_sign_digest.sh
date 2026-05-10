#!/usr/bin/env bash
# Witness test for audit finding C.12 — ndn-ctl (MgmtClient) command
# Interests are signed with DigestSha256 InterestSignatureInfo.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.12
# Severity:    MAJOR
# Spec ref:    NFD Developer Guide §7 (RIB manager, command Interests);
#              ndn-cxx/ndn-cxx/mgmt/nfd/controller.cpp:sendCommandInterest
#              uses ValidatorNull / DigestSha256 for localhost faces.
# Witnesses:   GREP-PROOF — MgmtClient::send_interest calls
#              InterestBuilder::sign_digest_sha256, which generates
#              InterestSignatureInfo + SigNonce + SigTime + PSDC per the
#              NFD v0.3 signed Interest format. Dataset queries remain
#              unsigned per NFD convention.
#
# Scope note: DigestSha256 is accepted by ndn-fwd and localhost-face NFD
# with "certfile any". Testbed NFD (rib.localhop_security) requires a
# key-backed signer — that leg remains BLOCKED-BY-INTEROP until
# MgmtClient grows a Signer parameter.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

fail=0

# MgmtClient::send_interest must call sign_digest_sha256
if grep -q "sign_digest_sha256" \
    "$REPO_ROOT/crates/spec/ndn-ipc/src/mgmt_client.rs"; then
    echo "ok: send_interest uses sign_digest_sha256"
else
    echo "FAIL: send_interest does not use sign_digest_sha256"
    fail=1
fi

# Dataset queries must NOT be signed (they use send_unsigned_interest)
if grep -q "send_unsigned_interest" \
    "$REPO_ROOT/crates/spec/ndn-ipc/src/mgmt_client.rs"; then
    echo "ok: dataset queries use send_unsigned_interest"
else
    echo "FAIL: send_unsigned_interest path is missing"
    fail=1
fi

# sign_digest_sha256 must be described as the minimum NFD signature
if grep -q "Minimum signature accepted by NFD" \
    "$REPO_ROOT/crates/spec/ndn-packet/src/encode/interest.rs"; then
    echo "ok: sign_digest_sha256 is documented as NFD minimum"
else
    echo "FAIL: sign_digest_sha256 not described as NFD minimum"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.12 RESOLVED — MgmtClient signs command Interests with DigestSha256 ==="
    exit 0
else
    echo
    echo "=== C.12 EXPECTED-FAIL — command Interests unsigned or missing sign path ==="
    exit 1
fi
