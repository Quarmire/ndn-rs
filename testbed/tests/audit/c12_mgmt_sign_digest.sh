#!/usr/bin/env bash
# Witness test for audit finding C.12 — ndn-ctl (MgmtClient) command
# Interests are signed with DigestSha256 InterestSignatureInfo.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.12
# Severity:    MAJOR
# Spec ref:    NFD Developer Guide §7 (RIB manager, command Interests);
#              ndn-cxx/ndn-cxx/mgmt/nfd/controller.cpp:sendCommandInterest
#              uses ValidatorNull / DigestSha256 for localhost faces.
# Witnesses:   RUST-UNIT — ndn-ipc builds a command Interest, decodes it,
#              reconstructs the signed region, and asserts DigestSha256
#              SignatureValue equals SHA-256(signed_region). A second test
#              checks the default signing policy emits SignatureType 0.
#
# Scope note: DigestSha256 is accepted by ndn-fwd and localhost-face NFD
# with "certfile any". Testbed NFD (rib.localhop_security) requires a
# key-backed signer — that leg remains BLOCKED-BY-INTEROP until
# MgmtClient grows a Signer parameter.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

LOG="${TMPDIR:-/tmp}/c12_digest_witness.log"
: > "$LOG"

if cargo test -p ndn-ipc --lib --quiet c12_digest_sha256_ >"$LOG" 2>&1; then
    echo "ok: DigestSha256 command Interest behavioral tests"
else
    echo "FAIL: DigestSha256 command Interest behavioral tests"
    cat "$LOG"
    exit 1
fi

TEST_LIST=$(cargo test -p ndn-ipc --lib -- --list 2>>"$LOG")
for test_name in \
    c12_digest_sha256_signed_region_verifies \
    c12_digest_sha256_policy_produces_signed_interest
do
    if [[ "$TEST_LIST" == *"::${test_name}: test"* ]]; then
        echo "ok: listed $test_name"
    else
        echo "FAIL: $test_name missing from ndn-ipc test list"
        cat "$LOG"
        exit 1
    fi
done

echo
echo "=== C.12 RESOLVED — MgmtClient signs command Interests with DigestSha256 ==="
