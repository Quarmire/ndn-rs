#!/usr/bin/env bash
# Witness test for audit finding A.10 — `DataBuilder::build()` forges
# `DigestSha256` by writing 32 zero bytes as the SignatureValue.
#
# Finding:     testbed/EXPECTED_FAILURES.md § A.10
# Severity:    MAJOR
# Spec ref:    NDN Packet Format v0.3 §6.3.2 "DigestSha256"; ndn-cxx
#              `security/transform/digest-filter.cpp` (the only definition of
#              "the SHA-256 of the signed portion") — DigestSha256
#              SignatureValue must equal `SHA-256(signed region)`. Writing
#              `[0u8; 32]` while declaring `SignatureType=0` is a forged label.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - a10_databuilder_build_emits_real_sha256
#              Builds a Data via `DataBuilder::build()`, decodes it, and
#              asserts `sig_value() == SHA-256(signed_region())`.
#              Before the fix: assertion fails (32 zero bytes vs the real digest).
#              After fix: passes — `build()` routes through the existing
#              `sign_digest_sha256()` path which writes the actual digest.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet \
        a10_databuilder_build_emits_real_sha256 \
        >/tmp/a10_witness.log 2>&1; then
    echo "ok: ndn-packet DataBuilder::build emits real SHA-256"
else
    echo "FAIL: ndn-packet DataBuilder::build forges DigestSha256"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.10 RESOLVED — DataBuilder::build() emits real SHA-256 ==="
    exit 0
else
    echo
    echo "=== A.10 EXPECTED-FAIL — DataBuilder::build() forges DigestSha256 ==="
    cat /tmp/a10_witness.log
    exit 1
fi
