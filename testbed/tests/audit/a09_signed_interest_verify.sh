#!/usr/bin/env bash
# Witness test for audit finding A.09 — Signed Interest signing and
# verification use the same spec signed region after the
# ParametersSha256DigestComponent is finalized.
#
# Finding:     testbed/EXPECTED_FAILURES.md § A.09
# Severity:    BLOCKER (RESOLVED)
# Spec ref:    NDN Packet Format v0.3 signed-interest.html — the signed
#              region includes the Name without PSDC, InterestSignatureInfo,
#              ApplicationParameters, and InterestSignatureValue framing.
# Witnesses:   RUST-UNIT — ndn-packet records the exact bytes handed to
#              the signer and proves they equal Interest::signed_region()
#              after decoding the final wire. ndn-security proves
#              KeyChain-signed Interests verify against that decoded region.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

LOG="${TMPDIR:-/tmp}/a09_witness.log"
: > "$LOG"

if cargo test -p ndn-packet --features std --lib --quiet \
        interest_builder_sign_sync_signed_region_matches_extractor \
        >"$LOG" 2>&1; then
    echo "ok: ndn-packet signed-region extractor matches signer bytes"
else
    echo "FAIL: ndn-packet signed-region extractor mismatch"
    cat "$LOG"
    exit 1
fi

if cargo test -p ndn-security --lib --quiet \
        keychain_sign_interest_signed_region_verifies \
        >>"$LOG" 2>&1; then
    echo "ok: ndn-security KeyChain-signed Interest verifies"
else
    echo "FAIL: ndn-security KeyChain-signed Interest does not verify"
    cat "$LOG"
    exit 1
fi

echo
echo "=== A.09 RESOLVED — Signed Interest region is witnessed by Rust verification ==="
