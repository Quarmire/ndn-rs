#!/usr/bin/env bash
# Witness test for audit finding H.10 — ndn-app's KeyChain::sign_interest
# inherits the A.09 signed-region fix and the C.06 sig_type fix.
# The signed region must be non-empty and the signature must verify.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § H.10
# Severity:    BLOCKER (inherited from A.09 / C.06)
# Spec ref:    NDN Packet Format v0.3 signed-interest.html §5.3 — signed
#              region = Name component TLVs (excl. PSDC) +
#              ApplicationParameters + InterestSignatureInfo.
#              SignatureType must reflect the actual algorithm used.
#              ndn-cxx security/key-chain.cpp:751-776
# Witnesses:   RUST-UNIT in `ndn-security`:
#                - h10_keychain_sign_interest_signed_region_verifies
#              Builds a KeyChain with Ed25519Signer, signs an Interest via
#              KeyChain::sign_interest, extracts signed_region, and verifies
#              the Ed25519 signature. SignatureType must be Ed25519.
#
# Scope note: ndn-app::security re-exports ndn_security::KeyChain directly
# (crates/ndn-app/src/security.rs). Tests in ndn-security cover
# the behaviour; this witness confirms the inheritance path is correct.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-security --lib h10_ \
        >/tmp/h10_witness.log 2>&1; then
    if grep -q "^running 0 tests" /tmp/h10_witness.log; then
        echo "FAIL: no h10_ tests found — witness test not yet written"
        fail=1
    else
        echo "ok: KeyChain::sign_interest signed region verifies and sig_type is correct"
    fi
else
    echo "FAIL: signed_region missing or signature invalid — A.09/C.06 not fully inherited"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== H.10 RESOLVED — ndn-app consumer signed Interests verify end-to-end ==="
    exit 0
else
    echo
    echo "=== H.10 EXPECTED-FAIL — KeyChain::sign_interest broken signed region ==="
    cat /tmp/h10_witness.log
    exit 1
fi
