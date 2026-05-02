#!/usr/bin/env bash
# Witness test for audit finding C.06 — `KeyChain::sign_data` and
# `KeyChain::sign_interest` hardcode `SignatureType::SignatureEd25519`
# regardless of which `Signer` is actually wired in.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.06
# Severity:    MAJOR
# Spec ref:    NDN Packet Format v0.3 §6.3.2 — `SignatureType` MUST identify
#              the algorithm used to compute `SignatureValue`. ndn-cxx derives
#              this from the signing key's pkey type
#              (`security/key-chain.cpp:751-776`); the Rust port must do the
#              same via the existing `Signer::sig_type()` accessor.
# Witnesses:   RUST-UNIT in `ndn-security`:
#                - c06_sign_data_uses_signer_sigtype_hmac
#                - c06_sign_interest_uses_signer_sigtype_hmac
#              Each constructs a `KeyChain` with `HmacSha256Signer`, signs a
#              Data / Interest, and asserts the decoded SignatureType is
#              `SignatureHmacWithSha256` (TLV code 4). Today: both decode as
#              `SignatureEd25519` (code 5) — wrong by 32-vs-64 byte length and
#              by algorithm. After fix: tests pass.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-security --lib --quiet c06_ \
        >/tmp/c06_witness.log 2>&1; then
    echo "ok: KeyChain reads sig_type from active Signer"
else
    echo "FAIL: KeyChain hardcodes SignatureEd25519"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== C.06 RESOLVED — KeyChain sign_data / sign_interest read signer.sig_type ==="
    exit 0
else
    echo
    echo "=== C.06 EXPECTED-FAIL — KeyChain hardcodes Ed25519 SignatureType ==="
    cat /tmp/c06_witness.log
    exit 1
fi
