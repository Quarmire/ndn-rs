#!/usr/bin/env bash
# Witness recipe for ARCH-8 (signing half) / S12 — `KeyChain::sign_packet(packet, &SigningInfo)`.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-8
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:   each `SignerSelection` variant — Identity / Key / Cert /
#              HmacKey / Digest / Suggested — round-trips through
#              `KeyChain::sign_packet` and produces a well-formed
#              signed Data (or surfaces an honest error). Mirrors
#              ndn-cxx `KeyChain::sign(packet, SigningInfo)` at
#              `~/Documents/Dev/ndn-cxx/ndn-cxx/security/key-chain.hpp:300,329`.
#
# Reverify recipe: RUST-UNIT. Runs the targeted ndn-security keychain
# test cases; no Docker, no toolchain beyond cargo.
#
# Exit codes:
#   0 — PASS (every variant resolves + signs as designed)
#   1 — FAIL (one or more variants regressed)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TESTS=(
    "s12_signing_info_digest"
    "s12_signing_info_identity_self"
    "s12_signing_info_identity_other_rejected"
    "s12_signing_info_named_key"
    "s12_signing_info_hmac_key"
    "s12_signing_info_cert"
    "s12_signing_info_suggested_falls_back"
    "s12_signing_info_unknown_key_errors"
    "s12_signing_info_interest"
)

fail=0
for t in "${TESTS[@]}"; do
    echo "→ cargo test -p ndn-security --lib keychain::tests::${t}"
    if ! cargo test --quiet -p ndn-security --lib "keychain::tests::${t}" \
            -- --exact >/dev/null 2>&1; then
        echo "FAIL: keychain::tests::${t}" >&2
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-8 (signing) — KeyChain::sign_packet(packet, &SigningInfo) resolves every SignerSelection variant."
fi
exit "$fail"
