#!/usr/bin/env bash
# Witness test for audit finding N.12 — every mgmt control-response
# Data is signed with `DigestSha256` only; ndn-cxx `nfd::Controller`
# configured for an NFD trust schema rejects bare-digest responses.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.12
# Severity:    MAJOR (depends on C.07/C.08 for ndn-rs to even produce
#              a usable signing identity — both RESOLVED 2026-05-01)
# Spec ref:    NFD signs every control response with the daemon's
#              identity key; ndn-cxx `nfd::Controller` validates
#              against the configured trust schema.
# Witnesses:   RUST-UNIT in `ndn-fwd::mgmt_ndn::tests`:
#                - n12_response_falls_back_to_digest_sha256_when_no_signer
#                - n12_response_uses_signer_when_wired
#              The first asserts back-compat with the legacy
#              DigestSha256 path; the second asserts the signed path
#              labels SignatureEd25519 and emits a KeyLocator.
#
# Deferred:    Live `nfdc status` against ndn-fwd configured with an
#              ndn-cxx-style trust schema is BLOCKED-BY-INTEROP until
#              the testclient image carries the ndn-cxx `nfdc` binary
#              + a configured trust anchor.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-fwd --bin ndn-fwd --quiet n12_ \
        >/tmp/n12_witness.log 2>&1; then
    echo "ok: mgmt response signer path emits SignatureEd25519+KeyLocator when wired"
else
    echo "FAIL: mgmt response signer path missing"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.12 RESOLVED 2026-05-02 (architecture; live nfdc trust-schema interop still BLOCKED-BY-INTEROP) ==="
    exit 0
else
    echo
    echo "=== N.12 EXPECTED-FAIL — mgmt responses DigestSha256-only ==="
    [ -f /tmp/n12_witness.log ] && cat /tmp/n12_witness.log
    exit 1
fi
