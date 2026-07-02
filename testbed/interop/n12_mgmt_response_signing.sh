#!/usr/bin/env bash
# Witness test for audit finding N.12 — management control-response
# Data must be signed with a key-backed daemon identity and validate
# against the configured trust anchor, not merely DigestSha256.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.12
# Severity:    MAJOR (depends on C.07/C.08 for ndn-rs to even produce
#              a usable signing identity — both RESOLVED 2026-05-01)
# Spec ref:    NFD signs every control response with the daemon's
#              identity key; ndn-cxx `nfd::Controller` validates
#              against the configured trust schema.
# Witnesses:   RUST-UNIT in `ndn-mgmt::auth::tests`:
#                - n12_response_falls_back_to_digest_sha256_when_no_signer
#                - n12_response_uses_signer_when_wired
#              The first asserts back-compat with the legacy
#              DigestSha256 path; the second asserts the signed path
#              labels SignatureEd25519 and emits a KeyLocator.
#
#              LIVE-INTEROP in Docker:
#                - reference `nfdc status` decodes ndn-fwd management data
#                  over the Unix face.
#                - `ndn-mgmt-response-verify` fetches the standard
#                  `/localhost/nfd/cs/config` control response and verifies
#                  its ECDSA-P256 signature against the PIB trust anchor
#                  shared from ndn-fwd.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-mgmt --quiet n12_ \
        >/tmp/n12_witness.log 2>&1; then
    echo "ok: mgmt response signer path emits SignatureEd25519+KeyLocator when wired"
else
    echo "FAIL: mgmt response signer path missing"
    fail=1
fi

if [ "$fail" -eq 0 ] && command -v docker >/dev/null 2>&1; then
    if docker compose -f testbed/docker-compose.yml exec -T interop true \
            >/dev/null 2>&1; then
        if docker compose -f testbed/docker-compose.yml exec -T interop bash -lc '
            set -euo pipefail
            export NDN_CLIENT_TRANSPORT=unix:///run/ndn-fwd/ndn-fwd.sock
            nfdc status >/tmp/n12_nfdc_status.txt
            ndn-mgmt-response-verify \
              --socket /run/ndn-fwd/ndn-fwd.sock \
              --pib /run/ndn-fwd/pib \
              --key-prefix /testbed/ndn-fwd
        ' >/tmp/n12_live_witness.log 2>&1; then
            echo "ok: reference nfdc decoded ndn-fwd management status"
            cat /tmp/n12_live_witness.log
        else
            echo "FAIL: live management response trust-anchor verification failed"
            cat /tmp/n12_live_witness.log
            fail=1
        fi
    else
        echo "SKIP: Docker interop services are not running; start with:"
        echo "      docker compose -f testbed/docker-compose.yml up -d interop ndn-fwd nfd yanfd"
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.12 RESOLVED 2026-05-28 (unit + live trust-anchor interop when Docker is running) ==="
    exit 0
else
    echo
    echo "=== N.12 FAIL — mgmt response signing/trust-anchor witness failed ==="
    [ -f /tmp/n12_witness.log ] && cat /tmp/n12_witness.log
    exit 1
fi
