#!/usr/bin/env bash
# Witness test for audit finding C.08 — cert Content as DER SPKI.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § C.08
# Severity:    BLOCKER
# Spec ref:    ndn-cxx security/transform/public-key.cpp:101 (loadPkcs8)
#              + RFC 8410 (Ed25519 SPKI).
# Witnesses:   The Content body of a cert produced by
#              `encode_cert_data` is a 44-byte Ed25519 SPKI envelope.
#              Today the encoder writes raw key bytes wrapped in
#              TLV-TYPE 0x00 (62 bytes total, wrong shape).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-security --test cert_format --quiet \
        c08_cert_content_body_is_der_spki \
        >/tmp/c08_witness.log 2>&1; then
    echo "=== C.08 RESOLVED — cert Content is DER SubjectPublicKeyInfo ==="
    exit 0
else
    echo "=== C.08 EXPECTED-FAIL — cert Content is raw key, not SPKI ==="
    cat /tmp/c08_witness.log
    exit 1
fi
