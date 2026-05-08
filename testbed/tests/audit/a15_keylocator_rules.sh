#!/usr/bin/env bash
# Witness test for audit finding A.15 — KeyLocator presence/absence not
# validated against SignatureType during SignatureInfo decode.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.15
# Severity:    MAJOR
# Spec ref:    NDN Packet Format v0.3 signature.html — KeyLocator table:
#              DigestSha256 (0): KeyLocator forbidden.
#              Sha256WithRsa (1), Sha256WithEcdsa (3), HmacWithSha256 (4),
#              Ed25519 (5): KeyLocator required.
#              DigestBlake3 (6): KeyLocator forbidden (blake3-signature-spec.md §1).
#              SignatureBlake3Keyed (7): KeyLocator required (§2).
# Witnesses:   RUST-UNIT in ndn-packet:
#                a15_keylocator_digest_sha256_rejects_locator
#                a15_keylocator_signing_types_require_locator
#                a15_keylocator_digest_blake3_rejects_locator
#                a15_keylocator_blake3_keyed_requires_locator
#                a15_keylocator_unknown_type_no_validation
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet \
        a15_keylocator_ \
        >/tmp/a15_witness.log 2>&1; then
    echo "ok: KeyLocator rules enforced per SignatureType"
else
    echo "FAIL: a15_keylocator_* tests did not pass"
    cat /tmp/a15_witness.log
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.15 RESOLVED — KeyLocator rules enforced per SignatureType ==="
    exit 0
else
    echo
    echo "=== A.15 EXPECTED-FAIL — KeyLocator rules not enforced ==="
    exit 1
fi
