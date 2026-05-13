#!/usr/bin/env bash
# Audit witness — A.16.
#
# Finding:     `Data::decode` did not validate `SignatureValue`
#              length against the declared `SignatureType`, so
#              malformed Ed25519 / DigestSha256 / Hmac / BLAKE3
#              packets with wrong-width signatures decoded
#              silently.
# Witness:     RUST-UNIT
#                a16_data_decode_rejects_short_ed25519_signature_value
#                a16_data_decode_rejects_oversize_digest_sha256_value
#                a16_variable_width_sig_types_pass_length_check
#              A new `SignatureType::required_signature_value_len`
#              returns the spec-mandated width for fixed-width
#              algorithms (Sha256/Hmac=32, Ed25519=64, BLAKE3=32)
#              and `None` for variable-width (RSA/ECDSA), which
#              `validate_data_body_structure` consults on every
#              `SIGNATURE_VALUE` decode.
# Spec ref:    NDN Packet Format `signature.html` SignatureValue
#              column.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet a16_ 2>&1 | tail -3; then
    echo "FAIL: A.16 unit tests"
    exit 1
fi
echo "=== A.16 RESOLVED — SignatureValue length enforced per SignatureType ==="
