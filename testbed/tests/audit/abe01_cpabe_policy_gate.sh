#!/usr/bin/env bash
# Witness test for the ndn-abe extension — attribute-based access control over
# NDN content (CP-ABE / BSW + MA-ABE / AW11).
#
# Finding:     n/a (feature port, not a spec-conformance fix). This witness
#              pins the behavioural contract of the `ndn-abe` extension crate.
# Severity:    DOCS / feature
# Spec ref:    No adopted community spec for the wire container; the schemes are
#              Bethencourt-Sahai-Waters CP-ABE and Lewko-Waters AW11 MA-ABE via
#              rabe 0.4 (BN-254). ABE is the one-to-many confidentiality tier
#              above the ChaCha20-Poly1305 AEAD baseline in ndn-crypto-core.
# Witnesses:   RUST-UNIT in `ndn-abe`:
#                - encrypt_decrypt_round_trip            (CP-ABE satisfying decrypt)
#                - decrypt_fails_wrong_attributes        (CP-ABE policy gate)
#                - ciphertext_wire_round_trip_with_real_rabe (NDN-TLV container)
#                - aw11_multi_authority_and_policy_round_trip (MA-ABE decrypt)
#                - aw11_multi_authority_missing_one_grant_fails (MA-ABE gate)
#              and the integration test `tests/abe_data_witness.rs`:
#                - cpabe_ciphertext_rides_signed_data_and_policy_gates
#                - maabe_ciphertext_rides_signed_data_and_policy_gates
#              The integration cases assert the AbeCiphertext is a well-formed
#              NDN-TLV container that survives carriage as the Content of a
#              DigestSha256-signed Data packet, and that the policy gate holds
#              end-to-end for both schemes.
#
# Expected today: PASS (exit 0) — the crate and its tests land together. Before
# the port, the crate did not exist and this script exits 2 (SKIP).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if ! cargo metadata --no-deps --format-version 1 2>/dev/null | grep -q '"name":"ndn-abe"'; then
    echo "SKIP: ndn-abe crate not present" >&2
    exit 2
fi

fail=0

if cargo test -p ndn-abe --lib --quiet \
        >/tmp/abe01_unit.log 2>&1; then
    echo "ok: ndn-abe scheme + container unit tests pass (CP-ABE + MA-ABE)"
else
    echo "FAIL: ndn-abe unit tests failed"
    fail=1
fi

if cargo test -p ndn-abe --test abe_data_witness --quiet \
        >/tmp/abe01_integ.log 2>&1; then
    echo "ok: ABE ciphertext rides a signed Data and the policy gate holds end-to-end"
else
    echo "FAIL: ABE-in-signed-Data integration witness failed"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== ndn-abe attribute-based access control: CONTRACT HELD ==="
    exit 0
else
    echo
    echo "=== ndn-abe witness FAILED ==="
    cat /tmp/abe01_unit.log /tmp/abe01_integ.log 2>/dev/null || true
    exit 1
fi
