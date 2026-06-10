#!/usr/bin/env bash
# Witness — F16(iii) (NDF): ContentHashTarget::InnerTlvType delegated hashing
# (NDF consumer faces hash the inner TLV type 364, not the whole Content).
#
# Finding:   ndf-vault/45-libraries/ndn-rs-feature-requests.md § F16 (also F8)
# Severity:  MAJOR (deliberate divergence: NDF's delegated-hashing contract is
#            InnerTlvType(364) on its consumer faces).
# Spec ref:  ndn-rs extension (ContentHashTarget); see docs § delegated hashing.
# Witnesses: RUST-UNIT, two layers:
#   ndn-packet (the digest primitive):
#     - implicit_digest_is_sha256_of_raw
#   ndn-engine decode stage (per-face InnerTlvType selection):
#     - app_face_inner_tlv_type_found      InnerTlvType(364) present → Some
#     - inner_tlv_type_not_found_is_none   target TLV absent → sidecar None
#
# Pins the InnerTlvType(364) behavior NDF depends on in the audited set.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

ok=1
if ! cargo test -p ndn-packet --features std --lib --quiet -- implicit_digest_is_sha256_of_raw \
        >/tmp/f16iii_pkt.log 2>&1; then
    echo "=== F16(iii) FAIL — implicit-digest primitive ==="; cat /tmp/f16iii_pkt.log; ok=0
fi
if ! cargo test -p ndn-engine --lib --quiet -- \
        app_face_inner_tlv_type_found inner_tlv_type_not_found_is_none \
        >/tmp/f16iii_engine.log 2>&1; then
    echo "=== F16(iii) FAIL — InnerTlvType delegated hashing ==="; cat /tmp/f16iii_engine.log; ok=0
fi

if [ "$ok" = 1 ]; then
    echo "=== F16(iii) PASS — InnerTlvType(364) delegated hashing holds ==="
    exit 0
fi
exit 1
