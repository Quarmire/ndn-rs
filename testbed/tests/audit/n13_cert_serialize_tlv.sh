#!/usr/bin/env bash
# Witness test for audit finding N.13 — NDNCERT cert transport must use
# Data TLVs.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.13
# Severity:    MAJOR (compounds C.07/C.08)
# Spec ref:    NDNCERT 0.3 — issued certs are real NDN Data packets, not
#              custom binary blobs.
# Witnesses:   `ndn_cert::ca::serialize_cert(&cert)` returns bytes that
#              parse as `ndn_packet::Data`. Today the function emits a
#              `[u64][u64][u32][bytes]…` blob that fails Data parse.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-cert --test n13_serialize_data --quiet \
        n13_serialize_cert_returns_parseable_data_tlv \
        >/tmp/n13_witness.log 2>&1; then
    echo "=== N.13 RESOLVED — serialize_cert emits a Data TLV ==="
    exit 0
else
    echo "=== N.13 EXPECTED-FAIL — serialize_cert emits custom binary blob ==="
    cat /tmp/n13_witness.log
    exit 1
fi
