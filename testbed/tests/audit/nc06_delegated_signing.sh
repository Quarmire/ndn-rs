#!/usr/bin/env bash
# Witness — NC.06: F2 delegated-recoder signing (doctrine §3b).
#
# A recoder signs Role=2 coded Data with a key under the descriptor's
# delegation namespace; `verify_delegated_recoder` accepts it (authorized +
# valid signature), rejects an out-of-namespace signer (authorization gate),
# and rejects a bad key (crypto). In-flight verification with ordinary
# Ed25519 signatures — no homomorphic crypto. Full cert-chain validation to
# the trust anchor remains the engine validator's job.
#
# Also: a producer TrustSchema (not just a raw prefix) authorizes the recoder
# key to sign the coded-request name (`verify_delegated_recoder_schema`).
#
# Witnesses (RUST-UNIT, feature `f2-recode-face`):
#   - recode_face::tests::delegated_signing_authorizes_by_namespace
#   - recode_face::tests::schema_authorizes_delegated_recoder
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        delegated_signing_authorizes_by_namespace \
        schema_authorizes_delegated_recoder \
        >/tmp/nc06_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc06_witness.log; then
    echo "=== NC.06 PASS — delegated recoder authorized by namespace/schema + signature ==="
    grep -E "test result|running" /tmp/nc06_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.06 FAIL — delegated-signing witness failed ==="
    cat /tmp/nc06_witness.log
    exit 1
fi
