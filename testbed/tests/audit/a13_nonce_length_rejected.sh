#!/usr/bin/env bash
# Audit witness — A.13.
#
# Finding:     Nonce length mismatch silently dropped the nonce; should
#              reject per NDN Packet Format v0.3 §3.2 (Nonce = 4 bytes).
# Witness:     RUST-UNIT — `cargo test -p ndn-packet --features std --lib
#              decode_rejects_short_nonce decode_rejects_long_nonce`.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib decode_rejects_short_nonce \
        --quiet 2>&1 | tail -3; then
    echo "FAIL: A.13 short-nonce unit test"
    exit 1
fi
if ! cargo test -p ndn-packet --features std --lib decode_rejects_long_nonce \
        --quiet 2>&1 | tail -3; then
    echo "FAIL: A.13 long-nonce unit test"
    exit 1
fi

echo "=== A.13 RESOLVED — Nonce length mismatch rejects Interest ==="
