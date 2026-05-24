#!/usr/bin/env bash
# Witness — NC.18: systematic-first recoding (perf).
#
# The recoder serves the K systematic source packets (unit vectors) for the
# first K requests — no GF combine to serve, and the consumer decodes them by
# the unit-vector fast path (no Gauss-Jordan) — minting random repair only
# beyond K. This is what drops the clean-path coding overhead from ~8x to ~1.2x
# (see NC.17). Requests req<K return unit-vector combinations.
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - recode_face::tests::systematic_first_serves_sources_then_repair
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        systematic_first_serves_sources_then_repair \
        >/tmp/nc18_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc18_witness.log; then
    echo "=== NC.18 PASS — systematic-first serves sources, repair beyond K ==="
    grep -E "test result|running" /tmp/nc18_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.18 FAIL ==="; cat /tmp/nc18_witness.log; exit 1
fi
