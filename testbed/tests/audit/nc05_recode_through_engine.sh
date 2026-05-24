#!/usr/bin/env bash
# Witness — NC.05: F2 recoding through a real ForwarderEngine.
#
# A `RecoderFace` (synthetic Transport, ndn-compute's attach pattern) is
# attached to a live engine and wired into the FIB for a generation prefix.
# A consumer pulls `…/_gen/<id>/_req/<j>` for j=0,1,2,… ; each distinct
# request is answered by a fresh innovative combination minted by the
# recoder; the consumer reaches rank K and decodes + verify-on-decode.
# Proves the recoder runs on the actual forwarding path (no core engine
# edits). NOTE: this proves the engine path, not a multi-hop lossy-multicast
# RTT comparison — that topology-level benchmark is future work.
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - tests/recode_engine.rs::recoder_face_serves_innovative_combinations_through_engine
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --test recode_engine --quiet \
        >/tmp/nc05_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc05_witness.log; then
    echo "=== NC.05 PASS — recoder serves innovative combinations through the engine ==="
    grep -E "test result|running" /tmp/nc05_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.05 FAIL — engine-path recode witness failed ==="
    cat /tmp/nc05_witness.log
    exit 1
fi
