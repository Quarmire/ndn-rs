#!/usr/bin/env bash
# Witness — NC.20: cross-impl interop wire vectors.
#
# Pins the F2 wire format another NDN library implements against: golden bytes
# for a CodedMetadata head (exact hex), a from-spec hand-decode, and canonical
# round-trips (decode∘encode byte-identical; outer TLV types) for the
# Name-bearing descriptor and recode token.
#
# Witnesses (RUST-UNIT, feature `f2-recode`):
#   - tests/recode_interop.rs (coded_metadata_matches_golden_bytes,
#     coded_metadata_decodes_from_spec_bytes, descriptor_and_token_canonical_roundtrip)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f2-recode --test recode_interop --quiet \
        >/tmp/nc20_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc20_witness.log; then
    echo "=== NC.20 PASS — F2 wire golden vectors + canonical round-trips ==="
    grep -E "test result|running" /tmp/nc20_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.20 FAIL ==="; cat /tmp/nc20_witness.log; exit 1
fi
