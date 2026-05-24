#!/usr/bin/env bash
# Witness — NC.04: F2 verify-on-decode (doctrine §3a, wire spec §7).
#
# A recovered generation is verified against the producer-signed descriptor's
# SourceCommitment after decode. Authentic sources verify; a polluted
# combination decodes to wrong sources and is rejected (authenticity holds —
# bad data never surfaces). Recoded combinations still verify against the
# same anchor.
#
# Witnesses (RUST-UNIT, feature `f2-recode`):
#   - recode::tests::buffer_decodes_and_verifies_sources
#   - recode::tests::recoded_combinations_still_verify
#   - recode::tests::pollution_fails_verify_on_decode
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode --quiet -- \
        buffer_decodes_and_verifies_sources \
        recoded_combinations_still_verify \
        pollution_fails_verify_on_decode \
        >/tmp/nc04_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc04_witness.log; then
    echo "=== NC.04 PASS — verify-on-decode accepts authentic, rejects pollution ==="
    grep -E "test result|running" /tmp/nc04_witness.log | tail -n 3
    exit 0
else
    echo "=== NC.04 FAIL — verify-on-decode witness failed ==="
    cat /tmp/nc04_witness.log
    exit 1
fi
