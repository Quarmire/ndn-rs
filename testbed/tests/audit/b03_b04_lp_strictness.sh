#!/usr/bin/env bash
# Audit witness — B.03 / B.04.
#
# B.03: `LpPacket::decode` synthesised an `LpFragment` around a
#       bare top-level `Interest` (0x05) or `Data` (0x06) inside
#       the LpPacket body.  NDNLPv2 requires the network packet
#       to be wrapped in `LpFragment` (0x50); the leniency
#       masked non-conformant peers.  Witness: RUST-UNIT
#         b03_lp_decode_rejects_bare_interest_in_body
#         b03_lp_decode_rejects_bare_data_in_body
#       The match arm now returns `MalformedPacket`.
#
# B.04: PitToken length was capped at 32 bytes.  NDNLPv2 only
#       requires "one or more bytes" with no upper bound; peers
#       using longer tokens (NDN-DPDK ecosystem ceiling
#       notwithstanding) had their entire LpPacket rejected.
#       Witness: RUST-UNIT
#         b04_lp_decode_accepts_long_pit_token
#         b04_lp_decode_still_rejects_empty_pit_token
#         decode_pit_token_long_is_accepted_post_b04
#       Empty PitToken still rejects (spec lower bound).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet b03_ 2>&1 | tail -3; then
    echo "FAIL: B.03 unit tests"
    exit 1
fi
if ! cargo test -p ndn-packet --features std --lib --quiet b04_ 2>&1 | tail -3; then
    echo "FAIL: B.04 unit tests"
    exit 1
fi
echo "=== B.03 / B.04 RESOLVED — strict LP body + unbounded PitToken length ==="
