#!/usr/bin/env bash
# Audit witness — B.02.
#
# Finding:     `LpPacket::decode` iterated header fields with `_ => {}`
#              and silently dropped every unrecognised LP TLV-TYPE.
#              NFD's `lp/packet.cpp:wireDecode` rejects via
#              `Detail::onUnknownFieldType` per the standard NDN
#              critical-bit rule.
# Witness:     RUST-UNIT
#                b02_lp_decode_rejects_unknown_critical_lp_field
#                b02_lp_decode_accepts_unknown_non_critical_lp_field
#              Critical-bit rule (per ndn-packet `is_critical_tlv_type`):
#                types ≤ 31 = grandfathered-critical
#                types ≥ 32 ODD = critical
#                types ≥ 32 EVEN = non-critical
#              Most defined LP fields (Nack=0x320, CongestionMark=0x340…)
#              are even and so were always tolerated; the odd-type
#              unknowns are what the historical `_ => {}` masked.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet b02_lp_ 2>&1 | tail -3; then
    echo "FAIL: B.02 unit tests"
    exit 1
fi

echo "=== B.02 RESOLVED — unknown critical LP TLV-TYPEs rejected ==="
