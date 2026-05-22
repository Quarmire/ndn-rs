#!/usr/bin/env bash
# Witness — reflexive forwarding §1: the REFLEXIVE_NAME Interest element and
# unpredictable reflexive-name generation (W-RF-2).
#
# Finding:   docs/notes/reflexive-forwarding-engine-2026-05-21.md §1, §3
# Spec ref:  draft-oran-icnrg-reflexive-forwarding
# Witnesses: RUST-UNIT in ndn-packet:
#              - interest_reflexive_name_roundtrip (wire encode/decode; the
#                strict Interest validator accepts the non-critical element)
#              - random_reflexive_name_is_unique_and_shaped (W-RF-2: ≥64-bit,
#                distinct /rfx/<16 byte> names)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-packet --features std --lib --quiet -- \
        interest_reflexive_name_roundtrip \
        random_reflexive_name_is_unique_and_shaped \
        >/tmp/rf_packet_witness.log 2>&1; then
    echo "=== RF §1 PASS — REFLEXIVE_NAME element + unpredictable names (W-RF-2) ==="
    exit 0
fi
echo "=== RF §1 FAIL ==="
cat /tmp/rf_packet_witness.log
exit 1
