#!/usr/bin/env bash
# Witness for audit finding G.05 — ndn-rs's DvrProtocol diverged from its
# intended ndnd-DV derivation. This witness pins the current ndn-rs wire
# format (regression catch) and asserts that ndnd's distinct TLV codes are
# NOT present in the current implementation — making the divergence
# mechanically visible until v0.2 alignment work lands.
#
# Finding:    docs/notes/spec-compliance-audit-2026-04-20.md § G.05
# Follow-up:  docs/notes/dvr-ndnd-alignment-NEXT.md
# Severity:   DOCUMENTED 2026-05-19 (intended ndnd derivation; current
#             implementation is a prefix-vector protocol with different
#             TLV codes and architecture — Interest broadcast vs ndnd's
#             SVS-driven advertisement sync).
# Type:       GREP-PROOF
# Reference:  ~/Documents/Dev/ndnd/dv/tlv/definitions.go (ndnd TLV codes);
#             ~/Documents/Dev/ndnd/dv/dv/{router.go,advert_sync.go}
#             (SVS-driven architecture).
#
# What this pins (ndn-rs's current wire format):
#   T_DVR_UPDATE = 0xD0 (root TLV for DVR advertisement AppParams)
#   T_NODE_NAME  = 0xD1
#   T_ROUTE      = 0xD2
#   T_PREFIX     = 0xD3
#   T_DVR_COST   = 0xD4
#   Interest name prefix: /ndn/local/dvr/adv
#
# What this asserts is NOT in the ndn-rs DVR file (ndnd's distinct codes):
#   - `0xC9` Advertisement
#   - `0xCA` Entries
#   - `0xCC` Destination
#   - `0xCE` NextHop
#   - `0x12D` PrefixOpList
#   - `Destination`, `NextHop`, `OtherCost`, `PrefixOpAdd`, `PrefixOpRemove`
#     identifiers (which would only appear if the ndnd model were adopted).
#
# Reverify recipe:
#   bash testbed/tests/audit/g05_dvr_wire_drift.sh
#   Expected: exit 0 (PASS) — divergence still present and labelled.
#   If this script ever fails, it means either (a) ndn-rs's DVR was
#   re-aligned with ndnd (good — close G.05 and delete this witness), or
#   (b) a partial alignment landed without updating the audit (bad — fix
#   the audit text or the code, depending on intent).
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

DVR="crates/spec/ndn-routing/src/protocols/dvr.rs"

if [ ! -f "$DVR" ]; then
    echo "FAIL: expected file missing: $DVR"
    exit 1
fi

fail=0

# (1) Current ndn-rs TLV codes are bound as declared.
declare -A EXPECTED=(
    ["T_DVR_UPDATE"]="0xD0"
    ["T_NODE_NAME"]="0xD1"
    ["T_ROUTE"]="0xD2"
    ["T_PREFIX"]="0xD3"
    ["T_DVR_COST"]="0xD4"
)
for name in "${!EXPECTED[@]}"; do
    val="${EXPECTED[$name]}"
    if grep -qE "const ${name}: u64 = ${val};" "$DVR"; then
        echo "ok: ${name} = ${val} bound in dvr.rs"
    else
        echo "FAIL: ${name} = ${val} not bound in $DVR"
        fail=1
    fi
done

# (2) Interest broadcast prefix is /ndn/local/dvr/adv (components may be
# on separate lines, so check each component independently).
if grep -q 'b"ndn"' "$DVR" \
    && grep -q 'b"local"' "$DVR" \
    && grep -q 'b"dvr"' "$DVR" \
    && grep -q 'b"adv"' "$DVR"; then
    echo "ok: /ndn/local/dvr/adv broadcast prefix bound"
else
    echo "FAIL: /ndn/local/dvr/adv broadcast prefix not bound in $DVR"
    fail=1
fi

# (3) ndnd's distinct TLV codes / type names are NOT present in ndn-rs DVR.
# (If any of these appear, an unannounced partial alignment landed.)
# Word-boundary match — "Advertisement" as a whole token would signal
# adoption of ndnd's TLV name; the existing local struct `DvrAdvertisement`
# (substring match) is not a signal of alignment.
NDND_ABSENT_TOKENS=(
    "AdvEntry"
    "OtherCost"
    "PrefixOpList"
    "PrefixOpAdd"
    "PrefixOpRemove"
    "NextHop"
)
for tok in "${NDND_ABSENT_TOKENS[@]}"; do
    if grep -qwE "$tok" "$DVR"; then
        echo "FAIL: ndnd token '${tok}' unexpectedly present in $DVR — partial alignment landed without audit update?"
        grep -nwE "$tok" "$DVR"
        fail=1
    else
        echo "ok: ndnd token '${tok}' absent (drift still in effect)"
    fi
done

# (4) ndnd's TLV codes (raw hex) are NOT present as `u64` constants in ndn-rs DVR.
# We check the specific codes 0xC9, 0xCA, 0xCC, 0xCE, 0x12D — the codes ndn-rs
# would use if it adopted ndnd's wire format.
NDND_ABSENT_CODES=(
    "0xC9"
    "0xCA"
    "0xCC"
    "0xCE"
    "0x12D"
)
for code in "${NDND_ABSENT_CODES[@]}"; do
    if grep -qE "const T_[A-Z_]+: u64 = ${code};" "$DVR"; then
        echo "FAIL: ndnd-style TLV code ${code} unexpectedly bound in $DVR"
        fail=1
    else
        echo "ok: ndnd TLV code ${code} not bound in $DVR"
    fi
done

# (5) FIXME/TODO hygiene — same regression catch as F.10.
count=$(grep -cE 'FIXME|TODO|XXX' "$DVR" || true)
if [ "$count" -ne 0 ]; then
    echo "FAIL: $DVR has $count FIXME/TODO/XXX token(s) (original audit claimed 5; if any reappear, track them)"
    grep -nE 'FIXME|TODO|XXX' "$DVR"
    fail=1
else
    echo "ok: dvr.rs — zero FIXME/TODO/XXX (original audit's '5 FIXMEs' claim was fabricated)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== G.05 DOCUMENTED — DVR drift from ndnd's dv/ still in effect; alignment tracked for v0.2 ==="
    exit 0
else
    echo "=== G.05 FAIL — wire format drifted unexpectedly; reconcile audit text or code ==="
    exit 1
fi
