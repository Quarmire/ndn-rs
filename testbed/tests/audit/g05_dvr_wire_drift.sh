#!/usr/bin/env bash
# Witness for audit finding G.05 — ndn-rs's DvrProtocol does not implement
# the published ndn-dv specification. This witness pins the current ndn-rs
# wire format (regression catch) and asserts that the spec's TLV codes are
# NOT present in the current implementation — making the gap mechanically
# visible until the v0.2 spec-aligned implementation lands.
#
# Finding:    docs/notes/spec-compliance-audit-2026-04-20.md § G.05
# Follow-up:  docs/notes/dvr-ndnd-alignment-NEXT.md (v0.2 implementation plan)
# Severity:   MAJOR (revised 2026-05-19 from MINOR; current impl uses
#             non-spec TLV codes 0xD0-0xD4 instead of the spec's 201/202/
#             204/206/208/210/301... and an Interest-broadcast architecture
#             instead of the spec's SVS-ALO advertisement sync).
# Type:       GREP-PROOF
# Spec:       ~/Documents/Dev/ndnd/dv/SPEC.md §3 (TLV codes are decimal:
#             ADVERTISEMENT=201, ADV-ENTRY=202, DESTINATION=204,
#             NEXT-HOP=206, COST=208, OTHER-COST=210, PREFIX-OP-LIST=301,
#             PREFIX-OP-RESET=302, PREFIX-OP-ADD=304, PREFIX-OP-REMOVE=306).
# Paper:      Patil et al, "Distance Vector Routing for Named Data
#             Networking", CoNEXT '24, DOI 10.1145/3680121.3699885
#             (local: ~/Downloads/ndn-drv.pdf).
# Reference:  ~/Documents/Dev/ndnd/dv/ (Go reference implementation).
#
# What this pins (ndn-rs's current wire format):
#   T_DVR_UPDATE = 0xD0 (root TLV for DVR advertisement AppParams)
#   T_NODE_NAME  = 0xD1
#   T_ROUTE      = 0xD2
#   T_PREFIX     = 0xD3
#   T_DVR_COST   = 0xD4
#   Interest name prefix: /ndn/local/dvr/adv
#
# What this asserts is NOT in the ndn-rs DVR file (spec's authoritative
# codes per SPEC.md §3 — should all appear once the v0.2 alignment lands):
#   - 0xC9  / 201  Advertisement
#   - 0xCA  / 202  AdvEntry
#   - 0xCC  / 204  Destination
#   - 0xCE  / 206  NextHop
#   - 0x12D / 301  PrefixOpList
#   - Spec identifiers AdvEntry, OtherCost, PrefixOpList, PrefixOpAdd,
#     PrefixOpRemove, NextHop (their presence would mean partial alignment
#     landed without an audit update).
#
# Reverify recipe:
#   bash testbed/tests/audit/g05_dvr_wire_drift.sh
#   Expected: exit 0 (PASS) — gap still present and labelled.
#   When the v0.2 spec-aligned implementation lands, this witness should be
#   inverted (or replaced): the spec codes MUST be present, the prefix-
#   vector codes (T_DVR_*) MUST NOT be present, and a real interop witness
#   against ndnd's dv/ router gates the closure of G.05.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

DVR="crates/ndn-routing/src/protocols/dvr.rs"

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
    echo "=== G.05 MAJOR — DVR does not implement published ndn-dv spec; v0.2 implementation plan tracked ==="
    exit 0
else
    echo "=== G.05 FAIL — wire format changed unexpectedly; reconcile audit text or code ==="
    exit 1
fi
