#!/usr/bin/env bash
# Witness for audit finding F.10 — raw Ethernet faces (Linux AF_PACKET,
# macOS PF_NDRV, Windows Npcap) bind the NDN EtherType and multicast MAC
# correctly.
#
# Finding:    testbed/EXPECTED_FAILURES.md § F.10
# Severity:   RESOLVED 2026-05-19 (was MINOR-quality).
# Type:       GREP-PROOF
# Spec refs:  NFD source uses EtherType 0x8624 and multicast MAC
#             01:00:5e:00:17:aa for raw-Ethernet faces.  Cross-referenced
#             against ndn-cxx (lp/face.cpp) and NFD (face/ethernet-channel.cpp).
#
# What this pins:
#   1. The seven l2 face source files have zero FIXME/TODO/XXX tokens.
#      (The original audit claimed "37 FIXMEs in af_packet.rs and 9 in
#      ndrv.rs"; git -p -S 'FIXME'/'TODO' confirms the tokens have never
#      appeared in either file.  This witness keeps the audit honest by
#      regressing if any future change introduces an untracked FIXME.)
#   2. NDN_ETHERTYPE = 0x8624 is bound once in crates/faces/ndn-face/src/l2/mod.rs.
#   3. NDN_ETHER_MCAST_MAC = [0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA] is bound in
#      pcap_face.rs and ndrv.rs (duplicate definition is a code-quality
#      follow-up; both values match the spec).
#
# Reverify recipe:
#   bash testbed/tests/audit/f10_l2_wire_constants.sh
#   Expected: exit 0 (PASS).
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

L2_DIR="crates/faces/ndn-face/src/l2"
FILES=(
    "$L2_DIR/ether.rs"
    "$L2_DIR/ether_macos.rs"
    "$L2_DIR/ether_windows.rs"
    "$L2_DIR/af_packet.rs"
    "$L2_DIR/ndrv.rs"
    "$L2_DIR/pcap_face.rs"
    "$L2_DIR/multicast_ether.rs"
)

fail=0

# (1) Zero FIXME/TODO/XXX in the seven l2 face source files.
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: expected file missing: $f"
        fail=1
        continue
    fi
    count=$(grep -cE 'FIXME|TODO|XXX' "$f" || true)
    if [ "$count" -ne 0 ]; then
        echo "FAIL: $f has $count FIXME/TODO/XXX token(s):"
        grep -nE 'FIXME|TODO|XXX' "$f" | sed 's/^/    /'
        fail=1
    else
        echo "ok: $(basename "$f") — zero FIXME/TODO/XXX"
    fi
done

# (2) NDN_ETHERTYPE = 0x8624 bound once in l2/mod.rs.
if grep -qE 'pub const NDN_ETHERTYPE: u16 = 0x8624;' "$L2_DIR/mod.rs"; then
    echo "ok: NDN_ETHERTYPE = 0x8624 bound in l2/mod.rs"
else
    echo "FAIL: NDN_ETHERTYPE = 0x8624 not bound in $L2_DIR/mod.rs"
    fail=1
fi

# (3) NDN_ETHER_MCAST_MAC bound to the spec value in both backends that
# define it locally.
EXPECTED_MAC='\[0x01, 0x00, 0x5E, 0x00, 0x17, 0xAA\]'
for f in "$L2_DIR/pcap_face.rs" "$L2_DIR/ndrv.rs"; do
    if grep -qE "pub const NDN_ETHER_MCAST_MAC.*$EXPECTED_MAC" "$f"; then
        echo "ok: NDN_ETHER_MCAST_MAC bound to spec value in $(basename "$f")"
    else
        echo "FAIL: NDN_ETHER_MCAST_MAC missing or wrong in $f"
        fail=1
    fi
done

# (4) `ether://` URI scheme emitted by macOS and Windows multicast face.
for f in "$L2_DIR/ether_macos.rs" "$L2_DIR/ether_windows.rs"; do
    if grep -qE 'format!\("ether://\[\{\}\]/\{\}"' "$f"; then
        echo "ok: ether:// URI scheme emitted by $(basename "$f")"
    else
        echo "FAIL: ether:// URI scheme not emitted by $f"
        fail=1
    fi
done

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.10 RESOLVED — l2 face wire constants spec-correct, no hidden FIXMEs ==="
    exit 0
else
    echo "=== F.10 FAIL — l2 face wire constants or FIXME hygiene regressed ==="
    exit 1
fi
