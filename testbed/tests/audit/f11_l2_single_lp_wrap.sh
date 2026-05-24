#!/usr/bin/env bash
# Witness for finding F.11 — Ethernet faces must be payload-only on the
# send path: the paired LpLinkService owns NDNLPv2 framing + fragmentation,
# so a face's `send_bytes` must NOT call `encode_lp_packet`/`fragment_packet`.
#
# Finding:    multicast Ethernet faces (Linux AF_PACKET, macOS PF_NDRV,
#             Windows Npcap) re-LP-wrapped and re-fragmented packets that the
#             LpLinkService had already framed → double NDNLPv2 header on the
#             wire → unparseable by NFD/ndn-cxx peers. UDP faces correctly
#             defer framing to the LinkService; the L2 faces did not.
# Severity:   MAJOR (wire-format / interop break on every EtherMulticast face).
# Type:       GREP-PROOF
# Spec refs:  NFD GenericLinkService owns LP framing once per packet
#             (NFD face/generic-link-service.cpp). FaceKind::EtherMulticast /
#             ::Ethernet are `uses_lp_framing()` → get an LpLinkService
#             (crates/ndn-transport/src/face.rs, link_service/mod.rs:
#             default_link_service_for_kind).
#
# What this pins:
#   1. None of the four L2 face source files call encode_lp_packet() or
#      fragment_packet() — framing happens exactly once, in the LinkService.
#   2. Every L2 face reports an MTU (`fn send_mtu`) so LpLinkService's
#      fragmentation branch (gated on `transport.send_mtu()` being Some) is
#      actually reached. Without this the LinkService never fragments and
#      oversized frames are silently dropped by the TX ring / driver.
#
# Reverify recipe:
#   bash testbed/tests/audit/f11_l2_single_lp_wrap.sh
#   Pre-fix:  exit 1 (encode_lp_packet present in the multicast send paths).
#   Post-fix: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

L2_DIR="crates/ndn-face-native/src/l2"
# (file, must-define-send_mtu?)
FILES=(
    "$L2_DIR/ether.rs"
    "$L2_DIR/ether_macos.rs"
    "$L2_DIR/ether_windows.rs"
    "$L2_DIR/multicast_ether.rs"
)

fail=0

# (1) No face-layer LP framing / fragmentation in any L2 face.
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "FAIL: expected file missing: $f"
        fail=1
        continue
    fi
    if grep -nE 'encode_lp_packet|fragment_packet' "$f"; then
        echo "FAIL: $(basename "$f") frames at the face layer — double-wraps the LinkService output"
        fail=1
    else
        echo "ok: $(basename "$f") — payload-only send path (no face-layer LP framing)"
    fi
done

# (2) Every L2 face reports an MTU so the LinkService fragments.
for f in "${FILES[@]}"; do
    [ -f "$f" ] || continue
    if grep -qE 'fn send_mtu\(' "$f"; then
        echo "ok: $(basename "$f") — reports send_mtu (LinkService fragmentation reachable)"
    else
        echo "FAIL: $(basename "$f") does not implement send_mtu — LinkService will not fragment"
        fail=1
    fi
done

# (3) The shared Ethernet MTU constant exists and matches NFD's 1500-byte payload.
if grep -qE 'pub const ETHER_PAYLOAD_MTU: usize = 1500;' "$L2_DIR/mod.rs"; then
    echo "ok: ETHER_PAYLOAD_MTU = 1500 bound in l2/mod.rs"
else
    echo "FAIL: ETHER_PAYLOAD_MTU = 1500 not bound in $L2_DIR/mod.rs"
    fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== F.11 PASS — L2 faces are payload-only; NDNLPv2 framing happens once ==="
    exit 0
else
    echo "=== F.11 FAIL — L2 face send path re-frames / lacks MTU reporting ==="
    exit 1
fi
