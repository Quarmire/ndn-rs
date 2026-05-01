#!/usr/bin/env bash
# Witness test for audit finding D.01 — HopLimit not decremented on forward.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.01
# Severity:    BLOCKER
# Spec ref:    NDN Packet Format v0.3 `interest.html` (HopLimit) + NFD Dev
#              Guide (NDN-0021) §3.4 Outgoing Interest Pipeline — "If
#              HopLimit is present, decrement it by 1; if the new value is
#              0, do not forward the Interest on this face."
# Witnesses:   An Interest emitted with HopLimit=3 and routed through
#              ndn-fwd emerges with HopLimit=3 on the egress interface
#              (should be 2).
#
# Expected today: FAIL (HopLimit unchanged).
# After fix:      PASS (HopLimit decremented by 1).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

NDN_FWD_SOCK="${NDN_FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/audit/d01-hoplimit"

for tool in ndn-ctl tcpdump python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: '$tool' not available" >&2
        exit 2
    fi
done

# Need CAP_NET_RAW to run tcpdump; if we're not privileged, SKIP.
if ! tcpdump -i any -c 1 -w /dev/null >/dev/null 2>&1 <<<""; then
    # Try a no-op capture to test permission.
    :
fi

# ── Setup: register /audit/d01-hoplimit pointing at a UDP face toward
#           testclient's own address so we can sniff the egress.
TESTCLIENT_IP="${TESTCLIENT_IP:-172.30.0.20}"

ndn-ctl --socket "$NDN_FWD_SOCK" \
    face add "udp4://${TESTCLIENT_IP}:6363" >/dev/null
FACE_ID=$(ndn-ctl --socket "$NDN_FWD_SOCK" face list 2>/dev/null \
    | python3 -c "
import re, sys
for line in sys.stdin:
    m = re.search(r'faceId=(\d+).*${TESTCLIENT_IP}:6363', line)
    if m:
        print(m.group(1)); sys.exit(0)
print('0')
")

if [ "$FACE_ID" = "0" ]; then
    echo "FAIL: could not resolve face_id after face/add"
    exit 1
fi

ndn-ctl --socket "$NDN_FWD_SOCK" \
    route add "$PREFIX" --face "$FACE_ID" >/dev/null

# ── Start tcpdump on the ndn-net bridge, filter on UDP:6363, write pcap.
PCAP=$(mktemp --suffix=.pcap)
tcpdump -i any -U -w "$PCAP" \
    "udp dst port 6363 and dst host ${TESTCLIENT_IP}" &
TCPDUMP_PID=$!
sleep 0.5

# ── Emit an Interest with HopLimit=3 (encoded as type 0x22, 1-byte value).
#    Using python-ndn-style hand-encoding so we don't depend on a CLI flag.
python3 <<PYEOF
import socket, os
def varnum(v):
    if v < 253: return bytes([v])
    if v < 0x10000: return b"\xfd" + v.to_bytes(2, "big")
    return b"\xfe" + v.to_bytes(4, "big")
def tlv(t, val): return varnum(t) + varnum(len(val)) + val
def name_tlv(uri):
    return tlv(0x07, b"".join(tlv(0x08, p.encode()) for p in uri.strip("/").split("/")))
interest_val = (
    name_tlv("${PREFIX}/probe") +
    tlv(0x0A, b"\xAB\xCD\xEF\x01") +          # Nonce
    tlv(0x0C, (2000).to_bytes(2, "big")) +    # InterestLifetime
    tlv(0x22, bytes([3]))                     # HopLimit=3
)
interest = tlv(0x05, interest_val)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(os.environ.get("NDN_FWD_SOCK", "/run/ndn-fwd/ndn-fwd.sock"))
s.sendall(interest)
PYEOF

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# ── Parse pcap with tshark/python: find the forwarded Interest and read the
#    HopLimit byte. The Interest on egress is wrapped in an LpPacket (0x64);
#    we scan for the inner Interest (0x05) then find HopLimit (0x22).
if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not available to parse pcap" >&2
    rm -f "$PCAP"
    exit 2
fi

# Dump raw UDP payloads.
PAYLOADS=$(tshark -r "$PCAP" -T fields -e data 2>/dev/null || true)
rm -f "$PCAP"

FOUND_HOPLIMIT=""
for hex in $PAYLOADS; do
    HOP=$(python3 <<PYEOF
hex = "$hex"
raw = bytes.fromhex(hex)
# LpPacket = 0x64 + len. Inner TLVs include Fragment=0x50 containing the Interest.
def scan(buf, target):
    i = 0
    while i < len(buf):
        if i >= len(buf): break
        t = buf[i]; i += 1
        if t >= 0xfd:
            w = {0xfd:2,0xfe:4,0xff:8}[t]; t = int.from_bytes(buf[i:i+w],"big"); i+=w
        l = buf[i]; i += 1
        if l >= 0xfd:
            w = {0xfd:2,0xfe:4,0xff:8}[l]; l = int.from_bytes(buf[i:i+w],"big"); i+=w
        if t == target: return buf[i:i+l]
        i += l
    return None
lp_val = scan(raw, 0x64) or raw
fragment = scan(lp_val, 0x50) or lp_val
interest_val = scan(fragment, 0x05) or fragment
hop = scan(interest_val, 0x22)
if hop: print(hop[0])
PYEOF
)
    if [ -n "$HOP" ]; then FOUND_HOPLIMIT="$HOP"; break; fi
done

if [ -z "$FOUND_HOPLIMIT" ]; then
    echo "FAIL: no HopLimit observed on egress (setup issue)"
    exit 1
fi

echo "HopLimit on egress: $FOUND_HOPLIMIT (expected 2 if decremented)"

if [ "$FOUND_HOPLIMIT" = "3" ]; then
    echo "FAIL (expected): HopLimit unchanged — D.01 confirmed"
    exit 1
elif [ "$FOUND_HOPLIMIT" = "2" ]; then
    echo "PASS: HopLimit correctly decremented"
    exit 0
else
    echo "FAIL: unexpected HopLimit value $FOUND_HOPLIMIT"
    exit 1
fi
