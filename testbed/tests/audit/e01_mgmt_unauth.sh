#!/usr/bin/env bash
# Witness test for audit finding E.01 — command Interests accepted without
# signature verification.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.01
# Severity:    BLOCKER
# Spec ref:    NFD Developer Guide (NDN-0021) §7 RIB manager — command
#              Interests under /localhost/nfd carry InterestSignatureInfo
#              + SigNonce + SigTime; NFD drops unsigned commands on a
#              privileged face.
# Witnesses:   ndn-fwd accepts an entirely unsigned /localhost/nfd/rib/register
#              command Interest and actually installs the route. NFD (control)
#              rejects the same packet.
#
# Expected today: FAIL (ndn-fwd installs route from unsigned Interest).
# After fix:      PASS (ndn-fwd rejects unsigned command with a 401/403-style
#                       ControlResponse status).
#
# Exit codes:
#   0 — PASS  1 — FAIL  2 — SKIP
set -euo pipefail

NDN_FWD_SOCK="${NDN_FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
PREFIX="/audit/e01-unauth-mgmt"

for tool in ndn-ctl ndnpeek; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: '$tool' not available in container" >&2
        exit 2
    fi
done

# ── Step 1. Build an unsigned ControlCommand Interest for /localhost/nfd/rib/register.
#
# ndn-ctl itself signs commands (per H.00), so we cannot use it directly to
# generate an unsigned Interest. Instead we use `ndnpeek --no-verify` against
# a hand-crafted name — /localhost/nfd/rib/register carries the encoded
# ControlParameters TLV as its last generic name component. We synthesise
# that component with Python.
#
# If python3 with ndn-python-lib isn't in the container, SKIP.
if ! python3 -c "import ndn" 2>/dev/null; then
    echo "SKIP: python-ndn not installed (needed to synthesise the unsigned command Interest)" >&2
    exit 2
fi

# Generate the ControlParameters TLV value: name=/audit/e01-unauth-mgmt, faceId=1, cost=0
# and build the full command name with that TLV as the last component. Emit via
# NDN-to-Unix-socket so ndn-fwd receives it.
python3 <<'PYEOF' || { echo "FAIL: python-ndn synthesis threw"; exit 1; }
from ndn.encoding import Name, TlvModel, BytesField, UintField, ModelField
from ndn.encoding.tlv_var import BinaryStr
import socket, struct, sys

# ControlParameters TLV = 0x68 { Name, FaceId=0x69, Cost=0x6A }
# We encode by hand because python-ndn's ControlParameters helper may
# add signature-specific fields we don't want here.

def varnum(v):
    if v < 253: return bytes([v])
    if v < 0x10000: return b"\xfd" + v.to_bytes(2, "big")
    if v < 0x1_0000_0000: return b"\xfe" + v.to_bytes(4, "big")
    return b"\xff" + v.to_bytes(8, "big")

def tlv(typ, val):
    return varnum(typ) + varnum(len(val)) + val

name_tlv = Name.encode("/audit/e01-unauth-mgmt")
face_id = tlv(0x69, bytes([1]))
cost = tlv(0x6A, bytes([0]))
cp_value = name_tlv + face_id + cost
cp_tlv = tlv(0x68, cp_value)

# Command Interest name: /localhost/nfd/rib/register/<cp-tlv-as-generic-component>
cmd_name = (
    tlv(0x08, b"localhost") + tlv(0x08, b"nfd") +
    tlv(0x08, b"rib") + tlv(0x08, b"register") +
    tlv(0x08, cp_tlv)
)
name_wrapper = tlv(0x07, cmd_name)

# Unsigned Interest: Name, Nonce, InterestLifetime.
nonce_tlv = tlv(0x0A, b"\xDE\xAD\xBE\xEF")
lifetime_tlv = tlv(0x0C, (2000).to_bytes(2, "big"))
interest_value = name_wrapper + nonce_tlv + lifetime_tlv
interest = tlv(0x05, interest_value)

import os
sock_path = os.environ.get("NDN_FWD_SOCK", "/run/ndn-fwd/ndn-fwd.sock")
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
s.sendall(interest)

# Read response (up to 1 data packet).
s.settimeout(3)
try:
    data = s.recv(65536)
except socket.timeout:
    print("NO-RESPONSE")
    sys.exit(0)

# Parse response — look for ControlResponse TLV (0x65) with StatusCode (0x66).
# Simple non-recursive scan: find 0x65 then read nested StatusCode.
def find_tlv(buf, typ):
    i = 0
    while i < len(buf):
        t = buf[i]; i += 1
        if t >= 0xfd:
            width = {0xfd: 2, 0xfe: 4, 0xff: 8}[t]
            t = int.from_bytes(buf[i:i+width], "big"); i += width
        ln = buf[i]; i += 1
        if ln >= 0xfd:
            width = {0xfd: 2, 0xfe: 4, 0xff: 8}[ln]
            ln = int.from_bytes(buf[i:i+width], "big"); i += width
        if t == typ:
            return buf[i:i+ln]
        i += ln
    return None

# Response is a Data packet (0x06); extract its Content (0x15).
data_body = find_tlv(data, 0x06)
content = find_tlv(data_body or data, 0x15) if data_body else None
ctrl_resp = find_tlv(content, 0x65) if content else None
status_code_tlv = find_tlv(ctrl_resp, 0x66) if ctrl_resp else None
if status_code_tlv is None:
    print("NO-CONTROL-RESPONSE")
else:
    status = int.from_bytes(status_code_tlv, "big")
    print(f"STATUS={status}")
PYEOF

RESULT=$(NDN_FWD_SOCK="$NDN_FWD_SOCK" python3 /dev/stdin <<'PYEOF2' 2>&1 || echo "PYEOF2-ERROR"
import os; exec(open("/proc/self/fd/0").read())
PYEOF2
)

# Interpretation:
#   STATUS=200 — command accepted (UNSIGNED!) — spec violation confirmed
#   STATUS=4xx — command rejected with auth error — spec-conformant
#   NO-RESPONSE / NO-CONTROL-RESPONSE — different failure mode; treat as FAIL
#     to surface for investigation.
echo "RESULT: $RESULT"

if echo "$RESULT" | grep -q "STATUS=200"; then
    echo "FAIL (expected): unsigned rib/register accepted with status 200 — E.01 confirmed"
    exit 1
fi

if echo "$RESULT" | grep -qE "STATUS=(401|403)"; then
    echo "PASS: unsigned rib/register correctly rejected"
    exit 0
fi

echo "FAIL: unexpected result — investigate"
exit 1
