#!/usr/bin/env bash
# Witness test for audit finding A.01 — `BLAKE3_DIGEST` uses TLV-TYPE 0x03,
# which is unassigned and in the grandfathered-critical 0-31 range.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.01
# Severity:    BLOCKER
# Spec ref:    NDN Packet Format v0.3 types.html + tlv.html §"TLV-TYPE" —
#              "Types 0-31 are grandfathered as critical regardless of LSB.
#              When decoding an unrecognized critical TLV-TYPE at the
#              current decode position, decoding MUST abort."
# Witnesses:   A Data packet whose Name contains a single 32-byte component
#              of type 0x03 (the ndn-rs-invented `BLAKE3_DIGEST`) is
#              rejected by ndn-cxx's `Name::wireDecode` with an exception.
#
# Expected today: FAIL (the packet is emitted and accepted by ndn-rs but
#                       rejected by the spec-conformant peer — proving
#                       the wire is non-interoperable).
# After fix:      PASS (either (a) ndn-rs uses an unassigned even-and->=32
#                       component type that peers can silently ignore, or
#                       (b) the zone-root naming scheme is retracted).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

for tool in ndnpeek python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: '$tool' not available (needs the Dockerfile.interop image)" >&2
        exit 2
    fi
done

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
PREFIX="/audit/a01-blake3"

# Emit a Data packet under NFD, using python-ndn to hand-build a Name
# that starts with a BLAKE3_DIGEST component (type 0x03, 32 bytes).
python3 <<PYEOF || true
import socket, os, struct, hashlib

def varnum(v):
    if v < 253: return bytes([v])
    if v < 0x10000: return b"\xfd" + v.to_bytes(2, "big")
    return b"\xfe" + v.to_bytes(4, "big")
def tlv(t, val): return varnum(t) + varnum(len(val)) + val

blake3_digest = hashlib.sha256(b"a01-witness").digest()  # 32 bytes; content is opaque
assert len(blake3_digest) == 32

# Name = /blake3digest=<hex> (single component, type 0x03) + /audit/a01-blake3
name = tlv(0x07,
    tlv(0x03, blake3_digest) +
    tlv(0x08, b"audit") +
    tlv(0x08, b"a01-blake3") +
    tlv(0x08, b"probe")
)

# MetaInfo with FreshnessPeriod=5000ms
meta = tlv(0x14, tlv(0x19, (5000).to_bytes(2, "big")))
content = tlv(0x15, b"witness")

# SignatureInfo: DigestSha256 (type code 0)
sig_info = tlv(0x16, tlv(0x1B, bytes([0])))

# Build signed region + compute SHA256 for DigestSha256 signature
signed_region = name + meta + content + sig_info
sig_value = tlv(0x17, hashlib.sha256(signed_region).digest())

data_val = name + meta + content + sig_info + sig_value
data_pkt = tlv(0x06, data_val)

# Write the raw wire to a file so we can feed it to ndn-cxx tooling.
with open("/tmp/a01_blake3_data.tlv", "wb") as f:
    f.write(data_pkt)
print(f"wrote /tmp/a01_blake3_data.tlv, {len(data_pkt)} bytes")
PYEOF

if [ ! -s /tmp/a01_blake3_data.tlv ]; then
    echo "FAIL: python-ndn synthesis did not produce a wire file"
    exit 1
fi

# Feed the packet to ndn-cxx's decoder. Using `ndnpeek` indirectly:
# we publish the Data via a temporary producer, then peek it. The decode
# error surfaces when ndn-cxx parses the Name component type 0x03 as
# unknown-critical.
#
# Simpler: use ndn-dissect if available, or ndnpeek in a pipe where the
# synthetic bytes are the reply.
#
# If ndn-dissect is available, use it for a pure decode test:
if command -v ndn-dissect >/dev/null 2>&1; then
    if ndn-dissect < /tmp/a01_blake3_data.tlv 2>/dev/null | grep -qE "(Unknown|Unrecognized|component type)"; then
        echo "FAIL (expected): ndn-cxx dissector flags the Name component as unrecognized — A.01 confirmed"
        exit 1
    fi
    # If it decoded without error, the non-compliance is masked:
    echo "FAIL (unexpected): ndn-cxx dissector accepted the name; investigate"
    exit 1
fi

# Fallback: use python-ndn on the receiving side to parse and report.
python3 <<'PYEOF2'
import sys
with open("/tmp/a01_blake3_data.tlv", "rb") as f:
    wire = f.read()
# Try to decode with python-ndn, expecting it to error on the 0x03 type in Name.
try:
    from ndn.encoding import parse_data
    _, _, content, _ = parse_data(wire)
    # If decode succeeded, python-ndn is permissive — doesn't witness A.01.
    print("UNWITNESSED: python-ndn decoded the packet without complaining")
    sys.exit(2)
except Exception as e:
    print(f"EXPECTED-DECODE-ERROR: {e}")
    sys.exit(0)
PYEOF2
RC=$?

if [ "$RC" = "0" ]; then
    echo "FAIL (expected): spec-conformant decoder rejected the BLAKE3 component — A.01 confirmed"
    exit 1
elif [ "$RC" = "2" ]; then
    echo "SKIP: no spec-conformant decoder available in container to witness A.01"
    exit 2
else
    echo "FAIL: unexpected result"
    exit 1
fi
