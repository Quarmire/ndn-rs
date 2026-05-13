#!/usr/bin/env bash
# Audit witness — A.05 / A.18.
#
# A.05: `read_varu64` accepted 9-byte form for TLV-TYPE.  Spec
#       (`tlv.html`): TLV-TYPE range [1, 4294967295]; uses
#       VAR-NUMBER-1/3/5 only.  The 9-byte form is legal only for
#       TLV-LENGTH.  Witness: RUST-UNIT
#         a05_read_type_rejects_9byte_form
#         a05_read_type_accepts_5byte_form_within_u32
#       `TlvReader::read_type` now returns
#       `TlvError::TypeOutOfRange` for 9-byte forms or values >
#       u32::MAX.
#
# A.18: NonNegativeInteger decoders silently accepted any byte
#       width via the shift-accumulator loop.  Spec: NNI is
#       encoded with 1, 2, 4, or 8 octets.  Witness: RUST-UNIT
#         a18_decode_nni_rejects_nonstandard_widths
#       A new `ndn_packet::decode_nni` helper enforces width ∈
#       {1, 2, 4, 8}; InterestLifetime, FreshnessPeriod,
#       ContentType, SignatureType, SignatureTime, and
#       SignatureSeqNum decoders all route through it.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-tlv --lib --quiet a05_ 2>&1 | tail -3; then
    echo "FAIL: A.05 unit tests"
    exit 1
fi
if ! cargo test -p ndn-packet --features std --lib --quiet a18_ 2>&1 | tail -3; then
    echo "FAIL: A.18 unit tests"
    exit 1
fi
echo "=== A.05 / A.18 RESOLVED — strict VarU64 + NNI widths ==="
