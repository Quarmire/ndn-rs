#!/usr/bin/env bash
# Witness test for audit finding A.01 — `BLAKE3_DIGEST` TLV-TYPE 0x03
# name-component squat.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § A.01
# Severity:    BLOCKER (RESOLVED 2026-05-01)
# Spec ref:    NDN Packet Format v0.3 types.html + tlv.html §"TLV-TYPE" —
#              "Types 0-31 are grandfathered as critical regardless of LSB.
#              When decoding an unrecognized critical TLV-TYPE at the current
#              decode position, decoding MUST abort."
# Witnesses:   RUST-UNIT — type 3 remains an opaque typed name component
#              with no `blake3digest=` URI alternate or BLAKE3 semantics.
#
# Resolution:  the BLAKE3_DIGEST constant, the `NameComponent::blake3_digest`
#              and `as_blake3_digest` helpers, the `Name::append_blake3_digest`
#              / `zone_root_from_hash` / `is_zone_root` helpers, and the
#              `blake3digest=` Display alt-form were removed. `ZoneKey` and
#              the zone-bound DID resolver / builder functions were extracted.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet a01_ >/tmp/a01_witness.log 2>&1; then
    echo "FAIL: a01_ behavioral tests"
    cat /tmp/a01_witness.log
    exit 1
else
    echo "ok: a01_ behavioral tests"
fi

echo
echo "=== A.01 RESOLVED — TLV-TYPE 0x03 has no BLAKE3 name-component semantics ==="
