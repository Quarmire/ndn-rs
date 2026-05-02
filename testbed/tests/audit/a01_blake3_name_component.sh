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
# Witnesses:   ndn-rs no longer defines or emits a TLV-TYPE 0x03 name
#              component, so spec-conformant peers cannot reject what isn't
#              produced. This is now a GREP-PROOF: the audit trips back to
#              FAIL the moment any of the listed surface re-appears.
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

fail=0

check() {
    local label="$1"
    local pattern="$2"
    shift 2
    local hits
    hits=$(grep -rnE "$pattern" "$@" 2>/dev/null || true)
    if [ -n "$hits" ]; then
        echo "FAIL: $label"
        echo "$hits"
        fail=1
    else
        echo "ok: $label"
    fi
}

# 1. The TLV-TYPE 0x03 constant must not exist in ndn-packet.
check "no BLAKE3_DIGEST constant in ndn-packet" \
    'BLAKE3_DIGEST' \
    crates/foundation/ndn-packet/src/

# 2. The Name component / helper / Display alt-form must not exist.
check "no blake3_digest helpers in ndn-packet" \
    'blake3_digest|blake3digest=|append_blake3_digest|as_blake3_digest|zone_root_from_hash|is_zone_root' \
    crates/foundation/ndn-packet/src/

# 3. The zone module and ZoneKey must not exist in ndn-security.
check "no ZoneKey / zone module in ndn-security" \
    'ZoneKey|crate::zone|pub mod zone\b|zone_root_from_pubkey|verify_zone_root|zone_root_to_did' \
    crates/engine/ndn-security/src/

# 4. The zone-bound DID builder functions must not exist.
check "no build_zone_did_document / build_zone_succession_document in ndn-security" \
    'build_zone_did_document|build_zone_succession_document' \
    crates/engine/ndn-security/src/

# 5. zone.rs file itself must be gone.
if [ -e crates/engine/ndn-security/src/zone.rs ]; then
    echo "FAIL: crates/engine/ndn-security/src/zone.rs still exists"
    fail=1
else
    echo "ok: zone.rs deleted"
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.01 RESOLVED — no BLAKE3_DIGEST 0x03 surface in ndn-rs ==="
    exit 0
else
    echo
    echo "=== A.01 REGRESSION — BLAKE3_DIGEST 0x03 surface re-introduced ==="
    exit 1
fi
