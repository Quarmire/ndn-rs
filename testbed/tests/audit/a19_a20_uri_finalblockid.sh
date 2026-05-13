#!/usr/bin/env bash
# Audit witness — A.19 / A.20.
#
# A.19: `Name::FromStr` ignored the URI alternates `Name::Display`
#       emits (`sha256digest=`, `params-sha256=`, `keyword=`) and
#       the canonical `<type-number>=<value>` form, so a round-
#       trip through `to_string()` then `parse()` lost typed-
#       component identity.  Witness: RUST-UNIT
#         a19_uri_roundtrip_sha256digest
#         a19_uri_roundtrip_params_sha256
#         a19_uri_roundtrip_keyword
#         a19_uri_roundtrip_canonical_typed_form
#
# A.20: `FinalBlockId` was stored as opaque `Bytes` even though
#       the spec defines it as a wrapper around a single
#       NameComponent TLV (data.html).  Witness: RUST-UNIT
#         a20_final_block_component_decodes_typed_segment
#         a20_final_block_component_none_when_absent
#       New `MetaInfo::final_block_component` returns the parsed
#       NameComponent.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet a19_ 2>&1 | tail -3; then
    echo "FAIL: A.19 round-trip tests"
    exit 1
fi
if ! cargo test -p ndn-packet --features std --lib --quiet a20_ 2>&1 | tail -3; then
    echo "FAIL: A.20 FinalBlockId tests"
    exit 1
fi
echo "=== A.19 / A.20 RESOLVED — URI round-trip + FinalBlockId typed accessor ==="
