#!/usr/bin/env bash
# Witness test for audit findings A.03 / A.04 / N.04 — body-level decoders
# silently skip unknown critical TLVs and do not enforce element ordering.
#
# Finding:     testbed/EXPECTED_FAILURES.md § A.03 / A.04
#              docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.04
# Severity:    MAJOR
# Spec ref:    NDN Packet Format v0.3 `tlv.html` §"TLV-TYPE" — types 0..31 are
#              grandfathered as critical; for type >= 32, odd is critical and
#              even is non-critical. ndn-cxx enforces this at every body level
#              (`interest.cpp:286-300`, `data.cpp:182`, `signature-info.cpp:158`).
#              Top-level Interest order is tracked via `lastElement` cursor in
#              `interest.cpp:183-300`; Data body order is fixed in `data.cpp`.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                A.03 (criticality):
#                  - a03_interest_decode_rejects_unknown_critical_tlv_in_body
#                  - a03_interest_decode_accepts_unknown_non_critical_tlv (sanity)
#                  - a03_data_decode_rejects_unknown_critical_tlv_in_body
#                A.04 (ordering):
#                  - a04_interest_decode_rejects_must_be_fresh_before_can_be_prefix
#                  - a04_interest_decode_rejects_duplicate_nonce
#                  - a04_data_decode_rejects_content_before_meta_info
#                N.04 (criticality inside MetaInfo / SignatureInfo):
#                  - n04_meta_info_decode_rejects_unknown_critical_tlv
#                  - n04_meta_info_decode_accepts_unknown_non_critical_tlv (sanity)
#                  - n04_sig_info_decode_rejects_unknown_critical_tlv
#                  - n04_sig_info_decode_accepts_unknown_non_critical_tlv (sanity)
#              Before the fix: every "rejects" case decodes Ok. After the fix:
#              `Interest::decode` and `Data::decode` track a body-level
#              `last_element` cursor and reject out-of-order or duplicate
#              spec elements; every body-level decoder (Interest body, Data
#              body, MetaInfo, SignatureInfo) checks `is_critical_tlv_type`
#              on unknowns and aborts on critical types.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
for filter in a03_ a04_ n04_; do
    if cargo test -p ndn-packet --features std --lib --quiet "$filter" \
            >>/tmp/a03_witness.log 2>&1; then
        echo "ok: $filter tests"
    else
        echo "FAIL: $filter tests"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== A.03 / A.04 / N.04 RESOLVED — body-level decoders enforce critical-bit + ordering ==="
    exit 0
else
    echo
    echo "=== A.03 / A.04 / N.04 EXPECTED-FAIL — body-level decoders silently skip critical TLVs / ordering ==="
    cat /tmp/a03_witness.log
    exit 1
fi
