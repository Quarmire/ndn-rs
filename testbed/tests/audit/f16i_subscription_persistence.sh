#!/usr/bin/env bash
# Witness — F16(i) (NDF): SubscriptionRequest TLV 0x230 with per-InRecord
# persistence state and data-count budgets.
#
# Finding:   ndf-vault/45-libraries/ndn-rs-feature-requests.md § F16
# Severity:  MAJOR (deliberate ndn-rs/NFD divergence NDF relies on)
# Spec ref:  ndn-rs extension — persistent Interest / SubscriptionRequest
#            (docs/wiki/src/reference/spec-compliance.md). Not in stock NFD.
# Witnesses: RUST-UNIT, two layers:
#   ndn-packet (wire codec, TLV-TYPE 0x230):
#     - encode_known_wire_layout      exact 0xfd 0x02 0x30 framing
#     - encode_decode_round_trip      (version, max_data_count, max_lifetime)
#   ndn-engine (PIT semantics):
#     - persistent_interest_survives_multiple_data_until_credit_exhausted
#         per-InRecord data-count budget decrements; entry reaped at zero
#     - persistent_interest_zero_count_is_dropped
#     - persistent_reissue_aggregates_without_revalidation
#     - persistent_and_classical_same_name_isolated
#         persistent attach is a distinct PIT entry from a classical Interest
#         at the same name.
#
# Pins the load-bearing behavior so the 0x230 divergence can't regress unseen.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

ok=1
if ! cargo test -p ndn-packet --features std --lib --quiet -- \
        encode_known_wire_layout encode_decode_round_trip \
        >/tmp/f16i_codec.log 2>&1; then
    echo "=== F16(i) FAIL — SubscriptionRequest 0x230 codec ==="; cat /tmp/f16i_codec.log; ok=0
fi
if ! cargo test -p ndn-engine --lib --quiet -- \
        persistent_interest_survives_multiple_data_until_credit_exhausted \
        persistent_interest_zero_count_is_dropped \
        persistent_reissue_aggregates_without_revalidation \
        persistent_and_classical_same_name_isolated \
        >/tmp/f16i_pit.log 2>&1; then
    echo "=== F16(i) FAIL — persistent PIT budget/isolation ==="; cat /tmp/f16i_pit.log; ok=0
fi

if [ "$ok" = 1 ]; then
    echo "=== F16(i) PASS — 0x230 codec + per-InRecord persistence & budgets hold ==="
    exit 0
fi
exit 1
