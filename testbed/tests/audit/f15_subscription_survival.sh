#!/usr/bin/env bash
# Witness — F15 (NDF): subscription survival across face churn (re-attach).
#
# Finding:   ndf-vault/45-libraries/ndn-rs-feature-requests.md § F15
# Severity:  MAJOR (keystone for mobile/radio NDF deployments + F11 downlink)
# Spec ref:  ndn-rs extension — persistent Interest / SubscriptionRequest re-attach.
# Witnesses: RUST-UNIT, three layers (variant 1: consumer re-expresses,
#            forwarder splices by stable SubscriptionId):
#   ndn-packet (wire): the SubscriptionId rides the 0x230 value, back-compat.
#     - subscription_id_round_trips
#     - no_id_decodes_to_none_and_keeps_9_byte_value
#     - over_long_id_is_rejected_to_classical
#   ndn-engine (PIT re-attach, B1): surviving budget is parked on face-down and
#     spliced back on re-expression with the same id; no id → no survival;
#     expired orphans are not reclaimed.
#     - persistent_subscription_reattaches_after_face_churn
#     - persistent_subscription_without_id_does_not_park
#     - expired_orphan_is_not_reclaimed
#   ndn-engine (upstream re-establish, B2): on upstream face-down the stale
#     out-record is pruned and a re-expressed subscription re-forwards instead
#     of aggregate-suppressing.
#     - persistent_reexpress_reforwards_after_upstream_face_down
#   ndn-app (consumer): one stable id reused across re-expressions, and a
#     staleness window re-expresses to recover an unseen upstream flap (B2).
#     - subscription_id_is_stable_across_re_expression
#     - recv_reexpresses_on_staleness
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

ok=1
if ! cargo test -p ndn-packet --features std --lib --quiet -- \
        subscription_id_round_trips \
        no_id_decodes_to_none_and_keeps_9_byte_value \
        over_long_id_is_rejected_to_classical \
        >/tmp/f15_pkt.log 2>&1; then
    echo "=== F15 FAIL — SubscriptionId wire ==="; cat /tmp/f15_pkt.log; ok=0
fi
if ! cargo test -p ndn-engine --lib --quiet -- \
        persistent_subscription_reattaches_after_face_churn \
        persistent_subscription_without_id_does_not_park \
        expired_orphan_is_not_reclaimed \
        persistent_reexpress_reforwards_after_upstream_face_down \
        >/tmp/f15_engine.log 2>&1; then
    echo "=== F15 FAIL — PIT re-attach / re-forward ==="; cat /tmp/f15_engine.log; ok=0
fi
if ! cargo test -p ndn-app --lib --quiet -- \
        subscription_id_is_stable_across_re_expression \
        recv_reexpresses_on_staleness \
        >/tmp/f15_app.log 2>&1; then
    echo "=== F15 FAIL — consumer re-express ==="; cat /tmp/f15_app.log; ok=0
fi

if [ "$ok" = 1 ]; then
    echo "=== F15 PASS — subscription survives face churn via SubscriptionId splice ==="
    exit 0
fi
exit 1
