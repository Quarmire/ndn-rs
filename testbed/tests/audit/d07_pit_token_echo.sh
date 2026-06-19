#!/usr/bin/env bash
# Witness test for audit finding D.07 — PIT in-records carry the
# NDNLPv2 `PitToken` from the consumer's LP header, but the outbound
# Data / Nack paths drop it instead of echoing it on the return wire.
#
# Finding:     testbed/EXPECTED_FAILURES.md § D.07
# Severity:    MAJOR
# Spec ref:    NDNLPv2 PitToken lifecycle. NFD `daemon/fw/forwarder.cpp:234`
#              `data.setTag(interest.getTag<lp::PitToken>())`. The Nack
#              return path mirrors this on the Nack header path.
# Witnesses:   RUST-UNIT in `ndn-packet`:
#                - d07_encode_lp_nack_with_pit_token_emits_token
#                - d07_encode_lp_nack_omits_pit_token_when_absent
#              RUST-UNIT in `ndn-engine`:
#                - d07_pit_match_propagates_lp_token_to_out_tokens
#              Before the fix: `encode_lp_nack_with_pit_token` does not exist (the
#              one-arg `encode_lp_nack` is the only encoder), and
#              `PacketContext.out_pit_tokens` does not exist (so
#              `PitMatchStage` cannot propagate tokens). After fix: both
#              APIs land, and the dispatcher's `satisfy` / Nack paths
#              wrap egress bytes in an LpPacket with the consumer's
#              token attached.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet d07_ \
        >/tmp/d07_witness.log 2>&1; then
    echo "ok: ndn-packet d07_* (encode_lp_nack_with_pit_token)"
else
    echo "FAIL: ndn-packet d07_* tests"
    fail=1
fi
if cargo test -p ndn-engine --lib --quiet d07_pit_match_propagates_lp_token_to_out_tokens \
        >>/tmp/d07_witness.log 2>&1; then
    echo "ok: ndn-engine d07_pit_match_propagates_lp_token_to_out_tokens"
else
    echo "FAIL: ndn-engine d07 PitMatch propagation"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.07 RESOLVED — PitToken echoed on Data/Nack egress ==="
    exit 0
else
    echo
    echo "=== D.07 EXPECTED-FAIL — PitToken not echoed on Data/Nack egress ==="
    [ -f /tmp/d07_witness.log ] && cat /tmp/d07_witness.log
    exit 1
fi
