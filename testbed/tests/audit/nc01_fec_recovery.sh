#!/usr/bin/env bash
# Witness test for F1 producer-side FEC recovery.
#
# Feature:     network-coding F1 — `crates/protocols/ndn-coding`.
# Spec ref:    RFC 9273 §3 (content coding); empirical anchor
#              Xu/Li/Zhang 2018 "Reliable Content Delivery in Lossy
#              NDN Based on Network Coding".
# Witnesses:   Two RUST-UNIT tests in `ndn-coding`'s tests/end_to_end:
#                - fec_round_trip_no_loss
#                - fec_round_trip_with_source_losses
#              The second drives a 2-face embedded `ForwarderEngine`,
#              withholds source segments 1/4/6 at the producer, and
#              asserts the consumer recovers the full payload via
#              parity. The first is the regression guard against the
#              decoder misfiring on the no-loss path.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --test end_to_end --quiet \
        fec_round_trip \
        >/tmp/nc01_witness.log 2>&1; then
    echo "=== NC.01 PASS — F1 systematic FEC recovers payload through embedded engine ==="
    tail -n 6 /tmp/nc01_witness.log
    exit 0
else
    echo "=== NC.01 FAIL — F1 FEC end-to-end witness failed ==="
    cat /tmp/nc01_witness.log
    exit 1
fi
