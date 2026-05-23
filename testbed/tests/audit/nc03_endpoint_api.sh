#!/usr/bin/env bash
# Witness — NC.03: the ndn-coding endpoint API (CodedProducer / CodedFetcher)
# round-trips through an embedded forwarder, including parity recovery.
#
# Feature:    network-coding F1 endpoint API — `crates/ndn-coding`.
# Witnesses:  two RUST-UNIT tests in ndn-coding's tests/end_to_end:
#               - endpoint_round_trip_no_loss
#                 (CodedProducer serves N segments; CodedFetcher recovers
#                  from the first K)
#               - endpoint_fetcher_recovers_via_parity
#                 (producer withholds sources 1/4/6; the fetcher's adaptive
#                  over-fetch pulls parity and still recovers the payload)
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
        endpoint_ \
        >/tmp/nc03_witness.log 2>&1; then
    echo "=== NC.03 PASS — CodedProducer/CodedFetcher round-trip + parity recovery ==="
    tail -n 6 /tmp/nc03_witness.log
    exit 0
else
    echo "=== NC.03 FAIL — endpoint-API witness failed ==="
    cat /tmp/nc03_witness.log
    exit 1
fi
