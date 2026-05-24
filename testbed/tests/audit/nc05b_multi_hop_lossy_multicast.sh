#!/usr/bin/env bash
# Witness — NC.05b: multi-hop lossy multicast through real forwarders.
#
# Two forwarders (A→B link), a recoder on B, two consumers on A. Each consumer
# drops a different half of the responses (independent lossy links); because
# every coded request is answered by a fresh innovative combination, both
# consumers still reach rank K and decode + verify. The multicast / loss-repair
# win on a genuine two-hop forwarding path — the topology NC.05 deferred.
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - tests/recode_engine.rs::multi_hop_lossy_multicast_recovers_at_both_consumers
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --test recode_engine --quiet -- \
        multi_hop_lossy_multicast_recovers_at_both_consumers \
        >/tmp/nc05b_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc05b_witness.log; then
    echo "=== NC.05b PASS — both consumers recover over a 2-hop lossy multicast path ==="
    grep -E "test result|running" /tmp/nc05b_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.05b FAIL — multi-hop multicast witness failed ==="
    cat /tmp/nc05b_witness.log
    exit 1
fi
