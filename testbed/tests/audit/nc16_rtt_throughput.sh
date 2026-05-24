#!/usr/bin/env bash
# Witness — NC.16: RTT-vs-no-recode throughput benchmark (structural).
#
# A seeded loss-channel simulation over the real coding logic, reporting two
# regimes honestly: (A) unicast parallel-retry fetch-rounds — recode ≈ ARQ
# (no win on a clean single path, per the F1 doctrine); (B) multicast source
# transmissions to M=16 receivers — recode beats ARQ (asserted), since one
# fungible coded stream serves all receivers' differing losses.
#
# Witness (RUST-UNIT, feature `f2-recode`):
#   - tests/recode_throughput.rs::rtt_vs_no_recode_tables
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode --test recode_throughput -- --nocapture \
        >/tmp/nc16_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc16_witness.log; then
    echo "=== NC.16 PASS — multicast recode beats ARQ; unicast comparable ==="
    grep -E "Scenario|loss%|^  +[0-9]" /tmp/nc16_witness.log
    exit 0
else
    echo "=== NC.16 FAIL — throughput-benchmark witness failed ==="
    cat /tmp/nc16_witness.log
    exit 1
fi
