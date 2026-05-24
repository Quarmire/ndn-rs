#!/usr/bin/env bash
# Witness — NC.19: delayed-seed fingerprint (adaptive-resistant, doctrine §6).
#
# The producer commits to SHA-256(r) and publishes the projections h while
# withholding the seed r; coders cannot filter in-flight, but once r is revealed
# the homomorphic check verifies retroactively and identifies polluters — which
# an attacker who committed before the reveal cannot pass. A wrong revealed seed
# fails the commitment.
#
# Witness (RUST-UNIT, feature `f2-recode`):
#   - recode::tests::delayed_fingerprint_detects_pollution_after_reveal
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f2-recode --quiet -- \
        delayed_fingerprint_detects_pollution_after_reveal \
        >/tmp/nc19_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc19_witness.log; then
    echo "=== NC.19 PASS — delayed-seed fingerprint detects pollution after reveal ==="
    grep -E "test result|running" /tmp/nc19_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.19 FAIL ==="; cat /tmp/nc19_witness.log; exit 1
fi
