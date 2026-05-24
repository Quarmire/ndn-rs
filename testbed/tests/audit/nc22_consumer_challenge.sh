#!/usr/bin/env bash
# Witness — NC.22: consumer-challenge fingerprint (adaptive-resistant, §6).
#
# The consumer picks a fresh random projection r and asks a holder with
# descriptor-verified sources for the fingerprint response (LinearFingerprint
# for r, signed). It then verifies its held packets: genuine sources pass; a
# packet chosen before r was known fails — the fresh challenge catches it.
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - recode_face::tests::consumer_challenge_detects_pollution
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-coding --features f2-recode-face --quiet -- \
        consumer_challenge_detects_pollution \
        >/tmp/nc22_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc22_witness.log; then
    echo "=== NC.22 PASS — consumer-challenge fingerprint detects pollution ==="
    grep -E "test result|running" /tmp/nc22_witness.log | tail -n 2
    exit 0
else
    echo "=== NC.22 FAIL ==="; cat /tmp/nc22_witness.log; exit 1
fi
