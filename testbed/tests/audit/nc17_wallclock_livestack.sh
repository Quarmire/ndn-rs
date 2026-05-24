#!/usr/bin/env bash
# Witness — NC.17: wall-clock live-stack benchmark.
#
# Times recovering a generation through the real ForwarderEngine, recode
# (RecoderFace mints K combinations + decode) vs plain (Producer serves K
# segments + concat), over fresh names each iteration. In-proc is lossless, so
# this measures coding's *processing cost* on a clean path — the doctrine's
# "clean-path coding is pure overhead" (the loss/multicast win is NC.16).
# Reports ms/generation + MB/s + the overhead ratio; asserts completion and a
# loose ceiling only (wall-clock thresholds are environment-dependent).
#
# Witness (RUST-UNIT, feature `f2-recode-face`):
#   - tests/recode_wallclock.rs::wallclock_recode_vs_plain
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-coding --features f2-recode-face --test recode_wallclock -- --nocapture \
        >/tmp/nc17_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/nc17_witness.log; then
    echo "=== NC.17 PASS — live-stack recode vs plain wall-clock measured ==="
    grep -E "Wall-clock|path|recode|plain|overhead" /tmp/nc17_witness.log
    exit 0
else
    echo "=== NC.17 FAIL — wall-clock benchmark witness failed ==="
    cat /tmp/nc17_witness.log
    exit 1
fi
