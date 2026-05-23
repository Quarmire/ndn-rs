#!/usr/bin/env bash
# Witness test for inbound Interest-flood rate limiting.
#
# Feature:     in-engine rate-limit — `crates/ndn-ratelimit`.
# Spec ref:    no NDN spec governs admission control; design memo at
#              `docs/notes/rate-limit-design-2026-05-12.md`. The hook
#              issues `NACK(reason=Congestion)` for inbound Interest
#              denials, which NDN does standardise.
# Witnesses:   Two RUST-UNIT tests in `ndn-ratelimit`'s tests/end_to_end:
#                - inbound_pps_burst_caps_floods
#                - no_hook_permits_everything
#              The first installs a 5-PPS / burst-5 inbound policy on
#              face 1 + `/test/rl`, drives a 25-Interest flood from an
#              embedded consumer, and asserts the rate limit engages
#              (some permits, some denials). The second is the
#              regression guard against the hook misfiring when
#              installed with no policy.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-ratelimit --test end_to_end --quiet \
        >/tmp/rl01_witness.log 2>&1; then
    echo "=== RL.01 PASS — inbound rate limit engages on flood, idle on no-policy ==="
    tail -n 6 /tmp/rl01_witness.log
    exit 0
else
    echo "=== RL.01 FAIL — rate-limit end-to-end witness failed ==="
    cat /tmp/rl01_witness.log
    exit 1
fi
