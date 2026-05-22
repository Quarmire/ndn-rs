#!/usr/bin/env bash
# Witness test for the ndn-app reflexive-forwarding endpoint seam.
#
# Design ref:  .claude/notes/ndncert-device-approval-transport-2026-05-22.md
#              (fork item 2 — the app-level reflexive helper), built on the
#              engine reflexive forwarding hardened by rf_*.sh.
# Claim:       ndn-app exposes Consumer::fetch_reflexive (advertiser: send a
#              forward Interest carrying R, serve reverse pulls under R) and
#              Consumer::pull_reflexive (puller: Interest R/<suffix> back along
#              the reverse path). A producer reaches the consumer over the
#              reverse path with no route to it.
# Witnesses:   ndn-app `reflexive` integration tests over an embedded engine.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-app --test reflexive --quiet >/tmp/rf_app_witness.log 2>&1; then
    echo "=== RF-APP RESOLVED — reflexive endpoint seam: reverse pull round-trips ==="
    exit 0
else
    echo "=== RF-APP EXPECTED-FAIL — reflexive endpoint seam broken ==="
    cat /tmp/rf_app_witness.log
    exit 1
fi
