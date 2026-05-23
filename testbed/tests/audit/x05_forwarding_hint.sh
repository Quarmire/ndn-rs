#!/usr/bin/env bash
# Witness for X.05 — NDNLPv2 ForwardingHint forwarding (NFD onIncomingInterest +
# NetworkRegionTable). Interest forwarded toward the hint delegation when its
# name is unrouted; hint stripped when the delegation reaches a producer region.
# Reverify: cargo test -p ndn-engine --test forwarding_hint
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$REPO_ROOT"
command -v cargo >/dev/null || { echo "SKIP: cargo missing" >&2; exit 2; }
if cargo test -p ndn-engine --test forwarding_hint --quiet >/tmp/x05.log 2>&1; then
  echo "=== X.05 RESOLVED — ForwardingHint routes by delegation; stripped in producer region ==="; exit 0
else
  echo "FAIL: ForwardingHint not honoured"; tail -20 /tmp/x05.log; exit 1
fi
