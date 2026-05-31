#!/usr/bin/env bash
# Witness for X.06 — self-learning strategy (NFD self-learning-strategy parity).
# Discovery-broadcast on no route; route learned from a PrefixAnnouncement
# carried on Data, gated on (1) the self-learning strategy being active and
# (2) the announcement passing the engine Validator.
# Reverify: cargo test -p ndn-engine --test self_learning; -p ndn-packet --features std prefix_announcement; -p ndn-strategy self_learning
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$REPO_ROOT"
command -v cargo >/dev/null || { echo "SKIP: cargo missing" >&2; exit 2; }
ok=1
cargo test -p ndn-engine --test self_learning --quiet >/tmp/x06a.log 2>&1 || ok=0
cargo test -p ndn-packet --features std --lib prefix_announcement --quiet >/tmp/x06b.log 2>&1 || ok=0
cargo test -p ndn-strategy --lib self_learning --quiet >/tmp/x06c.log 2>&1 || ok=0
if [ "$ok" = 1 ]; then
  echo "=== X.06 RESOLVED — self-learning: broadcast-on-no-route + validated PrefixAnnouncement route install/use ==="; exit 0
else echo "FAIL: self-learning"; tail -20 /tmp/x06a.log /tmp/x06b.log /tmp/x06c.log; exit 1; fi
