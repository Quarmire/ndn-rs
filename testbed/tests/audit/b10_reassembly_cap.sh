#!/usr/bin/env bash
# Audit witness — B.10.
#
# Finding:     `ReassemblyBuffer::pending` was an unbounded
#              `HashMap`.  Only `purge_expired()` ever shrank it,
#              and that ran only when a higher layer remembered
#              to tick.  A peer sending first-fragments of
#              never-completed groups inflated ndn-rs memory.
# Witness:     RUST-UNIT b10_reassembly_buffer_caps_pending_groups
#              The fix bounds the partial-packet table at
#              `MAX_PENDING_PACKETS = 1024` and falls back to
#              purge-expired + oldest-eviction when the cap is hit.
# Spec ref:    NFD's `daemon/face/lp-reassembler.hpp` keeps the
#              partial-packet map bounded via scheduler-driven
#              timeouts; ndn-rs picks a hard cap instead.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-packet --features std --lib --quiet \
        b10_reassembly_buffer_caps_pending_groups 2>&1 | tail -5; then
    echo "FAIL: B.10 unit test"
    exit 1
fi
echo "=== B.10 RESOLVED — reassembly buffer bounded with eviction ==="
