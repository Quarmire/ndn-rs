#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — per-neighbor liveness probe.
#
# Finding:   docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Severity:  MAJOR
# Type:      RUST-UNIT
#
# What this tests:
#   1. NeighborProbeProtocol replies to incoming probe Interests for the local
#      node with a Data packet — "I'm alive" reply.
#   2. NeighborProbeProtocol sends probe Interests to configured neighbors
#      on each tick when the probe interval has elapsed.
#   3. Probe Interest name is under /ndn/local/nd/probe/ping as specified.
#
# These properties are verified by unit tests in ndn-discovery:
#   probe::tests::probe_interest_has_correct_prefix
#   probe::tests::probe_protocol_replies_to_incoming_probe_interest
#   probe::tests::probe_protocol_sends_probe_on_tick
#
# Reverify recipe:
#   cargo test -p ndn-discovery probe::tests
#   Expected: all pass (exit 0)
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TRANSCRIPT="$TRANSCRIPT_DIR/g06_neighbor_probe_after.txt"

mkdir -p "$TRANSCRIPT_DIR"

echo "Running neighbor-probe unit tests..." | tee "$TRANSCRIPT"
if cargo test -p ndn-discovery "probe::tests" --no-fail-fast 2>&1 | tee -a "$TRANSCRIPT"; then
    echo "PASS: all neighbor-probe unit tests passed" | tee -a "$TRANSCRIPT"
    exit 0
else
    echo "FAIL: one or more neighbor-probe unit tests failed" | tee -a "$TRANSCRIPT"
    exit 1
fi
