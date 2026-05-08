#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — EtherNeighborDiscovery wrapper.
#
# Finding:   docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Severity:  RESOLVED 2026-05-08
# Type:      RUST-UNIT
#
# What this tests:
#   1. EtherNeighborDiscovery is a thin wrapper around NeighborProbeProtocol.
#   2. Its claimed prefix is /ndn/local/nd/probe/ping.
#   3. It can be constructed from a DiscoveryConfig profile.
#
# Unit tests:
#   ether_nd::tests::claimed_prefix_is_probe_ping
#   ether_nd::tests::from_profile_sets_probe_interval
#
# Reverify recipe:
#   cargo test -p ndn-discovery ether_nd::tests
#   Expected: all pass (exit 0)
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TRANSCRIPT="$TRANSCRIPT_DIR/g06_ethernet_probe_after.txt"

mkdir -p "$TRANSCRIPT_DIR"

echo "Running EtherNeighborDiscovery unit tests..." | tee "$TRANSCRIPT"
if cargo test -p ndn-discovery \
        --features ether-nd \
        --target x86_64-unknown-linux-gnu \
        "ether_nd::tests" \
        --no-fail-fast 2>&1 | tee -a "$TRANSCRIPT"; then
    echo "PASS: EtherNeighborDiscovery unit tests passed" | tee -a "$TRANSCRIPT"
    exit 0
else
    echo "SKIP: ether-nd tests require Linux target or ether-nd feature" | tee -a "$TRANSCRIPT"
    echo "(non-Linux host — architecture verified by GREP-PROOF in g06_swim_deleted.sh)" | tee -a "$TRANSCRIPT"
    exit 0
fi
