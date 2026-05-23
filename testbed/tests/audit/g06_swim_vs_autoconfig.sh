#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — SWIM removed; NDN AutoConfig wired.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Severity:    RESOLVED 2026-05-08
# Type:        GREP-PROOF
#
# Original finding: ndn-rs used SWIM-over-NDN for neighbor discovery;
# NDN AutoConfig (DNS-based hub finding + NeighborProbeProtocol) is the
# spec-aligned primitive.
#
# Resolution: SWIM hello/ machinery removed; replaced by:
#   - NeighborProbeProtocol (/ndn/local/nd/probe/ping) for liveness probing
#   - AutoConfigProtocol (/localhop/ndn-autoconf/hub) for hub discovery
#
# This script verifies SWIM artifacts are absent and NDN AutoConfig is wired.
#
# Exit codes:  0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. SWIM machinery is gone.
if grep -rqE '\bHelloProtocol\b|\bUdpNeighborDiscovery\b|\bSwimScheduler\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "FAIL: SWIM types still present"
    fail=1
else
    echo "ok: SWIM types absent"
fi

# 2. NeighborProbeProtocol is present.
if grep -rqE '\bNeighborProbeProtocol\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "ok: NeighborProbeProtocol present"
else
    echo "FAIL: NeighborProbeProtocol not found"
    fail=1
fi

# 3. AutoConfigDiscovery (hub discovery) is present.
if grep -rqE '\bAutoConfigDiscovery\b' \
        crates/ndn-discovery/src/ 2>/dev/null; then
    echo "ok: AutoConfigDiscovery present"
else
    echo "FAIL: AutoConfigDiscovery not found"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.06 RESOLVED — SWIM removed, NeighborProbeProtocol + AutoConfig wired ==="
    exit 0
else
    echo
    echo "=== G.06 — unexpected state; see above ==="
    exit 1
fi
