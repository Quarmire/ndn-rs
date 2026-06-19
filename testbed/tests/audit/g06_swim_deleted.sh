#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — SWIM hello/ tree deleted.
#
# Finding:   docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Type:      GREP-PROOF
#
# What this tests:
#   Asserts that no SWIM artifacts remain in the ndn-discovery crate or its
#   consumer crates (ndn-face, ndn-mobile).  The SWIM protocol family
#   (HelloProtocol, DirectProbe, IndirectProbe, swim_*) must be absent.
#
# Reverify recipe:
#   bash testbed/tests/audit/g06_swim_deleted.sh
#   Expected: exit 0 (all SWIM surface gone)
#
# Exit codes: 0 PASS / 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TRANSCRIPT="$TRANSCRIPT_DIR/g06_swim_deleted.txt"
mkdir -p "$TRANSCRIPT_DIR"

fail=0

check_absent() {
    local pattern="$1"
    local desc="$2"
    local dirs="${3:-crates/ndn-discovery crates/faces/ndn-face crates/ndn-mobile}"
    if grep -rqE "$pattern" $dirs --include="*.rs" 2>/dev/null; then
        echo "FAIL: found $desc" | tee -a "$TRANSCRIPT"
        grep -rE "$pattern" $dirs --include="*.rs" -l 2>/dev/null | tee -a "$TRANSCRIPT"
        fail=1
    else
        echo "ok: $desc absent" | tee -a "$TRANSCRIPT"
    fi
}

: > "$TRANSCRIPT"

echo "=== G.06 SWIM-deletion witness ===" | tee -a "$TRANSCRIPT"

check_absent '\bHelloProtocol\b'           "HelloProtocol type"
check_absent '\bDirectProbe\b'            "DirectProbe type"
check_absent '\bIndirectProbe\b'          "IndirectProbe type"
check_absent '\bLinkMedium\b'             "LinkMedium trait (SWIM hello interface)"
check_absent '\bHelloCore\b'              "HelloCore struct"
check_absent '\bHelloState\b'             "HelloState struct"
check_absent '\bUdpNeighborDiscovery\b'   "UdpNeighborDiscovery type"
check_absent '(?i)\bswim\b'              "swim substring (case-insensitive)"
check_absent '\bhello_prefix\b'           "hello_prefix scope constant"

# hello/ directory itself must not exist in ndn-discovery.
if [ -d "$REPO_ROOT/crates/ndn-discovery/src/hello" ]; then
    echo "FAIL: crates/ndn-discovery/src/hello/ still exists" | tee -a "$TRANSCRIPT"
    fail=1
else
    echo "ok: hello/ directory absent from ndn-discovery" | tee -a "$TRANSCRIPT"
fi

# Orphan ether_nd.rs in ndn-face must not exist.
if [ -f "$REPO_ROOT/crates/faces/ndn-face/src/l2/ether_nd.rs" ]; then
    echo "FAIL: crates/faces/ndn-face/src/l2/ether_nd.rs still exists" | tee -a "$TRANSCRIPT"
    fail=1
else
    echo "ok: ndn-face/src/l2/ether_nd.rs absent" | tee -a "$TRANSCRIPT"
fi

if [ "$fail" -eq 0 ]; then
    echo "" | tee -a "$TRANSCRIPT"
    echo "PASS: all SWIM artifacts removed" | tee -a "$TRANSCRIPT"
    exit 0
else
    echo "" | tee -a "$TRANSCRIPT"
    echo "FAIL: SWIM artifacts remain; see above" | tee -a "$TRANSCRIPT"
    exit 1
fi
