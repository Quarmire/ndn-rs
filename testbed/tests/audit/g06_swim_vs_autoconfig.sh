#!/usr/bin/env bash
# Witness recipe for audit finding G.06 — `ndn-discovery` uses a
# SWIM-style gossip protocol; NDN AutoConfig (DNS-based PROBE ↔
# Certificate) is the spec-side neighbor-discovery primitive.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.06
# Severity:    MAJOR (BLOCKED-BY-INTEROP — needs ndn-autoconfig-server)
# Spec ref:    ndn-cxx `tools/ndn-autoconfig` reads DNS TXT records to
#              fetch a NDN-cert chain; NFD's auto-discovery is via
#              `/localhop/nfd/*` prefixes and prefix announcements.
#              ndn-rs's `ndn-discovery` Hello/gossip protocol is a
#              SWIM-over-NDN design (Stutzbach/van Renesse) borrowed
#              into NDN packets, with its own TLV types
#              (`T_ADD_ENTRY` / `T_REMOVE_ENTRY` / capability set).
# Witness:     GREP-PROOF that ndn-rs's discovery surface remains the
#              SWIM design (architecture-side stamp). The live interop
#              part — sending a real `ndn-autoconfig` PROBE Interest at
#              ndn-rs and observing the empty / mismatched response —
#              is BLOCKED-BY-INTEROP: it needs the ndn-cxx
#              `ndn-autoconfig` binary in the testclient image, plus a
#              DNS TXT record fixture.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. SWIM machinery is still present (unchanged audit observation).
if grep -rqE '\bSwim\b|swim_failure|HelloProtocol\b|epidemic' \
        crates/engine/ndn-discovery/src/ 2>/dev/null; then
    echo "ok: SWIM-over-NDN discovery surface still present (audit-aligned)"
else
    echo "FAIL: SWIM/Hello surface no longer present — re-target this witness"
    fail=1
fi

# 2. There is no `ndn-autoconfig` PROBE handler in ndn-rs.
if grep -rqEi '\bndn[_-]?autoconfig\b|fn handle_autoconfig_probe' \
        crates/engine/ndn-discovery/src/ binaries/ 2>/dev/null; then
    echo "FAIL: an ndn-autoconfig PROBE handler appeared — update this witness for live interop"
    fail=1
else
    echo "ok: no ndn-autoconfig PROBE handler (architecture-side gap confirmed)"
fi

# 3. Live interop note.
echo 'info: live `ndn-autoconfig` PROBE → response interop is BLOCKED-BY-INTEROP'
echo '      until the ndn-cxx binary plus a DNS TXT fixture land in the testclient image.'

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.06 BLOCKED-BY-INTEROP — SWIM-over-NDN architecture confirmed; live AutoConfig deferred ==="
    exit 0
else
    echo
    echo "=== G.06 — architecture diverged from audit; update witness ==="
    exit 1
fi
