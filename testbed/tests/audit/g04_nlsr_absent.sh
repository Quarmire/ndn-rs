#!/usr/bin/env bash
# Witness recipe for audit finding G.04 — NLSR (Named-data Link State
# Routing) is not implemented in ndn-rs.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR (NOT-WITNESSABLE — feature-absence)
# Spec ref:    NLSR is the deployed NDN testbed routing protocol. Reference
#              implementation lives at github.com/named-data/NLSR. ndn-rs
#              ships only `StaticProtocol` and `DvrProtocol` (the latter is
#              an ndn-rs-original distance-vector protocol, see § G.05);
#              there is no NLSR module under `crates/protocols/ndn-routing/`.
# Witness:     GREP-PROOF — the test passes today because the NLSR surface
#              is absent. When NLSR lands the test must be re-purposed to
#              exercise the routing-protocol implementation directly (LSAs,
#              link-state flooding, RIB-manager origin=128 publication).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. No actual NLSR module / struct / impl under ndn-routing — comments
#    that mention "NLSR/DVR" in narrative are fine; we look for real code
#    surface (struct definitions, impl blocks, named modules).
nlsr_code=$(grep -rnE '^\s*(pub\s+)?(struct|enum|trait|fn|impl|mod)\s+\w*[Nn]lsr\b|::\s*Nlsr\s*\(' \
        crates/protocols/ndn-routing/src/ 2>/dev/null || true)
if [ -n "$nlsr_code" ]; then
    echo "FAIL: ndn-routing now defines NLSR surface — re-target this witness against the implementation"
    echo "$nlsr_code"
    fail=1
else
    echo "ok: no NLSR struct / impl / module in crates/protocols/ndn-routing/"
fi

# 2. The control_parameters.rs constant for origin=128 (NLSR) exists but
#    no caller emits routes *constructed with* origin=NLSR (the audit's
#    call-out). Label-table entries that map the constant to a string for
#    `nfdc list`-style output don't count.
hits=$(grep -rnE 'origin\s*[:=]\s*Origin::Nlsr|origin\s*[:=]\s*origin::NLSR\b|register_origin\(\s*Origin::Nlsr|with_origin\(\s*Origin::Nlsr' \
        crates/ binaries/ 2>/dev/null \
      | grep -vE 'src/control_parameters\.rs|notes/spec-compliance|EXPECTED_FAILURES' || true)
if [ -n "$hits" ]; then
    echo "FAIL: callers emit routes under origin=NLSR — re-target witness"
    echo "$hits"
    fail=1
else
    echo "ok: no callers emit routes under origin=NLSR"
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.04 NOT-WITNESSABLE — NLSR absence confirmed (roadmap item) ==="
    echo "    Re-target this witness once NLSR lands."
    exit 0
else
    echo
    echo "=== G.04 — NLSR surface re-introduced; update witness ==="
    exit 1
fi
