#!/usr/bin/env bash
# Witness recipe for audit finding G.04 — NLSR implemented in ndn-rs.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    RESOLVED 2026-05-08
# Spec ref:    NLSR is the deployed NDN testbed routing protocol.
# Witness:     GREP-PROOF — passes when the NlsrProtocol surface exists
#              under crates/ndn-routing/ and the forwarder binary
#              wires it up.  Fails if either surface disappears (regression).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. NlsrProtocol struct / impl must exist in ndn-routing.
nlsr_code=$(grep -rnE '^\s*(pub\s+)?(struct|enum|trait|fn|impl|mod)\s+\w*[Nn]lsr\b|::\s*Nlsr\s*\(' \
        crates/ndn-routing/src/ 2>/dev/null || true)
if [ -n "$nlsr_code" ]; then
    echo "ok: NLSR surface present in crates/ndn-routing/"
else
    echo "FAIL: NLSR surface missing from crates/ndn-routing/ — regression"
    fail=1
fi

# 2. The forwarder binary must reference NlsrProtocol (wired-up check).
if grep -qE 'NlsrProtocol|nlsr_cfg|routing\.nlsr' binaries/ndn-fwd/src/main.rs 2>/dev/null; then
    echo "ok: ndn-fwd wires NlsrProtocol"
else
    echo "FAIL: ndn-fwd no longer wires NlsrProtocol — regression"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.04 RESOLVED — NlsrProtocol surface confirmed ==="
    exit 0
else
    echo
    echo "=== G.04 REGRESSION — NLSR surface missing; see output above ==="
    exit 1
fi
