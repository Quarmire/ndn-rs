#!/usr/bin/env bash
# Witness recipe for audit finding G.04 — NLSR phase 0 skeleton in place.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR (skeleton only; full implementation tracked in
#              docs/notes/nlsr-implementation-plan-2026-05-07.md)
# Spec ref:    NLSR is the deployed NDN testbed routing protocol.
#              Reference: ~/Documents/Dev/NLSR/ (named-data/NLSR)
# Witnesses:   GREP-PROOF that the NlsrProtocol struct and mod nlsr exist
#              in ndn-routing, and that cargo build -p ndn-routing is clean.
#
# Expected today: FAIL (exit 1) before phase 0 lands.
# After phase 0: exit 0. Re-target for phase 6 interop once fully wired.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. NlsrProtocol struct exists in ndn-routing.
nlsr_struct=$(grep -rn 'pub struct NlsrProtocol' \
        crates/ndn-routing/src/ 2>/dev/null || true)
if [ -z "$nlsr_struct" ]; then
    echo "FAIL: NlsrProtocol not found in crates/ndn-routing/src/"
    fail=1
else
    echo "ok: NlsrProtocol struct present"
fi

# 2. mod nlsr is declared in protocols/mod.rs.
nlsr_mod=$(grep -n 'mod nlsr' \
        crates/ndn-routing/src/protocols/mod.rs 2>/dev/null || true)
if [ -z "$nlsr_mod" ]; then
    echo "FAIL: 'mod nlsr' not found in protocols/mod.rs"
    fail=1
else
    echo "ok: mod nlsr declared in protocols/mod.rs"
fi

# 3. cargo build -p ndn-routing must be clean.
if ! cargo build -p ndn-routing 2>&1 | tee /tmp/ndn-routing-build.log | grep -qE '^error'; then
    echo "ok: cargo build -p ndn-routing clean"
else
    echo "FAIL: cargo build -p ndn-routing reported errors"
    cat /tmp/ndn-routing-build.log
    fail=1
fi

# 4. Plan doc exists.
if [ -f "docs/notes/nlsr-implementation-plan-2026-05-07.md" ]; then
    echo "ok: implementation plan doc present"
else
    echo "FAIL: docs/notes/nlsr-implementation-plan-2026-05-07.md missing"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.04 phase-0 skeleton PASS — NLSR module tree in place ==="
    echo "    Re-target this witness for phase-6 interop once all sub-systems land."
    exit 0
else
    echo
    echo "=== G.04 phase-0 skeleton FAIL ==="
    exit 1
fi
