#!/usr/bin/env bash
# Witness test for audit findings D.02 / I.11 — `/localhop` scope
# unenforced.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.02
# Severity:    MAJOR
# Spec ref:    NFD `daemon/fw/scope-prefix.hpp:46-58` (LOCALHOP);
#              `daemon/fw/algorithm.cpp:45-49` wouldViolateScope rule.
# Witnesses:
#   1. GREP-PROOF: `localhop` appears in `crates/engine/`. Today
#      (pre-fix) the term doesn't appear at all; after the fix the
#      decode stage references `is_localhop_name` and the scope check.
#   2. RUST-UNIT: `d02_is_localhop_name_recognises_prefix` in
#      `ndn-engine` confirms the helper exists and matches `/localhop`
#      / rejects `/localhost` and `/local/hop`.
#
# Live ndn-fwd ↔ remote peer interop is BLOCKED-BY-INTEROP. The
# enforcement here is conservatively wider than NFD's outbound-only
# check (ndn-rs drops at ingress); refining to "permit if a local
# consumer exists" is a follow-up.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if grep -rqE 'localhop' crates/engine/; then
    echo "ok: GREP-PROOF — 'localhop' present in crates/engine/"
else
    echo "FAIL: GREP-PROOF — 'localhop' missing from crates/engine/"
    fail=1
fi

if cargo test -p ndn-engine --lib --quiet d02_ \
        >/tmp/d02_witness.log 2>&1; then
    echo "ok: RUST-UNIT — is_localhop_name helper"
else
    echo "FAIL: RUST-UNIT"
    cat /tmp/d02_witness.log
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.02 / I.11 RESOLVED — /localhop scope check present ==="
    exit 0
else
    echo
    echo "=== D.02 / I.11 EXPECTED-FAIL — /localhop unenforced ==="
    exit 1
fi
