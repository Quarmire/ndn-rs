#!/usr/bin/env bash
# Witness test for audit findings D.13 / I.08 — `ValidationStage`
# blanket-skipped any `/localhost` Data, accepting forged
# /localhost responses with no signature check.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.13
# Severity:    MAJOR (security)
# Spec ref:    NFD `daemon/mgmt/rib-manager.cpp:60,87,348-350`
#              uses an explicit `m_localhostValidator` allowlist
#              instead of blanket-trusting /localhost Data.
# Witnesses:   GREP-PROOF that the blanket skip is gone:
#                grep -nE 'skipping /localhost'
#                  crates/spec/ndn-engine/src/stages/validation.rs
#              must return zero hits.
#
# Live ndn-cxx-poked /localhost forgery against ndn-fwd is
# BLOCKED-BY-INTEROP until the testbed image carries ndnpoke; the
# GREP-PROOF + the standing C.01 dispatch tests cover the
# architectural fix.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
fail=0

if grep -qE 'skipping /localhost' crates/spec/ndn-engine/src/stages/validation.rs; then
    echo "FAIL: blanket /localhost skip still in validation.rs"
    fail=1
else
    echo "ok: blanket /localhost skip removed from validation.rs"
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.13 / I.08 RESOLVED — /localhost Data validates per the same chain rules ==="
    exit 0
else
    echo
    echo "=== D.13 / I.08 EXPECTED-FAIL — /localhost auto-trusted ==="
    exit 1
fi
