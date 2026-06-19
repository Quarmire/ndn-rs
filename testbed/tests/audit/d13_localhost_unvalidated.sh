#!/usr/bin/env bash
# Witness test for audit findings D.13 / I.08 — `ValidationStage`
# blanket-skipped any `/localhost` Data, accepting forged
# /localhost responses with no signature check.
#
# Finding:     testbed/EXPECTED_FAILURES.md § D.13
# Severity:    MAJOR (security)
# Spec ref:    NFD `daemon/mgmt/rib-manager.cpp:60,87,348-350`
#              uses an explicit `m_localhostValidator` allowlist
#              instead of blanket-trusting /localhost Data.
# Witnesses:   RUST-UNIT — a forged `/localhost/nfd/...` Data packet with
#              a bogus DigestSha256 signature is passed through
#              `ValidationStage` and dropped.
#
# Live ndn-cxx-poked /localhost forgery against ndn-fwd is
# BLOCKED-BY-INTEROP until the testbed image carries ndnpoke; the
# RUST-UNIT + the standing C.01 dispatch tests cover the architectural fix.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if cargo test -p ndn-engine --lib --quiet d13_ >/tmp/d13_witness.log 2>&1; then
    echo "ok: d13_ validation behavior tests"
else
    echo "FAIL: d13_ validation behavior tests"
    cat /tmp/d13_witness.log
    exit 1
fi

echo
echo "=== D.13 / I.08 RESOLVED — /localhost Data validates per the same chain rules ==="
