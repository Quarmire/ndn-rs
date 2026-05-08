#!/usr/bin/env bash
# Witness test for audit finding D.12 — ContentStore admits unvalidated Data.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.12
# Severity:    MAJOR (RESOLVED 2026-05-08)
# Spec ref:    NFD daemon/fw/forwarder.cpp:322,404 — CS insert follows PIT
#              match; validation drives whether the packet reaches that point.
#              NFD daemon/table/cs.cpp admission is gated by the upstream
#              pipeline's validation outcome. ndn-rs now enforces the same
#              invariant via ctx.verified on PacketContext.
#
# Witness type: RUST-UNIT (ndn-engine)
#
# Tests:
#   d12_cs_rejects_unverified_ctx  — CS must not admit Data with verified=false.
#   d12_cs_admits_verified_ctx     — CS must admit Data with verified=true.
#   d12_validation_sets_verified_on_valid — ValidationStage sets verified=true.
#   d12_validation_drops_bogus_sig — ValidationStage drops invalid signature.
#   d12_disabled_validator_sets_verified  — disabled validator sets verified=true
#                                           (permissive dev-mode path).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

fail=0

if cargo test -p ndn-engine --lib --quiet d12 \
        >/tmp/d12_witness.log 2>&1; then
    echo "ok: D.12 unit tests (CS verified gate + ValidationStage verified flag)"
else
    echo "FAIL: D.12 unit tests"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.12 RESOLVED — ContentStore only admits verified Data ==="
    exit 0
else
    echo
    echo "=== D.12 FAIL ==="
    cat /tmp/d12_witness.log
    exit 1
fi
