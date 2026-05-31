#!/usr/bin/env bash
# Witness — CTX.01: adopt-to-verify with no CA.
#
# A fresh node parses a scanned JoinTicket, fetches the published TrustContext,
# TOFU-checks it against the ticket fingerprint, adopts it, and verifies a
# producer-signed Data — with no CA interaction. The common case (consume/
# verify) needs no transaction. See trust-context-model-2026-05-25.md §3.
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase4_onboarding.rs):
#   - ctx01_adopt_to_verify_no_ca
#
# Expected before Phase 4: FAIL. After Phase 4: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase4_onboarding --quiet -- \
        ctx01_adopt_to_verify_no_ca \
        >/tmp/ctx01_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx01_witness.log; then
    echo "=== CTX.01 PASS — adopt-to-verify works with no CA ==="
    grep -E "test result|running" /tmp/ctx01_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.01 FAIL — adopt-to-verify path broken ==="
    cat /tmp/ctx01_witness.log
    exit 1
fi
