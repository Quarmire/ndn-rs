#!/usr/bin/env bash
# Witness — CTX.15: flooded fake advert does not enter the keyring.
#
# Adoption is never automatic: a forged context (attacker's anchor) for a
# namespace fails the TOFU fingerprint match against the trusted ticket and
# never enters the keyring; receiving an advert mutates nothing. The genuine
# context still adopts. Poisoning is a local nuisance, not trust compromise (N5).
# Witness (RUST-UNIT, ndn-cert, tests/ctx_phase4_onboarding.rs):
#   - ctx15_flooded_fake_advert_rejected
#
# Expected before Phase 4: FAIL. After Phase 4: exit 0.
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-cert --test ctx_phase4_onboarding --quiet -- \
        ctx15_flooded_fake_advert_rejected \
        >/tmp/ctx15_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx15_witness.log; then
    echo "=== CTX.15 PASS — fake advert rejected without TOFU ==="
    grep -E "test result|running" /tmp/ctx15_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.15 FAIL — fake advert poisoned the keyring ==="
    cat /tmp/ctx15_witness.log
    exit 1
fi
