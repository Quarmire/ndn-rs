#!/usr/bin/env bash
# Witness — CTX.13: self-certifying (key-digest / did:key-rooted) context.
#
# A context whose namespace is rooted at a self-signed key needs no
# hierarchical naming authority and is squat-proof: only the holder of that key
# can produce under the namespace, and the context validates its own data with
# no CA. A squatter presenting a different key under the same namespace fails.
#
# See trust-context-model-2026-05-25.md §16 (N2).
# Witness (RUST-UNIT, ndn-security, tests/trust_context_phase1.rs):
#   - ctx13_self_cert_rooted_context_validates
#
# Expected before Phase 2: FAIL (exit 1). After Phase 2: exit 0.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo missing" >&2; exit 2; }

if cargo test -p ndn-security --test trust_context_phase1 --quiet -- \
        ctx13_self_cert_rooted_context_validates \
        >/tmp/ctx13_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx13_witness.log; then
    echo "=== CTX.13 PASS — self-cert-rooted context validates, squat-proof ==="
    grep -E "test result|running" /tmp/ctx13_witness.log | tail -n 2
    exit 0
else
    echo "=== CTX.13 FAIL — self-certifying context path broken ==="
    cat /tmp/ctx13_witness.log
    exit 1
fi
