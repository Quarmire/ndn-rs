#!/usr/bin/env bash
# Witness — CTX.02b: skeleton-key authorization (NFD #2856, open since 2015).
#
# A certificate valid under a context's anchor cannot sign data *outside its
# own subtree*, even with the context adopted. A hierarchical TrustContext
# enforces the `keyLocator.isPrefixOf(name)` floor (key identity ⊑ data name)
# in addition to the schema, so a leaf key `/home/bob/alice/KEY/..` may sign
# `/home/bob/alice/...` but not `/home/bob/charlie/...`.
#
# See trust-context-model-2026-05-25.md §16 (N1). The Sydney-incident enforcer
# NFD never shipped because ValidatorConfig couldn't drill into command params.
#
# Witnesses (RUST-UNIT, ndn-security, tests/trust_context_phase1.rs):
#   - ctx02b_hierarchical_floor_allows_own_subtree
#   - ctx02b_skeleton_key_no_sign_outside_subtree
#
# Expected today: FAIL (exit 1) — no hierarchy floor exists; the loose
# first-component hierarchical schema admits cross-subtree signing.
# After Phase 1: exit 0 without script changes.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-security --test trust_context_phase1 --quiet -- \
        ctx02b_hierarchical_floor_allows_own_subtree \
        ctx02b_skeleton_key_no_sign_outside_subtree \
        >/tmp/ctx02b_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx02b_witness.log; then
    echo "=== CTX.02b PASS — hierarchical floor blocks cross-subtree signing ==="
    grep -E "test result|running" /tmp/ctx02b_witness.log | tail -n 3
    exit 0
else
    echo "=== CTX.02b FAIL — skeleton-key: cert signs outside its subtree ==="
    cat /tmp/ctx02b_witness.log
    exit 1
fi
