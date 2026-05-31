#!/usr/bin/env bash
# Witness — CTX.02a: per-namespace validation dispatch (TrustContext keyring).
#
# A node holding a keyring of trust contexts validates a Data/command only
# against the context selected by the *data name's* namespace (longest-prefix
# match) — never "any anchor I hold." So `/home/bob` Data signed by a `/work`
# key is rejected (the `/work` anchor is not in the `/home/bob` context), while
# each namespace still validates correctly under its own context.
#
# See .claude/notes/trust-context/trust-context-model-2026-05-25.md §15 (D2),
# §16 (N1). Closes the cross-context-forgery half of skeleton-key (NFD #2856).
#
# Witnesses (RUST-UNIT, ndn-security, tests/trust_context_phase1.rs):
#   - ctx02_multi_context_keyring_validates_each
#   - ctx02a_cross_namespace_forgery_rejected
#
# Expected today: FAIL (exit 1) — no Keyring / per-namespace dispatch exists.
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
        ctx02_multi_context_keyring_validates_each \
        ctx02a_cross_namespace_forgery_rejected \
        >/tmp/ctx02a_witness.log 2>&1 && grep -qE "result: ok\. [1-9]" /tmp/ctx02a_witness.log; then
    echo "=== CTX.02a PASS — per-namespace dispatch rejects cross-context forgery ==="
    grep -E "test result|running" /tmp/ctx02a_witness.log | tail -n 3
    exit 0
else
    echo "=== CTX.02a FAIL — cross-namespace forgery not rejected by dispatch ==="
    cat /tmp/ctx02a_witness.log
    exit 1
fi
