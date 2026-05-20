#!/usr/bin/env bash
# Witness recipe for ARCH-8 (validation half) / S13 — composable
# `ValidationPolicy` with first-Deny `ChainedPolicy`.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-8
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:   `ValidationPolicy` exists with the four prescribed
#              built-ins (`AcceptAllPolicy`, `HierarchicalPolicy`,
#              `LvsPolicy`, `ChainedPolicy`); `ChainedPolicy` is
#              **first-Deny** — a Data that passes one member and
#              fails another is denied; `NeedCert` propagates
#              through the chain; `PolicyVerdict::Allow / Deny /
#              NeedCert` are the only verdicts. Mirrors ndn-cxx
#              `policy-config-file.cpp` evaluation order (Phase 2
#              design sign-off §3).
#
# Reverify recipe: RUST-UNIT. Runs the targeted ndn-security
# validation-policy test cases; no Docker, no toolchain beyond
# cargo.
#
# Exit codes:
#   0 — PASS (every variant + chain semantics as designed)
#   1 — FAIL (one or more cases regressed)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

TESTS=(
    "accept_all_always_allows"
    "hierarchical_allows_same_namespace"
    "hierarchical_denies_cross_namespace"
    "chained_first_deny_short_circuits"
    "chained_empty_allows"
    "chained_propagates_need_cert"
)

fail=0
for t in "${TESTS[@]}"; do
    echo "→ cargo test -p ndn-security --lib validation_policy::tests::${t}"
    if ! cargo test --quiet -p ndn-security --lib "validation_policy::tests::${t}" \
            -- --exact >/dev/null 2>&1; then
        echo "FAIL: validation_policy::tests::${t}" >&2
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-8 (validation) — ValidationPolicy composes; ChainedPolicy is first-Deny."
fi
exit "$fail"
