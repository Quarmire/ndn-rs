#!/usr/bin/env bash
# Regression guard for D.12 dev-mode (validator_enabled = false).
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.12
# Severity:    RESOLVED 2026-05-08
#
# Confirms that the disabled-validator permissive path still sets
# ctx.verified=true so Data reaches the CS in dev/lab setups.
# This is covered by d12_disabled_validator_sets_verified in the
# RUST-UNIT witness; this script is an alias entry point.
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

if cargo test -p ndn-engine --lib --quiet d12_disabled_validator_sets_verified \
        >/tmp/d12_devmode.log 2>&1; then
    echo "ok: dev-mode disabled-validator path sets verified=true (CS admission works)"
else
    echo "FAIL: dev-mode regression"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.12 dev-mode smoke PASS — validator_enabled=false does not break CS admission ==="
    exit 0
else
    echo
    echo "=== D.12 dev-mode smoke FAIL ==="
    cat /tmp/d12_devmode.log
    exit 1
fi
