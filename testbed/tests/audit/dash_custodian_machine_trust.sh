#!/usr/bin/env bash
# Witness — the dashboard's machine-trust surfacing is backed by the canonical
# ndn-custodian CustodianRef, not ad-hoc inference.
#
# After extracting the wasm-safe ndn-custodian crate, the dashboard depends on
# it (native + wasm) and derives "where the signing key lives" + per-action
# prompting from CustodianRef's key_on_this_machine / prompts_per_action. This
# witness locks:
#   1. The dashboard depends on ndn-custodian.
#   2. engine_pill derives machine-trust from CustodianRef.
#   3. The machine-trust + custodian-ref unit tests pass.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

DASH="crates/tooling/ndn-dashboard"

if ! grep -q '^ndn-custodian' "$DASH/Cargo.toml"; then
    echo "FAIL: dashboard does not depend on ndn-custodian" >&2
    exit 1
fi
if ! grep -q 'CustodianRef' "$DASH/src/views/engine_pill.rs"; then
    echo "FAIL: machine-trust is not derived from CustodianRef" >&2
    exit 1
fi

if cargo test -p ndn-dashboard --bins -q machine_trust >/tmp/dash_ct.log 2>&1 \
   && cargo test -p ndn-custodian -q ref_tests >>/tmp/dash_ct.log 2>&1; then
    echo "ok: dashboard machine-trust backed by CustodianRef"
else
    echo "FAIL: machine-trust / custodian-ref unit tests failed" >&2
    cat /tmp/dash_ct.log >&2
    exit 1
fi
