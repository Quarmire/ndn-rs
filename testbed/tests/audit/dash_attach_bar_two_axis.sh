#!/usr/bin/env bash
# Witness — ndn-dashboard two-axis Attach bar (synthesis note §8).
#
# The Connection bar becomes an Attach bar with two independent axes — the
# Engine you operate and the identity you're Acting as — both fed by the
# reusable identity_axis view-model. This witness locks:
#   1. The IdentityAxis view-model + light-touch single/multi logic (unit tests).
#   2. Both shells render the Engine axis label and the IdentityAxisControl
#      (grep-proof) rather than the bare IdentityChip.
#
# Pre-change exits 1 (no identity_axis module, bars render IdentityChip
# directly). Post-change exits 0.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

DASH="crates/tooling/ndn-dashboard/src"

# 1. The reusable view-model module exists.
if [ ! -f "$DASH/identity_axis.rs" ]; then
    echo "FAIL: identity_axis view-model module missing" >&2
    exit 1
fi

# 2. Both shells render the IdentityAxisControl (the Acting-as axis) and an
#    Engine axis label.
for f in app.rs app_web.rs; do
    if ! grep -q 'IdentityAxisControl' "$DASH/$f"; then
        echo "FAIL: $f does not render the IdentityAxisControl (Acting-as axis)" >&2
        exit 1
    fi
    if ! grep -q 'axis-label' "$DASH/$f"; then
        echo "FAIL: $f does not render an axis label (Engine axis framing)" >&2
        exit 1
    fi
done

# 3. The view-model logic is pinned by unit tests.
if cargo test -p ndn-dashboard --bins identity_axis --quiet \
    >/tmp/dash_attach_axis_tests.log 2>&1; then
    cat /tmp/dash_attach_axis_tests.log
    echo "ok: two-axis Attach bar (Engine / Acting-as) + identity_axis view-model"
else
    echo "FAIL: identity_axis unit tests failed" >&2
    cat /tmp/dash_attach_axis_tests.log >&2
    exit 1
fi
