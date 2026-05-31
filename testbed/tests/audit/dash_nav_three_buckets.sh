#!/usr/bin/env bash
# Witness — ndn-dashboard three-bucket nav skeleton (synthesis note §8).
#
# The flat sidebar `View` list is regrouped under three top-level buckets —
# Engine / Identity / Compose — that split "operating an engine" from "managing
# my identity" from "what I publish". This witness locks:
#   1. The Bucket enum + consistent View<->Bucket mapping (unit tests).
#   2. Both the desktop and the web shell render grouped buckets, not a flat
#      `View::NAV` list (grep-proof — `View::NAV` must be gone).
#
# Pre-change this exits 1 (no `Bucket`, sidebar iterates `View::NAV`).
# Post-change it exits 0.
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

# 1. The flat nav must be gone from both shells.
if grep -rn 'View::NAV' "$DASH" >/tmp/dash_nav_flat.log 2>&1; then
    echo "FAIL: flat View::NAV still rendered — sidebar is not bucketed:" >&2
    cat /tmp/dash_nav_flat.log >&2
    exit 1
fi

# 2. Both shells iterate the three buckets.
for f in app.rs app_web.rs; do
    if ! grep -q 'Bucket::ALL' "$DASH/$f"; then
        echo "FAIL: $f does not render grouped Bucket::ALL nav" >&2
        exit 1
    fi
done

# 3. The Bucket enum + mapping is structurally consistent (unit tests).
if cargo test -p ndn-dashboard --bins nav_tests --quiet \
    >/tmp/dash_nav_tests.log 2>&1; then
    cat /tmp/dash_nav_tests.log
    echo "ok: three-bucket nav skeleton (Engine / Identity / Compose)"
else
    echo "FAIL: nav bucket unit tests failed" >&2
    cat /tmp/dash_nav_tests.log >&2
    exit 1
fi
