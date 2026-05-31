#!/usr/bin/env bash
# Witness — ndn-dashboard right-hand inspector pane (design note §3, Eagle spine).
#
# The master-detail shell's third pane: selecting an entity in the center table
# shows its full detail in a right-hand inspector. Slice 3 pilots Faces — the
# Overview Active Faces table feeds the pane. This witness locks:
#   1. The SelectedEntity view-model + Inspector module exist.
#   2. Both shells mount the Inspector inside a content-host flex row.
#   3. The Overview faces table sets SELECTED_ENTITY on row click.
#   4. The inspector unit tests pass.
#
# Pre-change exits 1 (no inspector module / pane). Post-change exits 0.
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

if [ ! -f "$DASH/views/inspector.rs" ]; then
    echo "FAIL: inspector module missing" >&2
    exit 1
fi

# Both shells mount the Inspector in a content-host.
for f in app.rs app_web.rs; do
    if ! grep -q 'inspector::Inspector' "$DASH/$f"; then
        echo "FAIL: $f does not mount the Inspector pane" >&2
        exit 1
    fi
    if ! grep -q 'content-host' "$DASH/$f"; then
        echo "FAIL: $f does not wrap content + inspector in a content-host" >&2
        exit 1
    fi
done

# The Overview faces table feeds the selection.
if ! grep -q 'SELECTED_ENTITY' "$DASH/views/overview.rs"; then
    echo "FAIL: overview faces table does not set SELECTED_ENTITY on click" >&2
    exit 1
fi

if cargo test -p ndn-dashboard --bins inspector --quiet \
    >/tmp/dash_inspector_tests.log 2>&1; then
    cat /tmp/dash_inspector_tests.log
    echo "ok: right-hand inspector pane (Faces pilot)"
else
    echo "FAIL: inspector unit tests failed" >&2
    cat /tmp/dash_inspector_tests.log >&2
    exit 1
fi
