#!/usr/bin/env bash
# Witness — ndn-dashboard-next desktop attach contract for local ndn-fwd.
#
# This witness first locks the dashboard-next attach normalization contract,
# then boots a local ndn-fwd and runs the ignored live socket witness against
# its NFD-compatible management datasets.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if cargo test -p ndn-dashboard-next --test attach_witnesses \
    desktop_attach_witness_normalizes_local_ndn_fwd_profile --quiet \
    >/tmp/dashboard_next_desktop_attach.log 2>&1; then
    cat /tmp/dashboard_next_desktop_attach.log
    echo "ok: dashboard-next desktop attach contract"
else
    echo "FAIL: dashboard-next desktop attach contract witness failed" >&2
    cat /tmp/dashboard_next_desktop_attach.log >&2
    exit 1
fi

if ! cargo build -p ndn-fwd --quiet >/tmp/dashboard_next_ndn_fwd_build.log 2>&1; then
    echo "FAIL: could not build ndn-fwd for live desktop attach witness" >&2
    cat /tmp/dashboard_next_ndn_fwd_build.log >&2
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() {
    if [ -n "${FWD_PID:-}" ]; then
        kill "$FWD_PID" 2>/dev/null || true
        wait "$FWD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

FWD_SOCK="$WORK/ndn-fwd.sock"
cat >"$WORK/ndn-fwd-dashboard-next.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[management]
face_socket = "$FWD_SOCK"

[logging]
level = "warn"
EOF

RUST_LOG=warn "$REPO_ROOT/target/debug/ndn-fwd" -c "$WORK/ndn-fwd-dashboard-next.toml" \
    >"$WORK/ndn-fwd.log" 2>&1 &
FWD_PID=$!

for _ in $(seq 1 50); do
    [ -S "$FWD_SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$FWD_SOCK" ]; then
    echo "FAIL: ndn-fwd socket did not appear" >&2
    cat "$WORK/ndn-fwd.log" >&2
    exit 1
fi

if NDN_DASHBOARD_NEXT_LIVE_NDN_FWD_SOCK="$FWD_SOCK" \
    cargo test -p ndn-dashboard-next --test attach_witnesses \
        desktop_live_ndn_fwd_socket_answers_management_probe --quiet -- --ignored \
        >/tmp/dashboard_next_desktop_live_attach.log 2>&1; then
    cat /tmp/dashboard_next_desktop_live_attach.log
    echo "=== dashboard-next PASS — desktop local ndn-fwd live attach witnessed ==="
    exit 0
fi

echo "FAIL: dashboard-next desktop live attach witness failed" >&2
cat /tmp/dashboard_next_desktop_live_attach.log >&2
echo "--- ndn-fwd log ---" >&2
cat "$WORK/ndn-fwd.log" >&2
exit 1
