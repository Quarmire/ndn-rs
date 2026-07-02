#!/usr/bin/env bash
# Witness — ndn-dashboard-next Observe disabled guidance for local ndn-fwd.
#
# Boots a local ndn-fwd with the NDN-native span publisher disabled and
# verifies dashboard-next renders an actionable disabled Observe state.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if ! cargo build -p ndn-fwd --quiet >/tmp/dashboard_next_observe_disabled_build.log 2>&1; then
    echo "FAIL: could not build ndn-fwd for Observe disabled witness" >&2
    cat /tmp/dashboard_next_observe_disabled_build.log >&2
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
cat >"$WORK/ndn-fwd-dashboard-next-observe-disabled.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[management]
face_socket = "$FWD_SOCK"

[observability]
publish_to_ndn = false

[logging]
level = "warn"
EOF

RUST_LOG=warn "$REPO_ROOT/target/debug/ndn-fwd" -c "$WORK/ndn-fwd-dashboard-next-observe-disabled.toml" \
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
    cargo test -p ndn-dashboard-next --test observe_witnesses \
        desktop_live_ndn_fwd_observability_disabled_shows_guidance --quiet -- --ignored \
        >/tmp/dashboard_next_observe_disabled.log 2>&1; then
    cat /tmp/dashboard_next_observe_disabled.log
    echo "=== dashboard-next PASS — Observe disabled guidance witnessed ==="
    exit 0
fi

echo "FAIL: dashboard-next Observe disabled witness failed" >&2
cat /tmp/dashboard_next_observe_disabled.log >&2
echo "--- ndn-fwd log ---" >&2
cat "$WORK/ndn-fwd.log" >&2
exit 1
