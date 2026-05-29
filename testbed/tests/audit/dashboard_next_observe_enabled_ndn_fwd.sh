#!/usr/bin/env bash
# Witness — ndn-dashboard-next Observe live traces for local ndn-fwd.
#
# Boots a local ndn-fwd with the NDN-native span publisher enabled and
# verifies dashboard-next can fetch /recent, fetch span Data, decode OTLP,
# and list at least one trace.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if ! cargo build -p ndn-fwd --quiet >/tmp/dashboard_next_observe_enabled_build.log 2>&1; then
    echo "FAIL: could not build ndn-fwd for Observe enabled witness" >&2
    cat /tmp/dashboard_next_observe_enabled_build.log >&2
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
cat >"$WORK/ndn-fwd-dashboard-next-observe-enabled.toml" <<EOF
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
publish_to_ndn = true
ndn_prefix = "/localhost/nfd/observability"
sample = 1.0
max_spans = 256

[logging]
level = "info"
EOF

RUST_LOG=info "$REPO_ROOT/target/debug/ndn-fwd" -c "$WORK/ndn-fwd-dashboard-next-observe-enabled.toml" \
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
        desktop_live_ndn_fwd_observability_enabled_lists_traces --quiet -- --ignored \
        >/tmp/dashboard_next_observe_enabled.log 2>&1; then
    cat /tmp/dashboard_next_observe_enabled.log
    echo "=== dashboard-next PASS — Observe enabled live traces witnessed ==="
    exit 0
fi

echo "FAIL: dashboard-next Observe enabled witness failed" >&2
cat /tmp/dashboard_next_observe_enabled.log >&2
echo "--- ndn-fwd log ---" >&2
cat "$WORK/ndn-fwd.log" >&2
exit 1
