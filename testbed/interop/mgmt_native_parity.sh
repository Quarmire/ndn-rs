#!/usr/bin/env bash
# Native counterpart to the wasm mgmt witness
# (`testbed/tests/browser/wasm_engine_mgmt_status.spec.ts`).
#
# Boots ndn-fwd unsigned-mode, then issues each verb the wasm spec
# issues via `ndn-ctl` over the management Unix socket and asserts
# the response shape matches the same parity contract:
#
#   ✓ status               → counters render (faces/fib/pit/cs)
#   ✓ faces/list           → ≥1 face entry on a freshly-booted fwd
#   ✓ fib/list             → /localhost/nfd present (mount_management
#                            installed it post-build)
#   ✓ rib/list             → well-formed (possibly empty)
#   ✓ strategy/list        → ≥1 entry (root default)
#
# This pins the "identical management surface across native and web"
# claim from the native side; the wasm side is pinned by
# wasm_engine_mgmt_status.spec.ts (6 cases).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TRANSCRIPT_DIR="$(dirname "$0")/transcripts"
mkdir -p "$TRANSCRIPT_DIR"

# ── Prerequisites ─────────────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

# Build required binaries if not already present.
if ! cargo build -p ndn-fwd -p ndn-tools --bins --quiet 2>/tmp/mgmt_parity_build.log; then
    echo "FAIL: build failed"
    cat /tmp/mgmt_parity_build.log
    exit 1
fi

NDN_FWD="$REPO_ROOT/target/debug/ndn-fwd"
NDN_CTL="$REPO_ROOT/target/debug/ndn-ctl"

WORK="$(mktemp -d)"
PASS=0
FAIL=0
FWD_PID=""

cleanup() {
    if [ -n "$FWD_PID" ]; then
        kill "$FWD_PID" 2>/dev/null || true
        wait "$FWD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── ndn-fwd config (dev mode, unsigned commands) ─────────────────────────────
FWD_SOCK="$WORK/ndn-fwd.sock"
cat >"$WORK/ndn-fwd.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb   = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[management]
face_socket = "$FWD_SOCK"

[logging]
level = "warn"
EOF

# ── Launch ndn-fwd ────────────────────────────────────────────────────────────
RUST_LOG=warn "$NDN_FWD" -c "$WORK/ndn-fwd.toml" \
    >"$TRANSCRIPT_DIR/mgmt_native_parity_fwd_stdout.txt" 2>&1 &
FWD_PID=$!

for _ in $(seq 1 50); do
    [ -S "$FWD_SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$FWD_SOCK" ]; then
    echo "FAIL: ndn-fwd socket did not appear"
    cat "$TRANSCRIPT_DIR/mgmt_native_parity_fwd_stdout.txt"
    exit 1
fi

check_pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
check_fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

run() { "$NDN_CTL" --socket "$FWD_SOCK" "$@"; }

# ── Case 1: status — counters render ─────────────────────────────────────────
echo "=== Case 1: status — counters render ==="
out="$(run status 2>&1)" || true
echo "$out" >"$TRANSCRIPT_DIR/mgmt_native_parity_status.txt"
if echo "$out" | grep -qE 'faces=[0-9]+'   && \
   echo "$out" | grep -qE 'fib=[0-9]+'     && \
   echo "$out" | grep -qE 'pit=[0-9]+'     && \
   echo "$out" | grep -qE 'cs=[0-9]+'; then
    check_pass "status reports faces/fib/pit/cs counters"
else
    check_fail "status output missing one or more counters:"
    echo "$out" | sed 's/^/    /'
fi
echo

# ── Case 2: faces/list — ≥1 entry ────────────────────────────────────────────
echo "=== Case 2: faces/list — ≥1 entry ==="
out="$(run face list 2>&1)" || true
echo "$out" >"$TRANSCRIPT_DIR/mgmt_native_parity_faces.txt"
# `ndn-ctl face list` prints one face per non-header line; require any
# line beginning with `id=` or `faceid=` (handles both renderers).
if echo "$out" | grep -qE '^\s*(id|faceid)='; then
    check_pass "faces/list returned ≥1 face entry"
else
    check_fail "faces/list produced no face entries:"
    echo "$out" | sed 's/^/    /'
fi
echo

# ── Case 3: fib/list — must include /localhost/nfd ───────────────────────────
echo "=== Case 3: fib/list includes /localhost/nfd ==="
out="$(run route list 2>&1)" || true
echo "$out" >"$TRANSCRIPT_DIR/mgmt_native_parity_fib.txt"
if echo "$out" | grep -q '/localhost/nfd'; then
    check_pass "fib/list contains /localhost/nfd (mount_management installed it)"
else
    check_fail "fib/list missing /localhost/nfd:"
    echo "$out" | sed 's/^/    /'
fi
if echo "$out" | grep -q '/localhop/nfd'; then
    check_pass "fib/list contains /localhop/nfd"
else
    check_fail "fib/list missing /localhop/nfd"
fi
echo

# ── Case 4: rib/list — well-formed (may be empty) ────────────────────────────
echo "=== Case 4: rib/list well-formed ==="
# ndn-ctl exposes rib via the same `route list` verb but the dataset
# distinction (FIB-from-rib vs RIB) is internal; what we assert here
# is that the command returns 0 even with an empty RIB.
if run route list >"$TRANSCRIPT_DIR/mgmt_native_parity_rib.txt" 2>&1; then
    check_pass "rib/list responded successfully (200)"
else
    check_fail "rib/list returned non-zero (route list failed)"
    cat "$TRANSCRIPT_DIR/mgmt_native_parity_rib.txt" | sed 's/^/    /'
fi
echo

# ── Case 5: strategy/list — ≥1 entry (root default) ──────────────────────────
echo "=== Case 5: strategy/list — ≥1 entry ==="
out="$(run strategy list 2>&1)" || true
echo "$out" >"$TRANSCRIPT_DIR/mgmt_native_parity_strategy.txt"
if echo "$out" | grep -qE '(best-route|multicast|/ndn/|strategy=)'; then
    check_pass "strategy/list returned ≥1 strategy choice"
else
    check_fail "strategy/list produced no entries:"
    echo "$out" | sed 's/^/    /'
fi
echo

# ── Summary ───────────────────────────────────────────────────────────────────
echo "Results: $PASS passed, $FAIL failed"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: native mgmt parity witness has failures"
    exit 1
fi

echo "=== mgmt-native-parity PASS — same surface as wasm witness ==="
exit 0
