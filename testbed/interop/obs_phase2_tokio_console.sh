#!/usr/bin/env bash
# INTEROP-SCRIPT witness: obs_phase2_tokio_console
#
# Verifies the tokio-console feature end-to-end:
#   1. ndn-fwd --features console --profile console builds (console-subscriber linked)
#   2. The binary starts and the console-subscriber gRPC server responds
#   3. The long-lived task span names from phase-2 are compiled into the binary
#
# Step (3) uses `strings` over the binary — a lightweight proxy for "the span
# literals exist at runtime".  Step (2) confirms the gRPC port is open (not just
# that the binary runs), which proves console-subscriber is actually serving.
#
# Exit 0 = all checks pass; exit 1 = any check fails.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

CONSOLE_PORT="${TOKIO_CONSOLE_PORT:-16669}"   # avoid clash with running consoles
CONSOLE_BIND="127.0.0.1:${CONSOLE_PORT}"

FWD_BIN="$REPO_ROOT/target/console/ndn-fwd"
FWD_PID=""
PASS=0
FAIL=0

cleanup() {
    if [[ -n "$FWD_PID" ]]; then
        kill "$FWD_PID" 2>/dev/null || true
        wait "$FWD_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

check() {
    local label="$1" ok="$2"
    if [[ "$ok" == "1" ]]; then
        echo "PASS  $label"; PASS=$((PASS + 1))
    else
        echo "FAIL  $label"; FAIL=$((FAIL + 1))
    fi
}

echo "=== obs_phase2_tokio_console — live attach witness ==="

# ── Step 1: build ─────────────────────────────────────────────────────────────
echo "[1/3] Building ndn-fwd --features console --profile console ..."
BUILD_OK=0
if RUSTFLAGS="--cfg tokio_unstable" \
   cargo build -p ndn-fwd --features console --profile console \
   --manifest-path "$REPO_ROOT/Cargo.toml" 2>&1 | grep -E "Finished|error"; then
    BUILD_OK=1
fi
if [[ "$BUILD_OK" == "1" ]] && [[ -x "$FWD_BIN" ]]; then
    check "ndn-fwd console build" "1"
else
    check "ndn-fwd console build" "0"
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# ── Step 2: verify span name literals embedded in binary ─────────────────────
echo "[2/3] Verifying task span names in binary ..."
for name in engine_task pipeline_dispatch face_write face_read expiry nlsr_sync nlsr_recompute; do
    if grep -qaF "$name" "$FWD_BIN"; then
        check "span name '$name' in binary" "1"
    else
        check "span name '$name' in binary" "0"
    fi
done

# ── Step 3: start and verify gRPC server responds ─────────────────────────────
echo "[3/3] Starting ndn-fwd and verifying console gRPC port ..."
TOKIO_CONSOLE_BIND="$CONSOLE_BIND" \
    RUST_LOG=error \
    "$FWD_BIN" &
FWD_PID=$!

# Wait up to 5 seconds for the gRPC server to bind.
GRPC_UP=0
for i in $(seq 1 10); do
    sleep 0.5
    if nc -z 127.0.0.1 "$CONSOLE_PORT" 2>/dev/null; then
        GRPC_UP=1
        break
    fi
done
check "console-subscriber gRPC port open ($CONSOLE_BIND)" "$GRPC_UP"

echo ""
echo "Results: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
