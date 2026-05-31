#!/usr/bin/env bash
# Witness test for audit finding G.03 — PSync live C++ interop.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.03
# Severity:    BLOCKED-BY-INTEROP (this script discharges the marker when it exits 0)
# Spec ref:    PSync/PSync/full-producer.{hpp,cpp}, consumer.{hpp,cpp}
# Witnesses:   A C++ PSync FullProducer and a Rust Consumer converge on N
#              item inserts in a shared NFD topology.
#
# Exit codes:
#   0 — PASS (live convergence witnessed)
#   1 — FAIL or prerequisites not met
#   2 — SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
if [[ "${G03_IN_CONTAINER:-0}" == "1" ]]; then
    TRANSCRIPT_DIR="/results/audit/transcripts"
else
    TRANSCRIPT_DIR="$(dirname "$0")/transcripts"
fi
mkdir -p "$TRANSCRIPT_DIR"

COMPOSE="${COMPOSE:-docker compose -f testbed/docker-compose.yml}"

if [[ "${G03_IN_CONTAINER:-0}" != "1" ]] && command -v docker >/dev/null 2>&1; then
    cd "$REPO_ROOT"
    if $COMPOSE up -d --build nfd interop >/tmp/g03_compose_up.log 2>&1; then
        exec $COMPOSE exec -T \
            -e G03_IN_CONTAINER=1 \
            -e NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}" \
            -e COUNT="${COUNT:-5}" \
            -e TIMEOUT="${TIMEOUT:-70}" \
            interop bash /testbed/tests/audit/g03_psync_interop.sh
    else
        echo "SKIP: docker interop service unavailable" >&2
        cat /tmp/g03_compose_up.log >&2
        exit 2
    fi
fi

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
if [ ! -S "$NFD_SOCK" ]; then
    echo "SKIP: NFD socket not found at $NFD_SOCK (is NFD running?)" >&2
    exit 2
fi

CPP_MODE="deterministic"
if command -v psync-deterministic-producer >/dev/null 2>&1; then
    CPP_PRODUCER="$(command -v psync-deterministic-producer)"
elif command -v psync-full-sync >/dev/null 2>&1; then
    CPP_PRODUCER="$(command -v psync-full-sync)"
    CPP_MODE="upstream-random"
else
    PSYNC_SRC="${PSYNC_SRC:-$HOME/Documents/Dev/PSync}"
    if [ ! -d "$PSYNC_SRC" ]; then
        echo "SKIP: PSync source not found at $PSYNC_SRC and psync-full-sync not in PATH" >&2
        exit 2
    fi
    if [ ! -x "$PSYNC_SRC/waf" ]; then
        echo "SKIP: PSync waf script not found at $PSYNC_SRC/waf" >&2
        exit 2
    fi
    PSYNC_BUILD="$PSYNC_SRC/build"
    JOBS="$(command -v nproc >/dev/null 2>&1 && nproc || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
    (
        cd "$PSYNC_SRC"
        ./waf configure --with-examples 2>&1 | tail -5
        ./waf build -j"$JOBS" 2>&1 | tail -5
    ) || { echo "FAIL: C++ PSync examples failed to build" >&2; exit 1; }

    CPP_PRODUCER="$PSYNC_BUILD/examples/psync-full-sync"
    CPP_MODE="upstream-random"
    if [ ! -x "$CPP_PRODUCER" ]; then
        echo "FAIL: C++ psync-full-sync binary not found" >&2; exit 1
    fi
fi

if command -v ndn-psync-consumer >/dev/null 2>&1; then
    RUST_PSYNC_CONSUMER="$(command -v ndn-psync-consumer)"
else
    if ! command -v cargo >/dev/null 2>&1; then
        echo "SKIP: cargo missing and ndn-psync-consumer not in PATH" >&2
        exit 2
    fi
    if ! cargo build -p ndn-tools --bin ndn-psync-consumer --quiet \
            >/tmp/g03_rust_build.log 2>&1; then
        echo "FAIL: ndn-psync-consumer build failed" >&2
        cat /tmp/g03_rust_build.log
        exit 1
    fi
    RUST_PSYNC_CONSUMER="$REPO_ROOT/target/debug/ndn-psync-consumer"
fi

SYNC_PREFIX="/ndn/audit/g03/psync/$(date +%s)"
USER_PREFIX="/ndn/audit/g03/user"
COUNT="${COUNT:-5}"
TIMEOUT="${TIMEOUT:-70}"

echo "Starting C++ FullProducer (${CPP_MODE}) …"
if [[ "$CPP_MODE" == "deterministic" ]]; then
    "$CPP_PRODUCER" "$SYNC_PREFIX" "$USER_PREFIX" "$COUNT" 1500 250 \
        >"$TRANSCRIPT_DIR/g03_psync_cpp_full_sync.txt" 2>&1 &
else
    "$CPP_PRODUCER" "$SYNC_PREFIX" "$USER_PREFIX" "$COUNT" 1 \
    >"$TRANSCRIPT_DIR/g03_psync_cpp_full_sync.txt" 2>&1 &
fi
CPP_PID=$!
trap 'kill $CPP_PID 2>/dev/null || true; wait $CPP_PID 2>/dev/null || true' EXIT
sleep 1

echo "Starting Rust PSync consumer …"
if "$RUST_PSYNC_CONSUMER" "$SYNC_PREFIX" \
        --face-socket "$NFD_SOCK" \
        --count "$COUNT" \
        --timeout "$TIMEOUT" \
        --interval-ms 500 \
        >"$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt" 2>&1; then
    observed="$(wc -l <"$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt" | tr -d ' ')"
    if [ "$observed" -lt "$COUNT" ]; then
        echo "FAIL: Rust consumer observed $observed/$COUNT updates" >&2
        cat "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt"
        exit 1
    fi
    distinct="$(sort -u "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt" | wc -l | tr -d ' ')"
    if [ "$distinct" -lt "$COUNT" ]; then
        echo "FAIL: Rust consumer observed only $distinct/$COUNT distinct updates" >&2
        cat "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt"
        exit 1
    fi
    for i in $(seq 0 $((COUNT - 1))); do
        if ! grep -F "/ndn/audit/g03/user-${i}/" \
                "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt" >/dev/null; then
            echo "FAIL: Rust consumer missed deterministic update /ndn/audit/g03/user-${i}/" >&2
            cat "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt"
            exit 1
        fi
    done
    echo "=== G.03 PASS — Rust PSync consumer converged with C++ FullProducer ==="
    exit 0
else
    echo "FAIL: Rust PSync consumer did not converge" >&2
    cat "$TRANSCRIPT_DIR/g03_psync_rust_consumer.txt"
    echo "--- C++ full-sync log ---" >&2
    cat "$TRANSCRIPT_DIR/g03_psync_cpp_full_sync.txt" >&2
    exit 1
fi
