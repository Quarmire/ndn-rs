#!/usr/bin/env bash
# wasm_phase1_compare.sh — measure spawn overhead introduced by ndn-runtime WASM abstraction.
#
# Runs the spawn_overhead criterion bench group from ndn-engine/benches/pipeline.rs.
# Compares:
#   spawn_concrete      — direct tokio::spawn(concrete_future) — "before" baseline
#   spawn_boxed         — tokio::spawn(Box::pin(concrete_future)) — "after" state
#   runtime_trait_boxed — TokioRuntime::spawn(Box::pin(...)) — after + vtable dispatch
#
# See docs/notes/wasm-phase1-bench-methodology-2026-05-08.md for design rationale.
#
# Usage: bash testbed/bench/wasm_phase1_compare.sh [--save-baseline <name>] [--baseline <name>]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-${REPO_ROOT}/docs/notes}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
OUT="${RESULTS_DIR}/wasm-phase1-bench-raw-${TIMESTAMP}.txt"

BASELINE_SAVE=""
BASELINE_CMP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --save-baseline) BASELINE_SAVE="$2"; shift 2 ;;
        --baseline)      BASELINE_CMP="$2";  shift 2 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

echo "=== wasm_phase1_compare — ${TIMESTAMP} ===" | tee "${OUT}"
echo "Repo: ${REPO_ROOT}" | tee -a "${OUT}"
echo "" | tee -a "${OUT}"

# ── Environment ───────────────────────────────────────────────────────────────
echo "=== environment ===" | tee -a "${OUT}"
uname -srm | tee -a "${OUT}"
if command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null | tee -a "${OUT}" || true
    sysctl -n hw.physicalcpu hw.logicalcpu 2>/dev/null | tee -a "${OUT}" || true
fi
if [[ -r /proc/cpuinfo ]]; then
    grep "model name" /proc/cpuinfo | head -1 | tee -a "${OUT}" || true
fi

LOAD=$(uptime | grep -oE 'load averages?: [0-9.]+' | grep -oE '[0-9.]+$' || echo "0")
if awk "BEGIN{exit !($LOAD > 1.0)}"; then
    echo "WARNING: system load average ${LOAD} > 1.0 — results may have high variance" | tee -a "${OUT}"
fi

# Frequency governor (Linux only; skips gracefully on macOS)
GOV_PATH="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
if [[ -w "${GOV_PATH}" ]]; then
    echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null 2>&1 || true
    echo "CPU governor set to performance" | tee -a "${OUT}"
fi
echo "" | tee -a "${OUT}"

# ── Build ─────────────────────────────────────────────────────────────────────
echo "=== build ===" | tee -a "${OUT}"
cd "${REPO_ROOT}"
RUSTFLAGS="-C target-cpu=native" cargo build --release -p ndn-engine 2>&1 | tail -5 | tee -a "${OUT}"
echo "" | tee -a "${OUT}"

# ── Bench ─────────────────────────────────────────────────────────────────────
BENCH_ARGS=(
    -p ndn-engine
    --bench pipeline
    --
    spawn_overhead
)

if [[ -n "${BASELINE_SAVE}" ]]; then
    BENCH_ARGS+=(--save-baseline "${BASELINE_SAVE}")
fi
if [[ -n "${BASELINE_CMP}" ]]; then
    BENCH_ARGS+=(--baseline "${BASELINE_CMP}")
fi

echo "=== criterion run ===" | tee -a "${OUT}"
echo "Command: RUSTFLAGS=-C target-cpu=native cargo bench ${BENCH_ARGS[*]}" | tee -a "${OUT}"
echo "" | tee -a "${OUT}"

RUSTFLAGS="-C target-cpu=native" cargo bench "${BENCH_ARGS[@]}" 2>&1 | tee -a "${OUT}"

echo "" | tee -a "${OUT}"
echo "Raw output: ${OUT}" | tee -a "${OUT}"
echo "Criterion HTML: ${REPO_ROOT}/target/criterion/spawn_overhead/" | tee -a "${OUT}"
