#!/usr/bin/env bash
# Witness: ndn-packet (and the no_std crate chain that depends on it) builds
# for `riscv32imc-unknown-none-elf` when `portable-atomic` is enabled.
#
# Severity:   BLOCKER for embedded forwarder targets (ESP32-C3, RP2040,
#             nRF51, MSP430, AVR — anything without atomic CAS in hardware).
# Reference:  examples/ble/esp32c3 (currently a draft scaffold that has
#             never built end-to-end on disk).
#
# Background: `ndn-packet` uses `alloc::sync::Arc` in its no_std path. On
# targets without the RISC-V A extension (or ARM v6m, etc.) `alloc::sync`
# is gated out by `cfg(target_has_atomic = "ptr")` and Arc is unavailable.
# `bytes` has the same issue and is solved by `bytes/extra-platforms` which
# routes through `portable-atomic`. For Arc itself we need
# `portable-atomic-util::Arc`.
#
# Expected today: FAIL (exit 1) — ndn-packet has no `portable-atomic` feature.
# After the refactor: PASS (exit 0).
#
# Exit codes:
#   0 — PASS  (target build clean)
#   1 — FAIL  (target build error)
#   2 — SKIP  (rustup target not installed)

set -euo pipefail

TARGET="riscv32imc-unknown-none-elf"

if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}\$"; then
    echo "SKIP: rustup target '$TARGET' not installed — run 'rustup target add ${TARGET}'" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# Single combined check; cheaper than building each crate independently because
# the lower crates compile once and get reused.
CARGO_FLAGS=(
    --target "$TARGET"
    --no-default-features
    --features portable-atomic
    -p ndn-packet
    -p ndn-tlv
    -p ndn-foundation-types
    -p ndn-embedded
)

# `portable-atomic` requires a CAS polyfill choice. The ESP32-C3 is genuinely
# single-core, so `unsafe-assume-single-core` is correct and overhead-free.
# Equivalent to setting this in the binary crate's .cargo/config.toml — the
# witness has no config of its own so we pass it on the command line.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg=portable_atomic_unsafe_assume_single_core"

if cargo build "${CARGO_FLAGS[@]}" 2>&1; then
    echo "PASS: ndn-packet et al. build clean on $TARGET with portable-atomic"
    exit 0
else
    echo "FAIL: target build did not succeed; see error above"
    exit 1
fi
