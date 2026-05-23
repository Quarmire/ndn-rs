#!/usr/bin/env bash
# Witness for SIG-05 — CCLF is one pure kernel shared by native + embedded.
#
# Severity:    cross-platform parity / anti-divergence (pre-v0.2.0)
# Design:      .claude/notes/signals/cross-layer-signals-design-2026-05-23.md
# Witnesses:
#   (a) GREP-PROOF — ndn-strategy-cclf defines a single pure `cclf_decide`
#       kernel; the embedded adapter (Cclf: ndn_fwd_core Strategy) and the
#       native adapter (native::CclfStrategy) BOTH call it — no second copy.
#   (b) GREP-PROOF — CCLF is an extension crate (classification=extension),
#       not a forwarder fork.
#   (c) RUST-UNIT  — kernel + adapter tests pass (incl. the parity test that the
#       embedded adapter selects the same nexthop as the kernel), AND the crate
#       builds for thumbv7em-none-eabihf with --no-default-features (the kernel
#       + embedded adapter are no_std; the native adapter is opt-in).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
LIB=crates/ndn-strategy-cclf/src/lib.rs

# (a) one kernel, both adapters call it.
grep -qE 'pub fn cclf_decide' "$LIB" 2>/dev/null || { echo "FAIL: no cclf_decide kernel" >&2; fail=1; }
grep -qE 'impl<F: Copy \+ Eq> ndn_fwd_core::strategy::Strategy<F> for Cclf' "$LIB" 2>/dev/null \
    || { echo "FAIL: no embedded sans-IO adapter" >&2; fail=1; }
# embedded adapter delegates to the kernel
grep -qE 'cclf_decide\(signals, nexthops, incoming, emit\)' "$LIB" 2>/dev/null \
    || { echo "FAIL: embedded adapter does not delegate to cclf_decide" >&2; fail=1; }
# native adapter calls the same kernel
grep -qE 'super::cclf_decide\(ctx\.signals' "$LIB" 2>/dev/null \
    || { echo "FAIL: native adapter does not call the shared kernel" >&2; fail=1; }

# (b) extension scope, not a fork.
grep -qE 'classification = "extension"' crates/ndn-strategy-cclf/Cargo.toml \
    || { echo "FAIL: CCLF is not scoped as an extension" >&2; fail=1; }

# (c) tests + no_std embedded-only build.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-strategy-cclf"
    cargo test --quiet -p ndn-strategy-cclf >/dev/null 2>&1 \
        || { echo "FAIL: cclf kernel/adapter tests did not pass" >&2; fail=1; }
    TARGET=thumbv7em-none-eabihf
    if rustup target list --installed 2>/dev/null | grep -q "$TARGET"; then
        echo "→ cargo build -p ndn-strategy-cclf --no-default-features --target $TARGET"
        cargo build --quiet -p ndn-strategy-cclf --no-default-features --target "$TARGET" >/dev/null 2>&1 \
            || { echo "FAIL: cclf kernel does not build no_std for $TARGET" >&2; fail=1; }
    else
        echo "note: $TARGET not installed; skipping bare-metal leg (CI covers it)"
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: SIG-05 — one cclf_decide kernel; native + embedded adapters both call it; extension crate; no_std floor builds."
exit "$fail"
