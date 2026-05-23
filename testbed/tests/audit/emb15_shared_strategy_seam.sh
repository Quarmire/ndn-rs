#!/usr/bin/env bash
# Witness for EMB-15 — shared forwarding-strategy seam (step 4 first brick).
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md (strategy seam, step 4)
# Severity:    anti-divergence — strategies (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core defines a `Strategy` trait + BestRoute +
#       Multicast (zero-alloc, emit-via-callback), producing ForwardAction lists.
#   (b) GREP-PROOF — the embedded forwarder drives BestRoute through the seam
#       (decide -> action list -> enact) rather than hard-coding the send.
#   (c) RUST-UNIT — ndn-fwd-core strategy tests + ndn-embedded tests pass.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)
FWD=crates/ndn-embedded/src/forwarder.rs

grep -rqE 'trait Strategy' "$CRATE_DIR/src/strategy.rs" 2>/dev/null || { echo "FAIL: no Strategy trait" >&2; fail=1; }
grep -rqE 'struct BestRoute' "$CRATE_DIR/src/strategy.rs" 2>/dev/null || { echo "FAIL: no BestRoute" >&2; fail=1; }
grep -rqE 'struct Multicast' "$CRATE_DIR/src/strategy.rs" 2>/dev/null || { echo "FAIL: no Multicast" >&2; fail=1; }
grep -qE 'BestRoute\.decide\(' "$FWD" || { echo "FAIL: embedded forwarder does not drive a strategy" >&2; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core strategy && cargo test -p ndn-embedded"
    if ! cargo test --quiet -p ndn-fwd-core strategy >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-embedded >/dev/null 2>&1; then
        echo "FAIL: strategy seam tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-15 — shared Strategy seam; embedded drives BestRoute through it."
exit "$fail"
