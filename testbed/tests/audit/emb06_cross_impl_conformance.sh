#!/usr/bin/env bash
# Witness for EMB-06 — shared cross-impl forwarding conformance suite.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2 (step 1)
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — a conformance test module exists that drives the SAME
#       Interest/Data vectors through both the native and embedded forwarders
#       and asserts identical PIT/FIB/CS outcomes (tagged `cross_impl` /
#       `conformance`).
#   (b) RUST-UNIT  — that suite compiles and passes.
#   This is the cheap bound on *semantic* divergence while code is still
#   duplicated — it must exist before, and outlive, the pure-fn extraction.
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Expected today: FAIL (exit 1) — no cross-impl conformance suite exists.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0

# (a) Locate a conformance suite that names both forwarders.
HITS=$(grep -rlnE 'cross.?impl|conformance' --include='*.rs' \
        crates/extension/ndn-embedded crates/spec/ndn-engine tests 2>/dev/null \
        | xargs -r grep -lE 'ndn_embedded' 2>/dev/null || true)
if [ -z "$HITS" ]; then
    echo "FAIL: no cross-impl conformance suite found (native vs embedded vectors)" >&2
    fail=1
fi

# (b) If present, it must pass. Scope to the embedded crate's tests.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-embedded conformance"
    if ! cargo test --quiet -p ndn-embedded conformance >/dev/null 2>&1; then
        echo "FAIL: cross-impl conformance suite did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-06 — cross-impl forwarding conformance suite present and green."
exit "$fail"
