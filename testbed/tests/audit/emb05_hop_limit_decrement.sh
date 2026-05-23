#!/usr/bin/env bash
# Witness for EMB-05 — embedded forwarder decrements HopLimit (no silent loops).
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 0, § 2 (step 1)
# Severity:    forwarding-semantics divergence (BLOCKER for native-compat)
# Spec ref:    NDN Packet Spec — HopLimit MUST be decremented before forwarding;
#              an Interest with HopLimit 0 MUST NOT be forwarded.
# Witnesses:
#   (a) GREP-PROOF — the "Hop limit decrement is skipped" excuse comment is gone
#       from ndn-embedded/src/forwarder.rs.
#   (b) GREP-PROOF — the forwarder actually decrements before re-emitting, via
#       the shared wire helper `decrement_hop_limit_in_place` (the byte-level
#       arithmetic lives once in ndn-packet, beside `decrement_hop_limit`).
#   This is a real semantics gap, not an optimization: a loop the native engine
#   breaks, the embedded one currently won't.
#
# Reverify recipe: GREP-PROOF. Runs in any checkout; no Docker.
#
# Expected today: FAIL (exit 1) — forwarder.rs:74 documents skipping the decrement.
#
# Exit codes: 0 PASS · 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
FWD=crates/ndn-embedded/src/forwarder.rs

if [ ! -f "$FWD" ]; then
    echo "FAIL: $FWD not found" >&2
    exit 1
fi

if grep -qiE 'hop limit decrement is skipped|forwarding raw bytes is acceptable' "$FWD"; then
    echo "FAIL: $FWD still documents skipping the HopLimit decrement" >&2
    fail=1
fi

if ! grep -qE 'decrement_hop_limit_in_place|hop_limit\s*-\s*1|saturating_sub\s*\(\s*1\s*\)|hop_limit\s*-=\s*1' "$FWD"; then
    echo "FAIL: $FWD never decrements hop_limit on the forwarding path" >&2
    fail=1
fi
# The shared in-place helper must exist in ndn-packet (its rightful home).
if ! grep -qE 'pub fn decrement_hop_limit_in_place' crates/ndn-packet/src/interest.rs; then
    echo "FAIL: ndn-packet lacks decrement_hop_limit_in_place (no-alloc wire helper)" >&2
    fail=1
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-05 — embedded forwarder decrements HopLimit before forwarding."
exit "$fail"
