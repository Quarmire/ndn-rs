#!/usr/bin/env bash
# Witness test for audit findings D.01 / I.09 — HopLimit not decremented
# on the incoming forwarder pipeline.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.01
# Severity:    BLOCKER
# Spec ref:    NFD `daemon/fw/forwarder.cpp:104-111`; ndnd
#              `fw/fw/thread.go:190-195` — both decrement HopLimit on
#              the incoming pipeline after the zero-check.
# Witnesses:   Three RUST-UNIT tests in `ndn-engine`'s decode stage:
#                - d01_decode_stage_decrements_hop_limit
#                - d01_decode_stage_drops_when_hop_limit_zero
#                - d01_decode_stage_no_hop_limit_passes_through
#              plus two helper-level tests in ndn-packet
#              (d01_decrement_hop_limit_*).
#
# Live tcpdump verification on the egress face is BLOCKED-BY-INTEROP
# until the testbed wires up a tcpdump-capable container; the
# RUST-UNIT witness covers the in-process decrement.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-packet --features std --lib --quiet d01_decrement_hop_limit \
        >/tmp/d01_witness.log 2>&1; then
    echo "ok: ndn-packet helper (decrement_hop_limit)"
else
    echo "FAIL: ndn-packet helper"; fail=1
fi
if cargo test -p ndn-engine --lib --quiet d01_decode_stage \
        >>/tmp/d01_witness.log 2>&1; then
    echo "ok: ndn-engine decode stage"
else
    echo "FAIL: ndn-engine decode stage"; fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.01 / I.09 RESOLVED — HopLimit decremented on incoming pipeline ==="
    exit 0
else
    echo
    echo "=== D.01 / I.09 EXPECTED-FAIL — HopLimit not decremented before forward ==="
    cat /tmp/d01_witness.log
    exit 1
fi
