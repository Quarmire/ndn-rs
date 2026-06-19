#!/usr/bin/env bash
# Witness test for audit findings B.01 / B.09 — NDNLPv2 link-layer
# reliability emits `Sequence` (TLV-TYPE 0x51) where the spec requires
# `TxSequence` (TLV-TYPE 0x0348). B.09 is the consequence: a fragmented
# + reliably-tracked LP packet cannot represent both fields because the
# encoder uses one slot for both purposes.
#
# Finding:     testbed/EXPECTED_FAILURES.md § B.01 + B.09
# Severity:    BLOCKER
# Spec ref:    NDNLPv2 Link-Layer Reliability;
#              ndn-cxx lp/tlv.hpp:39,51 (Sequence=81, TxSequence=840);
#              NFD daemon/face/lp-reliability.cpp:73-83 (orthogonal fields)
# Witnesses:   The ndn-packet RUST-UNIT tests
#              `b01_b09_reliable_wire_uses_tx_sequence` and
#              `b09_fragmented_reliable_carries_both_sequences` exercise
#              the wire-format invariant directly: a reliable LP frame
#              must contain `FD 03 48` (TxSequence varnumber); a
#              fragmented + reliable frame must additionally contain a
#              `Sequence` (0x51) header.
#
# Today (B.01 + B.09 unfixed): the unit test panics because the encoder
#                              writes 0x51 instead of 0x0348.
# After fix:                   the encoder writes 0x0348 and the test
#                              passes.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo not in PATH" >&2
    exit 2
fi

if cargo test -p ndn-packet --features std --lib --quiet b01_b09_ \
       >/tmp/b01_witness.log 2>&1; then
    echo "=== B.01 + B.09 RESOLVED — TxSequence emitted; fragmented frames carry both ==="
    exit 0
else
    echo "=== B.01 / B.09 EXPECTED-FAIL — encoder still writes Sequence (0x51) ==="
    cat /tmp/b01_witness.log
    exit 1
fi
