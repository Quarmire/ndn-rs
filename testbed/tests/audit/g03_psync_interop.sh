#!/usr/bin/env bash
# Witness test for audit finding G.03 — PSync live C++ interop.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.03
# Severity:    BLOCKED-BY-INTEROP (this script discharges the marker when it exits 0)
# Spec ref:    PSync/PSync/full-producer.{hpp,cpp}, consumer.{hpp,cpp}
# Witnesses:   A C++ PSync FullProducer and a Rust Consumer converge on N
#              item inserts in a shared NFD topology.
#
# Expected today: FAIL (exit 1).  The BLOCKED-BY-INTEROP marker remains
#                 until this script exits 0 with a live transcript.
#
# Exit codes:
#   0 — PASS (live convergence witnessed)
#   1 — FAIL or prerequisites not met
#   2 — SKIP
set -euo pipefail

PSYNC_SRC="${PSYNC_SRC:-$HOME/Documents/Dev/PSync}"

if [ ! -d "$PSYNC_SRC" ]; then
    echo "SKIP: PSync source not found at $PSYNC_SRC" >&2
    exit 2
fi

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
if [ ! -S "$NFD_SOCK" ]; then
    echo "SKIP: NFD socket not found at $NFD_SOCK (is NFD running?)" >&2
    exit 2
fi

# Build C++ examples
PSYNC_BUILD="$PSYNC_SRC/build"
mkdir -p "$PSYNC_BUILD"
(
    cd "$PSYNC_BUILD"
    cmake .. -DCMAKE_BUILD_TYPE=Release 2>&1 | tail -5
    make -j"$(nproc)" full-producer 2>&1 | tail -5
) || { echo "FAIL: C++ PSync examples failed to build" >&2; exit 1; }

CPP_FULL_PRODUCER="$PSYNC_BUILD/examples/full-producer"
if [ ! -x "$CPP_FULL_PRODUCER" ]; then
    echo "FAIL: C++ full-producer binary not found" >&2; exit 1
fi

SYNC_PREFIX="/ndn/audit/g03/psync"

echo "Starting C++ FullProducer …"
"$CPP_FULL_PRODUCER" "$SYNC_PREFIX" /alice &
CPP_PID=$!
trap 'kill $CPP_PID 2>/dev/null; wait $CPP_PID 2>/dev/null' EXIT
sleep 1

# TODO: wire up the Rust psync Consumer CLI in ndn-tools, then:
#   ndn-psync-consumer "$SYNC_PREFIX" --count 5 --timeout 5
# and assert that 5 updates arrive.
#
# The BLOCKED-BY-INTEROP marker stays in place until a live transcript exists.
echo "FAIL: Rust psync-consumer CLI not yet implemented in ndn-tools." >&2
echo "      Add ndn-tools/src/bin/psync_consumer.rs, then update this script." >&2
exit 1
