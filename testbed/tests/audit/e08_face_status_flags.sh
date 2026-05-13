#!/usr/bin/env bash
# Audit witness — E.08.
#
# Finding:     `FaceStatus` omitted `Flags` (0x6c),
#              `NSatisfiedInterests` (0x99), and
#              `NUnsatisfiedInterests` (0x9a) TLVs.  ndn-cxx
#              tlv-nfd.hpp lists all three (lines 42, 86, 87) and
#              `nfdc face list` displays them.
# Witness:     RUST-UNIT
#                e08_face_status_emits_flags_and_satisfaction_counters
#                face_status_roundtrip (round-trips the new fields)
# Spec ref:    ndn-cxx ndn-cxx/encoding/tlv-nfd.hpp Flags=108,
#              NSatisfiedInterests=153, NUnsatisfiedInterests=154.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

if ! cargo test -p ndn-config --lib --quiet \
        e08_face_status_emits_flags_and_satisfaction_counters 2>&1 | tail -5; then
    echo "FAIL: E.08 emit-tlv test"
    exit 1
fi
if ! cargo test -p ndn-config --lib --quiet \
        face_status_roundtrip 2>&1 | tail -5; then
    echo "FAIL: E.08 roundtrip test"
    exit 1
fi
echo "=== E.08 RESOLVED — FaceStatus emits Flags/NSatisfied/NUnsatisfied ==="
