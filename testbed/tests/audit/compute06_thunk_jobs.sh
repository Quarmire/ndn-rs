#!/usr/bin/env bash
# Witness — C-COMPUTE-06: long-running jobs via thunks (Tier 3).
#
# Finding:   docs/notes/compute-design-2026-05-21.md § 12 (C-COMPUTE-06);
#            wire spec § 7 / § 11 (Thunk TLVs 0xC910/0xC911/0xC913).
# Severity:  MAJOR (feature contract)
# Witnesses: RUST-UNIT:
#              - thunk::tests::thunk_round_trip   (Thunk TLV encode/decode)
#              - job_thunk_handshake_and_sharing  (fetch -> thunk -> poll;
#                                                  identical args share a job)
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if ! cargo test -p ndn-compute --lib --quiet thunk:: \
        >/tmp/compute06_witness.log 2>&1; then
    fail=1
fi
if ! cargo test -p ndn-compute --test end_to_end --quiet \
        job_thunk_handshake_and_sharing \
        >>/tmp/compute06_witness.log 2>&1; then
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "=== C-COMPUTE-06 PASS — thunk encode/decode + job poll handshake ==="
    exit 0
fi
echo "=== C-COMPUTE-06 FAIL ==="
cat /tmp/compute06_witness.log
exit 1
