#!/usr/bin/env bash
# Witness test for audit finding N.01 — `ReassemblyBuffer::process`
# allocates `vec![None; FragCount]` without bounding `FragCount`,
# allowing an unauthenticated peer to crash the forwarder by sending
# a single fragment with `FragCount = u32::MAX`.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.01
# Severity:    BLOCKER (security)
# Spec ref:    NFD `daemon/face/lp-reassembler.hpp:52-56`
#              (`nMaxFragments = 400`).
# Witnesses:   Two RUST-UNIT tests in `ndn-packet`:
#                - n01_oversized_frag_count_does_not_allocate
#                - n01_frag_count_at_limit_is_accepted
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-packet --features std --lib --quiet n01_ \
        >/tmp/n01_witness.log 2>&1; then
    echo "=== N.01 RESOLVED — FragCount capped at MAX_FRAGMENTS=400 before allocation ==="
    exit 0
else
    echo "=== N.01 EXPECTED-FAIL — FragCount unbounded; ReassemblyBuffer panics or OOMs ==="
    cat /tmp/n01_witness.log
    exit 1
fi
