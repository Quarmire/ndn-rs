#!/usr/bin/env bash
# Witness test for audit finding G.03 — PSync's IBF uses a custom
# splitmix64 + multiply hash family instead of MurmurHash3.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.03
# Severity:    BLOCKER
# Spec ref:    PSync `detail/util.cpp::murmurHash3` (Austin Appleby's
#              MurmurHash3_x86_32) + `detail/iblt.hpp` constants
#              `N_HASH = 3` (cell-selection seeds) and
#              `N_HASHCHECK = 11` (keyCheck seed).
# Witnesses:   Two RUST-UNIT tests in `ndn-sync`:
#                - g03_ibf_cell_hash_is_murmur3
#                  (per-cell hash check uses Murmur3, seed = 11)
#                - g03_ibf_cell_indices_use_murmur3_seeds
#                  (k = 3 cell-selection hashes use Murmur3, seeds 0..2)
#
# This is the architecture-side witness. Full PSync wire interop
# against the C++ peer is still BLOCKED-BY-INTEROP — the cell width
# (PSync uses uint32_t key sums, ndn-rs's IBF uses u64), the IBF TLV
# wire shape, and the segmented Sync Data flow all need their own
# work before live interop is possible.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-sync --lib --quiet g03_ \
        >/tmp/g03_witness.log 2>&1; then
    echo "=== G.03 RESOLVED (architecture) — IBF hash family is MurmurHash3 ==="
    exit 0
else
    echo "=== G.03 EXPECTED-FAIL — IBF still uses custom splitmix64 + multiply ==="
    cat /tmp/g03_witness.log
    exit 1
fi
