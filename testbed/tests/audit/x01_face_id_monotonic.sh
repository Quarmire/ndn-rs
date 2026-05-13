#!/usr/bin/env bash
# Audit witness — X.01 FaceId monotonic / ABA hazard closed.
#
# Finding:     FaceTable previously recycled face IDs via a free list,
#              opening a classic ABA window: face X (id N) closes →
#              N pushed onto free list → face Y allocated and gets N →
#              any code holding "id N" (NDNLPv2 IncomingFaceId tag,
#              source_face captured before an await, etc.) now points
#              to Y instead of the closed X.
#
# Fix:         FaceId widened to u64, alloc_id() is monotonic
#              (fetch_add), no free list.  Mirrors NFD
#              (daemon/fw/face-table.cpp:58 `++m_lastFaceId` on
#              uint64_t).  At 1 M alloc/sec the counter takes ~580 000
#              years to wrap.
#
# Witness:     GREP-PROOF + RUST-UNIT
#                - FaceTable has no `free:` field
#                - alloc_id() does not consult a free list
#                - remove() does not push to a free list
#                - FaceId backing is u64
#                - face_table::tests::ids_never_recycle round-trips
#                  that the second alloc after a remove yields a NEW
#                  id, not the removed one
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

FT="crates/spec/ndn-transport/src/face_table.rs"
FC="crates/spec/ndn-transport/src/face.rs"

fail() { echo "FAIL: $*"; exit 1; }

# 1. FaceId is u64.
grep -q 'pub struct FaceId(pub u64)' "$FC" \
    || fail "FaceId is not u64 (ABA window still wide via u32 wrap)"

# 2. No free list / recycling left in FaceTable.
if grep -q '^\s*free:' "$FT"; then
    fail "FaceTable still has a free-list field"
fi
if grep -q 'free\.pop()' "$FT"; then
    fail "alloc_id() still pops from a free list"
fi
if grep -q 'free\.push(' "$FT"; then
    fail "remove() still pushes to a free list"
fi

# 3. alloc_id is monotonic.
grep -q 'AtomicU64' "$FT" \
    || fail "next_id is not AtomicU64"
grep -q 'fetch_add(1' "$FT" \
    || fail "alloc_id is not monotonic fetch_add"

# 4. Behavioral check.
cargo test -p ndn-transport --quiet face_table 2>&1 | tail -5 \
    || fail "face_table tests fail (ids_never_recycle may have regressed)"

echo "=== X.01 RESOLVED — FaceId monotonic u64; ABA window closed ==="
