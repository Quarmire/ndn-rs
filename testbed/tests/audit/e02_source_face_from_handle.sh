#!/usr/bin/env bash
# Audit witness — E.02 source-face provenance via in-process tag bag.
#
# Finding history
# ---------------
# Original (2026-04-20): `run_ndn_mgmt_handler` derived `source_face`
#   from `engine.source_face_id(&interest)` — a PIT name-hash lookup
#   that could attribute two commands with colliding hashes inside the
#   ~4 s PIT lifetime to each other.  Authorization-boundary bug.
#
# First fix attempt (97e25a9):  `source_face = handle.face_id()` — but
#   that's the mgmt channel's own face, not the originator.  Caused a
#   170× ndn-fwd throughput regression because rib/register installed
#   the mgmt face as nexthop for app prefixes.  Hotfix revert in
#   a5f7792.  Lessons: feedback_face_id_provenance.md.
#
# Second fix (a2f7b6b):  dispatcher LP-wrapped egress to a
#   `LocalFieldsEnabled` face with `IncomingFaceId`; handler decoded
#   LP and used the carried id.  Worked, but pay encode/decode cost
#   per mgmt Interest and needed a per-face opt-in flag.
#
# Current fix (2026-05-13, tag bag):  mirrors NFD's
#   `IncomingFaceIdTag` (daemon/face/face-common.hpp).  The dispatcher
#   calls `face.send_with_source(bytes, ctx.face_id)` on every egress;
#   `InProcFace` overrides that to deliver a `TaggedBytes { wire,
#   source_face: Some(_) }` on its app channel; mgmt reads it back
#   via `recv_tagged()`.  No LP wrapping, no opt-in flag.
#
# Witness:   GREP-PROOF.
#   - InProcFace overrides `send_with_source`.
#   - InProcHandle exposes `recv_tagged`.
#   - dispatcher calls `enqueue_send_with_source` with ctx.face_id on
#     the Forward path.
#   - mgmt handler reads source via `recv_tagged` + `tagged.source_face`.
#   - The legacy LP-wrap-on-LocalFieldsEnabled branch is gone from
#     the dispatcher.
#   - Smoke build of ndn-fwd.
#
# Exit codes:  0 PASS / 1 FAIL.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

FACE_LOCAL="crates/spec/ndn-face-local/src/lib.rs"
OUT="crates/spec/ndn-engine/src/dispatcher/outbound.rs"
MGMT="crates/spec/ndn-mgmt/src/lib.rs"
TRANSPORT="crates/spec/ndn-transport/src/face.rs"

fail() { echo "FAIL: $*"; exit 1; }

# 1. Face trait offers send_with_source.
grep -q 'fn send_with_source' "$TRANSPORT" \
    || fail "Face trait lacks send_with_source extension point"

# 2. InProcFace overrides send_with_source to deliver a TaggedBytes.
grep -q 'async fn send_with_source' "$FACE_LOCAL" \
    || fail "InProcFace does not override Face::send_with_source"
grep -q 'source_face: Some(source)' "$FACE_LOCAL" \
    || fail "InProcFace::send_with_source does not stamp source on TaggedBytes"

# 3. InProcHandle exposes recv_tagged.
grep -q 'pub async fn recv_tagged' "$FACE_LOCAL" \
    || fail "InProcHandle has no recv_tagged accessor"

# 4. Dispatcher uses enqueue_send_with_source on the Forward branch.
grep -q 'enqueue_send_with_source(\*face_id, egress_bytes, ctx.face_id)' "$OUT" \
    || fail "dispatcher Forward branch does not pass ctx.face_id through"

# 5. Mgmt handler reads source via the tag bag.
grep -q 'handle.recv_tagged()' "$MGMT" \
    || fail "mgmt handler does not consume tagged packets"
grep -qE 'tagged(\.|\s*\.\s*\n?\s*)source_face|source_face\s*=\s*tagged' "$MGMT" \
    || fail "mgmt handler does not read source_face from the tag bag"

# 6. The retired LP-IncomingFaceId-on-LocalFieldsEnabled branch is gone.
if grep -q 'incoming_face_id: Some(ctx.face_id' "$OUT"; then
    fail "dispatcher still LP-wraps with IncomingFaceId on local fields"
fi
if grep -q 'engine.set_local_fields(face_id, true)' "$MGMT"; then
    fail "mount_management still opts into LocalFieldsEnabled (no longer needed)"
fi

cargo build --release --bin ndn-fwd --quiet 2>&1 | tail -3 \
    || fail "ndn-fwd does not build"

echo "=== E.02 RESOLVED — source_face via tag-bag (NFD IncomingFaceIdTag parity) ==="
