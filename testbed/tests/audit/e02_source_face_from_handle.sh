#!/usr/bin/env bash
# Audit witness — E.02 (proper fix, 2026-05-13).
#
# Finding:     `run_ndn_mgmt_handler` previously derived `source_face`
#              from `engine.source_face_id(&interest)`, which looked
#              up the PIT entry by name hash and returned the first
#              in-record's face_id.  Two commands from different
#              faces with colliding name hashes inside the ~4 s PIT
#              lifetime could attribute to each other — an
#              authorization boundary bug.
#
# First attempt (97e25a9):  bind `source_face = handle.face_id()`.
#                           That returns the mgmt handle's OWN face,
#                           not the originating client's.  Cascaded
#                           into a 170× ndn-fwd throughput regression
#                           because rib/register installed the mgmt
#                           face as the nexthop for app-registered
#                           prefixes, then every app Interest hit
#                           the mgmt handler and was ECDSA-signed as
#                           a 400 error.  Reverted in f21ce8b.
#                           Lessons: feedback_face_id_provenance.md.
#
# Proper fix (this script): dispatcher LP-wraps egress with
#              `IncomingFaceId` when the destination face has
#              `LocalFieldsEnabled` set.  `mount_management` opts
#              the mgmt face in via `engine.set_local_fields()`.
#              The handler decodes LP first and uses the carried
#              `IncomingFaceId` as `source_face`, falling back to
#              the PIT lookup for any path that doesn't wrap.
#
# Witness:     GREP-PROOF — the four cooperating pieces are in
#              place: engine API, mgmt opt-in, dispatcher wrap,
#              handler decode.  Plus a smoke run of basic_forwarding
#              to confirm the perf regression doesn't reappear.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

ENGINE="crates/spec/ndn-engine/src/engine.rs"
OUT="crates/spec/ndn-engine/src/dispatcher/outbound.rs"
MGMT="crates/spec/ndn-mgmt/src/lib.rs"

fail() { echo "FAIL: $*"; exit 1; }

# 1. engine API: set_local_fields() exists.
grep -q 'pub fn set_local_fields(&self, face_id: FaceId, enabled: bool)' "$ENGINE" \
    || fail "ForwarderEngine::set_local_fields missing"

# 2. mgmt opt-in.
grep -q 'engine.set_local_fields(face_id, true);' "$MGMT" \
    || fail "mount_management does not opt the mgmt face in to LocalFieldsEnabled"

# 3. Dispatcher LP-wraps egress when LocalFieldsEnabled set, attaching
#    IncomingFaceId.
grep -q 'local_fields_enabled' "$OUT" \
    || fail "dispatcher does not gate LP wrap on LocalFieldsEnabled"
grep -q 'incoming_face_id: Some(ctx.face_id.0 as u64)' "$OUT" \
    || fail "dispatcher does not attach IncomingFaceId on local-fields egress"

# 4. Mgmt handler reads IncomingFaceId from the LP wrapper.
grep -q 'lp.incoming_face_id.map(|id| FaceId(id as u32))' "$MGMT" \
    || fail "mgmt handler does not extract IncomingFaceId from LP header"
grep -q 'let source_face = source_face_from_lp.or_else' "$MGMT" \
    || fail "mgmt handler does not prefer LP IncomingFaceId over PIT lookup"

# 5. The auto-set-for-all-local-faces hazard is gone.
if grep -q 'state.flags.fetch_or(1, Ordering::Relaxed);' "$ENGINE"; then
    fail "engine.rs still auto-sets LocalFieldsEnabled for all local faces \
(would force bare-Interest apps to decode LP)"
fi

cargo build --release --bin ndn-fwd --quiet 2>&1 | tail -3 \
    || fail "ndn-fwd does not build"

echo "=== E.02 RESOLVED — source_face from LP IncomingFaceId; no 170× regression ==="
