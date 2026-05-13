#!/usr/bin/env bash
# Audit witness — E.02.
#
# Finding:     `run_ndn_mgmt_handler` derived `source_face` from
#              `engine.source_face_id(&interest)`, which looked up
#              the PIT entry by the same name hash the command
#              Interest had and returned the first in-record's
#              face_id.  If two commands from different faces
#              happened to collide on name hash within the ~4s
#              PIT lifetime, the second's `source_face` could
#              resolve to the first's face_id — an authorization
#              boundary bug.
# Witness:     GREP-PROOF — `InProcHandle` now exposes the paired
#              `InProcFace.id` via `face_id()`, and the mgmt
#              handler binds `source_face = Some(handle.face_id())`
#              directly.  No PIT lookup on the authorisation path.
# Spec ref:    NFD binds command source face to the LinkService
#              of the incoming face, not the PIT.
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

LOCAL="crates/spec/ndn-face-local/src/lib.rs"
MGMT="crates/spec/ndn-mgmt/src/lib.rs"

if ! grep -q 'pub fn face_id(&self) -> FaceId' "$LOCAL"; then
    echo "FAIL: InProcHandle::face_id accessor missing"
    exit 1
fi

if ! grep -q 'let source_face = Some(handle.face_id());' "$MGMT"; then
    echo "FAIL: mgmt handler does not bind source_face from InProcHandle"
    exit 1
fi

if ! cargo build -p ndn-mgmt -p ndn-face-local --quiet 2>&1 | tail -3; then
    echo "FAIL: build broken"
    exit 1
fi

echo "=== E.02 RESOLVED — mgmt source_face bound to InProcHandle, not PIT ==="
